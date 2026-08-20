const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");
const tee = @import("../common/primitive/tee.zig");
const deflate = @import("../leaf/deflate.zig");
pub const deflate_history_size = deflate.history_size;

const GzipTee = tee.CountingTee(true, false);
pub const Options = struct {
    modification_time: u32,
    extra_flags: u8,
    operating_system: u8,
    text: bool,
    header_crc: bool,
    extra: []const u8,
    name: []const u8,
    comment: []const u8,
    deflate: deflate.Options,
};

const id1 = 0x1f;
const id2 = 0x8b;
const compression_method = 8;
const flag_text = 0x01;
const flag_header_crc = 0x02;
const flag_extra = 0x04;
const flag_name = 0x08;
const flag_comment = 0x10;
const reserved_flags = 0xe0;

// The wrapper is the 10-byte header, the option-driven optional fields, and
// the 8-byte trailer; the deflate payload carries its own structural bound.
pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    var wrapper: usize = 18;
    if (options.extra.len != 0) wrapper +|= 2 +| options.extra.len;
    if (options.name.len != 0) wrapper +|= options.name.len +| 1;
    if (options.comment.len != 0) wrapper +|= options.comment.len +| 1;
    if (options.header_crc) wrapper +|= 2;
    return deflate.encodedSizeBound(input_len) +| wrapper;
}

pub fn decodedSize(input: []const u8, history: []u8) Failure!usize {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var counter = measurement.Counter.init(null);
    _ = try decode(input, &counter.writer, history);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub const SinglePass = union(enum) {
    decoded: usize,
    fallback: void,
};

// KD3 fast path: one inflate straight into the caller's span for a
// single-member stream. The tail ISIZE is trusted only far enough to start;
// the result commits only when the decoded count equals ISIZE exactly (the
// truncated comparison in decode would accept a wrapped size), the CRC32
// matches, and the member trailer ends exactly at the input end. Every
// anomaly — multi-member evidence, an input of 4 GiB or more (ISIZE wraps at
// 2^32), a count or CRC mismatch, a mid-stream capacity excess — defers to
// the two-pass route, which recomputes the exact size and answers capacity
// before any further write.
pub fn decodeSinglePass(input: []const u8, output: []u8, history: []u8) Failure!SinglePass {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    if (input.len >= std.math.maxInt(u32)) return .fallback;
    if (input.len < 18) return .fallback;
    const claimed_size = std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little);
    if (output.len < claimed_size) return .fallback;
    var source = std.Io.Reader.fixed(input);
    var fixed: [10]u8 = undefined;
    var index: usize = 0;
    while (index < fixed.len) {
        fixed[index] = source.takeByte() catch return .fallback;
        index += 1;
    }
    skipHeader(&source, &fixed) catch return .fallback;
    const data_start = source.seek;
    var sink_writer = std.Io.Writer.fixed(output);
    var tee_writer = GzipTee.init(&sink_writer);
    var inflater = deflate.Decompress.initSlice(input[data_start..], history);
    _ = inflater.reader.streamRemaining(&tee_writer.writer) catch return .fallback;
    source.seek = data_start + (inflater.inputBitsConsumed() + 7) / 8;
    var trailer: [8]u8 = undefined;
    var trailer_sink = std.Io.Writer.fixed(&trailer);
    source.streamExact(&trailer_sink, 8) catch return .fallback;
    if (source.seek != input.len) return .fallback;
    const stored_crc = std.mem.readInt(u32, trailer[0..4], .little);
    const stored_size = std.mem.readInt(u32, trailer[4..8], .little);
    if (tee_writer.size != stored_size or stored_crc != tee_writer.crc32Value()) return .fallback;
    return .{ .decoded = @intCast(tee_writer.size) };
}

pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8) Failure!usize {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var source = std.Io.Reader.fixed(input);
    var total: usize = 0;
    while (true) {
        var fixed: [10]u8 = undefined;
        var index: usize = 0;
        while (index < fixed.len) {
            const byte = source.takeByte() catch {
                if (index == 0) break;
                return error.InvalidData;
            };
            fixed[index] = byte;
            index += 1;
        }
        if (index == 0) break;
        try skipHeader(&source, &fixed);
        var tee_writer = GzipTee.init(output);
        const data_start = source.seek;
        var inflater = deflate.Decompress.initSlice(input[data_start..], history);
        const produced = inflater.reader.streamRemaining(&tee_writer.writer) catch |err| {
            return switch (err) {
                error.WriteFailed => error.IoFailure,
                else => error.InvalidData,
            };
        };
        total = try bounds.add(total, produced);
        source.seek = data_start + (inflater.inputBitsConsumed() + 7) / 8;
        var trailer: [8]u8 = undefined;
        var trailer_sink = std.Io.Writer.fixed(&trailer);
        source.streamExact(&trailer_sink, 8) catch return error.InvalidData;
        const stored_crc = std.mem.readInt(u32, trailer[0..4], .little);
        const stored_size = std.mem.readInt(u32, trailer[4..8], .little);
        if (stored_crc != tee_writer.crc32Value() or stored_size != @as(u32, @truncate(tee_writer.size))) return error.IntegrityFailure;
    }
    return total;
}

pub fn encodeStream(source: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: Options) Failure!void {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    try writeHeader(output, options);
    // The full slice goes to the compressor: optimal mode carves its scratch
    // past deflate_history_size.
    var compressor = deflate.Compress.init(output, history, options.deflate) catch |err| return err;
    var crc = checksum.Crc32.init();
    var total: u64 = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        var sink = std.Io.Writer.fixed(&buffer);
        const count = source.stream(&sink, std.Io.Limit.limited(buffer.len)) catch |err| {
            if (err == error.EndOfStream) break;
            return error.IoFailure;
        };
        if (count == 0) break;
        const part = buffer[0..count];
        crc.update(part);
        total = try bounds.add64(total, @intCast(count));
        compressor.writer.writeAll(part) catch return error.IoFailure;
    }
    compressor.finish() catch return error.IoFailure;
    try writeTrailer(output, crc.final(), total);
}

fn skipHeader(input: *std.Io.Reader, fixed: *[10]u8) Failure!void {
    if (fixed[0] != id1 or fixed[1] != id2) return error.InvalidData;
    if (fixed[2] != compression_method) return error.Unsupported;
    const flags = fixed[3];
    if (flags & reserved_flags != 0) return error.InvalidData;
    var hasher = checksum.Crc32.init();
    hasher.update(fixed);
    if (flags & flag_extra != 0) {
        const low = input.takeByte() catch return error.InvalidData;
        const high = input.takeByte() catch return error.InvalidData;
        hasher.update(&.{ low, high });
        var remaining: u16 = (@as(u16, high) << 8) | low;
        while (remaining != 0) : (remaining -= 1) {
            const byte = input.takeByte() catch return error.InvalidData;
            hasher.update(&.{byte});
        }
    }
    if (flags & flag_name != 0) try skipCString(input, &hasher);
    if (flags & flag_comment != 0) try skipCString(input, &hasher);
    if (flags & flag_header_crc != 0) {
        const low = input.takeByte() catch return error.InvalidData;
        const high = input.takeByte() catch return error.InvalidData;
        const stored = (@as(u16, high) << 8) | low;
        if (stored != @as(u16, @truncate(hasher.final()))) return error.IntegrityFailure;
    }
}

fn skipCString(input: *std.Io.Reader, hasher: *checksum.Crc32) Failure!void {
    while (true) {
        const byte = input.takeByte() catch return error.InvalidData;
        hasher.update(&.{byte});
        if (byte == 0) return;
    }
}

fn writeHeader(writer: *std.Io.Writer, options: Options) Failure!void {
    if (options.extra.len > std.math.maxInt(u16)) return error.InvalidCall;
    if (std.mem.indexOfScalar(u8, options.name, 0) != null or std.mem.indexOfScalar(u8, options.comment, 0) != null) return error.InvalidCall;
    var flags: u8 = 0;
    if (options.text) flags |= flag_text;
    if (options.header_crc) flags |= flag_header_crc;
    if (options.extra.len != 0) flags |= flag_extra;
    if (options.name.len != 0) flags |= flag_name;
    if (options.comment.len != 0) flags |= flag_comment;
    var hasher = checksum.Crc32.init();
    var fixed: [10]u8 = undefined;
    fixed[0] = id1;
    fixed[1] = id2;
    fixed[2] = compression_method;
    fixed[3] = flags;
    std.mem.writeInt(u32, fixed[4..8], options.modification_time, .little);
    fixed[8] = options.extra_flags;
    fixed[9] = options.operating_system;
    hasher.update(&fixed);
    try io.writeBytes(writer, &fixed);
    if (options.extra.len != 0) {
        var xlen: [2]u8 = undefined;
        std.mem.writeInt(u16, &xlen, @intCast(options.extra.len), .little);
        hasher.update(&xlen);
        hasher.update(options.extra);
        try io.writeBytes(writer, &xlen);
        try io.writeBytes(writer, options.extra);
    }
    for ([_][]const u8{ options.name, options.comment }) |value| {
        if (value.len == 0) continue;
        hasher.update(value);
        try io.writeBytes(writer, value);
        const zero = [_]u8{0};
        hasher.update(&zero);
        try io.writeBytes(writer, &zero);
    }
    if (options.header_crc) {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @truncate(hasher.final()), .little);
        try io.writeBytes(writer, &bytes);
    }
}

fn writeTrailer(writer: *std.Io.Writer, crc: u32, length: u64) Failure!void {
    writer.writeInt(u32, crc, .little) catch return error.IoFailure;
    writer.writeInt(u32, @truncate(length), .little) catch return error.IoFailure;
}
