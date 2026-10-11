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

const Crc32Tee = tee.CountingTee(.{ .crc32 = true });
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
    provider: checksum.Provider = checksum.default_provider,
};

const magic_1 = 0x1f;
const magic_2 = 0x8b;
const cm_deflate = 8;
const flag_text = 0x01;
const flag_header_crc = 0x02;
const flag_extra = 0x04;
const flag_name = 0x08;
const flag_comment = 0x10;
const reserved_flags = 0xe0;

pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    var wrapper_size: usize = 18;
    if (options.extra.len != 0) wrapper_size +|= 2 +| options.extra.len;
    if (options.name.len != 0) wrapper_size +|= options.name.len +| 1;
    if (options.comment.len != 0) wrapper_size +|= options.comment.len +| 1;
    if (options.header_crc) wrapper_size +|= 2;
    return deflate.encodedSizeBound(input_len) +| wrapper_size;
}

pub fn decodedSize(input: []const u8, history: []u8, provider: checksum.Provider) Failure!usize {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var counter = measurement.Counter.init(null);
    _ = try decode(input, &counter.writer, history, provider);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub const SinglePass = union(enum) {
    decoded: usize,
    fallback: void,
};

// ISIZE only seeds the attempt; commit needs exact count, CRC32, and trailer.
// Mismatch defers to the two-pass route.
pub fn decodeSinglePass(input: []const u8, output: []u8, history: []u8, provider: checksum.Provider) Failure!SinglePass {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    if (input.len >= std.math.maxInt(u32)) return .fallback;
    // The 10 byte header and the 8 byte trailer need 18 bytes before any deflate data is read.
    if (input.len < 18) return .fallback;
    const claimed_size = std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little);
    if (output.len < claimed_size) return .fallback;
    var source = std.Io.Reader.fixed(input);
    var fixed_header: [10]u8 = undefined;
    var index: usize = 0;
    while (index < fixed_header.len) {
        fixed_header[index] = source.takeByte() catch return .fallback;
        index += 1;
    }
    skipHeader(&source, &fixed_header, provider) catch return .fallback;
    const data_start = source.seek;
    var sink_writer = std.Io.Writer.fixed(output);
    var tee_writer = Crc32Tee.initWithProvider(&sink_writer, provider);
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

pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8, provider: checksum.Provider) Failure!usize {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var source = std.Io.Reader.fixed(input);
    var total: usize = 0;
    while (true) {
        var fixed_header: [10]u8 = undefined;
        var index: usize = 0;
        while (index < fixed_header.len) {
            const byte = source.takeByte() catch {
                if (index == 0) break;
                return error.InvalidData;
            };
            fixed_header[index] = byte;
            index += 1;
        }
        if (index == 0) break;
        try skipHeader(&source, &fixed_header, provider);
        var tee_writer = Crc32Tee.initWithProvider(output, provider);
        const data_start = source.seek;
        var inflater = deflate.Decompress.initSlice(input[data_start..], history);
        const produced = inflater.reader.streamRemaining(&tee_writer.writer) catch |err| {
            return switch (err) {
                error.WriteFailed => error.IoFailure,
                else => error.InvalidData,
            };
        };
        total = try bounds.addUsize(total, produced);
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
    // Optimal mode carves scratch past deflate_history_size, so the full slice is required.
    var compressor = try deflate.Compress.init(output, history, options.deflate);
    var crc32 = checksum.Crc32.bind(options.provider);
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
        crc32.update(part);
        total = try bounds.addU64(total, @intCast(count));
        compressor.writer.writeAll(part) catch return error.IoFailure;
    }
    compressor.finish() catch return error.IoFailure;
    try writeTrailer(output, crc32.final(), total);
}

fn skipHeader(source: *std.Io.Reader, fixed_header: *[10]u8, provider: checksum.Provider) Failure!void {
    if (fixed_header[0] != magic_1 or fixed_header[1] != magic_2) return error.InvalidData;
    if (fixed_header[2] != cm_deflate) return error.Unsupported;
    const flags = fixed_header[3];
    if (flags & reserved_flags != 0) return error.InvalidData;
    var hasher = checksum.Crc32.bind(provider);
    hasher.update(fixed_header);
    if (flags & flag_extra != 0) {
        const low = source.takeByte() catch return error.InvalidData;
        const high = source.takeByte() catch return error.InvalidData;
        hasher.update(&.{ low, high });
        var remaining: u16 = (@as(u16, high) << 8) | low;
        while (remaining != 0) : (remaining -= 1) {
            const byte = source.takeByte() catch return error.InvalidData;
            hasher.update(&.{byte});
        }
    }
    if (flags & flag_name != 0) try skipCString(source, &hasher);
    if (flags & flag_comment != 0) try skipCString(source, &hasher);
    if (flags & flag_header_crc != 0) {
        const low = source.takeByte() catch return error.InvalidData;
        const high = source.takeByte() catch return error.InvalidData;
        const stored_crc = (@as(u16, high) << 8) | low;
        if (stored_crc != @as(u16, @truncate(hasher.final()))) return error.IntegrityFailure;
    }
}

fn skipCString(source: *std.Io.Reader, hasher: *checksum.Crc32) Failure!void {
    while (true) {
        const byte = source.takeByte() catch return error.InvalidData;
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
    var hasher = checksum.Crc32.bind(options.provider);
    var fixed_header: [10]u8 = undefined;
    fixed_header[0] = magic_1;
    fixed_header[1] = magic_2;
    fixed_header[2] = cm_deflate;
    fixed_header[3] = flags;
    std.mem.writeInt(u32, fixed_header[4..8], options.modification_time, .little);
    fixed_header[8] = options.extra_flags;
    fixed_header[9] = options.operating_system;
    hasher.update(&fixed_header);
    try io.writeBytes(writer, &fixed_header);
    if (options.extra.len != 0) {
        var xlen: [2]u8 = undefined;
        std.mem.writeInt(u16, &xlen, @intCast(options.extra.len), .little);
        hasher.update(&xlen);
        hasher.update(options.extra);
        try io.writeBytes(writer, &xlen);
        try io.writeBytes(writer, options.extra);
    }
    for ([_][]const u8{ options.name, options.comment }) |field| {
        if (field.len == 0) continue;
        hasher.update(field);
        try io.writeBytes(writer, field);
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

fn writeTrailer(writer: *std.Io.Writer, crc32: u32, uncompressed_size: u64) Failure!void {
    writer.writeInt(u32, crc32, .little) catch return error.IoFailure;
    writer.writeInt(u32, @truncate(uncompressed_size), .little) catch return error.IoFailure;
}

pub const MemberInfo = struct {
    modification_time: u32,
    extra_flags: u8,
    operating_system: u8,
    text: bool,
    header_crc: bool,
    extra: []const u8,
    name: []const u8,
    comment: []const u8,
    // Compressed payload span, including the byte-aligned padding bit.
    data_offset: usize,
    data_size: usize,
    decoded_size: usize,
    crc32: u32,
    // The whole member: header, payload, and trailer.
    total_size: usize,
};

pub const MemberIterator = struct {
    input: []const u8,
    history: []u8,
    provider: checksum.Provider,
    offset: usize = 0,

    pub fn next(self: *MemberIterator) Failure!?MemberInfo {
        if (self.offset >= self.input.len) return null;
        if (self.input.len - self.offset < 18) return error.InvalidData;
        const member = try inspectMember(self.input[self.offset..], self.history, self.provider);
        self.offset = try bounds.addUsize(self.offset, member.total_size);
        return member;
    }
};

// Enumerates the members of a (possibly concatenated) gzip stream. Each next
// call parses one member strictly: the deflate payload is decoded and the
// trailer CRC and ISIZE are verified, so a corrupt member fails at its
// ordinal rather than silently ending the walk.
pub fn inspectMembers(input: []const u8, history: []u8, provider: checksum.Provider) MemberIterator {
    return .{ .input = input, .history = history, .provider = provider };
}

fn inspectMember(input: []const u8, history: []u8, provider: checksum.Provider) Failure!MemberInfo {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var cursor: usize = 0;
    if (input[0] != magic_1 or input[1] != magic_2) return error.InvalidData;
    if (input[2] != cm_deflate) return error.Unsupported;
    const flags = input[3];
    if (flags & reserved_flags != 0) return error.InvalidData;
    var hasher = checksum.Crc32.bind(provider);
    hasher.update(input[0..10]);
    cursor = 10;
    var extra: []const u8 = &.{};
    var name: []const u8 = &.{};
    var comment: []const u8 = &.{};
    if (flags & flag_extra != 0) {
        if (input.len - cursor < 2) return error.InvalidData;
        const remaining: usize = (@as(usize, input[cursor + 1]) << 8) | input[cursor];
        hasher.update(input[cursor..][0..2]);
        cursor += 2;
        if (input.len - cursor < remaining) return error.InvalidData;
        extra = input[cursor .. cursor + remaining];
        hasher.update(extra);
        cursor += remaining;
    }
    if (flags & flag_name != 0) {
        const end = std.mem.indexOfScalarPos(u8, input, cursor, 0) orelse return error.InvalidData;
        name = input[cursor..end];
        hasher.update(input[cursor .. end + 1]);
        cursor = end + 1;
    }
    if (flags & flag_comment != 0) {
        const end = std.mem.indexOfScalarPos(u8, input, cursor, 0) orelse return error.InvalidData;
        comment = input[cursor..end];
        hasher.update(input[cursor .. end + 1]);
        cursor = end + 1;
    }
    if (flags & flag_header_crc != 0) {
        if (input.len - cursor < 2) return error.InvalidData;
        const stored_crc = (@as(u16, input[cursor + 1]) << 8) | input[cursor];
        if (stored_crc != @as(u16, @truncate(hasher.final()))) return error.IntegrityFailure;
        cursor += 2;
    }

    const data_start = cursor;
    var counter = measurement.Counter.init(null);
    var tee_writer = Crc32Tee.initWithProvider(&counter.writer, provider);
    var inflater = deflate.Decompress.initSlice(input[data_start..], history);
    _ = inflater.reader.streamRemaining(&tee_writer.writer) catch return error.InvalidData;
    const data_size = (inflater.inputBitsConsumed() + 7) / 8;
    const trailer_at = data_start + data_size;
    if (input.len - trailer_at < 8) return error.InvalidData;
    const stored_crc = std.mem.readInt(u32, input[trailer_at..][0..4], .little);
    const stored_size = std.mem.readInt(u32, input[trailer_at + 4 ..][0..4], .little);
    if (stored_crc != tee_writer.crc32Value() or stored_size != @as(u32, @truncate(tee_writer.size))) return error.IntegrityFailure;
    return .{
        .modification_time = std.mem.readInt(u32, input[4..8], .little),
        .extra_flags = input[8],
        .operating_system = input[9],
        .text = flags & flag_text != 0,
        .header_crc = flags & flag_header_crc != 0,
        .extra = extra,
        .name = name,
        .comment = comment,
        .data_offset = data_start,
        .data_size = data_size,
        .decoded_size = stored_size,
        .crc32 = stored_crc,
        .total_size = trailer_at + 8,
    };
}

test "inspectMembers enumerates concatenated members with their fields" {
    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    const options_a: Options = .{
        .modification_time = 0x01020304,
        .extra_flags = 2,
        .operating_system = 3,
        .text = false,
        .header_crc = true,
        .extra = &.{ 1, 2, 3 },
        .name = "first.bin",
        .comment = "note",
        .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
    };
    const options_b: Options = .{
        .modification_time = 0,
        .extra_flags = 0,
        .operating_system = 255,
        .text = false,
        .header_crc = false,
        .extra = &.{},
        .name = "",
        .comment = "",
        .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
    };
    const payload_a = "first member payload, first member payload, first";
    const payload_b = "second!";
    var history: [deflate_history_size]u8 = undefined;
    var r1 = std.Io.Reader.fixed(payload_a);
    var w1 = std.Io.Writer.fixed(&first);
    try encodeStream(&r1, &w1, &history, options_a);
    var r2 = std.Io.Reader.fixed(payload_b);
    var w2 = std.Io.Writer.fixed(&second);
    try encodeStream(&r2, &w2, &history, options_b);
    var combined: [512]u8 = undefined;
    @memcpy(combined[0..w1.end], first[0..w1.end]);
    @memcpy(combined[w1.end .. w1.end + w2.end], second[0..w2.end]);
    const total = w1.end + w2.end;

    var iterator = inspectMembers(combined[0..total], &history, checksum.default_provider);
    const m1 = (try iterator.next()).?;
    try std.testing.expectEqualSlices(u8, "first.bin", m1.name);
    try std.testing.expectEqualSlices(u8, "note", m1.comment);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, m1.extra);
    try std.testing.expectEqual(@as(u32, 0x01020304), m1.modification_time);
    try std.testing.expectEqual(payload_a.len, m1.decoded_size);
    try std.testing.expect(m1.data_offset < total and m1.total_size < total);
    const m2 = (try iterator.next()).?;
    try std.testing.expectEqual(payload_b.len, m2.decoded_size);
    try std.testing.expectEqual(@as(usize, 255), m2.operating_system);
    try std.testing.expectEqual(total, m1.total_size + m2.total_size);
    try std.testing.expect((try iterator.next()) == null);
}
