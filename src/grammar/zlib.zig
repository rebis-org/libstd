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

pub const Options = struct {
    deflate: deflate.Options,
    provider: checksum.Provider = checksum.default_provider,
};

const window_size_max = 32768;
const cinfo_max = 7;
const cm_deflate = 8;
const fcheck_bits = 5;
const flag_dictionary = 0x20;
const level_default = 2;
const header_size = 2;
const trailer_size = 4;

pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    _ = options;
    return deflate.encodedSizeBound(input_len) +| (header_size + trailer_size);
}

pub const Header = struct {
    window_size: u32,
    level: u8,
    has_dictionary: bool,
};

pub fn inspect(input: []const u8) Failure!Header {
    if (input.len < header_size) return error.InvalidData;
    const cmf = input[0];
    const flg = input[1];
    if (cmf & 0x0f != cm_deflate) return error.Unsupported;
    if ((@as(u32, cmf) << 8 | flg) % 31 != 0) return error.InvalidData;
    return .{
        .window_size = @as(u32, 1) << @intCast((cmf >> 4) + 8),
        .level = flg >> 6,
        .has_dictionary = (flg & flag_dictionary) != 0,
    };
}

pub fn decodedSize(input: []const u8, history: []u8, provider: checksum.Provider) Failure!usize {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var counter = measurement.Counter.init(null);
    _ = try decode(input, &counter.writer, history, provider);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

// One stream per call: the adler32 trailer ends the stream, so trailing bytes are an error.
pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8, provider: checksum.Provider) Failure!usize {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    var source = std.Io.Reader.fixed(input);
    const cmf = source.takeByte() catch return error.InvalidData;
    const flg = source.takeByte() catch return error.InvalidData;
    const header = try inspect(&.{ cmf, flg });
    if (header.has_dictionary) return error.Unsupported;
    if (header.window_size > window_size_max) return error.Unsupported;
    var tee_writer = tee.CountingTee(.{ .adler32 = true }).initWithProvider(output, provider);
    var inflater = deflate.Decompress.initSlice(input[header_size..], history);
    const produced = inflater.reader.streamRemaining(&tee_writer.writer) catch |err| {
        return switch (err) {
            error.WriteFailed => error.IoFailure,
            else => error.InvalidData,
        };
    };
    const data_start = header_size;
    source.seek = data_start + (inflater.inputBitsConsumed() + 7) / 8;
    var trailer: [trailer_size]u8 = undefined;
    var trailer_sink = std.Io.Writer.fixed(&trailer);
    source.streamExact(&trailer_sink, trailer_size) catch return error.InvalidData;
    if (source.seek != input.len) return error.InvalidData;
    const stored_adler32 = std.mem.readInt(u32, &trailer, .big);
    if (stored_adler32 != tee_writer.adler32Value()) return error.IntegrityFailure;
    return produced;
}

pub fn encodeStream(source: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: Options) Failure!void {
    if (history.len < deflate_history_size) return error.InsufficientCapacity;
    try writeHeader(output);
    var compressor = try deflate.Compress.init(output, history, options.deflate);
    var adler32 = checksum.Adler32.bind(options.provider);
    var buffer: [4096]u8 = undefined;
    while (true) {
        var sink = std.Io.Writer.fixed(&buffer);
        const count = source.stream(&sink, std.Io.Limit.limited(buffer.len)) catch |err| {
            if (err == error.EndOfStream) break;
            return error.IoFailure;
        };
        if (count == 0) break;
        const part = buffer[0..count];
        adler32.update(part);
        compressor.writer.writeAll(part) catch return error.IoFailure;
    }
    compressor.finish() catch return error.IoFailure;
    output.writeInt(u32, adler32.final(), .big) catch return error.IoFailure;
}

fn writeHeader(writer: *std.Io.Writer) Failure!void {
    // FLEVEL 2 marks the default algorithm. The FCHECK bits of FLG make the 16 bit header a multiple of 31.
    const cmf: u8 = (cinfo_max << 4) | cm_deflate;
    var flg: u8 = level_default << 6;
    const remainder = (@as(u32, cmf) << 8 | flg) % 31;
    if (remainder != 0) flg += @intCast(31 - remainder);
    try io.writeBytes(writer, &.{ cmf, flg });
}

test "zlib round trip restores the original input" {
    const history = try std.testing.allocator.alloc(u8, deflate_history_size);
    defer std.testing.allocator.free(history);
    const input = "the quick brown fox jumps over the lazy dog, again and again and again";
    var source = std.Io.Reader.fixed(input);
    var encoded: [256]u8 = undefined;
    var sink = std.Io.Writer.fixed(&encoded);
    try encodeStream(&source, &sink, history, .{ .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 } });
    const compressed = encoded[0..sink.end];
    const info = try inspect(compressed);
    try std.testing.expectEqual(@as(u32, window_size_max), info.window_size);
    var counter = measurement.Counter.init(null);
    const produced = try decode(compressed, &counter.writer, history, checksum.default_provider);
    try std.testing.expectEqual(input.len, produced);
    var source_out: [256]u8 = undefined;
    var out_sink = std.Io.Writer.fixed(&source_out);
    _ = try decode(compressed, &out_sink, history, checksum.default_provider);
    try std.testing.expectEqualStrings(input, source_out[0..out_sink.end]);
}

test "zlib rejects a preset dictionary and trailing bytes" {
    const history = try std.testing.allocator.alloc(u8, deflate_history_size);
    defer std.testing.allocator.free(history);
    var discard_buffer: [0]u8 = .{};
    var discarding: std.Io.Writer.Discarding = .init(&discard_buffer);
    // 0x78/0x20 passes FCHECK ((0x78 << 8 | 0x20) % 31 == 0) and sets FDICT.
    try std.testing.expectError(error.Unsupported, decode(&.{ 0x78, 0x20, 0x03, 0x00, 0, 0, 0, 1 }, &discarding.writer, history, checksum.default_provider));
    const input = "payload";
    var source = std.Io.Reader.fixed(input);
    var encoded: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&encoded);
    try encodeStream(&source, &sink, history, .{ .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 } });
    var with_garbage: [65]u8 = undefined;
    @memcpy(with_garbage[0..sink.end], encoded[0..sink.end]);
    with_garbage[sink.end] = 0;
    try std.testing.expectError(error.InvalidData, decode(with_garbage[0 .. sink.end + 1], &discarding.writer, history, checksum.default_provider));
}
