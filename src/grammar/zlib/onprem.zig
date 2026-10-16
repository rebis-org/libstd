const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const exception_prim = @import("../../common/primitive/exception.zig");
const io = @import("../../common/primitive/io.zig");
const measurement = @import("../../common/primitive/measurement.zig");
const tee = @import("../../common/primitive/tee.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const deflate_seam = @import("../../leaf/deflate/seam.zig");

const Exception = exception_prim.Exception;
pub const deflate_history_size = deflate.history_size;

pub const Options = struct {
    deflate: deflate.Options,
    provider: checksum.Provider = checksum.default_provider,
};

const window_size_max = 32768;
const cinfo_max = 7;
const cm_deflate = 8;
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
    has_dictionary: bool,
};

pub fn inspect(input: []const u8) Exception!Header {
    if (input.len < header_size) return error.DataException;
    const cmf = input[0];
    const flg = input[1];
    if (cmf & 0x0f != cm_deflate) return error.UnsupportedException;
    // CINFO above 7 names a window larger than this decoder supports; refusing
    // here keeps inspect and decode symmetric instead of diverging downstream.
    if (cmf >> 4 > cinfo_max) return error.UnsupportedException;
    if ((@as(u32, cmf) << 8 | flg) % 31 != 0) return error.DataException;
    return .{
        .window_size = @as(u32, 1) << @intCast((cmf >> 4) + 8),
        .has_dictionary = (flg & flag_dictionary) != 0,
    };
}

pub fn decodedSize(input: []const u8, history: []u8, provider: checksum.Provider) Exception!usize {
    if (history.len < deflate_history_size) return error.CapacityException;
    var counter = measurement.Counter.init(null);
    _ = try decode(input, &counter.writer, history, provider);
    return measurement.measuredLength(&counter);
}

// One stream per call: the adler32 trailer ends the stream, so trailing bytes are an error.
pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8, provider: checksum.Provider) Exception!usize {
    if (history.len < deflate_history_size) return error.CapacityException;
    var source = std.Io.Reader.fixed(input);
    const cmf = source.takeByte() catch return error.DataException;
    const flg = source.takeByte() catch return error.DataException;
    const header = try inspect(&.{ cmf, flg });
    if (header.has_dictionary) return error.UnsupportedException;
    if (header.window_size > window_size_max) return error.UnsupportedException;
    var tee_writer = tee.CountingTee(.{ .adler32 = true }).initWithProvider(output, provider);
    var inflater: deflate_seam.Decode = undefined;
    inflater.initSliceBoundInPlace(provider, input[header_size..], history) catch return error.UnsupportedException;
    const produced = inflater.readerPtr().streamRemaining(&tee_writer.writer) catch |err| {
        return switch (err) {
            error.WriteFailed => error.IoException,
            else => error.DataException,
        };
    };
    const data_start = header_size;
    source.seek = data_start + (inflater.inputBitsConsumed() + 7) / 8;
    var trailer: [trailer_size]u8 = undefined;
    var trailer_sink = std.Io.Writer.fixed(&trailer);
    source.streamExact(&trailer_sink, trailer_size) catch return error.DataException;
    if (source.seek != input.len) return error.DataException;
    const stored_adler32 = std.mem.readInt(u32, &trailer, .big);
    if (stored_adler32 != tee_writer.adler32Value()) return error.IntegrityException;
    return produced;
}

pub fn encodeStream(source: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: Options) Exception!void {
    if (history.len < deflate_history_size) return error.CapacityException;
    try writeHeader(output);
    var compressor = try deflate.Compress.init(output, history, options.deflate);
    var adler32 = checksum.Adler32.bind(options.provider);
    _ = try deflate.feed(checksum.Adler32, source, &compressor, &adler32);
    compressor.finish() catch return error.IoException;
    output.writeInt(u32, adler32.final(), .big) catch return error.IoException;
}

fn writeHeader(writer: *std.Io.Writer) Exception!void {
    // FLEVEL 2 marks the default algorithm. The FCHECK bits of FLG make the 16 bit header a multiple of 31.
    const cmf: u8 = (cinfo_max << 4) | cm_deflate;
    var flg: u8 = level_default << 6;
    const remainder = (@as(u32, cmf) << 8 | flg) % 31;
    if (remainder != 0) flg += @intCast(31 - remainder);
    try io.writeBytes(writer, &.{ cmf, flg });
}

test "zlib round trip restores the original input" {
    // See the decode gate above: a mixed build cannot serve one call with
    // both arms.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;

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
    // See the decode gate above: a mixed build cannot serve one call with
    // both arms.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;

    const history = try std.testing.allocator.alloc(u8, deflate_history_size);
    defer std.testing.allocator.free(history);
    var discard_buffer: [0]u8 = .{};
    var discarding: std.Io.Writer.Discarding = .init(&discard_buffer);
    // 0x78/0x20 passes FCHECK ((0x78 << 8 | 0x20) % 31 == 0) and sets FDICT.
    try std.testing.expectError(error.UnsupportedException, decode(&.{ 0x78, 0x20, 0x03, 0x00, 0, 0, 0, 1 }, &discarding.writer, history, checksum.default_provider));
    const input = "payload";
    var source = std.Io.Reader.fixed(input);
    var encoded: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&encoded);
    try encodeStream(&source, &sink, history, .{ .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 } });
    var with_garbage: [65]u8 = undefined;
    @memcpy(with_garbage[0..sink.end], encoded[0..sink.end]);
    with_garbage[sink.end] = 0;
    try std.testing.expectError(error.DataException, decode(with_garbage[0 .. sink.end + 1], &discarding.writer, history, checksum.default_provider));
}
