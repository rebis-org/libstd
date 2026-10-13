const std = @import("std");

const failure = @import("../../common/primitive/failure.zig");
const onprem = @import("onprem.zig");

const std_lzma = std.compress.lzma;
pub const Failure = failure.Failure;
pub const Options = onprem.Options;
// std's tables and window carve from the caller's scratch; growth beyond it
// answers CapacityFailure — the accepted incompleteness of choosing std.
pub const Properties = onprem.Properties;

fn mapStreamError(err: std.Io.Reader.StreamError) Failure {
    return switch (err) {
        error.ReadFailed, error.EndOfStream => error.DataFailure,
        else => failure.fromStd(err),
    };
}

// The scratch the arm asks for: std's probability tables plus the match
// window, worst-cased. Callers size with max(onprem need, scratchNeed).
pub fn scratchNeed(properties: Properties) usize {
    const literal = @as(usize, 0x300) * properties.literalContextCount() * @sizeOf(u16);
    const state: usize = 4096;
    return std.mem.alignForward(usize, literal + state + properties.dictionary_size, @alignOf(u64)) + @alignOf(u64);
}

fn stdProperties(properties: Properties) std_lzma.Decode.Properties {
    return .{ .lc = @intCast(properties.lc), .lp = @intCast(properties.lp), .pb = @intCast(properties.pb) };
}

// std fuses the stop rule and the length assertion, reporting an early end marker as a size mismatch.
fn endedShortOfDeclared(decoder: *const std_lzma.Decompress, options: Options) bool {
    const declared = options.unpack_size orelse return false;
    const mismatch = decoder.err orelse return false;
    return mismatch == error.DecompressedSizeMismatch and decoder.buffer.len < declared;
}

// std flushes the window's tail only on the success path, so a short run leaves it unflushed.
fn drainShortRun(decoder: *std_lzma.Decompress, writer: *std.Io.Writer) Failure!void {
    writer.writeAll(decoder.reader.buffer[decoder.reader.seek..decoder.reader.end]) catch return error.CapacityFailure;
    decoder.buffer.finish(writer) catch return error.CapacityFailure;
}

// drive decodes the raw LZMA payload (after the 13-byte .lzma header, or an
// lzma2 chunk body) into output through the caller-provided reader.
pub fn drive(reader: *std.Io.Reader, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = options.properties.dictionary_size,
        .unpacked_size = options.unpack_size,
    };
    var decoder = std_lzma.Decompress.initParams(reader, allocator, &.{}, params, options.properties.dictionary_size) catch |err| return failure.fromStd(err);
    defer decoder.deinit();
    var sink = std.Io.Writer.fixed(output);
    _ = decoder.reader.streamRemaining(&sink) catch |err| {
        if (!endedShortOfDeclared(&decoder, options)) return mapStreamError(err);
        try drainShortRun(&decoder, &sink);
    };
    return sink.end;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var reader = std.Io.Reader.fixed(input);
    return drive(&reader, output, scratch, options);
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = options.properties.dictionary_size,
        .unpacked_size = options.unpack_size,
    };
    var reader = std.Io.Reader.fixed(input);
    var decoder = std_lzma.Decompress.initParams(&reader, allocator, &.{}, params, options.properties.dictionary_size) catch |err| return failure.fromStd(err);
    defer decoder.deinit();
    _ = decoder.reader.streamRemaining(writer) catch |err| {
        if (!endedShortOfDeclared(&decoder, options)) return mapStreamError(err);
        try drainShortRun(&decoder, writer);
    };
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    const measurement = @import("../../common/primitive/measurement.zig");
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = options.properties.dictionary_size,
        .unpacked_size = options.unpack_size,
    };
    var reader = std.Io.Reader.fixed(input);
    var decoder = std_lzma.Decompress.initParams(&reader, allocator, &.{}, params, options.properties.dictionary_size) catch |err| return failure.fromStd(err);
    defer decoder.deinit();
    var counter = measurement.Counter.init(null);
    _ = decoder.reader.streamRemaining(&counter.writer) catch |err| {
        if (!endedShortOfDeclared(&decoder, options)) return mapStreamError(err);
        try drainShortRun(&decoder, &counter.writer);
    };
    return counter.written();
}

test "offprem lzma payload decodes byte-identical to onprem" {
    const alloc = std.testing.allocator;

    const input = try alloc.alloc(u8, 120000);
    defer alloc.free(input);
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    prng.random().bytes(input);
    @memset(input[40000..90000], 0);

    const compressed = try alloc.alloc(u8, 400000);
    defer alloc.free(compressed);
    const onprem_out = try alloc.alloc(u8, 120000);
    defer alloc.free(onprem_out);
    const offprem_out = try alloc.alloc(u8, 120000);
    defer alloc.free(offprem_out);

    const props: Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 23 };
    const encode_scratch = try alloc.alloc(u8, @max(onprem.encodeWorkspaceSize(props), onprem.encodeWorkspaceSizeBt(props)));
    defer alloc.free(encode_scratch);

    var sink = std.Io.Writer.fixed(compressed);
    onprem.encodeToWriter(input, &sink, encode_scratch, .{ .properties = props }) catch return error.TestUnexpectedResult;
    const payload = compressed[0..sink.end];

    const offprem_scratch = try alloc.alloc(u8, scratchNeed(props));
    defer alloc.free(offprem_scratch);
    const onprem_scratch = try alloc.alloc(u8, onprem.decodeWorkspaceSize(props));
    defer alloc.free(onprem_scratch);

    const known: Options = .{ .properties = props, .unpack_size = input.len };
    const produced_on = try onprem.decode(payload, onprem_out, onprem_scratch, known);
    const produced_off = try decode(payload, offprem_out, offprem_scratch, known);

    try std.testing.expectEqual(produced_on, produced_off);
    try std.testing.expectEqual(input.len, produced_on);
    try std.testing.expectEqualSlices(u8, input, offprem_out[0..produced_off]);
}
