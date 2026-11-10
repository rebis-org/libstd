const std = @import("std");

const exception = @import("../../../common/primitive/exception.zig");
const onprem = @import("onprem.zig");

const std_lzma = std.compress.lzma;
pub const Exception = exception.Exception;
pub const Options = onprem.Options;
// The stdlib's tables and window carve from the caller's scratch; growth
// beyond it answers CapacityException, the accepted std incompleteness.
pub const Properties = onprem.Properties;

fn mapStreamError(err: std.Io.Reader.StreamError) Exception {
    return switch (err) {
        error.ReadFailed, error.EndOfStream => error.DataException,
        else => exception.fromStd(err),
    };
}

// The scratch the arm asks for: stdlib's probability tables plus the match
// window, worst-cased. Callers size with max(onprem need, scratchNeed).
pub fn scratchNeed(properties: Properties) usize {
    const literal = @as(usize, 0x300) * properties.literalContextCount() * @sizeOf(u16);
    const state: usize = 4096;
    return std.mem.alignForward(usize, literal + state + properties.dictionary_size, @alignOf(u64)) + @alignOf(u64);
}

fn stdProperties(properties: Properties) std_lzma.Decode.Properties {
    return .{ .lc = @intCast(properties.lc), .lp = @intCast(properties.lp), .pb = @intCast(properties.pb) };
}

// A declared size is authoritative, mirroring the onprem leaf. The stdlib's
// stop rule would mask an under-declared header as a clean finish, so the
// leaf hands the stdlib no size, decodes to the stream's true end, and
// checks the count itself.
fn guardDecodedCount(options: Options, produced: usize) Exception!void {
    const declared = options.unpack_size orelse return;
    const expected = std.math.cast(usize, declared) orelse return error.ResourceException;
    if (produced != expected) return error.DataException;
}

// The sink reports WriteFailed at a full buffer. A stream over-ran its
// declared size when its true decoded count passed the header and the sink
// had accepted everything up to that boundary; a write that stops short of
// the boundary is an honest capacity answer for an undersized sink.
fn overranDeclared(options: Options, written: usize, produced: usize) bool {
    const declared = options.unpack_size orelse return false;
    const expected = std.math.cast(usize, declared) orelse return false;
    return written == expected and produced > expected;
}

// Decodes the raw payload after the 13-byte .lzma header.
pub fn drive(reader: *std.Io.Reader, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = options.properties.dictionary_size,
        .unpacked_size = null,
    };
    var decoder = std_lzma.Decompress.initParams(reader, allocator, &.{}, params, options.properties.dictionary_size) catch |err| return exception.fromStd(err);
    defer decoder.deinit();
    var sink = std.Io.Writer.fixed(output);
    _ = decoder.reader.streamRemaining(&sink) catch |err| {
        if (err == error.WriteFailed and overranDeclared(options, sink.end, decoder.buffer.len)) return error.DataException;
        return mapStreamError(err);
    };
    try guardDecodedCount(options, decoder.buffer.len);
    return sink.end;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var reader = std.Io.Reader.fixed(input);
    return drive(&reader, output, scratch, options);
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = options.properties.dictionary_size,
        .unpacked_size = null,
    };
    var reader = std.Io.Reader.fixed(input);
    var decoder = std_lzma.Decompress.initParams(&reader, allocator, &.{}, params, options.properties.dictionary_size) catch |err| return exception.fromStd(err);
    defer decoder.deinit();
    _ = decoder.reader.streamRemaining(writer) catch |err| {
        if (err == error.WriteFailed and overranDeclared(options, writer.end, decoder.buffer.len)) return error.DataException;
        return mapStreamError(err);
    };
    try guardDecodedCount(options, decoder.buffer.len);
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Exception!usize {
    const measurement = @import("../../../common/primitive/measurement.zig");
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = options.properties.dictionary_size,
        .unpacked_size = null,
    };
    var reader = std.Io.Reader.fixed(input);
    var decoder = std_lzma.Decompress.initParams(&reader, allocator, &.{}, params, options.properties.dictionary_size) catch |err| return exception.fromStd(err);
    defer decoder.deinit();
    var counter = measurement.Counter.init(null);
    _ = decoder.reader.streamRemaining(&counter.writer) catch |err| return mapStreamError(err);
    const produced = std.math.cast(usize, counter.written()) orelse return error.ResourceException;
    try guardDecodedCount(options, produced);
    return produced;
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
    try onprem.encodeToWriter(input, &sink, encode_scratch, .{ .properties = props });
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

test "offprem lzma declared size is authoritative" {
    const alloc = std.testing.allocator;

    const input = "declared size labels a longer marker-terminated stream";
    const props: Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 12 };
    const encode_scratch = try alloc.alloc(u8, @max(onprem.encodeWorkspaceSize(props), onprem.encodeWorkspaceSizeBt(props)));
    defer alloc.free(encode_scratch);
    const decode_scratch = try alloc.alloc(u8, scratchNeed(props));
    defer alloc.free(decode_scratch);

    var encoded: [512]u8 = undefined;
    var sink = std.Io.Writer.fixed(&encoded);
    try onprem.encodeToWriter(input, &sink, encode_scratch, .{ .properties = props, .marker_required = true });
    const payload = encoded[0..sink.end];

    // A header under-reporting the stream fails with the prefix published.
    {
        const declared = input.len - 1;
        var output: [declared]u8 = undefined;
        @memset(&output, 0xa5);
        try std.testing.expectError(error.DataException, decode(payload, &output, decode_scratch, .{ .properties = props, .unpack_size = declared }));
        try std.testing.expectEqualSlices(u8, input[0..declared], &output);
        try std.testing.expectError(error.DataException, decodedSize(payload, decode_scratch, .{ .properties = props, .unpack_size = declared }));
    }

    // A header over-reporting the stream fails with the prefix published
    // and the untouched sink tail beyond it.
    {
        const declared = input.len + 32;
        var output: [declared]u8 = undefined;
        @memset(&output, 0xa5);
        try std.testing.expectError(error.DataException, decode(payload, &output, decode_scratch, .{ .properties = props, .unpack_size = declared }));
        try std.testing.expectEqualSlices(u8, input, output[0..input.len]);
        try std.testing.expect(std.mem.allEqual(u8, output[input.len..], 0xa5));
    }

    // A declared size matching the stream still accepts a redundant marker.
    {
        var output: [input.len]u8 = undefined;
        @memset(&output, 0xa5);
        const produced = try decode(payload, &output, decode_scratch, .{ .properties = props, .unpack_size = input.len });
        try std.testing.expectEqual(input.len, produced);
        try std.testing.expectEqualSlices(u8, input, &output);
    }

    // A correct declared size publishes exactly the decoded count when the
    // sink is larger, leaving the unused tail untouched.
    {
        var output: [input.len + 64]u8 = undefined;
        @memset(&output, 0xa5);
        var markerless: [512]u8 = undefined;
        var plain = std.Io.Writer.fixed(&markerless);
        try onprem.encodeToWriter(input, &plain, encode_scratch, .{ .properties = props });
        const produced = try decode(markerless[0..plain.end], &output, decode_scratch, .{ .properties = props, .unpack_size = input.len });
        try std.testing.expectEqual(input.len, produced);
        try std.testing.expectEqualSlices(u8, input, output[0..input.len]);
        try std.testing.expect(std.mem.allEqual(u8, output[input.len..], 0xa5));
    }
}
