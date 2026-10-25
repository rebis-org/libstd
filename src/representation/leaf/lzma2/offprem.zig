const std = @import("std");

const exception = @import("../../../common/primitive/exception.zig");
const onprem = @import("onprem.zig");

const std_lzma2 = std.compress.lzma2;
pub const Exception = exception.Exception;
pub const InPlaceResult = onprem.InPlaceResult;
// The stdlib's buffer grows with the decoded stream; outgrowing the scratch
// answers CapacityException, the accepted incompleteness. Encode always uses onprem.
pub const Options = onprem.Options;

// The stdlib's probability tables plus the AccumBuffer's start; the buffer
// grows with the decoded stream until the scratch ends.
pub fn scratchNeed(dictionary_size: u32) usize {
    const literal = @as(usize, 0x300) * 16 * @sizeOf(u16);
    const state: usize = 8192;
    return std.mem.alignForward(usize, literal + state + @max(dictionary_size, 4096), @alignOf(u64)) + @alignOf(u64);
}

fn drive(reader: *std.Io.Reader, output: []u8, scratch: []u8) Exception!struct { produced: usize, consumed: u64 } {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    var decoder = std_lzma2.Decode.init(allocator) catch |err| return exception.fromStd(err);
    defer decoder.deinit(allocator);
    var sink: std.Io.Writer.Allocating = .initOwnedSlice(allocator, output);
    // sink.deinit is deliberately not called: it would rawFree the caller's
    // output span, which the FBA did not allocate.
    const consumed = decoder.decompress(reader, &sink) catch |err| return exception.fromStd(err);
    return .{ .produced = sink.writer.end, .consumed = consumed };
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8) Exception!usize {
    var reader = std.Io.Reader.fixed(input);
    const result = try drive(&reader, output, scratch);
    return result.produced;
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8) Exception!InPlaceResult {
    var reader = std.Io.Reader.fixed(input);
    const result = try drive(&reader, output, scratch);
    return .{ .produced = result.produced, .consumed = @intCast(result.consumed) };
}

// decodeStream stages through the scratch: the caller's writer shape has no stdlib
// Allocating equivalent. Streams beyond the scratch answer CapacityException.
pub fn decodeStream(reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8) Exception!void {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    var decoder = std_lzma2.Decode.init(allocator) catch |err| return exception.fromStd(err);
    defer decoder.deinit(allocator);
    var staging: std.Io.Writer.Allocating = .init(allocator);
    defer staging.deinit();
    _ = decoder.decompress(reader, &staging) catch |err| return exception.fromStd(err);
    writer.writeAll(staging.writer.buffer[0..staging.writer.end]) catch return error.IoException;
}

pub fn decodedSize(input: []const u8, scratch: []u8) Exception!usize {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    var decoder = std_lzma2.Decode.init(allocator) catch |err| return exception.fromStd(err);
    defer decoder.deinit(allocator);
    var staging: std.Io.Writer.Allocating = .init(allocator);
    defer staging.deinit();
    var reader = std.Io.Reader.fixed(input);
    _ = decoder.decompress(&reader, &staging) catch |err| return exception.fromStd(err);
    return staging.writer.end;
}

test "offprem lzma2 decodes byte-identical to onprem" {
    const alloc = std.testing.allocator;

    const input = try alloc.alloc(u8, 200000);
    defer alloc.free(input);
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    prng.random().bytes(input);
    @memset(input[60000..150000], 0);

    const compressed = try alloc.alloc(u8, 220000);
    defer alloc.free(compressed);
    const onprem_out = try alloc.alloc(u8, 200000);
    defer alloc.free(onprem_out);
    const offprem_out = try alloc.alloc(u8, 200000);
    defer alloc.free(offprem_out);

    const dictionary: u32 = 1 << 23;
    const props = onprem.defaultProperties(dictionary);
    const options: Options = .{ .dictionary_size = dictionary, .properties = props };
    const encode_scratch = try alloc.alloc(u8, onprem.encodeWorkspaceSizeBt(dictionary));
    defer alloc.free(encode_scratch);

    var sink = std.Io.Writer.fixed(compressed);
    onprem.encodeToWriter(input, &sink, encode_scratch, options) catch return error.TestUnexpectedResult;
    const stream = compressed[0..sink.end];

    const offprem_scratch = try alloc.alloc(u8, scratchNeed(dictionary) + 200000);
    defer alloc.free(offprem_scratch);
    const onprem_scratch = try alloc.alloc(u8, onprem.decodeWorkspaceSize(dictionary));
    defer alloc.free(onprem_scratch);

    const produced_on = try onprem.decode(stream, onprem_out, onprem_scratch, options);
    const produced_off = try decode(stream, offprem_out, offprem_scratch);
    const in_place = try decodeInPlace(stream, offprem_out, offprem_scratch);
    const counted = try decodedSize(stream, offprem_scratch);

    try std.testing.expectEqual(produced_on, produced_off);
    try std.testing.expectEqual(produced_on, in_place.produced);
    try std.testing.expectEqual(produced_on, counted);
    try std.testing.expectEqual(input.len, produced_on);
    try std.testing.expectEqualSlices(u8, input, offprem_out[0..produced_off]);
}
