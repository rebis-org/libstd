const std = @import("std");

const exception = @import("../../../common/primitive/exception.zig");
const spanguard = @import("../../../common/primitive/spanguard.zig");
const onprem = @import("onprem.zig");

const std_lzma2 = std.compress.lzma2;
pub const Exception = exception.Exception;
pub const InPlaceResult = onprem.InPlaceResult;
// The stdlib shares the sink's allocator with its accumulation buffer and
// state resets, so those allocations answer from the scratch FBA; only the
// caller's span is guarded (the shared span guard primitive). A stream that
// outgrows the span or the scratch answers CapacityException. Encode always
// uses onprem.
pub const Options = onprem.Options;

// The stdlib's probability tables plus the accumulation buffer, whose high
// water mark is one chunk's unpacked size, independent of the dictionary.
pub fn scratchNeed(_: u32) usize {
    const literal = @as(usize, 0x300) * 16 * @sizeOf(u16);
    const state: usize = 8192;
    return std.mem.alignForward(usize, literal + state + onprem.chunk_max_unpacked, @alignOf(u64)) + @alignOf(u64);
}

// The stdlib growth path remaps the sink's buffer through the allocator, but
// that buffer starts as the caller's span: an FBA asserts ownership of it in
// debug builds and reads past it in release builds. The span guard delegates
// every request to the FBA except operations on the span itself, so growth
// falls back to fresh scratch and the bound in drive answers CapacityException
// exactly as the onprem arm's fixed writer does.
fn drive(reader: *std.Io.Reader, output: []u8, scratch: []u8) Exception!struct { produced: usize, consumed: u64 } {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    var decoder = std_lzma2.Decode.init(allocator) catch |err| return exception.fromStd(err);
    defer decoder.deinit(allocator);
    var guard = spanguard.SpanGuardAllocator{ .backing = allocator, .span = output };
    var sink: std.Io.Writer.Allocating = .initOwnedSlice(guard.allocator(), output);
    // sink.deinit is deliberately not called: the caller's span is not an
    // allocation, and the guard drops its free.
    const consumed = decoder.decompress(reader, &sink) catch |err| return exception.fromStd(err);
    // A stream longer than the span moves the sink into fresh scratch; the
    // onprem arm answers CapacityException there, so the arms must agree
    // instead of returning a count the caller's span cannot hold.
    if (sink.writer.end > output.len) return error.CapacityException;
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
    try onprem.encodeToWriter(input, &sink, encode_scratch, options);
    const stream = compressed[0..sink.end];

    const offprem_scratch = try alloc.alloc(u8, scratchNeed(dictionary));
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

test "offprem lzma2 rejects an undersized output span" {
    const alloc = std.testing.allocator;

    const input = "hello world, hello world, hello world";
    const dictionary: u32 = 1 << 12;
    const props = onprem.defaultProperties(dictionary);
    const options: Options = .{ .dictionary_size = dictionary, .properties = props };
    const encode_scratch = try alloc.alloc(u8, onprem.encodeWorkspaceSizeBt(dictionary));
    defer alloc.free(encode_scratch);

    const compressed = try alloc.alloc(u8, 256);
    defer alloc.free(compressed);
    var sink = std.Io.Writer.fixed(compressed);
    try onprem.encodeToWriter(input, &sink, encode_scratch, options);
    const stream = compressed[0..sink.end];

    const scratch = try alloc.alloc(u8, scratchNeed(dictionary));
    defer alloc.free(scratch);
    const output = try alloc.alloc(u8, input.len);
    defer alloc.free(output);

    try std.testing.expectError(error.CapacityException, decode(stream, output[0 .. input.len - 1], scratch));
    try std.testing.expectError(error.CapacityException, decodeInPlace(stream, output[0 .. input.len - 1], scratch));
    const produced = try decode(stream, output, scratch);
    try std.testing.expectEqual(input.len, produced);
    try std.testing.expectEqualSlices(u8, input, output);
}
