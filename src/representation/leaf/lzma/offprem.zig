const std = @import("std");

const exception = @import("../../../common/primitive/exception.zig");
const spanguard = @import("../../../common/primitive/spanguard.zig");
const onprem = @import("onprem.zig");

const std_lzma = std.compress.lzma;
pub const Exception = exception.Exception;
pub const Options = onprem.Options;
// The stdlib arm decodes through `std.compress.lzma` with the caller's span
// as the decoder's staging buffer under the span guard: a stream that fits
// copies straight into the span, and one that does not moves the staging
// into fresh scratch; an under-declared stream still publishes the decoded
// prefix that fits the span before its data verdict — a read publishes
// tentatively. The dictionary rides one byte above the window inside the
// stdlib's circular buffer so the honest window bound holds; a stream that
// outgrows the window stops exactly at the dictionary size and answers
// UnsupportedException. The declared size stays authoritative: the leaf
// checks the decoded count itself. Encode always uses onprem.
pub const Properties = onprem.Properties;

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

// Shared decoder construction for every verb. The dictionary rides one byte
// above the caller's window: the stdlib's circular buffer rejects an index
// at the memory limit itself, so the limit keeps the honest window size
// while every reachable offset stays inside the buffer. The declared size
// stays null; the leaf checks the decoded count itself.
fn initDecoder(
    reader: *std.Io.Reader,
    allocator: std.mem.Allocator,
    staging: []u8,
    options: Options,
) Exception!std_lzma.Decompress {
    const dict = options.properties.dictionary_size;
    if (dict == std.math.maxInt(u32)) return error.UnsupportedException;
    const params: std_lzma.Decode.Params = .{
        .properties = stdProperties(options.properties),
        .dict_size = dict + 1,
        .unpacked_size = null,
    };
    return std_lzma.Decompress.initParams(reader, allocator, staging, params, dict) catch |err| return exception.fromStd(err);
}

// Reserving the window's final size up front keeps the stdlib's geometric
// growth from carving more scratch than the arm promises, and makes any
// window growth during decode impossible.
fn primeWindow(decoder: *std_lzma.Decompress, options: Options) Exception!void {
    decoder.buffer.buf.ensureTotalCapacityPrecise(decoder.gpa, options.properties.dictionary_size) catch return error.CapacityException;
}

// Maps the stdlib's terminal error. A window that stopped growing exactly
// at the dictionary size is the stdlib's beyond-dictionary rejection — a
// stream property the arm does not support; everything else about the
// payload is corruption.
fn classifyFailure(options: Options, err: std_lzma.Decompress.Error, produced: usize, oom: Exception) Exception {
    return switch (err) {
        error.OutOfMemory => oom,
        error.CorruptInput => if (produced == options.properties.dictionary_size)
            error.UnsupportedException
        else
            error.DataException,
        else => error.DataException,
    };
}

// The verdict for a stream that outgrew the caller's span: an honest
// declared size larger than the span is a capacity answer, and a declared
// size the stream itself violates is corruption.
fn spanOverflow(options: Options, span_len: usize) Exception {
    const declared = options.unpack_size orelse return error.CapacityException;
    const expected = std.math.cast(usize, declared) orelse return error.CapacityException;
    if (expected > span_len) return error.CapacityException;
    return error.DataException;
}

// A declared size is authoritative; the stdlib stop rule would
// mask under-declaration, so the leaf checks the count itself.
fn guardDecodedCount(options: Options, produced: usize) Exception!void {
    const declared = options.unpack_size orelse return;
    const expected = std.math.cast(usize, declared) orelse return error.ResourceException;
    if (produced != expected) return error.DataException;
}

// A full-buffer WriteFailed is an honest capacity answer unless
// the sink reached the declared boundary and decoding produced more.
fn overranDeclared(options: Options, written: usize, produced: usize) bool {
    const declared = options.unpack_size orelse return false;
    const expected = std.math.cast(usize, declared) orelse return false;
    return written == expected and produced > expected;
}

// Publishes the decoded prefix that fits the span when the read's verdict
// is corruption of the declared range: a read publishes tentatively, the
// way the onprem arm leaves the same prefix in the span while it streams.
// The bytes the allocating writer already received are a correct prefix,
// and the ring holds the rest: the memory limit keeps the ring from ever
// wrapping, so its items are the decoded stream in order.
fn publishPrefix(decoder: *std_lzma.Decompress, output: []u8) void {
    const staged_len = @min(decoder.reader.end, output.len);
    if (decoder.reader.buffer.ptr != output.ptr) {
        @memcpy(output[0..staged_len], decoder.reader.buffer[0..staged_len]);
    }
    const produced = @min(decoder.buffer.len, output.len);
    const ring = decoder.buffer.buf.items;
    for (output[staged_len..produced], ring[staged_len..produced]) |*dst, src| dst.* = src;
}

// Decodes the raw payload after the 13-byte .lzma header into the span.
pub fn drive(reader: *std.Io.Reader, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    var guard = spanguard.SpanGuardAllocator{ .backing = fba.allocator(), .span = output };
    var decoder = try initDecoder(reader, guard.allocator(), output, options);
    defer decoder.deinit();
    // The stdlib's deinit frees its staging with the poisoning high-level
    // free, so a staging buffer that still is the span must be detached
    // before deinit runs or the decoded bytes would not survive this call.
    defer {
        if (decoder.reader.buffer.ptr == output.ptr) decoder.reader.buffer = &.{};
    }
    try primeWindow(&decoder, options);
    var sink = std.Io.Writer.Discarding.init(&.{});
    _ = decoder.reader.streamRemaining(&sink.writer) catch |err| {
        if (decoder.err) |derr| {
            const verdict = classifyFailure(options, derr, decoder.buffer.len, spanOverflow(options, output.len));
            // The staging write fails exactly when the decoded stream
            // outgrew the span; an under-declared one still owes the span
            // its decoded prefix.
            if (derr == error.OutOfMemory and verdict == error.DataException) publishPrefix(&decoder, output);
            return verdict;
        }
        return exception.fromStd(err);
    };
    const produced = decoder.buffer.len;
    if (produced > output.len) {
        const verdict = spanOverflow(options, output.len);
        if (verdict == error.DataException) publishPrefix(&decoder, output);
        return verdict;
    }
    try guardDecodedCount(options, produced);
    return produced;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var reader = std.Io.Reader.fixed(input);
    const produced = try drive(&reader, output, scratch, options);
    if (options.reject_trailing and reader.seek != input.len) return error.DataException;
    return produced;
}

// Decodes into a caller's writer. The whole stream stages through the
// scratch before it reaches the writer, so the scratch must hold the window
// plus the staged output; scratchNeed alone can be tight here.
pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    var reader = std.Io.Reader.fixed(input);
    var decoder = try initDecoder(&reader, allocator, &.{}, options);
    defer decoder.deinit();
    _ = decoder.reader.streamRemaining(writer) catch |err| {
        if (decoder.err) |derr| return classifyFailure(options, derr, decoder.buffer.len, error.CapacityException);
        if (err == error.WriteFailed and overranDeclared(options, writer.end, decoder.buffer.len)) return error.DataException;
        return exception.fromStd(err);
    };
    try guardDecodedCount(options, decoder.buffer.len);
    if (options.reject_trailing and reader.seek != input.len) return error.DataException;
}

// Counts the decoded bytes without publishing them; the stream stages
// through the scratch like the writer verb.
pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Exception!usize {
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const allocator = fba.allocator();
    var reader = std.Io.Reader.fixed(input);
    var decoder = try initDecoder(&reader, allocator, &.{}, options);
    defer decoder.deinit();
    var sink = std.Io.Writer.Discarding.init(&.{});
    _ = decoder.reader.streamRemaining(&sink.writer) catch |err| {
        if (decoder.err) |derr| return classifyFailure(options, derr, decoder.buffer.len, error.CapacityException);
        return exception.fromStd(err);
    };
    try guardDecodedCount(options, decoder.buffer.len);
    if (options.reject_trailing and reader.seek != input.len) return error.DataException;
    return decoder.buffer.len;
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

    // The writer and counter verbs land on the same bytes and count.
    @memset(offprem_out, 0xa5);
    var writer = std.Io.Writer.fixed(offprem_out);
    try decodeToWriter(payload, &writer, offprem_scratch, known);
    try std.testing.expectEqual(input.len, writer.end);
    try std.testing.expectEqualSlices(u8, input, offprem_out[0..writer.end]);
    try std.testing.expectEqual(input.len, try decodedSize(payload, offprem_scratch, known));
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

    // A header under-reporting the stream still publishes the decoded
    // prefix that fits the span before the count check fails the read.
    {
        const declared = input.len - 1;
        const known: Options = .{ .properties = props, .unpack_size = declared };
        var output: [declared]u8 = undefined;
        @memset(&output, 0xa5);
        try std.testing.expectError(error.DataException, decode(payload, &output, decode_scratch, known));
        try std.testing.expectEqualSlices(u8, input[0..declared], &output);
        try std.testing.expectError(error.DataException, decodedSize(payload, decode_scratch, known));
    }

    // A header over-reporting the stream publishes the decoded prefix in
    // the span and fails the count check, leaving the sink tail untouched.
    {
        const declared = input.len + 32;
        const known: Options = .{ .properties = props, .unpack_size = declared };
        var output: [declared]u8 = undefined;
        @memset(&output, 0xa5);
        try std.testing.expectError(error.DataException, decode(payload, &output, decode_scratch, known));
        try std.testing.expectEqualSlices(u8, input, output[0..input.len]);
        try std.testing.expect(std.mem.allEqual(u8, output[input.len..], 0xa5));
    }

    // A declared size matching the stream still accepts a redundant marker,
    // through both the span and the writer verbs.
    {
        const known: Options = .{ .properties = props, .unpack_size = input.len };
        var output: [input.len]u8 = undefined;
        @memset(&output, 0xa5);
        const produced = try decode(payload, &output, decode_scratch, known);
        try std.testing.expectEqual(input.len, produced);
        try std.testing.expectEqualSlices(u8, input, &output);
        var staged: [input.len]u8 = undefined;
        @memset(&staged, 0xa5);
        var writer = std.Io.Writer.fixed(&staged);
        try decodeToWriter(payload, &writer, decode_scratch, known);
        try std.testing.expectEqual(input.len, writer.end);
        try std.testing.expectEqualSlices(u8, input, &staged);
    }

    // A correct declared size publishes exactly the decoded count when the
    // sink is larger, leaving the unused tail untouched.
    {
        const known: Options = .{ .properties = props, .unpack_size = input.len };
        var output: [input.len + 64]u8 = undefined;
        @memset(&output, 0xa5);
        var markerless: [512]u8 = undefined;
        var plain = std.Io.Writer.fixed(&markerless);
        try onprem.encodeToWriter(input, &plain, encode_scratch, .{ .properties = props });
        const produced = try decode(markerless[0..plain.end], &output, decode_scratch, known);
        try std.testing.expectEqual(input.len, produced);
        try std.testing.expectEqualSlices(u8, input, output[0..input.len]);
        try std.testing.expect(std.mem.allEqual(u8, output[input.len..], 0xa5));
    }
}

test "offprem lzma beyond-dictionary stream fails closed" {
    const alloc = std.testing.allocator;

    // A repeating block keeps the compressed stream small while the decoded
    // stream runs far past the dictionary.
    var block: [500]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(&block);

    const input = try alloc.alloc(u8, 300000);
    defer alloc.free(input);
    var i: usize = 0;
    while (i < input.len) : (i += block.len) {
        @memcpy(input[i..][0..block.len], &block);
    }

    const props: Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 12 };
    const encode_scratch = try alloc.alloc(u8, @max(onprem.encodeWorkspaceSize(props), onprem.encodeWorkspaceSizeBt(props)));
    defer alloc.free(encode_scratch);

    const compressed = try alloc.alloc(u8, input.len / 4);
    defer alloc.free(compressed);
    var sink = std.Io.Writer.fixed(compressed);
    try onprem.encodeToWriter(input, &sink, encode_scratch, .{ .properties = props });
    const payload = compressed[0..sink.end];

    // The onprem arm streams the whole input regardless of the dictionary.
    const onprem_out = try alloc.alloc(u8, input.len);
    defer alloc.free(onprem_out);
    const onprem_scratch = try alloc.alloc(u8, onprem.decodeWorkspaceSize(props));
    defer alloc.free(onprem_scratch);
    const produced_on = try onprem.decode(payload, onprem_out, onprem_scratch, .{ .properties = props, .unpack_size = input.len });
    try std.testing.expectEqual(input.len, produced_on);
    try std.testing.expectEqualSlices(u8, input, onprem_out);

    // The stdlib arm stops at the dictionary and names the stream property,
    // publishing nothing into the span.
    const offprem_scratch = try alloc.alloc(u8, scratchNeed(props));
    defer alloc.free(offprem_scratch);
    const output = try alloc.alloc(u8, input.len);
    defer alloc.free(output);
    const honest: Options = .{ .properties = props, .unpack_size = input.len };
    const open: Options = .{ .properties = props };

    @memset(output, 0xa5);
    try std.testing.expectError(error.UnsupportedException, decode(payload, output, offprem_scratch, honest));
    try std.testing.expect(std.mem.allEqual(u8, output, 0xa5));

    @memset(output, 0xa5);
    try std.testing.expectError(error.UnsupportedException, decode(payload, output, offprem_scratch, open));
    try std.testing.expect(std.mem.allEqual(u8, output, 0xa5));

    var count_sink = std.Io.Writer.Discarding.init(&.{});
    try std.testing.expectError(error.UnsupportedException, decodeToWriter(payload, &count_sink.writer, offprem_scratch, honest));
    try std.testing.expectEqual(@as(u64, 0), count_sink.fullCount());

    try std.testing.expectError(error.UnsupportedException, decodedSize(payload, offprem_scratch, honest));
}

test "offprem lzma drive stages the span within the scratch" {
    const alloc = std.testing.allocator;

    const total = 20000;
    const input = try alloc.alloc(u8, total);
    defer alloc.free(input);
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    prng.random().bytes(input);
    @memset(input[5000..15000], 0);

    const props: Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 15 };
    const encode_scratch = try alloc.alloc(u8, @max(onprem.encodeWorkspaceSize(props), onprem.encodeWorkspaceSizeBt(props)));
    defer alloc.free(encode_scratch);

    const compressed = try alloc.alloc(u8, 2 * total);
    defer alloc.free(compressed);
    var sink = std.Io.Writer.fixed(compressed);
    try onprem.encodeToWriter(input, &sink, encode_scratch, .{ .properties = props });
    const payload = compressed[0..sink.end];

    const scratch = try alloc.alloc(u8, scratchNeed(props));
    defer alloc.free(scratch);
    const span = try alloc.alloc(u8, total);
    defer alloc.free(span);
    const known: Options = .{ .properties = props, .unpack_size = total };

    // The primed window plus the tables fit the promised scratch, and the
    // finish copy lands directly in the span.
    {
        @memset(span, 0xa5);
        const produced = try decode(payload, span, scratch, known);
        try std.testing.expectEqual(total, produced);
        try std.testing.expectEqualSlices(u8, input, span);
    }

    // A scratch that cannot hold the primed window answers CapacityException
    // before any decode work, with the span untouched.
    {
        const tight = scratch[0 .. scratch.len - 5000];
        @memset(span, 0xa5);
        try std.testing.expectError(error.CapacityException, decode(payload, span, tight, known));
        try std.testing.expect(std.mem.allEqual(u8, span, 0xa5));
    }

    // A stream longer than the span stages through the scratch; the
    // under-declared data verdict publishes the decoded prefix that fits
    // the span, and the capacity verdicts leave the span untouched.
    {
        const short_span = span[0..15000];
        const fits: Options = .{ .properties = props, .unpack_size = 15000 };
        const lies: Options = .{ .properties = props, .unpack_size = 16000 };
        @memset(short_span, 0xa5);
        try std.testing.expectError(error.DataException, decode(payload, short_span, scratch, fits));
        try std.testing.expectEqualSlices(u8, input[0..15000], short_span);
        @memset(short_span, 0xa5);
        try std.testing.expectError(error.CapacityException, decode(payload, short_span, scratch, open_options: {
            break :open_options Options{ .properties = props };
        }));
        try std.testing.expectError(error.CapacityException, decode(payload, short_span, scratch, lies));
        try std.testing.expect(std.mem.allEqual(u8, short_span, 0xa5));
    }

    // The writer verb stages the whole stream through the scratch: the
    // promised scratch is short for it, a roomier one answers, and the
    // caller's writer stays untouched on the capacity failure.
    {
        const out = try alloc.alloc(u8, total);
        defer alloc.free(out);
        @memset(out, 0xa5);
        var writer = std.Io.Writer.fixed(out);
        try std.testing.expectError(error.CapacityException, decodeToWriter(payload, &writer, scratch, known));
        try std.testing.expectEqual(0, writer.end);

        const roomy = try alloc.alloc(u8, scratchNeed(props) + 2 * total);
        defer alloc.free(roomy);
        try decodeToWriter(payload, &writer, roomy, known);
        try std.testing.expectEqual(total, writer.end);
        try std.testing.expectEqualSlices(u8, input, out);
    }
}

test "offprem lzma rejects trailing garbage when the framing asks" {
    const alloc = std.testing.allocator;
    const input = "bytes after the stream close are corruption, not padding";
    const props: Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 12 };
    const encode_scratch = try alloc.alloc(u8, @max(onprem.encodeWorkspaceSize(props), onprem.encodeWorkspaceSizeBt(props)));
    defer alloc.free(encode_scratch);
    const decode_scratch = try alloc.alloc(u8, scratchNeed(props));
    defer alloc.free(decode_scratch);

    const encoded = try alloc.alloc(u8, onprem.encodedSizeBound(input.len) + 4);
    defer alloc.free(encoded);
    const output = try alloc.alloc(u8, input.len);
    defer alloc.free(output);

    // Both framings: the marker form and the declared markerless form.
    const marker_form: Options = .{ .properties = props, .marker_required = true };
    const declared_form: Options = .{ .properties = props, .unpack_size = input.len };

    for ([_]Options{ marker_form, declared_form }) |form| {
        var sink = std.Io.Writer.fixed(encoded);
        try onprem.encodeToWriter(input, &sink, encode_scratch, form);

        // The clean stream decodes under the flag, through every verb.
        var strict = form;
        strict.reject_trailing = true;
        @memset(output, 0xa5);
        const produced = try decode(encoded[0..sink.end], output, decode_scratch, strict);
        try std.testing.expectEqual(input.len, produced);
        try std.testing.expectEqualSlices(u8, input, output);
        @memset(output, 0xa5);
        var writer = std.Io.Writer.fixed(output);
        try decodeToWriter(encoded[0..sink.end], &writer, decode_scratch, strict);
        try std.testing.expectEqual(input.len, writer.end);
        try std.testing.expectEqualSlices(u8, input, output[0..writer.end]);
        try std.testing.expectEqual(input.len, try decodedSize(encoded[0..sink.end], decode_scratch, strict));

        // Four trailing bytes fail every verb under the flag.
        @memset(encoded[sink.end..][0..4], 0xa5);
        const tainted = encoded[0 .. sink.end + 4];
        try std.testing.expectError(error.DataException, decode(tainted, output, decode_scratch, strict));
        var count_sink = std.Io.Writer.Discarding.init(&.{});
        try std.testing.expectError(error.DataException, decodeToWriter(tainted, &count_sink.writer, decode_scratch, strict));
        try std.testing.expectError(error.DataException, decodedSize(tainted, decode_scratch, strict));

        // Without the flag the embedded framings keep their lenient read:
        // the decoder answers for the leading stream alone.
        @memset(output, 0xa5);
        try std.testing.expectEqual(input.len, try decode(tainted, output, decode_scratch, form));
        try std.testing.expectEqualSlices(u8, input, output);
    }
}
