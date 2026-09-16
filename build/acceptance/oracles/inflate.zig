const std = @import("std");

const abi = @import("abi.zig");
const harness = @import("harness.zig");

var input_buffer: [4096]u8 = undefined;
var gzip_buffer: [9000]u8 = undefined;
var output_a: [4096]u8 = undefined;
var output_b: [4096]u8 = undefined;

fn encodeGzip(r: *harness.Runner, out: []u8) ![]const u8 {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    r.input = &input_buffer;
    try harness.spanProduce(r, harness.ids.write, &.{ harness.sourceSpan(&input_buffer), harness.sinkSpan(out) });
    return out[0..r.encoded_len];
}

fn readAs(r: *harness.Runner, profile_id: harness.Id, encoded: []const u8, out: []u8) u32 {
    harness.setup(r, profile_id, harness.mode_stream);
    return harness.call(r, harness.ids.read, &.{ harness.sourceSpan(encoded), harness.sinkSpan(out) }, .{ .ctx = true });
}

fn readGzipCallbackSink(r: *harness.Runner, encoded: []const u8, out: []u8) u32 {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    var ctx = harness.SinkBufferContext{ .buffer = out, .accept_limit = std.math.maxInt(usize) };
    return harness.call(r, harness.ids.read, &.{ harness.sourceSpan(encoded), harness.sinkCallbackNode(0, 0) }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &ctx });
}

fn compareReads(status_a: u32, status_b: u32, a: []u8, b: []u8, len_a: usize, len_b: usize) !void {
    if (status_a != status_b) {
        std.debug.print("Status mismatch: {d} vs {d}.\n", .{ status_a, status_b });
        return error.StatusMismatch;
    }
    const compare_len = if (status_a == abi.Status.ok) a.len else @min(len_a, len_b);
    if (!std.mem.eql(u8, a[0..compare_len], b[0..compare_len])) {
        std.debug.print("Output mismatch at status {d}.\n", .{status_a});
        return error.OutputMismatch;
    }
}

pub fn runRawVsGzip(r: *harness.Runner) anyerror!void {
    harness.xorshiftFill(&input_buffer, 0x9e3779b97f4a7c15);
    const gzip_encoded = try encodeGzip(r, &gzip_buffer);
    if (gzip_encoded.len < 18) return error.GzipEncodedTooShort;
    const payload = gzip_encoded[10 .. gzip_encoded.len - 8];

    @memset(&output_a, 0xa5);
    @memset(&output_b, 0xa5);
    const sa = readAs(r, harness.ids.deflate, payload, &output_a);
    const sb = readAs(r, harness.ids.gzip, gzip_encoded, &output_b);
    if (sa != abi.Status.ok or sb != abi.Status.ok) return error.ValidStreamRejected;
    if (!std.mem.eql(u8, &output_a, &output_b)) return error.ValidOutputMismatch;
    if (r.response.byte_length != input_buffer.len) return error.ValidLengthMismatch;

    // Statuses may differ: the gzip wrapper detects the missing trailer.
    const trunc_points = [_]usize{ 1, payload.len / 4, payload.len / 2, payload.len - 1 };
    for (trunc_points) |t| {
        if (t == 0 or t >= payload.len) continue;
        const trunc_gzip = gzip_buffer[0 .. 10 + t];
        @memset(&output_a, 0xa5);
        @memset(&output_b, 0xa5);
        const ta = readAs(r, harness.ids.deflate, payload[0..t], &output_a);
        const len_a = r.response.byte_length;
        const tb = readAs(r, harness.ids.gzip, trunc_gzip, &output_b);
        const len_b = r.response.byte_length;
        if (ta == abi.Status.ok or tb == abi.Status.ok) return error.TruncatedAccepted;
        const min_len = @min(len_a, len_b);
        if (!std.mem.eql(u8, output_a[0..min_len], output_b[0..min_len])) return error.TruncatedOutputMismatch;
    }

    // Raw deflate has no integrity check, so only the produced prefix is compared.
    const corrupt_offsets = [_]usize{ 0, payload.len / 3, payload.len / 2, payload.len - 2 };
    for (corrupt_offsets) |off| {
        if (off >= payload.len) continue;
        var bad_payload: [8192]u8 = undefined;
        @memcpy(bad_payload[0..payload.len], payload);
        bad_payload[off] ^= 0xff;
        var bad_gzip: [9000]u8 = undefined;
        @memcpy(bad_gzip[0..10], gzip_encoded[0..10]);
        @memcpy(bad_gzip[10..][0..payload.len], bad_payload[0..payload.len]);
        @memcpy(bad_gzip[10 + payload.len ..][0..8], gzip_encoded[gzip_encoded.len - 8 ..][0..8]);
        @memset(&output_a, 0xa5);
        @memset(&output_b, 0xa5);
        _ = readAs(r, harness.ids.deflate, bad_payload[0..payload.len], &output_a);
        const len_a = r.response.byte_length;
        _ = readAs(r, harness.ids.gzip, bad_gzip[0..gzip_encoded.len], &output_b);
        const len_b = r.response.byte_length;
        const min_len = @min(len_a, len_b);
        if (!std.mem.eql(u8, output_a[0..min_len], output_b[0..min_len])) return error.CorruptOutputMismatch;
    }
}

pub fn runSingleVsTwoPass(r: *harness.Runner) anyerror!void {
    harness.xorshiftFill(&input_buffer, 0x70d5e2f72d5a9c0b);
    const encoded = try encodeGzip(r, &gzip_buffer);

    @memset(&output_a, 0xa5);
    @memset(&output_b, 0xa5);
    const sa = readAs(r, harness.ids.gzip, encoded, &output_a);
    const len_a = r.response.byte_length;
    const sb = readGzipCallbackSink(r, encoded, &output_b);
    const len_b = r.response.byte_length;
    try compareReads(sa, sb, &output_a, &output_b, len_a, len_b);
    if (sa != abi.Status.ok) return error.GzipValidRejected;

    const trunc_points = [_]usize{ 11, encoded.len / 2, encoded.len - 5, encoded.len - 1 };
    for (trunc_points) |t| {
        if (t <= 10 or t >= encoded.len) continue;
        @memset(&output_a, 0xa5);
        @memset(&output_b, 0xa5);
        const ta = readAs(r, harness.ids.gzip, encoded[0..t], &output_a);
        const len_a_t = r.response.byte_length;
        const tb = readGzipCallbackSink(r, encoded[0..t], &output_b);
        const len_b_t = r.response.byte_length;
        try compareReads(ta, tb, &output_a, &output_b, len_a_t, len_b_t);
        if (ta == abi.Status.ok) return error.GzipTruncatedAccepted;
    }

    const corrupt_offsets = [_]usize{ 10, encoded.len / 3, encoded.len / 2, encoded.len - 6 };
    for (corrupt_offsets) |off| {
        if (off >= encoded.len) continue;
        var bad: [9000]u8 = undefined;
        @memcpy(bad[0..encoded.len], encoded);
        bad[off] ^= 0xff;
        @memset(&output_a, 0xa5);
        @memset(&output_b, 0xa5);
        const ca = readAs(r, harness.ids.gzip, bad[0..encoded.len], &output_a);
        const len_a_c = r.response.byte_length;
        const cb = readGzipCallbackSink(r, bad[0..encoded.len], &output_b);
        const len_b_c = r.response.byte_length;
        try compareReads(ca, cb, &output_a, &output_b, len_a_c, len_b_c);
        if (ca == abi.Status.ok) return error.GzipCorruptAccepted;
    }
}

pub fn runBatchBoundaries(r: *harness.Runner) anyerror!void {
    // Long literals plus matches force flushes across block boundaries.
    var pattern: [1024]u8 = undefined;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        pattern[i] = @truncate(i ^ (i >> 3) ^ 0xa5);
    }
    harness.xorshiftFill(&input_buffer, 0x243f6a8885a308d3);
    @memcpy(input_buffer[0..pattern.len], &pattern);

    const encoded = try encodeGzip(r, &gzip_buffer);
    @memset(&output_a, 0xa5);
    @memset(&output_b, 0xa5);
    const sa = readAs(r, harness.ids.gzip, encoded, &output_a);
    const len_a = r.response.byte_length;
    const sb = readGzipCallbackSink(r, encoded, &output_b);
    const len_b = r.response.byte_length;
    try compareReads(sa, sb, &output_a, &output_b, len_a, len_b);
    if (sa != abi.Status.ok) return error.BoundaryValidRejected;
    if (!std.mem.eql(u8, output_a[0..input_buffer.len], &input_buffer)) return error.BoundaryContentMismatch;
}

pub const scenarios = harness.scenarios("inflate", &.{}, &.{
    .{ .name = "raw vs gzip", .run = runRawVsGzip, .workspace_size = 65536 + 4096, .output_size = 4096, .encoded_size = 8192 },
    .{ .name = "single-pass vs two-pass", .run = runSingleVsTwoPass, .workspace_size = 65536 + 4096, .output_size = 4096, .encoded_size = 8192 },
    .{ .name = "literal boundaries", .run = runBatchBoundaries, .workspace_size = 65536 + 4096, .output_size = 4096, .encoded_size = 8192 },
});
