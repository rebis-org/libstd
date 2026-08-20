const std = @import("std");

const abi = @import("abi.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");

pub const MaxExtra = 4;
pub const Params = *const fn (r: *Runner, out: *[MaxExtra]harness.Node) usize;

pub const Nodes = struct {
    items: [16]harness.Node = undefined,
    len: usize = 0,
};

pub fn build(comptime extra: Params, r: *Runner, base: []const harness.Node) Nodes {
    var buf: [MaxExtra]harness.Node = undefined;
    const extra_count = extra(r, &buf);
    var result = Nodes{};
    @memcpy(result.items[0..extra_count], buf[0..extra_count]);
    result.len = extra_count;
    @memcpy(result.items[result.len .. result.len + base.len], base);
    result.len += base.len;
    return result;
}

pub fn queryWrite(comptime extra: Params, r: *Runner) !void {
    const nodes = build(extra, r, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.sourceSpan(r.input),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_write),
    });
    _ = harness.call(r, harness.ids.query, nodes.items[0..nodes.len], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > r.encoded.len) return error.QueryCapacity;
    r.required = @intCast(r.response.byte_length);
}

pub fn writeSpan(comptime extra: Params, r: *Runner) !void {
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.input), harness.sinkSpan(r.encoded) });
    _ = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    r.encoded_len = @intCast(r.response.byte_length);
    if (r.encoded_len == 0 or r.encoded_len > r.encoded.len) return error.EncodedLength;
    if (r.write_exact and r.encoded_len != r.required) return error.EncodedMismatch;
}

pub fn queryRead(comptime extra: Params, r: *Runner) !void {
    const nodes = build(extra, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    });
    _ = harness.call(r, harness.ids.query, nodes.items[0..nodes.len], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len) return error.ReadCapacity;
    r.required = @intCast(r.response.byte_length);
}

pub fn readSpan(comptime extra: Params, r: *Runner) !void {
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.encoded[0..r.encoded_len]), harness.sinkSpan(r.output) });
    _ = harness.call(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) {
        return error.ReadMismatch;
    }
}

pub fn writeCallbackSource(comptime extra: Params, r: *Runner) !void {
    var source_ctx = harness.SourceCallbackContext{ .data = r.input };
    const nodes = build(extra, r, &.{ harness.sourceCallbackNode(0, 0), harness.sinkSpan(r.encoded) });
    _ = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    r.encoded_len = @intCast(r.response.byte_length);
    if (r.encoded_len == 0 or r.encoded_len > r.encoded.len) return error.CallbackEncodedLength;
}

pub fn readCallbackSink(comptime extra: Params, r: *Runner) !void {
    const accept_limit: usize = if (r.sink_accept != 0) @intCast(r.sink_accept) else std.math.maxInt(usize);
    var sink_ctx = harness.SinkBufferContext{ .buffer = r.output, .accept_limit = accept_limit };
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.encoded[0..r.encoded_len]), harness.sinkCallbackNode(0, 0) });
    _ = harness.call(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) {
        return error.CallbackReadMismatch;
    }
}

pub fn invalidReject(comptime extra: Params, r: *Runner) !void {
    var output = [_]u8{0xa5} ** 16;
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.invalid), harness.sinkSpan(&output) });
    try harness.reject(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true }, r.invalid_status, &output);
}

pub fn capacitySmallSink(comptime extra: Params, r: *Runner) !void {
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.input), harness.sinkSpan(r.output[0..1]) });
    try harness.expectCapacity(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true }, harness.ids.diagnostic_required_capacity, harness.ids.diagnostic_available_capacity, r.encoded_len, 1, r.output[0..1]);
}

pub fn limitReject(comptime extra: Params, r: *Runner) !void {
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.encoded[0..r.encoded_len]), harness.sinkSpan(r.output), harness.lim(r.input.len - 1) });
    try harness.reject(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true }, abi.Status.resource_limit, r.output);
}

pub fn corruptReject(comptime extra: Params, r: *Runner) !void {
    if (r.encoded_len == 0) return error.NoEncodedData;
    @memset(r.output, 0xa5);
    r.encoded[0] ^= 0xff;
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.encoded[0..r.encoded_len]), harness.sinkSpan(r.output) });
    _ = harness.call(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true });
    r.encoded[0] ^= 0xff;
    if (r.corrupt_status != 0) {
        try harness.requireStatus(r, r.corrupt_status);
    } else if (r.status == abi.Status.ok) {
        return error.CorruptInputAccepted;
    }
    if (!harness.allBytesEqual(r.output, 0xa5)) return error.CorruptChangedOutput;
}

pub fn truncateReject(comptime extra: Params, r: *Runner) !void {
    if (r.encoded_len <= 1) return error.NoEncodedData;
    const nodes = build(extra, r, &.{ harness.sourceSpan(r.encoded[0 .. r.encoded_len - 1]), harness.sinkSpan(r.output) });
    try harness.reject(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true }, r.invalid_status, r.output);
}

pub fn foreignTool(r: *Runner) !void {
    const valid = if (abi.idEqual(r.profile_id, harness.ids.gzip))
        lib.gzipValid(r.encoded[0..r.encoded_len])
    else if (abi.idEqual(r.profile_id, harness.ids.bzip2))
        lib.bzip2Valid(r.encoded[0..r.encoded_len])
    else
        return error.UnsupportedForeignTool;
    if (!valid) return error.ReferenceToolRejectedOutput;
}
