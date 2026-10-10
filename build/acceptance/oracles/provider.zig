const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const options = @import("options");
const Runner = harness.Runner;

// Provider-selection coverage: existing scenarios run every call with no
// provider parameter, which is the absent-means-onprem case. These scenarios
// pin the explicit parameter: roundtrips per format must agree byte for byte
// between the boundary default and the offprem provider, a provider no
// capability can serve is rejected with unsupported, and unknown values are
// invalid_call.

var provider_input: [64 * 1024]u8 = undefined;
var provider_encoded: [80 * 1024]u8 = undefined;
var provider_reference: [80 * 1024]u8 = undefined;
var provider_output: [64 * 1024]u8 = undefined;

fn roundtripWithProvider(r: *Runner, profile_id: harness.Id, mode: harness.Mode, provider: ?u64, extra_write: []const harness.Node, extra_read: []const harness.Node, encoded: []u8) !void {
    harness.setup(r, profile_id, mode);
    corpus.fillTiled(r.corpus_index, &provider_input);
    var write_nodes: [8]harness.Node = undefined;
    var count: usize = 0;
    nodesAppend(&write_nodes, &count, harness.sourceSpan(&provider_input));
    nodesAppend(&write_nodes, &count, harness.sinkSpan(encoded));
    for (extra_write) |extra| {
        nodesAppend(&write_nodes, &count, extra);
    }
    if (provider) |value| {
        nodesAppend(&write_nodes, &count, harness.providerParam(value));
    }
    try harness.spanProduce(r, harness.ids.write, write_nodes[0..count]);
    var read_nodes: [6]harness.Node = undefined;
    var read_count: usize = 0;
    nodesAppend(&read_nodes, &read_count, harness.sourceSpan(encoded[0..r.encoded_len]));
    nodesAppend(&read_nodes, &read_count, harness.sinkSpan(&provider_output));
    for (extra_read) |extra| {
        nodesAppend(&read_nodes, &read_count, extra);
    }
    if (provider) |value| {
        nodesAppend(&read_nodes, &read_count, harness.providerParam(value));
    }
    _ = harness.call(r, harness.ids.read, read_nodes[0..read_count], .{ .ctx = true });
    if (r.status != abi.Status.ok) {
        std.debug.print("provider roundtrip read failed: status {d} provider {?d}\n", .{ r.status, provider });
        return error.ProviderRoundtripReadFailed;
    }
    if (r.response.byte_length != provider_input.len) return error.ProviderRoundtripLengthMismatch;
    if (!std.mem.eql(u8, provider_output[0..provider_input.len], &provider_input)) return error.ProviderRoundtripContentMismatch;
}

fn nodesAppend(nodes: []harness.Node, count: *usize, node: harness.Node) void {
    nodes[count.*] = node;
    count.* += 1;
}

fn providersAgree(r: *Runner, profile_id: harness.Id, mode: harness.Mode, extra_write: []const harness.Node, extra_read: []const harness.Node) anyerror!void {
    if (!harness.offprem_servable) return;
    try roundtripWithProvider(r, profile_id, mode, null, extra_write, extra_read, &provider_encoded);
    const reference_len = r.encoded_len;
    @memcpy(provider_reference[0..reference_len], provider_encoded[0..reference_len]);
    try roundtripWithProvider(r, profile_id, mode, 1, extra_write, extra_read, &provider_encoded);
    if (r.encoded_len != reference_len) return error.ProviderWriteLengthMismatch;
    if (!std.mem.eql(u8, provider_encoded[0..r.encoded_len], provider_reference[0..reference_len])) return error.ProviderWriteContentMismatch;
}

pub fn runGzipProvider(r: *Runner) anyerror!void {
    try providersAgree(r, harness.ids.gzip, harness.mode_stream, &.{}, &.{});
}

pub fn runZstdProvider(r: *Runner) anyerror!void {
    const window = [_]harness.Node{harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 22)};
    try providersAgree(r, harness.ids.zstd, harness.mode_xz, &window, &window);
}

pub fn runXzSha256Provider(r: *Runner) anyerror!void {
    const write_params = [_]harness.Node{ harness.lzmaDictionaryParam(4096), harness.xzCheckParam(0x0A) };
    const read_params = [_]harness.Node{harness.lzmaDictionaryParam(4096)};
    try providersAgree(r, harness.ids.xz, harness.mode_xz, &write_params, &read_params);
}

pub fn runBzip2Provider(r: *Runner) anyerror!void {
    try providersAgree(r, harness.ids.bzip2, harness.mode_stream, &.{}, &.{});
}

pub fn runLz4Provider(r: *Runner) anyerror!void {
    try providersAgree(r, harness.ids.lz4, harness.mode_stream, &.{}, &.{});
}

pub fn runUnsupportedProvider(r: *Runner) anyerror!void {
    if (harness.both_servable) return;
    const unserved: u64 = if (comptime options.primitives_impl == .onprem) 1 else 0;
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, &provider_input);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(&provider_input),
        harness.sinkSpan(&provider_output),
        harness.providerParam(unserved),
    }, .{});
    try harness.requireStatus(r, abi.Status.unsupported);
}

pub fn runInvalidProviderValue(r: *Runner) anyerror!void {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, &provider_input);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(&provider_input),
        harness.sinkSpan(&provider_output),
        harness.providerParam(2),
    }, .{});
    try harness.requireStatus(r, abi.Status.invalid_call);
}

pub const scenarios = harness.scenarios("provider", &.{
    .{ .label = "gzip providers agree", .run = runGzipProvider, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "zstd providers agree", .run = runZstdProvider, .workspace_size = 32 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "xz sha256 providers agree", .run = runXzSha256Provider, .workspace_size = 8 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 16384 },
    .{ .label = "bzip2 providers agree", .run = runBzip2Provider, .workspace_size = 32 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "lz4 providers agree", .run = runLz4Provider, .workspace_size = 8 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "unserved provider rejected", .run = runUnsupportedProvider, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "invalid provider value", .run = runInvalidProviderValue, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
}, &.{});
