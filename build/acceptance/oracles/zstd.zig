const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const Runner = harness.Runner;
const steps = @import("steps.zig");

fn zstdParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 22);
    out[1] = harness.paramScalar(harness.param_family_zstd, harness.zstd_hash_bits, harness.cmd_all, 17);
    out[2] = harness.paramScalar(harness.param_family_zstd, harness.zstd_double_hash, harness.cmd_all, 1);
    return 3;
}

fn zstdRowParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 22);
    out[1] = harness.paramScalar(harness.param_family_zstd, harness.zstd_hash_bits, harness.cmd_all, 17);
    out[2] = harness.paramScalar(harness.param_family_zstd, harness.zstd_row_match, harness.cmd_all, 1);
    return 3;
}

fn setupProfile(r: *Runner) void {
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    r.sink_accept = 3;
    r.write_exact = false;
    r.invalid_status = abi.Status.invalid_data;
    r.invalid = &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x00 };
    corpus.select(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..32];
}

fn runRoundtrip(r: *Runner) anyerror!void {
    setupProfile(r);
    try steps.queryWrite(&zstdParams, r);
    try steps.writeSpan(&zstdParams, r);
    try steps.queryRead(&zstdParams, r);
    try steps.readSpan(&zstdParams, r);
    try steps.writeCallbackSource(&zstdParams, r);
    try steps.readCallbackSink(&zstdParams, r);
    try steps.invalidReject(&zstdParams, r);
    try steps.truncateReject(&zstdParams, r);
    try steps.capacitySmallSink(&zstdParams, r);
}

fn runLarge(r: *Runner) anyerror!void {
    var input: [1 << 20]u8 = undefined;
    corpus.select(r.corpus_index, &input);
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    r.input = &input;
    r.write_exact = false;
    try steps.queryWrite(&zstdParams, r);
    try steps.writeSpan(&zstdParams, r);
    try steps.queryRead(&zstdParams, r);
    try steps.readSpan(&zstdParams, r);
}

fn runForeignEncode(r: *Runner) anyerror!void {
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    var input: [64 * 1024]u8 = undefined;
    corpus.select(r.corpus_index, &input);
    const ref_size = lib.zstdCompress(&input, r.encoded) orelse return error.ZstdOracleRejectedInput;
    if (ref_size == 0 or ref_size >= r.encoded.len) return error.ZstdOracleOutputSize;
    r.encoded_len = ref_size;
    r.input = &input;
    try steps.queryRead(&zstdParams, r);
    try steps.readSpan(&zstdParams, r);
}

fn runForeignValidate(r: *Runner) anyerror!void {
    setupProfile(r);
    try steps.writeSpan(&zstdParams, r);
    if (!lib.zstdValid(r.encoded[0..r.encoded_len])) return error.ZstdReferenceRejectedOutput;
}

fn runRowRoundtrip(r: *Runner) anyerror!void {
    setupProfile(r);
    try steps.queryWrite(&zstdRowParams, r);
    try steps.writeSpan(&zstdRowParams, r);
    try steps.queryRead(&zstdRowParams, r);
    try steps.readSpan(&zstdRowParams, r);
    try steps.writeCallbackSource(&zstdRowParams, r);
    try steps.readCallbackSink(&zstdRowParams, r);
    try steps.invalidReject(&zstdRowParams, r);
    try steps.truncateReject(&zstdRowParams, r);
    try steps.capacitySmallSink(&zstdRowParams, r);
}

fn runRowLarge(r: *Runner) anyerror!void {
    var input: [1 << 20]u8 = undefined;
    corpus.select(r.corpus_index, &input);
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    r.input = &input;
    r.write_exact = false;
    try steps.queryWrite(&zstdRowParams, r);
    try steps.writeSpan(&zstdRowParams, r);
    try steps.queryRead(&zstdRowParams, r);
    try steps.readSpan(&zstdRowParams, r);
}

fn runRowForeignValidate(r: *Runner) anyerror!void {
    setupProfile(r);
    try steps.writeSpan(&zstdRowParams, r);
    if (!lib.zstdValid(r.encoded[0..r.encoded_len])) return error.ZstdReferenceRejectedOutput;
}

var row_input: [64 * 1024]u8 = undefined;
var row_reference: [64 * 1024 + 4096]u8 = undefined;

fn runRowEngages(r: *Runner) anyerror!void {
    setupProfile(r);
    r.write_exact = false;
    // The periodic oracle corpus collapses every finder onto the rep-offset
    // paths; an 8-symbol xorshift stream is collision-heavy without periodic
    // reps, so the row finder's multi-candidate scan must diverge from dfast.
    var state: u64 = 0x9E3779B97F4A7C15;
    for (&row_input) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @truncate(state % 8);
    }
    r.input = &row_input;
    try steps.writeSpan(&zstdRowParams, r);
    const row_len = r.encoded_len;
    @memcpy(row_reference[0..row_len], r.encoded[0..row_len]);
    try steps.writeSpan(&zstdParams, r);
    if (r.encoded_len == row_len and std.mem.eql(u8, r.encoded[0..r.encoded_len], row_reference[0..row_len])) return error.RowMatchNotEngaged;
    if (!lib.zstdValid(row_reference[0..row_len])) return error.ZstdReferenceRejectedOutput;
    r.encoded_len = row_len;
    @memcpy(r.encoded[0..row_len], row_reference[0..row_len]);
    try steps.readSpan(&zstdRowParams, r);
}

fn runCorrupt(r: *Runner) anyerror!void {
    setupProfile(r);
    try steps.writeSpan(&zstdParams, r);
    try steps.corruptReject(&zstdParams, r);
}

fn runInvalidWindow(r: *Runner) !void {
    const input = "invalid window";
    const nodes = steps.build(&zstdParams, r, &.{
        harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 3),
        harness.sourceSpan(input),
        harness.sinkSpan(r.encoded),
    });
    _ = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.invalid_call);
}

pub const scenarios = harness.scenarios("zstd", &.{
    .{ .label = "zstd roundtrip", .run = runRoundtrip, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "zstd large", .run = runLarge, .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536 },
    .{ .label = "zstd foreign encode", .run = runForeignEncode, .workspace_size = 256 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "zstd foreign validate", .run = runForeignValidate, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "zstd row roundtrip", .run = runRowRoundtrip, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "zstd row large", .run = runRowLarge, .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536 },
    .{ .label = "zstd row foreign validate", .run = runRowForeignValidate, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
}, &.{
    .{ .name = "zstd corrupt", .run = runCorrupt, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .name = "zstd invalid window", .run = runInvalidWindow, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .name = "zstd row engages", .run = runRowEngages, .workspace_size = 256 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
});
