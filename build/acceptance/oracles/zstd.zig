const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const Runner = harness.Runner;
const steps = @import("steps.zig");

fn baseParams(out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 22);
    out[1] = harness.paramScalar(harness.param_family_zstd, harness.zstd_hash_bits, harness.cmd_all, 17);
    return 2;
}

fn zstdParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_double_hash, harness.cmd_all, 1);
    return count + 1;
}

fn zstdRowParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_row_match, harness.cmd_all, 1);
    return count + 1;
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

fn roundtrip(comptime params: steps.Params) fn (*Runner) anyerror!void {
    return struct {
        fn run(r: *Runner) anyerror!void {
            setupProfile(r);
            try steps.queryWrite(params, r);
            try steps.writeSpan(params, r);
            try steps.queryRead(params, r);
            try steps.readSpan(params, r);
            try steps.writeCallbackSource(params, r);
            try steps.readCallbackSink(params, r);
            try steps.invalidReject(params, r);
            try steps.truncateReject(params, r);
            try steps.capacitySmallSink(params, r);
        }
    }.run;
}

fn large(comptime params: steps.Params) fn (*Runner) anyerror!void {
    return struct {
        fn run(r: *Runner) anyerror!void {
            var input: [1 << 20]u8 = undefined;
            corpus.select(r.corpus_index, &input);
            harness.setup(r, harness.ids.zstd, harness.mode_xz);
            r.input = &input;
            r.write_exact = false;
            try steps.queryWrite(params, r);
            try steps.writeSpan(params, r);
            try steps.queryRead(params, r);
            try steps.readSpan(params, r);
        }
    }.run;
}

fn foreignEncode(r: *Runner) anyerror!void {
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

fn foreignValidate(comptime params: steps.Params) fn (*Runner) anyerror!void {
    return struct {
        fn run(r: *Runner) anyerror!void {
            setupProfile(r);
            try steps.writeSpan(params, r);
            if (!lib.zstdValid(r.encoded[0..r.encoded_len])) return error.ZstdReferenceRejectedOutput;
        }
    }.run;
}

var row_input: [64 * 1024]u8 = undefined;
var row_reference: [64 * 1024 + 4096]u8 = undefined;

fn runRowEngages(r: *Runner) anyerror!void {
    setupProfile(r);
    r.write_exact = false;
    // Periodic input collapses finders onto rep-offset paths; xorshift avoids periodic reps.
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

const Variant = struct {
    label: []const u8,
    params: steps.Params,
    foreign_encode: bool,
};
const variants = [_]Variant{
    .{ .label = "zstd", .params = &zstdParams, .foreign_encode = true },
    .{ .label = "zstd row", .params = &zstdRowParams, .foreign_encode = false },
};

pub const scenarios = harness.scenarios("zstd", blk: {
    var list: [7]harness.Spec = undefined;
    var index: usize = 0;
    for (variants) |variant| {
        list[index] = .{ .label = variant.label ++ " roundtrip", .run = roundtrip(variant.params), .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 };
        index += 1;
        list[index] = .{ .label = variant.label ++ " large", .run = large(variant.params), .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536 };
        index += 1;
        if (variant.foreign_encode) {
            list[index] = .{ .label = "zstd foreign encode", .run = &foreignEncode, .workspace_size = 256 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 };
            index += 1;
        }
        list[index] = .{ .label = variant.label ++ " foreign validate", .run = foreignValidate(variant.params), .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 };
        index += 1;
    }
    break :blk &list;
}, &.{
    .{ .name = "zstd corrupt", .run = runCorrupt, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .name = "zstd invalid window", .run = runInvalidWindow, .workspace_size = 256 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .name = "zstd row engages", .run = runRowEngages, .workspace_size = 256 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
});
