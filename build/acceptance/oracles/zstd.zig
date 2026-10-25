const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const steps = @import("steps.zig");

const Runner = harness.Runner;

fn baseParams(out: *[steps.max_extra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmds, 1 << 22);
    out[1] = harness.paramScalar(harness.param_family_zstd, harness.zstd_hash_bits, harness.cmds, 17);
    return 2;
}

fn zstdParams(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_double_hash, harness.cmds, 1);
    return count + 1;
}

fn zstdRowParams(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_row_match, harness.cmds, 1);
    return count + 1;
}

// A/B dump path: these bytes diff between builds, covering record layout,
// parser tier, and entropy heuristic. Shared dump in harness.zig.
fn abEncodeAndWrite(r: *Runner, comptime params: steps.Params, input: []const u8, label: []const u8) !void {
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    r.input = input;
    r.write_exact = false;
    steps.queryWrite(params, r) catch |err| {
        std.debug.print("abEncodeAndWrite query failed: {s}, status {d}.\n", .{ label, r.status });
        return err;
    };
    steps.writeSpan(params, r) catch |err| {
        std.debug.print("abEncodeAndWrite write failed: {s}, status {d}.\n", .{ label, r.status });
        return err;
    };
    try harness.abDumpEncoded(r, label);
}

fn zstdFastParams(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    // The true chain parser: dfast stays off (double_hash = 0), so the
    // dump reflects the hash-chain walk.
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_double_hash, harness.cmds, 0);
    return count + 1;
}

fn zstdGreedyParams(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_strategy, harness.cmds, 1);
    return count + 1;
}

fn zstdLazy2Params(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_strategy, harness.cmds, 2);
    return count + 1;
}

fn zstdEntropyParams(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_entropy, harness.cmds, 1);
    return count + 1;
}

fn zstdDpParams(_: *Runner, out: *[steps.max_extra]harness.Node) usize {
    const count = baseParams(out);
    out[count] = harness.paramScalar(harness.param_family_zstd, harness.zstd_strategy, harness.cmds, 3);
    return count + 1;
}

fn runZstdAbDumps(r: *Runner) !void {
    for (0..4) |corpus_index| {
        var input: [1 << 16]u8 = undefined;
        corpus.fillTiled(corpus_index, &input);
        const dfast = try r.gpa.print("dfast_{d}.bin", .{corpus_index});
        defer r.gpa.free(dfast);
        const chain = try r.gpa.print("chain_{d}.bin", .{corpus_index});
        defer r.gpa.free(chain);
        const row = try r.gpa.print("row_{d}.bin", .{corpus_index});
        defer r.gpa.free(row);
        const greedy = try r.gpa.print("greedy_{d}.bin", .{corpus_index});
        defer r.gpa.free(greedy);
        const lazy2 = try r.gpa.print("lazy2_{d}.bin", .{corpus_index});
        defer r.gpa.free(lazy2);
        const dp = try r.gpa.print("dp_{d}.bin", .{corpus_index});
        defer r.gpa.free(dp);
        try abEncodeAndWrite(r, zstdParams, &input, dfast);
        try abEncodeAndWrite(r, zstdFastParams, &input, chain);
        try abEncodeAndWrite(r, zstdRowParams, &input, row);
        try abEncodeAndWrite(r, zstdGreedyParams, &input, greedy);
        try abEncodeAndWrite(r, zstdLazy2Params, &input, lazy2);
        try abEncodeAndWrite(r, zstdDpParams, &input, dp);
    }
    var large_input: [1 << 20]u8 = undefined;
    corpus.fillTiled(r.corpus_index, &large_input);
    try abEncodeAndWrite(r, zstdParams, &large_input, "dfast_large.bin");
    try abEncodeAndWrite(r, zstdFastParams, &large_input, "chain_large.bin");
    try abEncodeAndWrite(r, zstdRowParams, &large_input, "row_large.bin");
    try abEncodeAndWrite(r, zstdGreedyParams, &large_input, "greedy_large.bin");
    try abEncodeAndWrite(r, zstdLazy2Params, &large_input, "lazy2_large.bin");
    try abEncodeAndWrite(r, zstdDpParams, &large_input, "dp_large.bin");
    // Tiled corpora collapse every finder onto repeat-offset paths (the
    // row-match lesson); tier quality needs a deterministic, non-periodic 8-symbol stream.
    var mixed: [1 << 20]u8 = undefined;
    var state: u64 = 0x9E3779B97F4A7C15;
    for (&mixed) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @as(u8, @truncate(state)) & 7;
    }
    try abEncodeAndWrite(r, zstdParams, &mixed, "dfast_mixed.bin");
    try abEncodeAndWrite(r, zstdFastParams, &mixed, "chain_mixed.bin");
    try abEncodeAndWrite(r, zstdRowParams, &mixed, "row_mixed.bin");
    try abEncodeAndWrite(r, zstdGreedyParams, &mixed, "greedy_mixed.bin");
    try abEncodeAndWrite(r, zstdLazy2Params, &mixed, "lazy2_mixed.bin");
    try abEncodeAndWrite(r, zstdDpParams, &mixed, "dp_mixed.bin");
    // Natural text separates deferral tiers where synthetic streams tie.
    // COPYING is static and tracked, so both builds encode identical bytes.
    const copying = try std.Io.Dir.cwd().readFileAlloc(harness.oracle_io, "COPYING", r.gpa, .limited(1 << 20));
    defer r.gpa.free(copying);
    try abEncodeAndWrite(r, zstdParams, copying, "dfast_text.bin");
    try abEncodeAndWrite(r, zstdFastParams, copying, "chain_text.bin");
    try abEncodeAndWrite(r, zstdRowParams, copying, "row_text.bin");
    try abEncodeAndWrite(r, zstdGreedyParams, copying, "greedy_text.bin");
    try abEncodeAndWrite(r, zstdLazy2Params, copying, "lazy2_text.bin");
    try abEncodeAndWrite(r, zstdDpParams, copying, "dp_text.bin");
    // Collision-heavy structure: repeated segments at varying distances with single-byte
    // mutations; same-length matches at different offsets separate search and deferral tiers.
    var collide: [1 << 20]u8 = undefined;
    for (&collide) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @as(u8, @truncate(state)) & 7;
    }
    var write_at: usize = 4096;
    while (write_at + 300 < collide.len) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const dist = 20_000 + @as(usize, @truncate(state)) % 60_000;
        const step = 4096 + @as(usize, @truncate(state >> 32)) % 2048;
        if (write_at >= dist) {
            @memcpy(collide[write_at..][0..200], collide[write_at - dist ..][0..200]);
            collide[write_at + @as(usize, @truncate(state >> 16)) % 200] ^= 0x5A;
        }
        write_at += step;
    }
    try abEncodeAndWrite(r, zstdParams, &collide, "dfast_collide.bin");
    try abEncodeAndWrite(r, zstdFastParams, &collide, "chain_collide.bin");
    try abEncodeAndWrite(r, zstdRowParams, &collide, "row_collide.bin");
    try abEncodeAndWrite(r, zstdGreedyParams, &collide, "greedy_collide.bin");
    try abEncodeAndWrite(r, zstdLazy2Params, &collide, "lazy2_collide.bin");
    try abEncodeAndWrite(r, zstdDpParams, &collide, "dp_collide.bin");
    // One-off tier separation probe against the local Silesia copy: natural
    // collision-heavy data. Not a permanent input (zig-out is not stable).
    if (std.Io.Dir.cwd().readFileAlloc(harness.oracle_io, "zig-out/benchmark/corpus/nci", r.gpa, .limited(1 << 25))) |nci| {
        defer r.gpa.free(nci);
        const nci_slice = nci[0..@min(nci.len, 1 << 20)];
        try abEncodeAndWrite(r, zstdParams, nci_slice, "dfast_nci.bin");
        try abEncodeAndWrite(r, zstdFastParams, nci_slice, "chain_nci.bin");
        try abEncodeAndWrite(r, zstdRowParams, nci_slice, "row_nci.bin");
        try abEncodeAndWrite(r, zstdGreedyParams, nci_slice, "greedy_nci.bin");
        try abEncodeAndWrite(r, zstdLazy2Params, nci_slice, "lazy2_nci.bin");
        try abEncodeAndWrite(r, zstdDpParams, nci_slice, "dp_nci.bin");
        try abEncodeAndWrite(r, zstdEntropyParams, nci_slice, "entropy_nci.bin");
        try abEncodeAndWrite(r, zstdEntropyParams, copying, "entropy_text.bin");
    } else |_| {
        // Missing corpus input skips the dumps; the suite still checks the tables.
    }
}

fn setupProfile(r: *Runner) void {
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    r.sink_accept = 3;
    r.write_exact = false;
    r.invalid_status = abi.Status.invalid_data;
    r.invalid = &.{ 0x28, 0xb5, 0x2f, 0xfd, 0x00 };
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..32];
}

fn roundtrip(comptime params: steps.Params) fn (*Runner) anyerror!void {
    return struct {
        fn run(r: *Runner) anyerror!void {
            setupProfile(r);
            try steps.roundtripTruncate(params, r);
            try steps.writeLimitReject(params, r);
        }
    }.run;
}

fn large(comptime params: steps.Params) fn (*Runner) anyerror!void {
    return struct {
        fn run(r: *Runner) anyerror!void {
            var input: [1 << 20]u8 = undefined;
            corpus.fillTiled(r.corpus_index, &input);
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

// A new parser tier must round-trip and decode under the reference library;
// zstdValid's 64 KiB window bounds the input.
fn strategyInterop(comptime params: steps.Params) fn (*Runner) anyerror!void {
    return struct {
        fn run(r: *Runner) anyerror!void {
            var input: [1 << 16]u8 = undefined;
            corpus.fillTiled(r.corpus_index, &input);
            harness.setup(r, harness.ids.zstd, harness.mode_xz);
            r.input = &input;
            r.write_exact = false;
            try steps.queryWrite(params, r);
            try steps.writeSpan(params, r);
            if (!lib.zstdValid(r.encoded[0..r.encoded_len])) return error.ReferenceToolRejectedOutput;
            try steps.queryRead(params, r);
            try steps.readSpan(params, r);
        }
    }.run;
}

fn foreignEncode(r: *Runner) anyerror!void {
    harness.setup(r, harness.ids.zstd, harness.mode_xz);
    var input: [64 * 1024]u8 = undefined;
    corpus.fillTiled(r.corpus_index, &input);
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
    // Periodic input collapses finders onto rep-offset paths. Xorshift avoids periodic reps.
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
        harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmds, 3),
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
    .{ .name = "zstd ab dumps", .run = runZstdAbDumps, .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536, .suite = "zstd_ab" },
    .{ .name = "zstd greedy interop", .run = strategyInterop(zstdGreedyParams), .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536, .suite = "zstd" },
    .{ .name = "zstd lazy2 interop", .run = strategyInterop(zstdLazy2Params), .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536, .suite = "zstd" },
    .{ .name = "zstd dp interop", .run = strategyInterop(zstdDpParams), .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536, .suite = "zstd" },
    .{ .name = "zstd entropy early-outs interop", .run = strategyInterop(zstdEntropyParams), .workspace_size = 256 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536, .suite = "zstd" },
});
