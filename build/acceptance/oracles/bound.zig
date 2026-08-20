const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;

const Kind = enum { deflate, gzip, bzip2, lzma, lzma2, xz, zstd };

const Param = struct { family: u16, ordinal: u32, value: u64 };

const Case = struct {
    kind: Kind,
    params: []const Param = &.{},
    dictionary: ?[]const u8 = null,
};

fn param(family: u16, ordinal: u32, value: u64) Param {
    return .{ .family = family, .ordinal = ordinal, .value = value };
}

const deflate_high = [_]Param{
    param(harness.param_family_deflate, harness.deflate_good, 16),
    param(harness.param_family_deflate, harness.deflate_nice, 258),
    param(harness.param_family_deflate, harness.deflate_lazy, 48),
    param(harness.param_family_deflate, harness.deflate_chain, 256),
};
const bzip2_100k = [_]Param{param(harness.param_family_bzip2, harness.bzip2_block_size, 100000)};
const lzma_dict = [_]Param{
    param(harness.param_family_lzma, harness.lzma_dictionary, 1 << 23),
    param(harness.param_family_lzma, harness.lzma_match_finder_depth, 48),
};
const lzma_bt = [_]Param{
    param(harness.param_family_lzma, harness.lzma_dictionary, 1 << 23),
    param(harness.param_family_lzma, harness.lzma_match_finder, 1),
    param(harness.param_family_lzma, harness.lzma_match_finder_depth, 48),
};
const lzma_bt_lazy = [_]Param{
    param(harness.param_family_lzma, harness.lzma_dictionary, 1 << 23),
    param(harness.param_family_lzma, harness.lzma_match_finder, 1),
    param(harness.param_family_lzma, harness.lzma_lazy, 1),
    param(harness.param_family_lzma, harness.lzma_match_finder_depth, 48),
};
const zstd_window = [_]Param{
    param(harness.param_family_zstd, harness.zstd_window, 1 << 22),
    param(harness.param_family_zstd, harness.zstd_hash_bits, 17),
    param(harness.param_family_zstd, harness.zstd_double_hash, 1),
};
const zstd_lazy = [_]Param{
    param(harness.param_family_zstd, harness.zstd_window, 1 << 20),
    param(harness.param_family_zstd, harness.zstd_lazy, 1),
};
const zstd_fast = [_]Param{
    param(harness.param_family_zstd, harness.zstd_window, 1 << 20),
    param(harness.param_family_zstd, harness.zstd_skip_interior_insert, 1),
};
const zstd_dfast = [_]Param{
    param(harness.param_family_zstd, harness.zstd_window, 1 << 21),
    param(harness.param_family_zstd, harness.zstd_double_hash, 1),
};

const cases = [_]Case{
    .{ .kind = .deflate },
    .{ .kind = .deflate, .params = &deflate_high },
    .{ .kind = .gzip },
    .{ .kind = .gzip, .params = &deflate_high },
    .{ .kind = .bzip2 },
    .{ .kind = .bzip2, .params = &bzip2_100k },
    .{ .kind = .lzma, .params = &lzma_dict },
    .{ .kind = .lzma, .params = &lzma_bt },
    .{ .kind = .lzma, .params = &lzma_bt_lazy },
    .{ .kind = .lzma2, .params = &lzma_dict },
    .{ .kind = .xz, .params = &lzma_dict },
    .{ .kind = .xz, .params = &lzma_bt },
    .{ .kind = .zstd, .params = &zstd_window },
    .{ .kind = .zstd, .params = &zstd_lazy },
    .{ .kind = .zstd, .params = &zstd_fast },
    .{ .kind = .zstd, .params = &zstd_dfast },
};

fn profileId(kind: Kind) harness.Id {
    return switch (kind) {
        .deflate => harness.ids.deflate,
        .gzip => harness.ids.gzip,
        .bzip2 => harness.ids.bzip2,
        .lzma => harness.ids.lzma,
        .lzma2 => harness.ids.lzma2,
        .xz => harness.ids.xz,
        .zstd => harness.ids.zstd,
    };
}

fn setupCase(r: *Runner, case: Case) void {
    const verified = case.kind == .zstd or case.kind == .xz;
    harness.setup(r, profileId(case.kind), if (verified) harness.mode_xz else harness.mode_stream);
}

fn addParams(nodes: []harness.Node, count: *usize, case: Case) void {
    for (case.params) |p| {
        nodes[count.*] = harness.paramScalar(p.family, p.ordinal, harness.cmd_all, p.value);
        count.* += 1;
    }
    if (case.dictionary) |dict| {
        nodes[count.*] = harness.paramBytes(harness.param_family_zstd, harness.zstd_dictionary, harness.cmd_all, dict);
        count.* += 1;
    }
}

fn queryWriteSize(r: *Runner, case: Case, input: []const u8, bound: bool) !usize {
    var nodes: [12]harness.Node = undefined;
    var count: usize = 0;
    if (bound) {
        nodes[count] = harness.paramPlanningBound();
        count += 1;
    }
    nodes[count] = harness.paramTargetCommand(harness.ids.write);
    count += 1;
    nodes[count] = harness.sourceSpan(input);
    count += 1;
    addParams(&nodes, &count, case);
    nodes[count] = harness.cap(r.caps_query);
    count += 1;
    nodes[count] = harness.pln(r.planning);
    count += 1;
    nodes[count] = harness.dlv(r.delivery_write);
    count += 1;
    _ = harness.call(r, harness.ids.query, nodes[0..count], .{});
    try harness.requireStatus(r, abi.Status.ok);
    return @intCast(r.response.byte_length);
}

fn writeSpan(r: *Runner, case: Case, input: []const u8, sink: []u8, bound: bool) !usize {
    var nodes: [9]harness.Node = undefined;
    var count: usize = 0;
    if (bound) {
        nodes[count] = harness.paramPlanningBound();
        count += 1;
    }
    nodes[count] = harness.sourceSpan(input);
    count += 1;
    nodes[count] = harness.sinkSpan(sink);
    count += 1;
    addParams(&nodes, &count, case);
    _ = harness.call(r, harness.ids.write, nodes[0..count], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    return @intCast(r.response.byte_length);
}

fn readBack(r: *Runner, case: Case, encoded: []const u8, output: []u8, input: []const u8) !void {
    var nodes: [9]harness.Node = undefined;
    var count: usize = 0;
    nodes[count] = harness.sourceSpan(encoded);
    count += 1;
    nodes[count] = harness.sinkSpan(output);
    count += 1;
    addParams(&nodes, &count, case);
    _ = harness.call(r, harness.ids.read, nodes[0..count], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, output[0..input.len], input)) return error.BoundReadMismatch;
}

var roundtrip_input: [64 * 1024]u8 = undefined;
var bound_sink: [384 * 1024]u8 = undefined;

fn runRoundtrip(r: *Runner) anyerror!void {
    corpus.select(r.corpus_index, &roundtrip_input);
    const input = roundtrip_input[0..];
    for (cases) |case| {
        setupCase(r, case);
        const exact = try queryWriteSize(r, case, input, false);
        const replay_len = try writeSpan(r, case, input, r.encoded[0..exact], false);
        if (replay_len != exact) return error.ReplayExactMismatch;
        const bound = try queryWriteSize(r, case, input, true);
        if (bound < exact or bound > bound_sink.len) return error.BoundRange;
        const bound_len = try writeSpan(r, case, input, bound_sink[0..bound], true);
        if (bound_len != replay_len) return error.BoundLengthMismatch;
        if (!std.mem.eql(u8, bound_sink[0..bound_len], r.encoded[0..replay_len])) return error.BoundNotIdentical;
        try readBack(r, case, bound_sink[0..bound_len], r.output, input);
    }
}

fn runCapacity(r: *Runner) anyerror!void {
    corpus.select(r.corpus_index, &roundtrip_input);
    const input = roundtrip_input[0..];
    for (cases) |case| {
        setupCase(r, case);
        const bound = try queryWriteSize(r, case, input, true);
        if (bound > r.encoded.len) return error.BoundRange;
        var nodes: [9]harness.Node = undefined;
        var count: usize = 0;
        nodes[count] = harness.paramPlanningBound();
        count += 1;
        nodes[count] = harness.sourceSpan(input);
        count += 1;
        nodes[count] = harness.sinkSpan(r.encoded[0 .. bound - 1]);
        count += 1;
        addParams(&nodes, &count, case);
        try harness.expectCapacity(r, harness.ids.write, nodes[0..count], .{ .ctx = true }, harness.ids.diagnostic_required_capacity, harness.ids.diagnostic_available_capacity, bound, bound - 1, r.encoded[0 .. bound - 1]);
        const produced = try writeSpan(r, case, input, r.encoded[0..bound], true);
        if (produced > bound) return error.BoundViolated;
    }
}

var path_random: [1 << 20]u8 = undefined;
var path_same: [1 << 20]u8 = undefined;
var path_period: [1 << 20]u8 = undefined;
var path_mixed: [8 << 20]u8 = undefined;
// The lzma2 sizing probe's greedy estimate is fast, but the real encode that
// follows is the full DP parser, so truly incompressible megabytes still cost
// ~1000x in a Debug oracle build. The lzma family takes the uniform inputs at
// 64 KiB and the mixed input at mixed_small; corpus-scale incompressible
// coverage for those profiles runs in ReleaseFast through the benchmark rows.
var path_mixed_small: [(1 << 20) + 3 * 64 * 1024]u8 = undefined;
var zstd_dict: [64 * 1024]u8 = undefined;
var dict_text: [1 << 20]u8 = undefined;

fn fillRandom(buf: []u8, seed: u64) void {
    var state = seed | 1;
    for (buf) |*byte| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        byte.* = @truncate(state *% 0x2545F4914F6CDD1D >> 32);
    }
}

fn fillPeriod(buf: []u8, comptime period: usize, seed: u64) void {
    var pattern: [period]u8 = undefined;
    fillRandom(&pattern, seed);
    for (buf, 0..) |*byte, i| byte.* = pattern[i % period];
}

fn pathologicalInputs() [4][]const u8 {
    fillRandom(&path_random, 0x9e3779b97f4a7c15);
    @memset(&path_same, 0x55);
    fillPeriod(&path_period, 4, 0xd1b54a32d192ed03);
    fillRandom(path_mixed[0 .. 2 << 20], 0x94d049bb133111eb);
    @memset(path_mixed[2 << 20 .. 4 << 20], 0xa7);
    fillPeriod(path_mixed[4 << 20 .. 6 << 20], 4, 0x2545f4914f6cdd1d);
    corpus.select(1, path_mixed[6 << 20 .. 8 << 20]);
    corpus.select(1, path_mixed_small[0 .. 1 << 20]);
    @memcpy(path_mixed_small[1 << 20 ..][0 .. 64 * 1024], path_mixed[0 .. 64 * 1024]);
    @memset(path_mixed_small[(1 << 20) + 64 * 1024 ..][0 .. 64 * 1024], 0xa7);
    fillPeriod(path_mixed_small[(1 << 20) + 2 * 64 * 1024 ..][0 .. 64 * 1024], 4, 0x2545f4914f6cdd1d);
    return .{ &path_random, &path_same, &path_period, &path_mixed };
}

fn pathCap(kind: Kind) usize {
    return switch (kind) {
        .lzma, .lzma2, .xz => 64 * 1024,
        else => std.math.maxInt(usize),
    };
}

fn checkAtBound(r: *Runner, case: Case, input: []const u8) !void {
    setupCase(r, case);
    const bound = try queryWriteSize(r, case, input, true);
    if (bound > r.encoded.len) return error.BoundRange;
    const produced = try writeSpan(r, case, input, r.encoded[0..bound], true);
    if (produced > bound) return error.BoundViolated;
    if (input.len <= r.output.len) try readBack(r, case, r.encoded[0..produced], r.output, input);
}

fn runPathological(r: *Runner) anyerror!void {
    const inputs = pathologicalInputs();
    for (inputs) |input| {
        for (cases) |case| {
            const sized_input = switch (case.kind) {
                .lzma, .lzma2, .xz => if (input.len == path_mixed.len) path_mixed_small[0..] else input[0..@min(input.len, pathCap(case.kind))],
                else => input,
            };
            try checkAtBound(r, case, sized_input);
        }
    }
    for ([_]usize{ 0, 1, 64 * 1024, 1 << 20 }) |size| {
        for (cases) |case| try checkAtBound(r, case, path_random[0..@min(size, pathCap(case.kind))]);
    }
    corpus.select(2, &zstd_dict);
    const dict_case = Case{ .kind = .zstd, .params = &zstd_window, .dictionary = &zstd_dict };
    for (inputs) |input| try checkAtBound(r, dict_case, input);
    corpus.select(3, &dict_text);
    try checkAtBound(r, dict_case, &dict_text);
}

var callback_direct: [384 * 1024]u8 = undefined;
var callback_sink_buffer: [384 * 1024]u8 = undefined;

fn runCallback(r: *Runner) anyerror!void {
    corpus.select(r.corpus_index, &roundtrip_input);
    const input = roundtrip_input[0..];
    for (cases) |case| {
        setupCase(r, case);
        const bound = try queryWriteSize(r, case, input, true);
        if (bound > callback_direct.len) return error.BoundRange;
        const direct_len = try writeSpan(r, case, input, callback_direct[0..bound], true);

        var source_ctx = harness.SourceCallbackContext{ .data = input };
        var source_nodes: [9]harness.Node = undefined;
        var source_count: usize = 0;
        source_nodes[source_count] = harness.paramPlanningBound();
        source_count += 1;
        source_nodes[source_count] = harness.sourceCallbackNode(0, 0);
        source_count += 1;
        source_nodes[source_count] = harness.sinkSpan(bound_sink[0..bound]);
        source_count += 1;
        addParams(&source_nodes, &source_count, case);
        _ = harness.call(r, harness.ids.write, source_nodes[0..source_count], .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != direct_len or !std.mem.eql(u8, bound_sink[0..direct_len], callback_direct[0..direct_len])) return error.CallbackSourceMismatch;

        var sink_ctx = harness.SinkBufferContext{ .buffer = &callback_sink_buffer, .accept_limit = std.math.maxInt(usize) };
        var sink_nodes: [9]harness.Node = undefined;
        var sink_count: usize = 0;
        sink_nodes[sink_count] = harness.paramPlanningBound();
        sink_count += 1;
        sink_nodes[sink_count] = harness.sourceSpan(input);
        sink_count += 1;
        sink_nodes[sink_count] = harness.sinkCallbackNode(0, 0);
        sink_count += 1;
        addParams(&sink_nodes, &sink_count, case);
        _ = harness.call(r, harness.ids.write, sink_nodes[0..sink_count], .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
        try harness.requireStatus(r, abi.Status.ok);
        if (sink_ctx.offset != direct_len or !std.mem.eql(u8, callback_sink_buffer[0..direct_len], callback_direct[0..direct_len])) return error.CallbackSinkMismatch;

        var fail_ctx = harness.SinkCallbackContext{ .fail_after = 5 };
        var downstream = harness.scalarNode(harness.ids.diagnostic_downstream_status);
        var diagnostic = harness.node(null, 0);
        diagnostic.child = &downstream;
        _ = harness.call(r, harness.ids.write, sink_nodes[0..sink_count], .{ .ctx = true, .callback = harness.sinkCallback, .context = &fail_ctx, .diagnostic = &diagnostic });
        try harness.requireStatus(r, abi.Status.io_failure);
        if (fail_ctx.accepted_total != 4) return error.CallbackAcceptedTotalMismatch;
        if (downstream.value_low != abi.Status.insufficient_capacity) return error.DownstreamStatusMismatch;
    }
}

fn runMisuse(r: *Runner) !void {
    const input = "planning bound misuse";
    var sink: [256]u8 = undefined;
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    try harness.expect(r, harness.ids.read, &.{
        harness.paramPlanningBound(),
        harness.sourceSpan(input),
        harness.sinkSpan(&sink),
    }, .{ .ctx = true }, abi.Status.unsupported);
    try harness.expect(r, harness.ids.query, &.{
        harness.paramPlanningBound(),
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(input),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    }, .{}, abi.Status.unsupported);
    try harness.expect(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.tar),
        harness.paramPlanningBound(),
        harness.sourceSpan(input),
        harness.sinkSpan(&sink),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
    }, .{ .profile = false }, abi.Status.unsupported);
    try harness.expect(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.test_echo),
        harness.paramPlanningBound(),
        harness.sourceSpan(input),
        harness.sinkSpan(&sink),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false }, abi.Status.unsupported);
}

fn runGzipHeaders(r: *Runner) anyerror!void {
    corpus.select(r.corpus_index, &roundtrip_input);
    const input = roundtrip_input[0..];
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    const name = "payload.txt";
    const comment = "stdk gzip comment";
    const extra = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const header_nodes = [_]harness.Node{
        harness.mtime(0x12345678),
        harness.xflags(2),
        harness.os(3),
        harness.text(1),
        harness.hcrc(1),
        harness.gname(name),
        harness.gcomment(comment),
        harness.gextra(&extra),
    };
    var nodes: [14]harness.Node = undefined;
    var count: usize = 0;
    nodes[count] = harness.paramPlanningBound();
    count += 1;
    nodes[count] = harness.paramTargetCommand(harness.ids.write);
    count += 1;
    nodes[count] = harness.sourceSpan(input);
    count += 1;
    for (header_nodes) |node| {
        nodes[count] = node;
        count += 1;
    }
    nodes[count] = harness.cap(r.caps_query);
    count += 1;
    nodes[count] = harness.pln(r.planning);
    count += 1;
    nodes[count] = harness.dlv(r.delivery_write);
    count += 1;
    _ = harness.call(r, harness.ids.query, nodes[0..count], .{});
    try harness.requireStatus(r, abi.Status.ok);
    const bound: usize = @intCast(r.response.byte_length);
    if (bound > bound_sink.len) return error.BoundRange;

    var write_nodes: [14]harness.Node = undefined;
    var write_count: usize = 0;
    write_nodes[write_count] = harness.sourceSpan(input);
    write_count += 1;
    write_nodes[write_count] = harness.sinkSpan(r.encoded);
    write_count += 1;
    for (header_nodes) |node| {
        write_nodes[write_count] = node;
        write_count += 1;
    }
    _ = harness.call(r, harness.ids.write, write_nodes[0..write_count], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    const replay_len: usize = @intCast(r.response.byte_length);
    if (bound < replay_len) return error.BoundRange;

    write_nodes[1] = harness.sinkSpan(bound_sink[0..bound]);
    var bound_nodes: [14]harness.Node = undefined;
    bound_nodes[0] = harness.paramPlanningBound();
    @memcpy(bound_nodes[1 .. write_count + 1], write_nodes[0..write_count]);
    _ = harness.call(r, harness.ids.write, bound_nodes[0 .. write_count + 1], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    const bound_len: usize = @intCast(r.response.byte_length);
    if (bound_len != replay_len or !std.mem.eql(u8, bound_sink[0..bound_len], r.encoded[0..replay_len])) return error.BoundNotIdentical;

    var read_nodes: [2]harness.Node = undefined;
    read_nodes[0] = harness.sourceSpan(bound_sink[0..bound_len]);
    read_nodes[1] = harness.sinkSpan(r.output);
    _ = harness.call(r, harness.ids.read, &read_nodes, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, r.output[0..input.len], input)) return error.BoundReadMismatch;
}

pub const scenarios = harness.scenarios("bound", &.{
    .{ .label = "bound roundtrip", .run = runRoundtrip, .workspace_size = 256 * 1024 * 1024, .output_size = 128 * 1024, .encoded_size = 384 * 1024 },
    .{ .label = "bound capacity", .run = runCapacity, .workspace_size = 256 * 1024 * 1024, .output_size = 1024, .encoded_size = 384 * 1024 },
    .{ .label = "bound callback", .run = runCallback, .workspace_size = 256 * 1024 * 1024, .output_size = 1024, .encoded_size = 384 * 1024 },
    .{ .label = "bound gzip headers", .run = runGzipHeaders, .workspace_size = 128 * 1024, .output_size = 128 * 1024, .encoded_size = 384 * 1024 },
}, &.{
    .{ .name = "bound pathological", .run = runPathological, .workspace_size = 320 * 1024 * 1024, .output_size = 9 * 1024 * 1024, .encoded_size = 28 * 1024 * 1024 },
    .{ .name = "bound misuse", .run = runMisuse, .workspace_size = 1024 * 1024, .output_size = 4096, .encoded_size = 65536 },
});
