const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const Runner = harness.Runner;
const steps = @import("steps.zig");

fn noParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    _ = out;
    return 0;
}

fn optimalParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_deflate, harness.deflate_optimal, harness.cmd_all, 1);
    out[1] = harness.paramScalar(harness.param_family_deflate, harness.deflate_nice, harness.cmd_all, 258);
    out[2] = harness.paramScalar(harness.param_family_deflate, harness.deflate_chain, harness.cmd_all, 256);
    return 3;
}

fn setupProfile(r: *Runner, profile_id: harness.Id) void {
    harness.setup(r, profile_id, harness.mode_stream);
    r.input = r.corpus_buffer[0..32];
    r.sink_accept = 3;
    r.write_exact = true;
    r.invalid_status = abi.Status.invalid_data;
    r.invalid = &.{0x06};
    corpus.select(r.corpus_index, r.corpus_buffer[0..]);
}

fn runRoundtrip(r: *Runner, profile_id: harness.Id) anyerror!void {
    setupProfile(r, profile_id);
    try steps.queryWrite(&noParams, r);
    try steps.writeSpan(&noParams, r);
    try steps.queryRead(&noParams, r);
    try steps.readSpan(&noParams, r);
    try steps.writeCallbackSource(&noParams, r);
    try steps.readCallbackSink(&noParams, r);
    try steps.invalidReject(&noParams, r);
    try steps.capacitySmallSink(&noParams, r);
}

pub fn runDeflate(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.deflate);
}

pub fn runDeflateOptimal(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.deflate);
    try steps.queryWrite(&optimalParams, r);
    try steps.writeSpan(&optimalParams, r);
    try steps.queryRead(&noParams, r);
    try steps.readSpan(&noParams, r);
    try steps.writeCallbackSource(&optimalParams, r);
    try steps.readCallbackSink(&noParams, r);
    try steps.capacitySmallSink(&optimalParams, r);
}

var optimal_input: [64 * 1024]u8 = undefined;
var optimal_reference: [64 * 1024 + 4096]u8 = undefined;

pub fn runGzipOptimal(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    r.write_exact = false;
    corpus.select(r.corpus_index, optimal_input[0..]);
    r.input = optimal_input[0..];
    try steps.writeSpan(&optimalParams, r);
    try steps.readSpan(&noParams, r);
    try steps.foreignTool(r);
    // Parser must engage: optimal stream differs from the default lazy stream here.
    const optimal_len = r.encoded_len;
    @memcpy(optimal_reference[0..optimal_len], r.encoded[0..optimal_len]);
    try steps.writeSpan(&noParams, r);
    if (r.encoded_len == optimal_len and std.mem.eql(u8, r.encoded[0..r.encoded_len], optimal_reference[0..optimal_len])) return error.OptimalParserNotEngaged;
    try steps.readSpan(&noParams, r);
}

pub fn runGzip(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.gzip);
    try steps.truncateReject(&noParams, r);
    try steps.foreignTool(r);
}

pub fn runBzip2Roundtrip(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.bzip2);
}

pub fn runBzip2Extras(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.bzip2);
    r.write_exact = false;
    try steps.writeSpan(&noParams, r);
    try steps.readSpan(&noParams, r);
    try steps.foreignTool(r);
    try bzOracleFixture(r);
    try bzBlockSizeRoundtrip(r);
    try bzMutations(r);
}

fn bzOracleFixture(r: *Runner) !void {
    var fixture_input: [65536]u8 = undefined;
    var compressed: [131072]u8 = undefined;
    var decoded: [65536]u8 = undefined;
    corpus.select(r.corpus_index, &fixture_input);
    try harness.oracleFixture(r, lib.bzip2Compress, &fixture_input, &compressed, &decoded);
}

fn bzBlockSizeRoundtrip(r: *Runner) !void {
    try steps.plan(&noParams, r, &.{
        harness.bzip2BlockParam(900000),
        harness.paramTargetCommand(harness.ids.write),
        harness.sourceSpan(r.input),
        harness.capabilityParam(r.caps_query),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_write),
    });
    try harness.spanProduce(r, harness.ids.write, &.{
        harness.bzip2BlockParam(900000),
        harness.sourceSpan(r.input),
        harness.sinkSpan(r.encoded),
    });
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (r.response.byte_length != r.input.len) return error.BlockSizeRoundtripLengthMismatch;
    if (!std.mem.eql(u8, r.output[0..r.input.len], r.input)) return error.BlockSizeRoundtripContentMismatch;
}

fn bzMutations(r: *Runner) !void {
    var mutated: [256]u8 = undefined;
    if (r.encoded_len == 0 or r.encoded_len > mutated.len) return error.EncodedSizeOutOfRange;
    @memcpy(mutated[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    mutated[10] ^= 0x08;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(mutated[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    if (r.status == abi.Status.ok) return error.MutatedBlockAccepted;
    @memcpy(mutated[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    if (r.encoded_len > 20) {
        mutated[r.encoded_len / 2] ^= 0x01;
        _ = harness.call(r, harness.ids.read, &.{
            harness.sourceSpan(mutated[0..r.encoded_len]),
            harness.sinkSpan(r.output),
        }, .{ .ctx = true });
        if (r.status == abi.Status.ok) return error.MidCorruptedBlockAccepted;
    }
    if (r.encoded_len > 14) {
        _ = harness.call(r, harness.ids.read, &.{
            harness.sourceSpan(r.encoded[0 .. r.encoded_len - 10]),
            harness.sinkSpan(r.output),
        }, .{ .ctx = true });
        if (r.status == abi.Status.ok) return error.TruncatedBlockAccepted;
    }
}

fn gzOptionalHeaders(r: *Runner) !void {
    const name = "payload.txt";
    const comment = "stdk gzip comment";
    const extra = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const header_params = [_]harness.Node{
        harness.gzipMtimeParam(0x12345678),
        harness.gzipExtraFlagsParam(2),
        harness.gzipOsParam(3),
        harness.gzipTextParam(1),
        harness.gzipHeaderCrcParam(1),
        harness.gzipNameParam(name),
        harness.gzipCommentParam(comment),
        harness.gzipExtraParam(&extra),
    };
    try steps.plan(&noParams, r, &[_]harness.Node{
        harness.paramTargetCommand(harness.ids.write),
        harness.sourceSpan(r.input),
    } ++ header_params ++ [_]harness.Node{
        harness.capabilityParam(r.caps_query),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_write),
    });
    try harness.spanProduce(r, harness.ids.write, &[_]harness.Node{harness.sourceSpan(r.input)} ++ header_params ++ [_]harness.Node{harness.sinkSpan(r.encoded)});
    if (r.encoded_len != r.required) return error.OptionalHeaderWriteLengthMismatch;
    if (r.encoded_len < 10 or r.encoded[0] != 0x1f or r.encoded[1] != 0x8b or r.encoded[2] != 0x08) return error.GzipMagicMismatch;
    if (r.encoded[3] != 0x1f) return error.GzipFlagsMismatch;
    const stored_mtime = @as(u32, r.encoded[4]) | (@as(u32, r.encoded[5]) << 8) | (@as(u32, r.encoded[6]) << 16) | (@as(u32, r.encoded[7]) << 24);
    if (stored_mtime != 0x12345678) return error.GzipMtimeMismatch;
    if (r.encoded[8] != 2 or r.encoded[9] != 3) return error.GzipXflagsOsMismatch;
    if (!harness.containsBytes(r.encoded[0..r.encoded_len], name)) return error.GzipNameMissing;
    if (!harness.containsBytes(r.encoded[0..r.encoded_len], comment)) return error.GzipCommentMissing;
    if (!harness.containsBytes(r.encoded[0..r.encoded_len], &extra)) return error.GzipExtraMissing;
    try steps.plan(&noParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.capabilityParam(r.caps_query),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_read),
    });
    if (r.required != r.input.len) return error.OptionalHeaderReadCapacityMismatch;
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) return error.OptionalHeaderRoundtripMismatch;
}

fn gzHeaderCrc(r: *Runner) !void {
    try harness.spanProduce(r, harness.ids.write, &.{
        harness.sourceSpan(r.input),
        harness.gzipHeaderCrcParam(1),
        harness.sinkSpan(r.encoded),
    });
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (!std.mem.eql(u8, r.output[0..r.input.len], r.input)) return error.HeaderCrcReadMismatch;
    if (r.encoded_len <= 11) return error.HeaderCrcFrameTooShort;
    r.encoded[10] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, r.output);
    r.encoded[10] ^= 0xff;
}

fn gzConcat(r: *Runner) !void {
    const part1_len: usize = 11;
    const part2_len: usize = 11;
    try harness.spanCall(r, harness.ids.write, r.input[0..part1_len], r.encoded);
    const member1_size: usize = r.encoded_len;
    try harness.spanCall(r, harness.ids.write, r.input[part1_len .. part1_len + part2_len], r.encoded[member1_size..]);
    r.encoded_len += member1_size;
    if (r.encoded_len > r.encoded.len) return error.ConcatenatedGzipOverflow;
    try steps.plan(&noParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.capabilityParam(r.caps_query),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_read),
    });
    if (r.required != part1_len + part2_len) return error.ConcatenatedQueryLengthMismatch;
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (r.response.byte_length != 22 or !std.mem.eql(u8, r.output[0..22], r.input[0..22])) return error.ConcatenatedReadMismatch;
    // Tail ISIZE belongs to the second member, so the fast path aborts and falls back; the prefix may be tentative.
    const short: usize = part1_len + part2_len - 6;
    var required: harness.Node = undefined;
    var available: harness.Node = undefined;
    var diagnostic = harness.capacityDiagnostic(harness.ids.diagnostic_required_capacity, harness.ids.diagnostic_available_capacity, &required, &available);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output[0..short]),
    }, .{ .ctx = true, .diagnostic = &diagnostic });
    try harness.requireStatus(r, abi.Status.insufficient_capacity);
    if (required.value_low != part1_len + part2_len) return error.ConcatCapacityRequiredMismatch;
    if (available.value_low != short) return error.ConcatCapacityAvailableMismatch;
}

fn gzCorruption(r: *Runner) !void {
    var bad_copy: [256]u8 = undefined;
    try harness.spanCall(r, harness.ids.write, r.input, r.encoded);
    @memcpy(bad_copy[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    bad_copy[0] = 0x00;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(bad_copy[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.invalid_data, r.output);
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0 .. r.encoded_len - 1]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.invalid_data, r.output);
    @memcpy(bad_copy[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    bad_copy[r.encoded_len - 1] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(bad_copy[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, r.output);
    // Low ISIZE byte fits the sink, so the fast path decodes fully before falling back; only status is asserted.
    @memcpy(bad_copy[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    bad_copy[r.encoded_len - 4] ^= 0xff;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(bad_copy[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.integrity_failure);
}

fn gzSmallSinkRead(r: *Runner) !void {
    try harness.spanCall(r, harness.ids.write, r.input, r.encoded);
    // One byte short of ISIZE: the fast path declines before any write.
    try harness.expectCapacity(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output[0 .. r.input.len - 1]),
    }, .{ .ctx = true }, r.input.len, r.input.len - 1, r.output[0 .. r.input.len - 1]);
}

fn gzCallbackSinkFailure(r: *Runner) !void {
    try harness.spanCall(r, harness.ids.write, r.input, r.encoded);
    // Callback sinks keep the staged route with committed-prefix progress reporting.
    var fail_ctx = harness.SinkCallbackContext{ .fail_after = 5 };
    var downstream = harness.scalarNode(harness.ids.diagnostic_downstream_status);
    var diagnostic = harness.node(null, 0);
    diagnostic.child = &downstream;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkCallback, .context = &fail_ctx, .diagnostic = &diagnostic });
    try harness.requireStatus(r, abi.Status.io_failure);
    if (fail_ctx.accepted_total != 4) return error.CallbackAcceptedTotalMismatch;
    if (downstream.value_low != abi.Status.insufficient_capacity) return error.DownstreamStatusMismatch;
}

fn runGzipExtras(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    try gzOptionalHeaders(r);
    try gzHeaderCrc(r);
    try gzConcat(r);
    try gzCorruption(r);
    try gzSmallSinkRead(r);
    try gzCallbackSinkFailure(r);
}

var gzip_large_input: [64 * 1024]u8 = undefined;

fn runGzipLarge(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    r.write_exact = false;
    corpus.select(r.corpus_index, gzip_large_input[0..]);
    r.input = gzip_large_input[0..];
    try steps.writeSpan(&noParams, r);
    try steps.readSpan(&noParams, r);
    try steps.foreignTool(r);
}

fn runGzipOracleFixture(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    corpus.select(r.corpus_index, gzip_large_input[0..]);
    var compressed: [64 * 1024 + 4096]u8 = undefined;
    try harness.oracleFixture(r, lib.gzipCompress, gzip_large_input[0..], &compressed, r.output);
}

var gzip_staged_output: [64 * 1024]u8 = undefined;

fn runGzipSinglePass(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    r.write_exact = false;
    corpus.select(r.corpus_index, gzip_large_input[0..]);
    r.input = gzip_large_input[0..];
    try steps.writeSpan(&noParams, r);
    // Capacity == ISIZE engages the single-pass path.
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) return error.SinglePassReadMismatch;
    var sink_ctx = harness.SinkBufferContext{ .buffer = &gzip_staged_output, .accept_limit = std.math.maxInt(usize) };
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or sink_ctx.offset != r.input.len) return error.SinglePassStagedLengthMismatch;
    if (!std.mem.eql(u8, gzip_staged_output[0..r.input.len], r.output[0..r.input.len])) return error.SinglePassStagedMismatch;
}

pub const scenarios = harness.scenarios("transform", &.{
    .{ .label = "deflate roundtrip", .run = runDeflate, .workspace_size = 65536 + 4096, .output_size = 256, .encoded_size = 256 },
    .{ .label = "deflate optimal", .run = runDeflateOptimal, .workspace_size = 2 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip roundtrip", .run = runGzip, .workspace_size = 65536 + 4096, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip optimal", .run = runGzipOptimal, .workspace_size = 2 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "bzip2 roundtrip", .run = runBzip2Roundtrip, .workspace_size = 32 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "bzip2 extras", .run = runBzip2Extras, .workspace_size = 32 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip extras", .run = runGzipExtras, .workspace_size = 65536 + 4096, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip large", .run = runGzipLarge, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "gzip oracle", .run = runGzipOracleFixture, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "gzip single-pass", .run = runGzipSinglePass, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
}, &.{});
