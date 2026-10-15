const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const steps = @import("steps.zig");

const Runner = harness.Runner;

fn optimalParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_deflate, harness.deflate_optimal, harness.cmds, 1);
    out[1] = harness.paramScalar(harness.param_family_deflate, harness.deflate_nice, harness.cmds, 258);
    out[2] = harness.paramScalar(harness.param_family_deflate, harness.deflate_chain, harness.cmds, 256);
    return 3;
}

fn setupProfile(r: *Runner, profile_id: harness.Id) void {
    harness.setup(r, profile_id, harness.mode_stream);
    r.input = r.corpus_buffer[0..32];
    r.sink_accept = 3;
    r.write_exact = true;
    r.invalid_status = abi.Status.invalid_data;
    r.invalid = &.{0x06};
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
}

fn runRoundtrip(r: *Runner, profile_id: harness.Id) anyerror!void {
    setupProfile(r, profile_id);
    try steps.roundtrip(&steps.noParams, r);
}

pub fn runDeflate(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.deflate);
}

pub fn runBrotli(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.brotli);
    // 0x06 is a valid empty stream (WBITS 16, ISLAST, ISLASTEMPTY); the
    // reject probe needs a byte with nonzero fill bits.
    r.invalid = &.{0x0e};
    try steps.roundtrip(&steps.noParams, r);
}

pub fn runDeflateOptimal(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.deflate);
    try steps.queryWrite(&optimalParams, r);
    try steps.writeSpan(&optimalParams, r);
    try steps.queryRead(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);
    try steps.writeCallbackSource(&optimalParams, r);
    try steps.readCallbackSink(&steps.noParams, r);
    try steps.capacitySmallSink(&optimalParams, r);
}

var optimal_input: [64 * 1024]u8 = undefined;
var optimal_reference: [64 * 1024 + 4096]u8 = undefined;

pub fn runGzipOptimal(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    r.write_exact = false;
    corpus.fillTiled(r.corpus_index, optimal_input[0..]);
    r.input = optimal_input[0..];
    try steps.writeSpan(&optimalParams, r);
    try steps.readSpan(&steps.noParams, r);
    try steps.foreignTool(r);
    // Parser must engage: optimal stream differs from the default lazy stream here.
    const optimal_len = r.encoded_len;
    @memcpy(optimal_reference[0..optimal_len], r.encoded[0..optimal_len]);
    try steps.writeSpan(&steps.noParams, r);
    if (r.encoded_len == optimal_len and std.mem.eql(u8, r.encoded[0..r.encoded_len], optimal_reference[0..optimal_len])) return error.OptimalParserNotEngaged;
    try steps.readSpan(&steps.noParams, r);
}

pub fn runGzip(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.gzip);
    try steps.truncateReject(&steps.noParams, r);
    try steps.foreignTool(r);
}

pub fn runBzip2Roundtrip(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.bzip2);
}

pub fn runBzip2Extras(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.bzip2);
    r.write_exact = false;
    try steps.writeSpan(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);
    try steps.foreignTool(r);
    try bzOracleFixture(r);
    try bzBlockSizeRoundtrip(r);
    try bzMutations(r);
}

fn bzOracleFixture(r: *Runner) !void {
    var fixture_input: [65536]u8 = undefined;
    var compressed: [131072]u8 = undefined;
    var decoded: [65536]u8 = undefined;
    corpus.fillTiled(r.corpus_index, &fixture_input);
    try harness.oracleFixture(r, lib.bzip2Compress, &fixture_input, &compressed, &decoded);
}

fn bzBlockSizeRoundtrip(r: *Runner) !void {
    try steps.plan(&steps.noParams, r, &.{
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
    try steps.plan(&steps.noParams, r, &[_]harness.Node{
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
    try steps.plan(&steps.noParams, r, &.{
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
    try steps.plan(&steps.noParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.capabilityParam(r.caps_query),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_read),
    });
    if (r.required != part1_len + part2_len) return error.ConcatenatedQueryLengthMismatch;
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (r.response.byte_length != 22 or !std.mem.eql(u8, r.output[0..22], r.input[0..22])) return error.ConcatenatedReadMismatch;
    // Tail ISIZE belongs to the second member, so the fast path aborts and falls back. The prefix may be tentative.
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
    // Low ISIZE byte fits the sink, so the fast path decodes fully before falling back. Only status is asserted.
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
    var fail_ctx: harness.SinkBudget = undefined;
    var downstream: harness.Node = undefined;
    var diagnostic: harness.Node = undefined;
    harness.sinkFailureInit(&fail_ctx, &downstream, &diagnostic);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkCallback, .context = &fail_ctx, .diagnostic = &diagnostic });
    try harness.expectSinkFailure(r, &fail_ctx, &downstream);
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
    corpus.fillTiled(r.corpus_index, gzip_large_input[0..]);
    r.input = gzip_large_input[0..];
    try steps.writeSpan(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);
    try steps.foreignTool(r);
}

fn runGzipOracleFixture(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    corpus.fillTiled(r.corpus_index, gzip_large_input[0..]);
    var compressed: [64 * 1024 + 4096]u8 = undefined;
    try harness.oracleFixture(r, lib.gzipCompress, gzip_large_input[0..], &compressed, r.output);
}

var gzip_staged_output: [64 * 1024]u8 = undefined;

fn runGzipSinglePass(r: *Runner) anyerror!void {
    setupProfile(r, harness.ids.gzip);
    r.write_exact = false;
    corpus.fillTiled(r.corpus_index, gzip_large_input[0..]);
    r.input = gzip_large_input[0..];
    try steps.writeSpan(&steps.noParams, r);
    // Capacity == ISIZE engages the single-pass path.
    try harness.spanCall(r, harness.ids.read, r.encoded[0..r.encoded_len], r.output);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) return error.SinglePassReadMismatch;
    var sink_ctx = harness.SinkBuffer{ .buffer = &gzip_staged_output, .accept_limit = std.math.maxInt(usize) };
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or sink_ctx.offset != r.input.len) return error.SinglePassStagedLengthMismatch;
    if (!std.mem.eql(u8, gzip_staged_output[0..r.input.len], r.output[0..r.input.len])) return error.SinglePassStagedMismatch;
}

fn runBrotliReference(r: *Runner) anyerror!void {
    // Reference-encoder vectors (brotli CLI quality 5) through the envelope
    // read path. Complex prefix codes and context modeling on the text
    // vector; block machinery and matches on the repetitive one.
    // Random 4 KiB (no dictionary references) plus the empty stream; the
    // text-shaped vectors wait for the static dictionary support.
    var random: [4096]u8 = undefined;
    for (&random, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    const random_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00  };
    const empty_br = [_]u8{0x3f};
    const random_out = try r.gpa.alloc(u8, random.len);
    defer r.gpa.free(random_out);
    harness.setup(r, harness.ids.brotli, harness.mode_stream);
    try harness.spanCall(r, harness.ids.read, &random_br, random_out);
    if (!std.mem.eql(u8, random_out, &random)) return error.OracleContentMismatch;
    const empty_out = try r.gpa.alloc(u8, 1);
    defer r.gpa.free(empty_out);
    try harness.spanCall(r, harness.ids.read, &empty_br, empty_out);
    if (r.response.byte_length != 0) return error.OracleContentMismatch;
}

pub const scenarios = harness.scenarios("transform", &.{
    .{ .label = "deflate roundtrip", .run = runDeflate, .workspace_size = 65536 + 4096, .output_size = 256, .encoded_size = 256 },
    .{ .label = "deflate optimal", .run = runDeflateOptimal, .workspace_size = 2 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip roundtrip", .run = runGzip, .workspace_size = 65536 + 4096, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip optimal", .run = runGzipOptimal, .workspace_size = 2 * 1024 * 1024, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "bzip2 roundtrip", .run = runBzip2Roundtrip, .workspace_size = 32 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "bzip2 extras", .run = runBzip2Extras, .workspace_size = 32 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "brotli roundtrip", .run = runBrotli, .workspace_size = 32 * 1024 * 1024, .output_size = 256, .encoded_size = 256 },
    .{ .label = "brotli reference decode", .run = runBrotliReference, .workspace_size = 8 * 1024 * 1024, .output_size = 4096, .encoded_size = 4096 },
    .{ .label = "gzip extras", .run = runGzipExtras, .workspace_size = 65536 + 4096, .output_size = 256, .encoded_size = 256 },
    .{ .label = "gzip large", .run = runGzipLarge, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "gzip oracle", .run = runGzipOracleFixture, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
    .{ .label = "gzip single-pass", .run = runGzipSinglePass, .workspace_size = 65536 + 4096, .output_size = 64 * 1024, .encoded_size = 64 * 1024 + 4096 },
}, &.{});
