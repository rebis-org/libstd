const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");
const steps = @import("steps.zig");

var lzma_file_input: [48]u8 = undefined;

fn lzmaParams(r: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.lzd(r.extra);
    var count: usize = 1;
    if (r.extra2) |value| {
        out[count] = harness.paramScalar(harness.param_family_lzma, harness.lzma_match_finder, harness.cmd_all, value);
        count += 1;
    }
    return count;
}

fn setupLzma(r: *Runner, profile_id: harness.Id, dictionary: u64) void {
    harness.setup(r, profile_id, harness.mode_stream);
    r.extra = dictionary;
    r.sink_accept = 3;
}

const lzma_invalid = [_]u8{ 0x5d, 0x00, 0x10, 0x00, 0x00, 0x00 };
const lzma2_invalid = [_]u8{0x03};
const lzma2_invalid_reset = [_]u8{ 0x90, 0x00, 0x00, 0x00, 0x05 };
const lzma2_invalid_props = [_]u8{ 0xC0, 0x00, 0x00, 0x00, 0x05, 0x5d };

fn sinkCallbackWriteParity(r: *Runner) !void {
    var callback_compressed: [256]u8 = undefined;
    var sink_ctx = harness.SinkBufferContext{ .buffer = &callback_compressed, .accept_limit = std.math.maxInt(usize) };
    const nodes = steps.build(&lzmaParams, r, &.{ harness.sourceSpan(r.input), harness.sinkCallbackNode(0, 0) });
    _ = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (sink_ctx.offset != r.encoded_len or !std.mem.eql(u8, callback_compressed[0..r.encoded_len], r.encoded[0..r.encoded_len])) {
        return error.CallbackWriteParityMismatch;
    }
}

fn longRoundtrip(r: *Runner) !void {
    var long_input: [600]u8 = undefined;
    var long_compressed: [768]u8 = undefined;
    var long_decompressed: [768]u8 = undefined;
    corpus.select(r.corpus_index, &long_input);
    var nodes = steps.build(&lzmaParams, r, &.{ harness.sourceSpan(&long_input), harness.sinkSpan(&long_compressed) });
    _ = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    const long_compressed_size: usize = @intCast(r.response.byte_length);
    nodes = steps.build(&lzmaParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(long_compressed[0..long_compressed_size]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    });
    _ = harness.call(r, harness.ids.query, nodes.items[0..nodes.len], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != long_input.len) return error.LongReadCapacity;
    const long_decompressed_size: usize = @intCast(r.response.byte_length);
    nodes = steps.build(&lzmaParams, r, &.{ harness.sourceSpan(long_compressed[0..long_compressed_size]), harness.sinkSpan(long_decompressed[0..long_decompressed_size]) });
    _ = harness.call(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != long_decompressed_size or !std.mem.eql(u8, long_decompressed[0..long_input.len], &long_input)) {
        return error.LongRoundtripMismatch;
    }
}

fn missingDictionary(r: *Runner) !void {
    try harness.expect(r, harness.ids.write, &.{
        harness.sourceSpan(r.input),
        harness.sinkSpan(r.encoded),
    }, .{ .ctx = true }, abi.Status.invalid_call);
}

fn smallDictionary(r: *Runner) !void {
    try harness.expect(r, harness.ids.write, &.{
        harness.lzd(1024),
        harness.sourceSpan(r.input),
        harness.sinkSpan(r.encoded),
    }, .{ .ctx = true }, abi.Status.invalid_call);
}

fn limitQueryWrite(r: *Runner) !void {
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.sourceSpan(r.input),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_write),
        harness.lim(r.input.len + r.encoded_len - 1),
    });
    try harness.expect(r, harness.ids.query, nodes.items[0..nodes.len], .{}, abi.Status.resource_limit);
}

fn limitQueryRead(r: *Runner) !void {
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
        harness.lim(r.encoded_len + r.input.len - 1),
    });
    try harness.expect(r, harness.ids.query, nodes.items[0..nodes.len], .{}, abi.Status.resource_limit);
}

fn runRoundtrip(r: *Runner, profile_id: harness.Id, invalid: []const u8, extra_steps: []const *const fn (r: *Runner) anyerror!void) anyerror!void {
    var lzma_corpus_buffer: [72]u8 = undefined;
    corpus.select(r.corpus_index, &lzma_corpus_buffer);
    setupLzma(r, profile_id, 4096);
    r.input = lzma_corpus_buffer[0..48];
    r.invalid = invalid;
    r.invalid_status = abi.Status.invalid_data;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
    try steps.writeCallbackSource(&lzmaParams, r);
    try sinkCallbackWriteParity(r);
    try steps.readCallbackSink(&lzmaParams, r);
    try steps.invalidReject(&lzmaParams, r);
    for (extra_steps) |step| try step(r);
    try limitQueryWrite(r);
    try limitQueryRead(r);
    try steps.capacitySmallSink(&lzmaParams, r);
}

pub fn runLzma(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.lzma, &lzma_invalid, &.{ &longRoundtrip, &missingDictionary, &smallDictionary });
}

fn invalidResetState(r: *Runner) !void {
    r.invalid = &lzma2_invalid_reset;
    try steps.invalidReject(&lzmaParams, r);
}

fn invalidNewProps(r: *Runner) !void {
    r.invalid = &lzma2_invalid_props;
    try steps.invalidReject(&lzmaParams, r);
}

pub fn runLzma2(r: *Runner) anyerror!void {
    try runRoundtrip(r, harness.ids.lzma2, &lzma2_invalid, &.{ &invalidResetState, &invalidNewProps });
}

fn lzmaFileForeign(r: *Runner) !void {
    var output: [4096]u8 = undefined;
    const decoded = lib.lzmaAloneDecode(r.encoded[0..r.encoded_len], &output);
    if (decoded == null) return error.ReferenceToolRejectedOutput;
}

fn lzmaFileWrite(r: *Runner) !void {
    corpus.select(r.corpus_index, &lzma_file_input);
    setupLzma(r, harness.ids.lzma_file, 4096);
    r.input = &lzma_file_input;
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.lzma),
        harness.lzd(r.extra),
        harness.sourceSpan(&lzma_file_input),
        harness.sinkSpan(r.encoded[13..]),
        harness.cap(r.caps_io),
        harness.pln(r.planning),
        harness.dlv(r.delivery_write),
    }, .{ .profile = false });
    try harness.requireStatus(r, abi.Status.ok);
    r.encoded[0] = 0x5d;
    r.encoded[1] = 0x00;
    r.encoded[2] = 0x10;
    r.encoded[3] = 0x00;
    r.encoded[4] = 0x00;
    const size = lzma_file_input.len;
    for (0..8) |i| r.encoded[5 + i] = @truncate(size >> @intCast(8 * i));
    r.encoded_len = 13 + @as(usize, @intCast(r.response.byte_length));
}

fn lzmaFileRead(r: *Runner) !void {
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len) return error.LzmaFileQueryLength;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) {
        return error.LzmaFileReadMismatch;
    }
}

fn lzmaFileCases(r: *Runner) !void {
    if (r.encoded_len <= 16) {
        var truncated: [16]u8 = undefined;
        @memcpy(truncated[0..r.encoded_len], r.encoded[0..r.encoded_len]);
        _ = harness.call(r, harness.ids.read, &.{
            harness.sourceSpan(truncated[0 .. r.encoded_len - 4]),
            harness.sinkSpan(r.output),
        }, .{ .ctx = true });
        if (r.status == abi.Status.ok) return error.TruncatedLzmaFileAccepted;
    }
    var clamped: [256]u8 = undefined;
    @memcpy(clamped[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    @memset(clamped[1..5], 0);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(clamped[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, r.output[0..r.input.len], r.input)) {
        return error.ClampedLzmaFileMismatch;
    }
    var oversized: [256]u8 = undefined;
    @memcpy(oversized[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    oversized[1] = 0x01;
    oversized[2] = 0x00;
    oversized[3] = 0x00;
    oversized[4] = 0x41;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(oversized[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.unsupported, r.output);
    const truncated_header = [_]u8{ 0x5d, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(&truncated_header),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.invalid_data, r.output);
}

pub fn runLzmaFile(r: *Runner) anyerror!void {
    try lzmaFileWrite(r);
    try lzmaFileRead(r);
    try lzmaFileCases(r);
    try lzmaFileForeign(r);
}

pub fn runLzmaLarge(r: *Runner) anyerror!void {
    var input: [1 << 20]u8 = undefined;
    corpus.select(r.corpus_index, &input);
    setupLzma(r, harness.ids.lzma, 128 << 20);
    r.extra2 = 0;
    r.input = &input;
    r.write_exact = true;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
}

pub fn runIncompressible(r: *Runner) anyerror!void {
    var input: [1 << 20]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate((i * 31 + 17) & 0xff);
    setupLzma(r, harness.ids.lzma2, 4096);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
}

pub fn runMultichunk(r: *Runner) anyerror!void {
    var input: [(1 << 20) + 1024]u8 = undefined;
    @memset(&input, 'A');
    setupLzma(r, harness.ids.lzma2, 4096);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
    const raw_unpack: usize = ((@as(usize, r.encoded[0] & 0x0F)) << 16) | (@as(usize, r.encoded[1]) << 8) | r.encoded[2];
    const first_unpack = raw_unpack + 1;
    const first_pack: usize = ((@as(usize, r.encoded[3]) << 8) | r.encoded[4]) + 1;
    const next_offset = 1 + 4 + 1 + first_pack;
    if ((r.encoded[0] & 0x80) == 0) return error.UnexpectedChunkControl;
    if (first_unpack != (1 << 20)) return error.UnexpectedFirstChunkSize;
    if (next_offset >= r.encoded_len - 1) return error.ChunkLayoutMismatch;
    if (next_offset >= r.encoded.len or r.encoded[next_offset] != 0x80) return error.UnexpectedEndMarker;
}

fn dictionaryCap(r: *Runner) !void {
    const candidates = [_]u64{ 4096, @as(u64, 1) << 30, (@as(u64, 1) << 30) + 1 };
    const expected = [_]u32{ abi.Status.ok, abi.Status.insufficient_capacity, abi.Status.invalid_call };
    const input = "dictionary cap";
    for (candidates, 0..) |candidate, index| {
        _ = harness.call(r, harness.ids.query, &.{
            harness.lzd(candidate),
            harness.paramTargetCommand(harness.ids.write),
            harness.sourceSpan(input),
            harness.cap(r.caps_query),
            harness.pln(r.planning),
            harness.dlv(r.delivery_write),
        }, .{});
        try harness.requireStatus(r, expected[index]);
    }
}

fn setupCap(r: *Runner, profile_id: harness.Id, delivery_write: u64) void {
    r.profile_id = profile_id;
    r.caps_query = harness.cap_read | harness.cap_size | harness.cap_replay;
    r.planning = harness.plan_replay_pass;
    r.delivery_write = delivery_write;
}

pub fn runLzmaCap(r: *Runner) anyerror!void {
    setupCap(r, harness.ids.lzma, harness.delivery_provisional);
    try dictionaryCap(r);
}

pub fn runLzma2Cap(r: *Runner) anyerror!void {
    setupCap(r, harness.ids.lzma2, harness.delivery_provisional);
    try dictionaryCap(r);
}

pub fn runXzCap(r: *Runner) anyerror!void {
    setupCap(r, harness.ids.xz, harness.delivery_verified);
    try dictionaryCap(r);
}

pub fn runOversizeRestore(r: *Runner) anyerror!void {
    // An incompressible prefix floor-copies first, so the alternating
    // 2-symbol/random 2 KiB blocks that follow start at a chunk boundary;
    // their statistics flip inside the encoder's frozen-price windows, the
    // greedy sizing estimate dips under the real encode, and the accepted
    // chunk oversizes the 64 KiB pack field. The oversize-restore path must
    // discard it and emit a valid copy chunk instead. Parameters measured by
    // the U3 calibration driver (several neighboring lengths restore, so the
    // case is not a knife-edge).
    var input: [65536 + 77312]u8 = undefined;
    var state: u64 = 0x12345678;
    for (0..65536) |i| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        input[i] = @truncate(state >> 32);
    }
    state = 0x5eed1234 + 77312 * 4 + 11;
    for (0..77312) |i| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        input[65536 + i] = if (((i / 2048) & 1) == 0) 'a' + @as(u8, @truncate(state % 26)) else @truncate(state >> 32);
    }
    setupLzma(r, harness.ids.lzma2, 1 << 23);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
    // A mid-stream copy chunk above the 2 KiB halving floor is the restore
    // signature: the probe accepted the chunk, so only the oversize fallback
    // could emit it as a copy. Also assert dictionary resets appear at most
    // at the stream head: the in-place read path shares the output buffer
    // with the dictionary, and a mid-stream reset would clobber produced
    // output.
    var pos: usize = 0;
    var restored = false;
    while (true) {
        const control = r.encoded[pos];
        if (control == 0x00) break;
        if (control >= 0x80) {
            const pack = ((@as(usize, r.encoded[pos + 3]) << 8) | r.encoded[pos + 4]) + 1;
            pos += (if (control >= 0xC0) @as(usize, 6) else 5) + pack;
        } else {
            const unpack = ((@as(usize, r.encoded[pos + 1]) << 8) | r.encoded[pos + 2]) + 1;
            if (control == 0x01 and pos != 0) return error.UnexpectedMidstreamReset;
            if (control == 0x02 and unpack >= 8192) restored = true;
            pos += 3 + unpack;
        }
    }
    if (pos + 1 != r.encoded_len) return error.ChunkLayoutMismatch;
    if (!restored) return error.ExpectedOversizeRestore;
}

pub fn runCopyFloor(r: *Runner) anyerror!void {
    // Pure noise never probes compressible, so every chunk reaches the
    // halving floor and goes out as a copy: the stream is all 0x01/0x02
    // controls and must roundtrip unchanged.
    var input: [48 << 10]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc09f10);
    prng.fill(&input);
    setupLzma(r, harness.ids.lzma2, 4096);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
    var pos: usize = 0;
    var chunks: usize = 0;
    while (true) {
        const control = r.encoded[pos];
        if (control == 0x00) break;
        if (control >= 0x80) return error.UnexpectedCompressedChunk;
        if (control != (if (pos == 0) @as(u8, 0x01) else 0x02)) return error.UnexpectedChunkControl;
        const unpack = ((@as(usize, r.encoded[pos + 1]) << 8) | r.encoded[pos + 2]) + 1;
        pos += 3 + unpack;
        chunks += 1;
    }
    if (pos + 1 != r.encoded_len) return error.ChunkLayoutMismatch;
    if (chunks == 0) return error.UnexpectedChunkControl;
}

// A hand-assembled lzma2 stream with dictionary resets mid-stream: two
// copy-with-reset chunks, then an 0xE0 compressed chunk (props + state reset
// + dictionary reset) whose payload self-references. In-place decode must
// keep the write position advancing across the resets — the dictionary
// reset is a validation floor, not a rewind. The compressed payload is the
// lzma leaf encoding of the 100-byte `(i * 7) % 23` pattern.
const midstream_reset_pack = [_]u8{ 0x00, 0x00, 0x02, 0x0f, 0x57, 0x00, 0xc2, 0x48, 0xf8, 0xb2, 0xf1, 0x19, 0x52, 0xc8, 0x9a, 0xd6, 0x54, 0xb6, 0xa1, 0xd4, 0xe6, 0x05, 0x40, 0x9c, 0xd4, 0x50, 0xfa, 0x32, 0x00, 0x00 };

pub fn runMidstreamReset(r: *Runner) anyerror!void {
    var plain: [196]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    prng.fill(plain[0..32]);
    for (plain[32..96], 32..) |*b, i| b.* = @intCast((i * 5 + 1) % 31);
    for (plain[96..196], 0..) |*b, i| b.* = @intCast((i * 7) % 23);
    var stream: [256]u8 = undefined;
    var n: usize = 0;
    stream[n] = 0x01;
    stream[n + 1] = 0;
    stream[n + 2] = 31;
    n += 3;
    @memcpy(stream[n..][0..32], plain[0..32]);
    n += 32;
    stream[n] = 0x01;
    stream[n + 1] = 0;
    stream[n + 2] = 63;
    n += 3;
    @memcpy(stream[n..][0..64], plain[32..96]);
    n += 64;
    const pack_len = midstream_reset_pack.len;
    stream[n] = 0xE0;
    stream[n + 1] = 0;
    stream[n + 2] = 99;
    stream[n + 3] = 0;
    stream[n + 4] = pack_len - 1;
    stream[n + 5] = 0x5d; // lc 3, lp 0, pb 2
    n += 6;
    @memcpy(stream[n..][0..pack_len], &midstream_reset_pack);
    n += pack_len;
    stream[n] = 0x00;
    n += 1;
    r.input = &plain;
    @memcpy(r.encoded[0..n], stream[0..n]);
    r.encoded_len = n;
    setupLzma(r, harness.ids.lzma2, 1 << 20);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
}

pub fn runMixedChunks(r: *Runner) anyerror!void {
    // Incompressible prefix (probes down to a copy chunk first) followed by
    // compressible content spanning several 1 MiB lzma2 chunks: covers the
    // copy-before-first-compressed props ordering and cross-chunk bt4 state.
    var input: [(64 << 10) + (2 << 20)]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    prng.fill(input[0..(64 << 10)]);
    const pattern = "the quick brown fox jumps over the lazy dog 0123456789";
    for (input[(64 << 10)..], (64 << 10)..) |*byte, i| byte.* = pattern[i % pattern.len];
    setupLzma(r, harness.ids.lzma2, 1 << 20);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    try steps.queryRead(&lzmaParams, r);
    try steps.readSpan(&lzmaParams, r);
    // Walk the chunk headers: the first chunk must be a copy with dictionary
    // reset, and the first compressed chunk must carry properties.
    var pos: usize = 0;
    var first_compressed: ?u8 = null;
    while (true) {
        const control = r.encoded[pos];
        if (control == 0x00) break;
        if (control >= 0x80) {
            const pack: usize = ((@as(usize, r.encoded[pos + 3]) << 8) | r.encoded[pos + 4]) + 1;
            if (first_compressed == null) first_compressed = control & 0xE0;
            pos += (if (control >= 0xC0) @as(usize, 6) else 5) + pack;
        } else {
            const unpack: usize = ((@as(usize, r.encoded[pos + 1]) << 8) | r.encoded[pos + 2]) + 1;
            if (pos == 0) {
                if (control != 0x01) return error.UnexpectedChunkControl;
            } else if (control != 0x02) return error.UnexpectedChunkControl;
            pos += 3 + unpack;
        }
    }
    const fc = first_compressed orelse return error.UnexpectedChunkControl;
    if (fc != 0xC0 and fc != 0xE0) return error.UnexpectedChunkControl;
}

pub const scenarios = harness.scenarios(
    "lzma",
    &.{
        .{ .label = "lzma roundtrip", .run = runLzma, .workspace_size = 1310720, .output_size = 256, .encoded_size = 256 },
        .{ .label = "lzma file", .run = runLzmaFile, .workspace_size = 1310720, .output_size = 256, .encoded_size = 256 },
        .{ .label = "lzma2 roundtrip", .run = runLzma2, .workspace_size = 3670016, .output_size = 256, .encoded_size = 256 },
        .{ .label = "lzma large dictionary", .run = runLzmaLarge, .workspace_size = 680 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 65536 },
    },
    &.{
        .{ .name = "lzma2 incompressible", .run = runIncompressible, .workspace_size = 3 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 4096 },
        .{ .name = "lzma2 multichunk", .run = runMultichunk, .workspace_size = 8 * 1024 * 1024, .output_size = (1 << 20) + 1024, .encoded_size = 65536 },
        .{ .name = "lzma2 midstream reset", .run = runMidstreamReset, .workspace_size = 3670016, .output_size = 4096, .encoded_size = 1024 },
        .{ .name = "lzma2 mixed chunks", .run = runMixedChunks, .workspace_size = 48 * 1024 * 1024, .output_size = (64 << 10) + (2 << 20), .encoded_size = (1 << 20) + 4096 },
        .{ .name = "lzma2 copy floor", .run = runCopyFloor, .workspace_size = 3 * 1024 * 1024, .output_size = 48 << 10, .encoded_size = (48 << 10) + 2048 },
        .{ .name = "lzma2 oversize restore", .run = runOversizeRestore, .workspace_size = 240 * 1024 * 1024, .output_size = 142848 + 16, .encoded_size = 142848 + 4096 },
        .{ .name = "lzma dictionary cap provisional", .run = runLzmaCap, .workspace_size = 1310720, .output_size = 16, .encoded_size = 256 },
        .{ .name = "lzma2 dictionary cap provisional", .run = runLzma2Cap, .workspace_size = 3670016, .output_size = 16, .encoded_size = 256 },
        .{ .name = "xz dictionary cap verified", .run = runXzCap, .workspace_size = 8 * 1024 * 1024, .output_size = 16, .encoded_size = 256 },
    },
);
