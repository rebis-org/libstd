const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");
const steps = @import("steps.zig");
const catalog = @import("catalog.zig");

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

const lzma_alone_header_size = 13;

fn lzmaAloneEncode(r: *Runner, input: []const u8, declared_size: ?usize, out: []u8) !usize {
    const dict: u64 = @max(input.len, 4096);
    const saved_profile = r.profile_id;
    const saved_extra = r.extra;
    const saved_extra2 = r.extra2;
    defer {
        r.profile_id = saved_profile;
        r.extra = saved_extra;
        r.extra2 = saved_extra2;
    }
    r.profile_id = harness.ids.lzma;
    r.extra = dict;
    r.extra2 = null;
    const payload_buf = out[lzma_alone_header_size..];
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(input),
        harness.sinkSpan(payload_buf),
    });
    _ = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    const payload_len: usize = @intCast(r.response.byte_length);
    out[0] = 0x5d;
    std.mem.writeInt(u32, out[1..5], @intCast(dict), .little);
    const size = declared_size orelse std.math.maxInt(u64);
    std.mem.writeInt(u64, out[5..13], size, .little);
    return lzma_alone_header_size + payload_len;
}

fn runLzmaFileDeclaredEqual(r: *Runner) !void {
    const input = "AE1 equal-size declared-size lzma-alone path";
    var encoded: [512]u8 = undefined;
    setupLzma(r, harness.ids.lzma_file, 4096);
    const encoded_len = try lzmaAloneEncode(r, input, input.len, &encoded);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len) return error.EqualQueryLength;
    var output: [input.len]u8 = undefined;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, &output, input)) {
        return error.EqualReadMismatch;
    }
}

fn runLzmaFileDeclaredGreater(r: *Runner) !void {
    const input = "AE1 declared greater than actual decoded count pattern";
    const actual = input.len;
    const declared = actual + 100;
    var encoded: [512]u8 = undefined;
    setupLzma(r, harness.ids.lzma_file, 4096);
    const encoded_len = try lzmaAloneEncode(r, input, declared, &encoded);
    var output: [declared]u8 = undefined;
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != declared) return error.GreaterByteLength;
    if (!std.mem.eql(u8, output[0..actual], input)) return error.GreaterPrefixMismatch;
    if (!harness.allBytesEqual(output[actual..declared], 0xa5)) return error.GreaterTailChanged;
}

fn runLzmaFileDeclaredLess(r: *Runner) !void {
    const input = "AE1 declared less than actual decoded count pattern";
    const actual = input.len;
    const declared = actual - 1;
    var encoded: [512]u8 = undefined;
    setupLzma(r, harness.ids.lzma_file, 4096);
    const encoded_len = try lzmaAloneEncode(r, input, declared, &encoded);
    var output: [declared]u8 = undefined;
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != declared) return error.LessByteLength;
    if (!std.mem.eql(u8, &output, input[0..declared])) return error.LessPrefixMismatch;
}

const CountingSourceContext = struct {
    data: []const u8,
    offset: usize = 0,
    size_calls: usize = 0,
    read_calls: usize = 0,
    rewind_calls: usize = 0,
};

fn countingSourceCallback(c: *harness.Call) callconv(.c) u32 {
    const ctx: *CountingSourceContext = @ptrCast(@alignCast(c.callback_context orelse return abi.Status.unsupported));
    const response = c.response orelse return abi.Status.unsupported;
    if (abi.idEqual(c.operation, catalog.callback_size)) {
        ctx.size_calls += 1;
        response.value_low = ctx.data.len;
        return abi.Status.ok;
    }
    if (abi.idEqual(c.operation, catalog.callback_rewind)) {
        ctx.rewind_calls += 1;
        ctx.offset = 0;
        return abi.Status.ok;
    }
    if (abi.idEqual(c.operation, catalog.callback_read)) {
        ctx.read_calls += 1;
        const remaining = ctx.data.len - ctx.offset;
        const capacity: usize = @intCast(response.byte_capacity);
        const n = @min(capacity, remaining);
        if (n > 0) {
            const dst = response.bytes orelse return abi.Status.unsupported;
            @memcpy(dst[0..n], ctx.data[ctx.offset .. ctx.offset + n]);
        }
        ctx.offset += n;
        response.byte_length = n;
        return abi.Status.ok;
    }
    return abi.Status.unsupported;
}

fn runLzmaFileSourceOnce(r: *Runner) !void {
    const input = "AE1 callback source consumed exactly once";
    var encoded: [512]u8 = undefined;
    setupLzma(r, harness.ids.lzma_file, 4096);
    const encoded_len = try lzmaAloneEncode(r, input, input.len, &encoded);
    var output: [input.len]u8 = undefined;
    var ctx = CountingSourceContext{ .data = encoded[0..encoded_len] };
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(&output),
    }, .{ .ctx = true, .callback = countingSourceCallback, .context = &ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, &output, input)) {
        return error.SourceOnceMismatch;
    }
    if (ctx.size_calls != 1 or ctx.read_calls < 1 or ctx.rewind_calls != 0) {
        return error.SourceOnceCount;
    }
}

fn runLzmaFileMarkerMode(r: *Runner) !void {
    const input = "AE2 marker-mode lzma-alone two-pass route";
    var encoded: [512]u8 = undefined;
    setupLzma(r, harness.ids.lzma_file, 4096);
    const encoded_len = try lzmaAloneEncode(r, input, null, &encoded);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len) return error.MarkerQueryLength;
    var output: [input.len]u8 = undefined;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, &output, input)) {
        return error.MarkerDirectMismatch;
    }
    var callback_output: [input.len]u8 = undefined;
    var sink_ctx = harness.SinkBufferContext{ .buffer = &callback_output, .accept_limit = std.math.maxInt(usize) };
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, &callback_output, input)) {
        return error.MarkerCallbackMismatch;
    }
    var small: [1]u8 = undefined;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(encoded[0..encoded_len]),
        harness.sinkSpan(&small),
    }, .{ .ctx = true }, abi.Status.insufficient_capacity, &small);
}

fn runLzma2Empty(r: *Runner) !void {
    setupLzma(r, harness.ids.lzma2, 4096);
    const stream = [_]u8{0x00};
    const query_nodes = steps.build(&lzmaParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(&stream),
    });
    _ = harness.call(r, harness.ids.query, query_nodes.items[0..query_nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 0) return error.EmptyQueryLength;
    const sink = [_]u8{};
    const read_nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(&stream),
        harness.sinkSpan(&sink),
    });
    _ = harness.call(r, harness.ids.read, read_nodes.items[0..read_nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 0) return error.EmptyReadLength;
}

fn runLzma2TrailingGarbage(r: *Runner) !void {
    const input = "trailing garbage after control_end";
    setupLzma(r, harness.ids.lzma2, 4096);
    r.input = input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    var stream: [512]u8 = undefined;
    @memcpy(stream[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    stream[r.encoded_len] = 0xde;
    stream[r.encoded_len + 1] = 0xad;
    const stream_len = r.encoded_len + 2;
    const query_nodes = steps.build(&lzmaParams, r, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(stream[0..stream_len]),
    });
    _ = harness.call(r, harness.ids.query, query_nodes.items[0..query_nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len) return error.TrailingQueryLength;
    var output: [input.len]u8 = undefined;
    const read_nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(stream[0..stream_len]),
        harness.sinkSpan(&output),
    });
    _ = harness.call(r, harness.ids.read, read_nodes.items[0..read_nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, &output, input)) {
        return error.TrailingReadMismatch;
    }
}

fn runLzma2SingleByte(r: *Runner) !void {
    setupLzma(r, harness.ids.lzma2, 4096);
    const stream = [_]u8{ 0x01, 0x00, 0x00, 'X', 0x00 };
    var output: [1]u8 = undefined;
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(&stream),
        harness.sinkSpan(&output),
    });
    _ = harness.call(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 1 or output[0] != 'X') return error.SingleByteMismatch;
}

fn runLzma2PackBounds(r: *Runner) !void {
    var input: [512]u8 = undefined;
    corpus.select(r.corpus_index, &input);
    setupLzma(r, harness.ids.lzma2, 4096);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    var pos: usize = 0;
    while (true) {
        if (pos >= r.encoded_len) return error.BoundsWalkOverflow;
        const control = r.encoded[pos];
        if (control == 0x00) break;
        if (control & 0x80 != 0) {
            if (pos + 5 > r.encoded_len) return error.BoundsHeaderTruncated;
            const pack = ((@as(usize, r.encoded[pos + 3]) << 8) | r.encoded[pos + 4]) + 1;
            if (pack < 5 or pack > 65536) return error.BoundsPackSize;
            const header_len: usize = if (control >= 0xC0) 6 else 5;
            pos += header_len + pack;
        } else {
            if (pos + 3 > r.encoded_len) return error.BoundsCopyTruncated;
            const unpack = ((@as(usize, r.encoded[pos + 1]) << 8) | r.encoded[pos + 2]) + 1;
            if (unpack > 1 << 20) return error.BoundsUnpackSize;
            pos += 3 + unpack;
        }
    }
    if (pos + 1 != r.encoded_len) return error.BoundsLayoutMismatch;
}

fn runLzma2BadPackSize(r: *Runner) !void {
    setupLzma(r, harness.ids.lzma2, 4096);
    const stream = [_]u8{ 0xC0, 0x00, 0x00, 0x00, 0x02, 0x5d };
    var output: [16]u8 = undefined;
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(&stream),
        harness.sinkSpan(&output),
    });
    try harness.reject(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true }, abi.Status.invalid_data, &output);
}

fn runLzma2TruncatedHeader(r: *Runner) !void {
    setupLzma(r, harness.ids.lzma2, 4096);
    const stream = [_]u8{ 0xC0, 0x00 };
    var output: [16]u8 = undefined;
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(&stream),
        harness.sinkSpan(&output),
    });
    try harness.reject(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true }, abi.Status.invalid_data, &output);
}

fn runLzma2CorruptPayload(r: *Runner) !void {
    var input: [48]u8 = undefined;
    corpus.select(r.corpus_index, &input);
    setupLzma(r, harness.ids.lzma2, 4096);
    r.input = &input;
    try steps.queryWrite(&lzmaParams, r);
    try steps.writeSpan(&lzmaParams, r);
    var pos: usize = 0;
    while (true) {
        if (pos >= r.encoded_len) return error.CorruptNoCompressedChunk;
        const control = r.encoded[pos];
        if (control == 0x00) return error.CorruptNoCompressedChunk;
        if (control & 0x80 != 0) break;
        const unpack = ((@as(usize, r.encoded[pos + 1]) << 8) | r.encoded[pos + 2]) + 1;
        pos += 3 + unpack;
    }
    const header_len: usize = if (r.encoded[pos] >= 0xC0) 6 else 5;
    if (r.encoded_len <= pos + header_len) return error.CorruptNoCompressedChunk;
    r.encoded[pos + header_len] ^= 0xff;
    var output: [48]u8 = undefined;
    @memset(&output, 0xa5);
    const nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(&output),
    });
    _ = harness.call(r, harness.ids.read, nodes.items[0..nodes.len], .{ .ctx = true });
    if (r.status == abi.Status.ok) return error.CorruptPayloadAccepted;
}

const Timespec = extern struct { sec: c_long, nsec: c_long };
extern "c" fn clock_gettime(clk_id: c_int, tp: *Timespec) c_int;
const CLOCK_REALTIME = 0;

fn nowNs() u64 {
    var ts: Timespec = undefined;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn scanSize(input: []const u8) !?usize {
    const control_end_byte: u8 = 0x00;
    const control_copy_reset_dic: u8 = 0x01;
    const control_copy: u8 = 0x02;
    const control_lzma_new_props: u8 = 0xC0;
    const control_lzma_new_props_reset_dic: u8 = 0xE0;
    const max_pack_size = 1 << 16;
    const chunk_max_unpacked_local = 1 << 20;
    var pos: usize = 0;
    var total: usize = 0;
    var need_properties = true;
    var need_dictionary_reset = true;
    while (pos < input.len) {
        const control = input[pos];
        pos += 1;
        if (control == control_end_byte) return total;
        if (control >= control_lzma_new_props_reset_dic or control == control_copy_reset_dic) {
            need_properties = true;
            need_dictionary_reset = true;
        } else if (need_dictionary_reset) {
            return error.InvalidData;
        }
        if (control & 0x80 != 0) {
            if (pos + 2 > input.len) return error.InvalidData;
            const unpack_size = (((@as(usize, control & 0x0F) << 16) | (@as(usize, input[pos]) << 8) | input[pos + 1]) + 1);
            pos += 2;
            if (pos + 2 > input.len) return error.InvalidData;
            const pack_size = ((@as(usize, input[pos]) << 8) | input[pos + 1]) + 1;
            pos += 2;
            if (unpack_size > chunk_max_unpacked_local or pack_size < 5 or pack_size > max_pack_size) return error.InvalidData;
            if (control >= control_lzma_new_props) {
                if (pos >= input.len) return error.InvalidData;
                pos += 1;
                need_properties = false;
                if (control >= control_lzma_new_props_reset_dic) need_dictionary_reset = false;
            } else {
                if (need_properties) return error.InvalidData;
            }
            pos += pack_size;
            if (pos > input.len) return error.InvalidData;
            total = std.math.add(usize, total, unpack_size) catch return error.ResourceLimit;
        } else {
            if (control != control_copy_reset_dic and control != control_copy) return error.InvalidData;
            if (pos + 2 > input.len) return error.InvalidData;
            const unpack_size = ((@as(usize, input[pos]) << 8) | input[pos + 1]) + 1;
            pos += 2;
            if (unpack_size > chunk_max_unpacked_local) return error.InvalidData;
            if (need_dictionary_reset) need_dictionary_reset = false;
            pos += unpack_size;
            if (pos > input.len) return error.InvalidData;
            total = std.math.add(usize, total, unpack_size) catch return error.ResourceLimit;
        }
    }
    return error.InvalidData;
}

pub fn runScanTiming(r: *Runner) !void {
    const input_len = 4 << 20;
    const chunk_size = 1 << 16;
    const chunks = input_len / chunk_size;
    const stream_len = chunks * (3 + chunk_size) + 1;
    const stream = try r.gpa.alloc(u8, stream_len);
    defer r.gpa.free(stream);
    var pos: usize = 0;
    for (0..chunks) |i| {
        stream[pos] = if (i == 0) 0x01 else 0x02;
        pos += 1;
        const size_minus_1 = chunk_size - 1;
        stream[pos] = @truncate(size_minus_1 >> 8);
        stream[pos + 1] = @truncate(size_minus_1);
        pos += 2;
        const base = i * chunk_size;
        for (0..chunk_size) |j| stream[pos + j] = @truncate((base + j) & 0xff);
        pos += chunk_size;
    }
    stream[pos] = 0x00;
    setupLzma(r, harness.ids.lzma2, 4096);
    const scan_size = try scanSize(stream[0..stream_len]);
    if (scan_size != input_len) return error.ScanSizeMismatch;
    const iterations: usize = 1000;
    const scan_start = nowNs();
    for (0..iterations) |_| _ = try scanSize(stream[0..stream_len]);
    const scan_end = nowNs();
    const scan_total_ns = @as(u64, @intCast(scan_end - scan_start));
    const scan_ns = scan_total_ns / iterations;
    const decode_start = nowNs();
    const read_nodes = steps.build(&lzmaParams, r, &.{
        harness.sourceSpan(stream[0..stream_len]),
        harness.sinkSpan(r.output[0..input_len]),
    });
    _ = harness.call(r, harness.ids.read, read_nodes.items[0..read_nodes.len], .{ .ctx = true });
    const decode_end = nowNs();
    try harness.requireStatus(r, abi.Status.ok);
    const decode_ns = @as(u64, @intCast(decode_end - decode_start));
    if (r.response.byte_length != input_len) return error.ScanDecodeLength;
    for (0..input_len) |i| {
        if (r.output[i] != @as(u8, @truncate(i & 0xff))) return error.ScanDecodeMismatch;
    }
    const scan_ms = @as(f64, @floatFromInt(scan_ns)) / 1.0e6;
    const decode_ms = @as(f64, @floatFromInt(decode_ns)) / 1.0e6;
    std.debug.print("U4 scanSize timing: input_len={d} iterations={d} scan_per_call_ns={d} ({d:.3} ms) decode_ns={d} ({d:.3} ms) fraction={d:.4}%\n", .{
        input_len,
        iterations,
        scan_ns,
        scan_ms,
        decode_ns,
        decode_ms,
        @as(f64, @floatFromInt(scan_ns)) * 100.0 / @as(f64, @floatFromInt(decode_ns)),
    });
}

const ab_variant = @import("ab_variant");

fn abEncodeAndWrite(r: *Runner, profile_id: harness.Id, dictionary: u64, finder: ?u64, input: []const u8, label: []const u8) !void {
    const mode = if (abi.idEqual(profile_id, harness.ids.xz)) harness.mode_xz else harness.mode_stream;
    harness.setup(r, profile_id, mode);
    r.extra = dictionary;
    r.input = input;
    r.extra2 = finder;
    steps.queryWrite(&lzmaParams, r) catch |err| {
        std.debug.print("abEncodeAndWrite query failed {s} status={d}\n", .{ label, r.status });
        return err;
    };
    steps.writeSpan(&lzmaParams, r) catch |err| {
        std.debug.print("abEncodeAndWrite write failed {s} status={d}\n", .{ label, r.status });
        return err;
    };
    const encoded_len: usize = r.encoded_len;

    const dir = try std.fs.path.join(r.gpa, &.{
        "zig-out", "oracles", "ab", ab_variant.name, r.scenario_name,
    });
    defer r.gpa.free(dir);
    const path = try std.fs.path.join(r.gpa, &.{ dir, label });
    defer r.gpa.free(path);
    if (std.fs.path.dirname(path)) |parent| {
        try std.Io.Dir.cwd().createDirPath(harness.io, parent);
    }
    try std.Io.Dir.cwd().writeFile(harness.io, .{
        .sub_path = path,
        .data = r.encoded[0..encoded_len],
    });
}

fn runLzmaAbCorpus(r: *Runner) !void {
    var input: [48]u8 = undefined;
    for (0..4) |corpus_index| {
        corpus.select(corpus_index, &input);
        const suffix = try std.fmt.allocPrint(r.gpa, "corpus_{d}", .{corpus_index});
        defer r.gpa.free(suffix);
        const dict: u64 = @max(input.len, 4096);
        const lzma_hc = try std.fmt.allocPrint(r.gpa, "{s}/lzma_hc.bin", .{suffix});
        defer r.gpa.free(lzma_hc);
        const lzma_bt4 = try std.fmt.allocPrint(r.gpa, "{s}/lzma_bt4.bin", .{suffix});
        defer r.gpa.free(lzma_bt4);
        const lzma2_hc = try std.fmt.allocPrint(r.gpa, "{s}/lzma2_hc.bin", .{suffix});
        defer r.gpa.free(lzma2_hc);
        const lzma2_bt4 = try std.fmt.allocPrint(r.gpa, "{s}/lzma2_bt4.bin", .{suffix});
        defer r.gpa.free(lzma2_bt4);
        const xz_hc = try std.fmt.allocPrint(r.gpa, "{s}/xz_hc.bin", .{suffix});
        defer r.gpa.free(xz_hc);
        const xz_bt4 = try std.fmt.allocPrint(r.gpa, "{s}/xz_bt4.bin", .{suffix});
        defer r.gpa.free(xz_bt4);
        try abEncodeAndWrite(r, harness.ids.lzma, dict, 0, &input, lzma_hc);
        try abEncodeAndWrite(r, harness.ids.lzma, dict, 1, &input, lzma_bt4);
        try abEncodeAndWrite(r, harness.ids.lzma2, dict, 0, &input, lzma2_hc);
        try abEncodeAndWrite(r, harness.ids.lzma2, dict, 1, &input, lzma2_bt4);
        try abEncodeAndWrite(r, harness.ids.xz, dict, 0, &input, xz_hc);
        try abEncodeAndWrite(r, harness.ids.xz, dict, 1, &input, xz_bt4);
    }
}

fn runLzmaAbZeros(r: *Runner) !void {
    const input = [_]u8{0} ** 1024;
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 1, &input, "lzma_bt4.bin");
}

fn runLzmaAbSameByte(r: *Runner) !void {
    const input = [_]u8{0xa5} ** 1024;
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 1, &input, "lzma_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 0, &input, "lzma2_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 1, &input, "lzma2_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 0, &input, "xz_hc.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 1, &input, "xz_bt4.bin");
}

fn runLzmaAbRandom(r: *Runner) !void {
    var input: [1024]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc09f10);
    prng.fill(&input);
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 1, &input, "lzma_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 0, &input, "lzma2_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 1, &input, "lzma2_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 0, &input, "xz_hc.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 1, &input, "xz_bt4.bin");
}

fn runLzmaAbSparseRuns(r: *Runner) !void {
    var input: [2048]u8 = undefined;
    var i: usize = 0;
    while (i < input.len) : (i += 64) {
        const byte: u8 = @truncate((i / 64) + 1);
        @memset(input[i..][0..@min(64, input.len - i)], byte);
    }
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 1, &input, "lzma_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 0, &input, "lzma2_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 1, &input, "lzma2_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 0, &input, "xz_hc.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 1, &input, "xz_bt4.bin");
}

fn runLzmaAbText(r: *Runner) !void {
    const pattern = "the quick brown fox jumps over the lazy dog 0123456789 ";
    var input: [2000]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = pattern[i % pattern.len];
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 1, &input, "lzma_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 0, &input, "lzma2_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 1, &input, "lzma2_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 0, &input, "xz_hc.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 1, &input, "xz_bt4.bin");
}

fn runLzmaAbAlternating(r: *Runner) !void {
    var input: [2048]u8 = undefined;
    var i: usize = 0;
    while (i < input.len) : (i += 32) {
        const byte: u8 = if ((i / 32) & 1 == 0) @as(u8, 'a') + @as(u8, @truncate((i / 64) % 26)) else 0;
        @memset(input[i..][0..@min(32, input.len - i)], byte);
    }
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 4096, 1, &input, "lzma_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 0, &input, "lzma2_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 4096, 1, &input, "lzma2_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 0, &input, "xz_hc.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 4096, 1, &input, "xz_bt4.bin");
}

fn runLzmaAbZerosChunkBoundary(r: *Runner) !void {
    var input: [(1 << 20) + 1024]u8 = undefined;
    @memset(&input, 0);
    try abEncodeAndWrite(r, harness.ids.lzma2, 1 << 20, 0, &input, "lzma2_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma2, 1 << 20, 1, &input, "lzma2_bt4.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 1 << 20, 0, &input, "xz_hc.bin");
    try abEncodeAndWrite(r, harness.ids.xz, 1 << 20, 1, &input, "xz_bt4.bin");
}

fn runLzmaAbZerosDictionaryWrap(r: *Runner) !void {
    var input: [(64 << 10) + 1]u8 = undefined;
    @memset(&input, 0);
    try abEncodeAndWrite(r, harness.ids.lzma, 64 << 10, 0, &input, "lzma_hc.bin");
    try abEncodeAndWrite(r, harness.ids.lzma, 64 << 10, 1, &input, "lzma_bt4.bin");
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
        .{ .name = "lzma file declared equal", .run = runLzmaFileDeclaredEqual, .workspace_size = 1310720, .output_size = 256, .encoded_size = 512 },
        .{ .name = "lzma file declared greater", .run = runLzmaFileDeclaredGreater, .workspace_size = 1310720, .output_size = 256, .encoded_size = 512 },
        .{ .name = "lzma file declared less", .run = runLzmaFileDeclaredLess, .workspace_size = 1310720, .output_size = 256, .encoded_size = 512 },
        .{ .name = "lzma file source once", .run = runLzmaFileSourceOnce, .workspace_size = 1310720, .output_size = 256, .encoded_size = 512 },
        .{ .name = "lzma file marker mode", .run = runLzmaFileMarkerMode, .workspace_size = 1310720, .output_size = 256, .encoded_size = 512 },
        .{ .name = "lzma2 empty", .run = runLzma2Empty, .workspace_size = 3670016, .output_size = 16, .encoded_size = 64 },
        .{ .name = "lzma2 trailing garbage", .run = runLzma2TrailingGarbage, .workspace_size = 3670016, .output_size = 256, .encoded_size = 512 },
        .{ .name = "lzma2 single byte", .run = runLzma2SingleByte, .workspace_size = 3670016, .output_size = 16, .encoded_size = 16 },
        .{ .name = "lzma2 pack bounds", .run = runLzma2PackBounds, .workspace_size = 3670016, .output_size = 512, .encoded_size = 1024 },
        .{ .name = "lzma2 bad pack size", .run = runLzma2BadPackSize, .workspace_size = 3670016, .output_size = 16, .encoded_size = 16 },
        .{ .name = "lzma2 truncated header", .run = runLzma2TruncatedHeader, .workspace_size = 3670016, .output_size = 16, .encoded_size = 16 },
        .{ .name = "lzma2 corrupt payload", .run = runLzma2CorruptPayload, .workspace_size = 3670016, .output_size = 48, .encoded_size = 512 },
        .{ .name = "lzma2 incompressible", .run = runIncompressible, .workspace_size = 3 * 1024 * 1024, .output_size = 1 << 20, .encoded_size = (1 << 20) + 4096 },
        .{ .name = "lzma2 multichunk", .run = runMultichunk, .workspace_size = 8 * 1024 * 1024, .output_size = (1 << 20) + 1024, .encoded_size = 65536 },
        .{ .name = "lzma2 midstream reset", .run = runMidstreamReset, .workspace_size = 3670016, .output_size = 4096, .encoded_size = 1024 },
        .{ .name = "lzma2 mixed chunks", .run = runMixedChunks, .workspace_size = 48 * 1024 * 1024, .output_size = (64 << 10) + (2 << 20), .encoded_size = (1 << 20) + 4096 },
        .{ .name = "lzma2 copy floor", .run = runCopyFloor, .workspace_size = 3 * 1024 * 1024, .output_size = 48 << 10, .encoded_size = (48 << 10) + 2048 },
        .{ .name = "lzma2 oversize restore", .run = runOversizeRestore, .workspace_size = 240 * 1024 * 1024, .output_size = 142848 + 16, .encoded_size = 142848 + 4096 },
        .{ .name = "lzma dictionary cap provisional", .run = runLzmaCap, .workspace_size = 1310720, .output_size = 16, .encoded_size = 256 },
        .{ .name = "lzma2 dictionary cap provisional", .run = runLzma2Cap, .workspace_size = 3670016, .output_size = 16, .encoded_size = 256 },
        .{ .name = "xz dictionary cap verified", .run = runXzCap, .workspace_size = 8 * 1024 * 1024, .output_size = 16, .encoded_size = 256 },
        .{ .name = "lzma2 scan timing", .run = runScanTiming, .workspace_size = 4 * 1024 * 1024, .output_size = 4 << 20, .encoded_size = 64 },
        .{ .name = "lzma ab corpus", .run = runLzmaAbCorpus, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab zeros", .run = runLzmaAbZeros, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab same byte", .run = runLzmaAbSameByte, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab random", .run = runLzmaAbRandom, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab sparse runs", .run = runLzmaAbSparseRuns, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab text", .run = runLzmaAbText, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab alternating", .run = runLzmaAbAlternating, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab zeros chunk boundary", .run = runLzmaAbZerosChunkBoundary, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
        .{ .name = "lzma ab zeros dictionary wrap", .run = runLzmaAbZerosDictionaryWrap, .workspace_size = 680 * 1024 * 1024, .output_size = 16, .encoded_size = 1 << 20, .suite = "lzma_ab" },
    },
);
