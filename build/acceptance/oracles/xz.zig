const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");

fn setupXz(r: *Runner) void {
    harness.setup(r, harness.ids.xz, harness.mode_xz);
    r.extra = 4096;
}

var xz_corpus: [100]u8 = undefined;
var xz_payload_a: [55]u8 = undefined;
var xz_payload_b: [55]u8 = undefined;
var xz_encoded: [4096]u8 = undefined;
const xz_x86_input = [_]u8{ 0xe8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x02, 0x00, 0x00, 0x00, 'x', '8', '6', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_ppc_input = [_]u8{ 0x48, 0x00, 0x00, 0x01, 'p', 'p', 'c', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_ia64_input = [_]u8{ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50, 'i', 'a', '6', '4', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_arm_input = [_]u8{ 0x00, 0x00, 0x00, 0xeb, 'a', 'r', 'm', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_armt_input = [_]u8{ 0x00, 0xf0, 0x00, 0xf8, 'a', 'r', 'm', 't', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_sparc_input = [_]u8{ 0x40, 0x00, 0x00, 0x01, 's', 'p', 'a', 'r', 'c', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_arm64_input = [_]u8{ 0x08, 0x00, 0x00, 0x94, 'a', 'r', 'm', '6', '4', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd' };
const xz_riscv_input = [_]u8{ 0xef, 0x00, 0x00, 0x01, 0xef, 0xf2, 0x1f, 0xfe };

fn xzMakeReference(data: []const u8, check: u64, delta_dist: ?u32, bcj: ?u32, out: []u8) ?usize {
    return lib.xzEncode(data, out, check, delta_dist, bcj, 4096);
}

fn xzRead(r: *Runner, archive: []const u8, output: []u8) !void {
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(archive),
        harness.sinkSpan(output),
    }, .{ .ctx = true });
}

fn runChecks(r: *Runner) !void {
    var stream1: [4096]u8 = undefined;
    var output: [256]u8 = undefined;
    const checks = [_]u64{ 0, 1, 4 };
    for (checks) |check| {
        _ = harness.call(r, harness.ids.query, &.{
            harness.lzd(r.extra),
            harness.xck(check),
            harness.paramTargetCommand(harness.ids.write),
            harness.sourceSpan(xz_corpus[0..32]),
            harness.cap(r.caps_query),
            harness.pln(r.planning),
            harness.dlv(r.delivery_write),
        }, .{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length == 0 or r.response.byte_length > stream1.len) return error.CheckQueryCapacity;
        r.required = @intCast(r.response.byte_length);
        _ = harness.call(r, harness.ids.write, &.{
            harness.lzd(r.extra),
            harness.xck(check),
            harness.sourceSpan(xz_corpus[0..32]),
            harness.sinkSpan(&stream1),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        const compressed_size: usize = @intCast(r.response.byte_length);
        if (compressed_size != r.required) return error.CheckWriteLengthMismatch;
        _ = harness.call(r, harness.ids.query, &.{
            harness.lzd(r.extra),
            harness.paramTargetCommand(harness.ids.read),
            harness.sourceSpan(stream1[0..compressed_size]),
            harness.cap(r.caps_query),
            harness.pln(r.planning),
            harness.dlv(r.delivery_read),
        }, .{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != 32) return error.CheckReadCapacity;
        @memset(&output, 0xa5);
        _ = harness.call(r, harness.ids.read, &.{
            harness.lzd(r.extra),
            harness.sourceSpan(stream1[0..compressed_size]),
            harness.sinkSpan(output[0..@intCast(r.response.byte_length)]),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != 32 or !std.mem.eql(u8, output[0..32], xz_corpus[0..32])) {
            return error.CheckRoundtripContentMismatch;
        }
        r.encoded = &xz_encoded;
        @memcpy(xz_encoded[0..compressed_size], stream1[0..compressed_size]);
        r.encoded_len = compressed_size;
    }
}

fn runCallback(r: *Runner) !void {
    var stream1: [4096]u8 = undefined;
    var output: [256]u8 = undefined;
    var source_ctx = harness.SourceCallbackContext{ .data = xz_corpus[0..32] };
    _ = harness.call(r, harness.ids.write, &.{
        harness.lzd(r.extra),
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(&stream1),
    }, .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    r.encoded_len = @intCast(r.response.byte_length);
    r.encoded = &xz_encoded;
    @memcpy(xz_encoded[0..r.encoded_len], stream1[0..r.encoded_len]);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(stream1[0..r.encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 32 or !std.mem.eql(u8, output[0..32], xz_corpus[0..32])) {
        return error.CallbackRoundtripMismatch;
    }
}

fn runCombined(r: *Runner) !void {
    var stream1: [4096]u8 = undefined;
    var stream2: [4096]u8 = undefined;
    var combined: [8192]u8 = undefined;
    var output: [4096]u8 = undefined;
    _ = harness.call(r, harness.ids.query, &.{
        harness.lzd(r.extra),
        harness.xck(4),
        harness.paramTargetCommand(harness.ids.write),
        harness.sourceSpan(&xz_payload_a),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_write),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    _ = harness.call(r, harness.ids.write, &.{
        harness.lzd(r.extra),
        harness.xck(4),
        harness.sourceSpan(&xz_payload_a),
        harness.sinkSpan(&stream2),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    const stream2_size: usize = @intCast(r.response.byte_length);
    @memcpy(stream1[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    const stream1_size = r.encoded_len;
    @memcpy(combined[0..stream1_size], stream1[0..stream1_size]);
    @memcpy(combined[stream1_size .. stream1_size + stream2_size], stream2[0..stream2_size]);
    const combined_size = stream1_size + stream2_size;
    _ = harness.call(r, harness.ids.query, &.{
        harness.lzd(r.extra),
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(combined[0..combined_size]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_read),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 32 + xz_payload_a.len) return error.CombinedQueryLength;
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(combined[0..combined_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 32 + xz_payload_a.len) return error.CombinedReadLength;
    if (!std.mem.eql(u8, output[0..32], xz_corpus[0..32])) return error.CombinedFirstContent;
    if (!std.mem.eql(u8, output[32 .. 32 + xz_payload_a.len], &xz_payload_a)) return error.CombinedSecondContent;
}

fn runForeign(r: *Runner) !void {
    var output: [4096]u8 = undefined;
    const decoded = lib.lzmaBufferDecode(r.encoded[0..r.encoded_len], &output);
    if (decoded == null) return error.ReferenceToolRejectedOutput;
}

fn runReferenceDecode(r: *Runner) !void {
    var stream1: [4096]u8 = undefined;
    var output: [256]u8 = undefined;
    const checks = [_]u64{ 0, 1, 4 };
    for (checks) |check| {
        const ref_size = xzMakeReference(xz_corpus[0..32], check, null, null, &stream1) orelse return error.XzReferenceFailed;
        @memset(&output, 0xa5);
        _ = harness.call(r, harness.ids.read, &.{
            harness.lzd(r.extra),
            harness.sourceSpan(stream1[0..ref_size]),
            harness.sinkSpan(&output),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != 32 or !std.mem.eql(u8, output[0..32], xz_corpus[0..32])) {
            return error.ReferenceDecodeMismatch;
        }
    }
}

fn runEdgeCases(r: *Runner) !void {
    var stream1: [4096]u8 = undefined;
    var corrupted: [4096]u8 = undefined;
    var output: [256]u8 = undefined;
    var reserved_flags: [4096]u8 = undefined;
    var two_filters: [4096]u8 = undefined;
    const invalid_magic = [_]u8{ 0x00, 0x37, 0x7a, 0x58, 0x5a, 0x00 };
    @memcpy(stream1[0..r.encoded_len], r.encoded[0..r.encoded_len]);
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(stream1[0 .. r.encoded_len - 1]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, &output);
    @memcpy(corrupted[0..r.encoded_len], stream1[0..r.encoded_len]);
    corrupted[r.encoded_len - 3] ^= 0xff;
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(corrupted[0..r.encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, &output);
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(&invalid_magic),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, &output);
    try harness.expect(r, harness.ids.query, &.{
        harness.lzd(r.extra),
        harness.xck(2),
        harness.paramTargetCommand(harness.ids.write),
        harness.sourceSpan(xz_corpus[0..32]),
        harness.cap(r.caps_query),
        harness.pln(r.planning),
        harness.dlv(r.delivery_write),
    }, .{}, abi.Status.unsupported);
    @memcpy(reserved_flags[0..r.encoded_len], stream1[0..r.encoded_len]);
    reserved_flags[13] |= 0x04;
    try harness.reject(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(reserved_flags[0..r.encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, abi.Status.invalid_data, &output);
    @memset(&two_filters, 0);
    @memcpy(two_filters[0..12], stream1[0..12]);
    two_filters[12] = 0x03;
    two_filters[13] = 0xC1;
    two_filters[14] = stream1[14];
    two_filters[15] = stream1[15];
    two_filters[16] = 0x21;
    two_filters[17] = 0x01;
    two_filters[18] = stream1[18];
    two_filters[19] = 0x00;
    two_filters[20] = 0x00;
    const header_crc = harness.crc32Ieee(two_filters[12..24]);
    std.mem.writeInt(u32, two_filters[24..28], header_crc, .little);
    @memcpy(two_filters[28 .. 28 + (r.encoded_len - 24)], stream1[24..r.encoded_len]);
    try harness.reject(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(two_filters[0 .. r.encoded_len + 4]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, abi.Status.unsupported, &output);
}

pub fn runRoundtrip(r: *Runner) anyerror!void {
    setupXz(r);
    corpus.select(r.corpus_index, &xz_corpus);
    corpus.select(r.corpus_index, &xz_payload_a);
    corpus.select(r.corpus_index, &xz_payload_b);
    try runChecks(r);
    try runCallback(r);
    try runCombined(r);
    try runForeign(r);
    try runReferenceDecode(r);
    try runEdgeCases(r);
}

fn runFilterCases(r: *Runner) !void {
    var filter_xz: [4096]u8 = undefined;
    var output: [4096]u8 = undefined;
    const cases = [_]struct {
        delta: ?u32,
        bcj: ?u32,
        data: []const u8,
        len: usize,
    }{
        .{ .delta = 1, .bcj = null, .data = xz_corpus[0..], .len = 32 },
        .{ .delta = 4, .bcj = null, .data = xz_corpus[0..], .len = 32 },
        .{ .delta = null, .bcj = 0x04, .data = &xz_x86_input, .len = xz_x86_input.len },
        .{ .delta = null, .bcj = 0x05, .data = &xz_ppc_input, .len = xz_ppc_input.len },
        .{ .delta = null, .bcj = 0x06, .data = &xz_ia64_input, .len = xz_ia64_input.len },
        .{ .delta = null, .bcj = 0x07, .data = &xz_arm_input, .len = xz_arm_input.len },
        .{ .delta = null, .bcj = 0x08, .data = &xz_armt_input, .len = xz_armt_input.len },
        .{ .delta = null, .bcj = 0x09, .data = &xz_sparc_input, .len = xz_sparc_input.len },
        .{ .delta = null, .bcj = 0x0A, .data = &xz_arm64_input, .len = xz_arm64_input.len },
        .{ .delta = null, .bcj = 0x0B, .data = &xz_riscv_input, .len = xz_riscv_input.len },
        .{ .delta = 1, .bcj = 0x04, .data = &xz_x86_input, .len = xz_x86_input.len },
    };
    for (cases) |item| {
        const ref_size = xzMakeReference(item.data[0..item.len], 4, item.delta, item.bcj, &filter_xz) orelse {
            std.debug.print("xz filter case unsupported (system liblzma does not support filter 0x{x})\n", .{item.bcj orelse 0});
            continue;
        };
        @memset(&output, 0xa5);
        _ = harness.call(r, harness.ids.read, &.{
            harness.lzd(r.extra),
            harness.sourceSpan(filter_xz[0..ref_size]),
            harness.sinkSpan(&output),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != item.len or !std.mem.eql(u8, output[0..item.len], item.data[0..item.len])) {
            return error.FilterDecodeMismatch;
        }
    }
    var bad: [4096]u8 = undefined;
    const ref_size = xzMakeReference(&xz_arm_input, 4, null, 0x07, &bad) orelse return error.BadHeaderReferenceFailed;
    if (ref_size < 32) return error.BadHeaderReferenceSize;
    const header_size = (@as(usize, bad[12] & 0x3f) + 1) * 4;
    var mutated_filter = false;
    for (bad[12 .. 12 + header_size], 0..) |byte, offset| {
        if (byte == 0x07) {
            bad[12 + offset] = 0x02;
            mutated_filter = true;
            break;
        }
    }
    if (!mutated_filter) return error.BadFilterIdNotFound;
    const header_crc = harness.crc32Ieee(bad[12 .. 12 + header_size - 4]);
    std.mem.writeInt(u32, bad[12 + header_size - 4 ..][0..4], header_crc, .little);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(bad[0..ref_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    if (r.status != abi.Status.invalid_data and r.status != abi.Status.unsupported) {
        return error.BadFilterHeaderStatus;
    }
    if (!harness.allBytesEqual(&output, 0xa5)) return error.BadFilterHeaderChangedOutput;
}

pub fn runFilters(r: *Runner) anyerror!void {
    setupXz(r);
    corpus.select(r.corpus_index, &xz_corpus);
    try runFilterCases(r);
}

fn runOptionalBody(r: *Runner) !void {
    var stream_a: [4096]u8 = undefined;
    var stream_b: [4096]u8 = undefined;
    var combined_payload: [16384]u8 = undefined;
    var output: [4096]u8 = undefined;
    const stream_a_size = xzMakeReference(&xz_payload_a, 10, null, null, &stream_a) orelse return error.StreamAReferenceFailed;
    const stream_b_size = xzMakeReference(&xz_payload_b, 10, null, null, &stream_b) orelse return error.StreamBReferenceFailed;
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(stream_a[0..stream_a_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != xz_payload_a.len or !std.mem.eql(u8, output[0..xz_payload_a.len], &xz_payload_a)) {
        return error.Sha256StreamMismatch;
    }
    stream_a[stream_a_size - 4] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(stream_a[0..stream_a_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, &output);
    const stream_a_size2 = xzMakeReference(&xz_payload_a, 10, null, null, &stream_a) orelse return error.StreamARegenerationFailed;
    @memcpy(combined_payload[0..stream_a_size2], stream_a[0..stream_a_size2]);
    @memset(combined_payload[stream_a_size2 .. stream_a_size2 + 4], 0);
    @memcpy(combined_payload[stream_a_size2 + 4 .. stream_a_size2 + 4 + stream_b_size], stream_b[0..stream_b_size]);
    @memset(combined_payload[stream_a_size2 + 4 + stream_b_size .. stream_a_size2 + 4 + stream_b_size + 4], 0);
    const combined_size = stream_a_size2 + 4 + stream_b_size + 4;
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(combined_payload[0..combined_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != xz_payload_a.len + xz_payload_b.len) return error.PaddedCombinedMismatch;
    if (!std.mem.eql(u8, output[0..xz_payload_a.len], &xz_payload_a) or !std.mem.eql(u8, output[xz_payload_a.len .. xz_payload_a.len + xz_payload_b.len], &xz_payload_b)) {
        return error.PaddedCombinedContentMismatch;
    }
    const stream_a3 = xzMakeReference(&xz_payload_a, 10, null, null, &stream_a) orelse return error.PaddingReferenceFailed;
    for (1..4) |pad_len| {
        var combined: [8192]u8 = undefined;
        @memset(&combined, 0);
        @memcpy(combined[0..stream_a3], stream_a[0..stream_a3]);
        try harness.reject(r, harness.ids.read, &.{
            harness.lzd(r.extra),
            harness.sourceSpan(combined[0 .. stream_a3 + pad_len]),
            harness.sinkSpan(&output),
        }, .{ .ctx = true }, abi.Status.invalid_data, &output);
    }
    var mutated: [4096]u8 = undefined;
    const old_header_size = (@as(usize, stream_a[12] & 0x3f) + 1) * 4;
    const old_header_end = 12 + old_header_size;
    const compressed_size = stream_a[14];
    const uncompressed_size = stream_a[15];
    const block_padding = (4 - (compressed_size % 4)) % 4;
    const old_index_start = old_header_end + @as(usize, compressed_size) + block_padding + 32;
    const old_index_end = stream_a_size - 12;
    const new_unpadded = old_header_size + @as(usize, compressed_size) + 32 - 4;
    if (old_header_size != 16 or old_index_start > old_index_end or stream_a[16] != 0x21 or new_unpadded > 127 or uncompressed_size > 127) {
        std.debug.print("xz optional sizes: skipped (liblzma stream shape differs from xz CLI reference)\n", .{});
        return;
    }
    var new_header: [12]u8 = undefined;
    var new_index: [8]u8 = undefined;
    new_header[0] = 0x02;
    new_header[1] = 0x40;
    new_header[2] = compressed_size;
    @memcpy(new_header[3..6], stream_a[16..19]);
    new_header[6] = 0x00;
    new_header[7] = 0x00;
    var header_crc = harness.crc32Ieee(new_header[0..8]);
    std.mem.writeInt(u32, new_header[8..12], header_crc, .little);
    new_index[0] = 0x00;
    new_index[1] = 0x01;
    new_index[2] = @intCast(new_unpadded);
    new_index[3] = @intCast(uncompressed_size);
    var index_crc = harness.crc32Ieee(new_index[0..4]);
    std.mem.writeInt(u32, new_index[4..8], index_crc, .little);
    @memcpy(mutated[0..12], stream_a[0..12]);
    @memcpy(mutated[12..24], &new_header);
    var pos: usize = 24;
    @memcpy(mutated[pos .. pos + (old_index_start - old_header_end)], stream_a[old_header_end..old_index_start]);
    pos += old_index_start - old_header_end;
    @memcpy(mutated[pos .. pos + 8], &new_index);
    pos += 8;
    @memcpy(mutated[pos .. pos + (stream_a_size - old_index_end)], stream_a[old_index_end..stream_a_size]);
    const new_size = pos + (stream_a_size - old_index_end);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(mutated[0..new_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != xz_payload_a.len or !std.mem.eql(u8, output[0..xz_payload_a.len], &xz_payload_a)) {
        return error.NoSizeBlockMismatch;
    }
    new_header[1] = 0x80;
    new_header[2] = uncompressed_size;
    header_crc = harness.crc32Ieee(new_header[0..8]);
    std.mem.writeInt(u32, new_header[8..12], header_crc, .little);
    new_index[3] = uncompressed_size;
    index_crc = harness.crc32Ieee(new_index[0..4]);
    std.mem.writeInt(u32, new_index[4..8], index_crc, .little);
    @memcpy(mutated[0..12], stream_a[0..12]);
    @memcpy(mutated[12..24], &new_header);
    pos = 24;
    @memcpy(mutated[pos .. pos + (old_index_start - old_header_end)], stream_a[old_header_end..old_index_start]);
    pos += old_index_start - old_header_end;
    @memcpy(mutated[pos .. pos + 8], &new_index);
    pos += 8;
    @memcpy(mutated[pos .. pos + (stream_a_size - old_index_end)], stream_a[old_index_end..stream_a_size]);
    const new_size2 = pos + (stream_a_size - old_index_end);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(mutated[0..new_size2]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != xz_payload_a.len or !std.mem.eql(u8, output[0..xz_payload_a.len], &xz_payload_a)) {
        return error.UncompressedSizeOnlyBlockMismatch;
    }
}

pub fn runOptional(r: *Runner) anyerror!void {
    setupXz(r);
    corpus.select(r.corpus_index, &xz_payload_a);
    corpus.select(r.corpus_index, &xz_payload_b);
    try runOptionalBody(r);
}

fn runEncodeFilters(r: *Runner) !void {
    var encoded: [16384]u8 = undefined;
    var output: [1024]u8 = undefined;
    const filters = [_]u64{ 1, 2 };
    for (filters) |filter| {
        _ = harness.call(r, harness.ids.write, &.{
            harness.lzd(r.extra),
            harness.xflt(filter),
            harness.sourceSpan(xz_corpus[0..100]),
            harness.sinkSpan(&encoded),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length == 0 or r.response.byte_length > encoded.len) return error.FilteredEncodeSize;
        r.encoded = &encoded;
        r.encoded_len = @intCast(r.response.byte_length);
        @memset(&output, 0xa5);
        _ = harness.call(r, harness.ids.read, &.{
            harness.lzd(r.extra),
            harness.sourceSpan(encoded[0..r.encoded_len]),
            harness.sinkSpan(&output),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != 100 or !std.mem.eql(u8, output[0..100], &xz_corpus)) {
            return error.FilteredEncodeRoundtrip;
        }
        var foreign_output: [1024]u8 = undefined;
        const decoded = lib.lzmaBufferDecode(encoded[0..r.encoded_len], &foreign_output);
        if (decoded == null) return error.XzToolRejectedFilteredEncode;
        if (decoded.? != 100 or !std.mem.eql(u8, foreign_output[0..100], &xz_corpus)) return error.XzToolContentMismatch;
    }
}

fn runEncodeSha256(r: *Runner) !void {
    var encoded: [16384]u8 = undefined;
    var output: [1024]u8 = undefined;
    _ = harness.call(r, harness.ids.write, &.{
        harness.lzd(r.extra),
        harness.xck(0x0A),
        harness.sourceSpan(xz_corpus[0..100]),
        harness.sinkSpan(&encoded),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    r.encoded = &encoded;
    r.encoded_len = @intCast(r.response.byte_length);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(encoded[0..r.encoded_len]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 100 or !std.mem.eql(u8, output[0..100], &xz_corpus)) {
        return error.Sha256EncodeRoundtrip;
    }
    var foreign_output: [1024]u8 = undefined;
    const decoded = lib.lzmaBufferDecode(encoded[0..r.encoded_len], &foreign_output);
    if (decoded == null) return error.XzToolRejectedSha256Encode;
}

fn runEncodeInvalidFilter(r: *Runner) !void {
    var encoded: [16384]u8 = undefined;
    try harness.expect(r, harness.ids.write, &.{
        harness.lzd(r.extra),
        harness.xflt(99),
        harness.sourceSpan(xz_corpus[0..100]),
        harness.sinkSpan(&encoded),
    }, .{ .ctx = true }, abi.Status.invalid_call);
}

fn runEncodeMultistream(r: *Runner) !void {
    const allocator = std.heap.page_allocator;
    const big_payload = try allocator.alloc(u8, 6 * 1024 * 1024);
    defer allocator.free(big_payload);
    const big_encoded = try allocator.alloc(u8, 8 * 1024 * 1024);
    defer allocator.free(big_encoded);
    const big_output = try allocator.alloc(u8, 6 * 1024 * 1024);
    defer allocator.free(big_output);
    const pattern = "multi stream xz payload %d\n";
    for (big_payload, 0..) |*byte, i| byte.* = pattern[i % pattern.len];
    _ = harness.call(r, harness.ids.write, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(big_payload),
        harness.sinkSpan(big_encoded),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    r.encoded = big_encoded;
    r.encoded_len = @intCast(r.response.byte_length);
    @memset(big_output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.lzd(r.extra),
        harness.sourceSpan(big_encoded[0..r.encoded_len]),
        harness.sinkSpan(big_output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != big_payload.len or !std.mem.eql(u8, big_output, big_payload)) {
        return error.MultistreamRoundtrip;
    }
    const foreign_output = try allocator.alloc(u8, 6 * 1024 * 1024);
    defer allocator.free(foreign_output);
    const decoded = lib.lzmaBufferDecode(big_encoded[0..r.encoded_len], foreign_output);
    if (decoded == null) return error.XzToolRejectedMultistreamEncode;
}

pub fn runEncode(r: *Runner) anyerror!void {
    setupXz(r);
    corpus.select(r.corpus_index, &xz_corpus);
    try runEncodeFilters(r);
    try runEncodeSha256(r);
    try runEncodeInvalidFilter(r);
    try runEncodeMultistream(r);
}

pub const scenarios = harness.scenarios("xz", &.{
    .{ .label = "xz roundtrip", .run = runRoundtrip, .workspace_size = 8 * 1024 * 1024, .output_size = 4096, .encoded_size = 16384 },
    .{ .label = "xz filters", .run = runFilters, .workspace_size = 8 * 1024 * 1024, .output_size = 4096, .encoded_size = 16384 },
    .{ .label = "xz optional", .run = runOptional, .workspace_size = 8 * 1024 * 1024, .output_size = 4096, .encoded_size = 16384 },
    .{ .label = "xz encode advanced", .run = runEncode, .workspace_size = 8 * 1024 * 1024, .output_size = 4096, .encoded_size = 16384 },
}, &.{});
