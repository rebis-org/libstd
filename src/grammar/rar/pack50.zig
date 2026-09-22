const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitWriter = bits.BitWriter;
const primitive_huffman = @import("../../common/primitive/huffman.zig");
const slots = @import("slots.zig");
const finder_mod = @import("finder.zig");
const MatchFinder = finder_mod.MatchFinder;
const LzToken = finder_mod.LzToken;
const unpack50 = @import("unpack50.zig");

// Produces one complete RAR5 compressed block (header + tables + symbols)
// for a file block's data area. Nothing allocates; the output staging cannot
// exceed 2x the input plus slack (worst case is ~8 bits per symbol plus the
// table, and matches only shrink it).

const nc: u16 = unpack50.nc;
const dc: u16 = unpack50.dc_rar5;
const ldc: u16 = unpack50.ldc;
const rc: u16 = unpack50.rc;

const code_length_symbols: u16 = 20;
const total_symbols: usize = nc + dc + ldc + rc;

// Caller buffer sizes (see writer.zig for the archive-level plan).
pub const max_expansion = 2;
pub const output_slack = 8192;

pub const token_bytes_per_input = @sizeOf(LzToken);
pub const tree_bytes_per_input = 2 * @sizeOf(u32);

pub const Workspaces = struct {
    hash: []u32,
    hash2: []u32,
    hash3: []u32,
    bt_left: []u32,
    bt_right: []u32,
    tokens: []LzToken,
    staging: []u8,
};

pub fn workspacesFor(input_len: usize) WorkspacesSizes {
    return .{
        .hash_words = MatchFinder.hash_size,
        .hash2_words = MatchFinder.hash2_size,
        .hash3_words = MatchFinder.hash3_size,
        .bt_words = input_len,
        .token_count = @max(input_len, 1),
        .staging_bytes = input_len * max_expansion + output_slack,
    };
}

pub const WorkspacesSizes = struct {
    hash_words: usize,
    hash2_words: usize,
    hash3_words: usize,
    bt_words: usize,
    token_count: usize,
    staging_bytes: usize,
};

const CLSymbol = struct {
    symbol: u8, // 0-15 direct length, 16-19 repeat/zero
    extra: u32,
    extra_bits: u5,
};

pub fn compressBlock(
    data: []const u8,
    level: u3,
    is_last_block: bool,
    ws: Workspaces,
    out: []u8,
) Failure!usize {
    if (data.len == 0) return error.InvalidCall;

    var mf = try MatchFinder.init(ws.hash, ws.hash2, ws.hash3, MatchFinder.windowSizeFor(level), level);
    const raw_tokens = try mf.compress(data, ws.tokens, ws.bt_left, ws.bt_right);

    // Replace matches whose bonus-adjusted length drops below 2 with
    // literals: the decoder adds the distance-dependent bonus back, so a
    // match that small cannot be encoded at all.
    var count: usize = 0;
    var data_pos: usize = 0;
    for (raw_tokens) |tok| {
        switch (tok) {
            .literal => {
                raw_tokens[count] = tok;
                count += 1;
                data_pos += 1;
            },
            .match => |m| {
                const adj_len = slots.adjustLengthForDistance(m.length, m.distance);
                if (adj_len < 2) {
                    for (0..m.length) |i| {
                        raw_tokens[count] = .{ .literal = data[data_pos + i] };
                        count += 1;
                    }
                } else {
                    raw_tokens[count] = tok;
                    count += 1;
                }
                data_pos += m.length;
            },
        }
    }
    const tokens = raw_tokens[0..count];

    var ld_freq: [nc]u32 = [_]u32{0} ** nc;
    var dd_freq: [dc]u32 = [_]u32{0} ** dc;
    var ldd_freq: [ldc]u32 = [_]u32{0} ** ldc;
    var rd_freq: [rc]u32 = [_]u32{0} ** rc;

    var prev_distances: [4]u32 = .{ 0, 0, 0, 0 };

    for (tokens) |tok| {
        switch (tok) {
            .literal => |byte| {
                ld_freq[byte] += 1;
            },
            .match => |m| {
                if (findRepeatDistance(prev_distances, m.distance)) |idx| {
                    // Repeat-distance symbol (258+idx); length goes to the RD
                    // table RAW — the decoder does not add the distance bonus
                    // on the repeat path.
                    ld_freq[258 + idx] += 1;
                    rotatePrevDistances(&prev_distances, idx);
                    const len_enc = slots.encodeLengthSlot(m.length);
                    rd_freq[len_enc.slot] += 1;
                } else {
                    const adj_len = slots.adjustLengthForDistance(m.length, m.distance);
                    const len_enc = slots.encodeLengthSlot(adj_len);
                    ld_freq[262 + len_enc.slot] += 1;

                    const dist_enc = slots.encodeDistanceSlot(m.distance);
                    dd_freq[dist_enc.dd_slot] += 1;
                    if (dist_enc.use_ldd) {
                        ldd_freq[dist_enc.ldd_value] += 1;
                    }

                    prev_distances[3] = prev_distances[2];
                    prev_distances[2] = prev_distances[1];
                    prev_distances[1] = prev_distances[0];
                    prev_distances[0] = m.distance;
                }
            },
        }
    }

    // A table with zero total frequency is invalid for the decoder.
    ensureMinFreq(&ld_freq);
    ensureMinFreq(&dd_freq);
    ensureMinFreq(&ldd_freq);
    ensureMinFreq(&rd_freq);

    var ld_lengths: [nc]u8 = undefined;
    var dd_lengths: [dc]u8 = undefined;
    var ldd_lengths: [ldc]u8 = undefined;
    var rd_lengths: [rc]u8 = undefined;

    primitive_huffman.limitedLengths(&ld_freq, &ld_lengths, 15);
    primitive_huffman.limitedLengths(&dd_freq, &dd_lengths, 15);
    primitive_huffman.limitedLengths(&ldd_freq, &ldd_lengths, 15);
    primitive_huffman.limitedLengths(&rd_freq, &rd_lengths, 15);

    var ld_codes: [nc]u32 = undefined;
    var dd_codes: [dc]u32 = undefined;
    var ldd_codes: [ldc]u32 = undefined;
    var rd_codes: [rc]u32 = undefined;

    computeCanonicalCodes(&ld_lengths, &ld_codes);
    computeCanonicalCodes(&dd_lengths, &dd_codes);
    computeCanonicalCodes(&ldd_lengths, &ldd_codes);
    computeCanonicalCodes(&rd_lengths, &rd_codes);

    if (ws.staging.len < data.len * max_expansion + output_slack) return error.InternalFailure;
    var bw = BitWriter.init(ws.staging);

    var cl_symbols: [total_symbols * 2]CLSymbol = undefined;
    var cl_count: usize = 0;
    encodeCLSymbols(&ld_lengths, &dd_lengths, &ldd_lengths, &rd_lengths, &cl_symbols, &cl_count);

    var cl_freq: [code_length_symbols]u32 = [_]u32{0} ** code_length_symbols;
    for (cl_symbols[0..cl_count]) |sym| {
        cl_freq[sym.symbol] += 1;
    }
    if (allZero(&cl_freq)) cl_freq[0] = 1;

    var cl_lengths: [code_length_symbols]u8 = undefined;
    primitive_huffman.limitedLengths(&cl_freq, &cl_lengths, 15);
    var cl_codes: [code_length_symbols]u32 = undefined;
    computeCanonicalCodes(&cl_lengths, &cl_codes);

    // Stage 1: the 20 CL lengths, 4 bits each, with value-15 zero-run escapes.
    {
        var i: usize = 0;
        while (i < code_length_symbols) {
            const len = cl_lengths[i];
            if (len == 15) {
                try bw.writeBits(15, 4);
                try bw.writeBits(0, 4);
                i += 1;
            } else if (len == 0) {
                var run: usize = 0;
                while (i + run < code_length_symbols and cl_lengths[i + run] == 0) : (run += 1) {}
                if (run >= 3) {
                    // 15 + (count-2), count in 3..18 per encoding.
                    try bw.writeBits(15, 4);
                    const count_raw: u8 = @intCast(@min(run, 18) - 2);
                    try bw.writeBits(count_raw, 4);
                    i += @min(run, 18);
                } else {
                    try bw.writeBits(0, 4);
                    i += 1;
                }
            } else {
                try bw.writeBits(len, 4);
                i += 1;
            }
        }
    }

    // Stage 2: the combined symbol lengths, encoded with the CL table.
    for (cl_symbols[0..cl_count]) |sym| {
        try bw.writeBits(cl_codes[sym.symbol], @intCast(cl_lengths[sym.symbol]));
        if (sym.extra_bits > 0) {
            try bw.writeBits(sym.extra, sym.extra_bits);
        }
    }

    // Stage 3: the symbols themselves.
    prev_distances = .{ 0, 0, 0, 0 };
    for (tokens) |tok| {
        switch (tok) {
            .literal => |byte| {
                try bw.writeBits(ld_codes[byte], @intCast(ld_lengths[byte]));
            },
            .match => |m| {
                if (findRepeatDistance(prev_distances, m.distance)) |idx| {
                    // Repeat-distance symbol; RD carries the raw length.
                    const sym: usize = 258 + idx;
                    try bw.writeBits(ld_codes[sym], @intCast(ld_lengths[sym]));
                    rotatePrevDistances(&prev_distances, idx);

                    const len_enc = slots.encodeLengthSlot(m.length);
                    try bw.writeBits(rd_codes[len_enc.slot], @intCast(rd_lengths[len_enc.slot]));
                    if (len_enc.extra_bits > 0) {
                        try bw.writeBits(len_enc.extra, len_enc.extra_bits);
                    }
                } else {
                    const adj_len = slots.adjustLengthForDistance(m.length, m.distance);
                    const len_enc = slots.encodeLengthSlot(adj_len);
                    const ld_sym: usize = 262 + len_enc.slot;
                    try bw.writeBits(ld_codes[ld_sym], @intCast(ld_lengths[ld_sym]));
                    if (len_enc.extra_bits > 0) {
                        try bw.writeBits(len_enc.extra, len_enc.extra_bits);
                    }

                    const dist_enc = slots.encodeDistanceSlot(m.distance);
                    try bw.writeBits(dd_codes[dist_enc.dd_slot], @intCast(dd_lengths[dist_enc.dd_slot]));
                    if (dist_enc.dd_extra_bits > 0) {
                        try bw.writeBits(dist_enc.dd_extra, dist_enc.dd_extra_bits);
                    }
                    if (dist_enc.use_ldd) {
                        try bw.writeBits(ldd_codes[dist_enc.ldd_value], @intCast(ldd_lengths[dist_enc.ldd_value]));
                    }

                    prev_distances[3] = prev_distances[2];
                    prev_distances[2] = prev_distances[1];
                    prev_distances[1] = prev_distances[0];
                    prev_distances[0] = m.distance;
                }
            },
        }
    }

    const data_total_bits = bw.totalBits();
    const data_bytes = try bw.flush();

    return try wrapBlockHeader(ws.staging[0..data_bytes], data_total_bits, is_last_block, out);
}

fn computeCanonicalCodes(lengths: []const u8, codes: []u32) void {
    var len_count: [16]u32 = [_]u32{0} ** 16;
    var max_len: u8 = 0;
    for (lengths) |cl| {
        if (cl > 0) {
            len_count[cl] += 1;
            max_len = @max(max_len, cl);
        }
    }

    var next_code: [16]u32 = [_]u32{0} ** 16;
    var code: u32 = 0;
    for (1..@as(usize, max_len) + 1) |bit_count| {
        code = (code + len_count[bit_count - 1]) << 1;
        next_code[bit_count] = code;
    }

    for (lengths, 0..) |cl, i| {
        if (cl > 0) {
            codes[i] = next_code[cl];
            next_code[cl] += 1;
        } else {
            codes[i] = 0;
        }
    }
}

fn encodeCLSymbols(
    ld_lengths: *const [nc]u8,
    dd_lengths: *const [dc]u8,
    ldd_lengths: *const [ldc]u8,
    rd_lengths: *const [rc]u8,
    out: []CLSymbol,
    count: *usize,
) void {
    count.* = 0;
    var combined: [total_symbols]u8 = undefined;
    @memcpy(combined[0..nc], ld_lengths);
    @memcpy(combined[nc .. nc + dc], dd_lengths);
    @memcpy(combined[nc + dc .. nc + dc + ldc], ldd_lengths);
    @memcpy(combined[nc + dc + ldc .. total_symbols], rd_lengths);

    var i: usize = 0;
    while (i < combined.len) {
        const val = combined[i];

        if (val == 0) {
            var run: usize = 0;
            while (i + run < combined.len and combined[i + run] == 0) : (run += 1) {}
            while (run > 0) {
                if (run >= 11) {
                    // Symbol 19: 11 + readBits(7) zeros = 11..138
                    const emit = @min(run, 138);
                    out[count.*] = .{ .symbol = 19, .extra = @intCast(emit - 11), .extra_bits = 7 };
                    count.* += 1;
                    run -= emit;
                    i += emit;
                } else if (run >= 3) {
                    // Symbol 18: 3 + readBits(3) zeros = 3..10
                    const emit = @min(run, 10);
                    out[count.*] = .{ .symbol = 18, .extra = @intCast(emit - 3), .extra_bits = 3 };
                    count.* += 1;
                    run -= emit;
                    i += emit;
                } else {
                    out[count.*] = .{ .symbol = 0, .extra = 0, .extra_bits = 0 };
                    count.* += 1;
                    run -= 1;
                    i += 1;
                }
            }
        } else {
            out[count.*] = .{ .symbol = val, .extra = 0, .extra_bits = 0 };
            count.* += 1;
            i += 1;

            var run: usize = 0;
            while (i + run < combined.len and combined[i + run] == val) : (run += 1) {}
            while (run > 0) {
                if (run >= 11) {
                    // Symbol 17: repeat previous 11 + readBits(7) = 11..138
                    const emit = @min(run, 138);
                    out[count.*] = .{ .symbol = 17, .extra = @intCast(emit - 11), .extra_bits = 7 };
                    count.* += 1;
                    run -= emit;
                    i += emit;
                } else if (run >= 3) {
                    // Symbol 16: repeat previous 3 + readBits(3) = 3..10
                    const emit = @min(run, 10);
                    out[count.*] = .{ .symbol = 16, .extra = @intCast(emit - 3), .extra_bits = 3 };
                    count.* += 1;
                    run -= emit;
                    i += emit;
                } else {
                    out[count.*] = .{ .symbol = val, .extra = 0, .extra_bits = 0 };
                    count.* += 1;
                    run -= 1;
                    i += 1;
                }
            }
        }
    }
}

// Wrap block data in a RAR5 block header: flags byte (valid-bits count, size
// width, last-block, table-present), the 0x5a XOR checksum, and the size.
fn wrapBlockHeader(block_data: []const u8, total_bits: usize, is_last_block: bool, out: []u8) Failure!usize {
    const block_size: u32 = @intCast(block_data.len);
    const last_byte_bits: u8 = @intCast(if (total_bits % 8 == 0) 8 else total_bits % 8);
    const byte_count: u8 = if (block_size <= 0xFF) 1 else if (block_size <= 0xFFFF) 2 else 3;

    var flags: u8 = (last_byte_bits - 1) & 0x07;
    flags |= (byte_count - 1) << 3;
    if (is_last_block) flags |= 0x40;
    flags |= 0x80; // table_present

    var checksum: u8 = 0x5a ^ flags;
    checksum ^= @as(u8, @truncate(block_size));
    if (byte_count >= 2) checksum ^= @as(u8, @truncate(block_size >> 8));
    if (byte_count >= 3) checksum ^= @as(u8, @truncate(block_size >> 16));

    const header_size: usize = 2 + byte_count;
    const total_size = header_size + block_data.len;
    if (out.len < total_size) return error.InsufficientCapacity;

    out[0] = flags;
    out[1] = checksum;
    out[2] = @truncate(block_size);
    if (byte_count >= 2) out[3] = @truncate(block_size >> 8);
    if (byte_count >= 3) out[4] = @truncate(block_size >> 16);

    @memcpy(out[header_size..total_size], block_data);
    return total_size;
}

fn findRepeatDistance(prev: [4]u32, distance: u32) ?usize {
    if (distance == 0) return null;
    for (prev, 0..) |d, i| {
        if (d == distance) return i;
    }
    return null;
}

fn rotatePrevDistances(prev: *[4]u32, idx: usize) void {
    const d = prev[idx];
    var j: usize = idx;
    while (j > 0) : (j -= 1) {
        prev[j] = prev[j - 1];
    }
    prev[0] = d;
}

fn ensureMinFreq(freq: anytype) void {
    for (freq) |f| {
        if (f > 0) return;
    }
    freq[0] = 1;
}

fn allZero(arr: []const u32) bool {
    for (arr) |v| {
        if (v > 0) return false;
    }
    return true;
}

test "compress block round-trips through the decoder" {
    var hash: [MatchFinder.hash_size]u32 = undefined;
    var hash2: [MatchFinder.hash2_size]u32 = undefined;
    var hash3: [MatchFinder.hash3_size]u32 = undefined;
    var bt_left: [4096]u32 = undefined;
    var bt_right: [4096]u32 = undefined;
    var tokens: [4096]LzToken = undefined;
    var staging: [4096 * 2 + 8192]u8 = undefined;
    var compressed: [4096 * 2 + 8192]u8 = undefined;

    const data = "Hello World! Hello World! Hello World! Hello World!";
    const sizes = workspacesFor(data.len);
    _ = sizes;
    const ws = Workspaces{
        .hash = &hash,
        .hash2 = &hash2,
        .hash3 = &hash3,
        .bt_left = &bt_left,
        .bt_right = &bt_right,
        .tokens = &tokens,
        .staging = &staging,
    };
    const written = try compressBlock(data, 3, true, ws, &compressed);

    // Decode through the real engine. The scratch must mirror the compose
    // layout: window bytes first, then filter_scratch_extra of working
    // space; the decoder slices the latter at max_filter_block.
    var window_buf: [4096]u8 = undefined;
    var pool: [unpack50.table_pool_words * 4]u16 = undefined;
    var pending: [unpack50.max_pending_filters]@import("filters50.zig").Filter = undefined;
    const filter_scratch = try std.heap.page_allocator.alloc(
        u8,
        window_buf.len + @import("../rar.zig").filter_scratch_extra,
    );
    defer std.heap.page_allocator.free(filter_scratch);
    var st: unpack50.State = undefined;
    var session = try unpack50.Session.init(&st, &window_buf, &pool, &pending, filter_scratch, false);

    var out: [4096]u8 = undefined;
    var bs = @import("../../common/sink.zig").BufferSink.init(&out);
    try session.decodeFile(compressed[0..written], data.len, false, bs.sink());
    try std.testing.expect(!bs.overflowed);
    try std.testing.expectEqualSlices(u8, data, out[0..data.len]);
}

test "block header checksum matches" {
    const block_data = [_]u8{ 0x12, 0x34, 0x56 };
    var out: [16]u8 = undefined;
    const n = try wrapBlockHeader(&block_data, 24, true, &out);
    const flags = out[0];
    const checksum = out[1];
    const byte_count: u8 = ((flags >> 3) & 3) + 1;
    var computed: u8 = 0x5a ^ flags;
    for (0..byte_count) |i| computed ^= out[2 + i];
    try std.testing.expectEqual(checksum, computed);
    try std.testing.expectEqual(@as(usize, 2 + byte_count + 3), n);
    try std.testing.expect((flags & 0x40) != 0);
    try std.testing.expect((flags & 0x80) != 0);
}
