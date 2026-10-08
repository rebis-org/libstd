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

// Nothing allocates. The staging buffer cannot exceed 2x the input plus slack:
// the worst case is ~8 bits per symbol plus the tables, and matches only
// shrink it.

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
    symbol: u8, // 0-15 direct length, 16-17 repeat previous, 18-19 zero run
    extra: u32,
    extra_bits: u5,
};

pub fn compressBlock(
    input: []const u8,
    level: u3,
    is_last_block: bool,
    ws: Workspaces,
    out: []u8,
) Failure!usize {
    if (input.len == 0) return error.InvalidCall;

    var finder = try MatchFinder.init(ws.hash, ws.hash2, ws.hash3, MatchFinder.windowSizeFor(level), level);
    const raw_tokens = try finder.compress(input, ws.tokens, ws.bt_left, ws.bt_right);

    // The decoder adds the distance-dependent bonus back, so an adjusted
    // length below 2 has no slot. Replace those matches with literals.
    var token_count: usize = 0;
    var input_pos: usize = 0;
    for (raw_tokens) |token| {
        switch (token) {
            .literal => {
                raw_tokens[token_count] = token;
                token_count += 1;
                input_pos += 1;
            },
            .match => |match| {
                const adjusted_length = slots.adjustLengthForDistance(match.length, match.distance);
                if (adjusted_length < 2) {
                    for (0..match.length) |i| {
                        raw_tokens[token_count] = .{ .literal = input[input_pos + i] };
                        token_count += 1;
                    }
                } else {
                    raw_tokens[token_count] = token;
                    token_count += 1;
                }
                input_pos += match.length;
            },
        }
    }
    const tokens = raw_tokens[0..token_count];

    var ld_freq: [nc]u32 = @splat(0);
    var dd_freq: [dc]u32 = @splat(0);
    var ldd_freq: [ldc]u32 = @splat(0);
    var rd_freq: [rc]u32 = @splat(0);

    var prev_distances: [4]u32 = .{ 0, 0, 0, 0 };

    for (tokens) |token| {
        switch (token) {
            .literal => |byte| {
                ld_freq[byte] += 1;
            },
            .match => |match| {
                if (findRepeatDistance(prev_distances, match.distance)) |repeat_index| {
                    // The repeat path adds no distance bonus, so the raw
                    // length goes to the RD table. The repeat-distance symbol
                    // is 258 + repeat_index.
                    ld_freq[258 + repeat_index] += 1;
                    rotatePrevDistances(&prev_distances, repeat_index);
                    const length_encoding = slots.encodeLengthSlot(match.length);
                    rd_freq[length_encoding.slot] += 1;
                } else {
                    const adjusted_length = slots.adjustLengthForDistance(match.length, match.distance);
                    const length_encoding = slots.encodeLengthSlot(adjusted_length);
                    ld_freq[262 + length_encoding.slot] += 1;

                    const distance_encoding = slots.encodeDistanceSlot(match.distance);
                    dd_freq[distance_encoding.dd_slot] += 1;
                    if (distance_encoding.use_ldd) {
                        ldd_freq[distance_encoding.ldd_value] += 1;
                    }

                    prev_distances[3] = prev_distances[2];
                    prev_distances[2] = prev_distances[1];
                    prev_distances[1] = prev_distances[0];
                    prev_distances[0] = match.distance;
                }
            },
        }
    }

    // The decoder rejects a table whose frequencies are all zero.
    ensureNonZeroFreq(&ld_freq);
    ensureNonZeroFreq(&dd_freq);
    ensureNonZeroFreq(&ldd_freq);
    ensureNonZeroFreq(&rd_freq);

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

    if (ws.staging.len < input.len * max_expansion + output_slack) return error.InternalFailure;
    var bw = BitWriter.init(ws.staging);

    var cl_symbols: [total_symbols * 2]CLSymbol = undefined;
    var cl_count: usize = 0;
    encodeCLSymbols(&ld_lengths, &dd_lengths, &ldd_lengths, &rd_lengths, &cl_symbols, &cl_count);

    var cl_freq: [code_length_symbols]u32 = @splat(0);
    for (cl_symbols[0..cl_count]) |cl_symbol| {
        cl_freq[cl_symbol.symbol] += 1;
    }
    if (isAllZero(&cl_freq)) cl_freq[0] = 1;

    var cl_lengths: [code_length_symbols]u8 = undefined;
    primitive_huffman.limitedLengths(&cl_freq, &cl_lengths, 15);
    var cl_codes: [code_length_symbols]u32 = undefined;
    computeCanonicalCodes(&cl_lengths, &cl_codes);

    // Stage 1: the 20 CL lengths, 4 bits each. A 15 is an escape: a following
    // 0 means a real length of 15, and any other value is a zero run of
    // (value + 2).
    {
        var i: usize = 0;
        while (i < code_length_symbols) {
            const code_length = cl_lengths[i];
            if (code_length == 15) {
                try bw.writeBits(15, 4);
                try bw.writeBits(0, 4);
                i += 1;
            } else if (code_length == 0) {
                var run: usize = 0;
                while (i + run < code_length_symbols and cl_lengths[i + run] == 0) : (run += 1) {}
                if (run >= 3) {
                    // One escape covers 3 to 18 zeros, so the field holds
                    // count - 2.
                    try bw.writeBits(15, 4);
                    const count_raw: u8 = @intCast(@min(run, 18) - 2);
                    try bw.writeBits(count_raw, 4);
                    i += @min(run, 18);
                } else {
                    try bw.writeBits(0, 4);
                    i += 1;
                }
            } else {
                try bw.writeBits(code_length, 4);
                i += 1;
            }
        }
    }

    for (cl_symbols[0..cl_count]) |cl_symbol| {
        try bw.writeBits(cl_codes[cl_symbol.symbol], @intCast(cl_lengths[cl_symbol.symbol]));
        if (cl_symbol.extra_bits > 0) {
            try bw.writeBits(cl_symbol.extra, cl_symbol.extra_bits);
        }
    }

    prev_distances = .{ 0, 0, 0, 0 };
    for (tokens) |token| {
        switch (token) {
            .literal => |byte| {
                try bw.writeBits(ld_codes[byte], @intCast(ld_lengths[byte]));
            },
            .match => |match| {
                if (findRepeatDistance(prev_distances, match.distance)) |repeat_index| {
                    const repeat_symbol: usize = 258 + repeat_index;
                    try bw.writeBits(ld_codes[repeat_symbol], @intCast(ld_lengths[repeat_symbol]));
                    rotatePrevDistances(&prev_distances, repeat_index);

                    const length_encoding = slots.encodeLengthSlot(match.length);
                    try bw.writeBits(rd_codes[length_encoding.slot], @intCast(rd_lengths[length_encoding.slot]));
                    if (length_encoding.extra_bits > 0) {
                        try bw.writeBits(length_encoding.extra, length_encoding.extra_bits);
                    }
                } else {
                    const adjusted_length = slots.adjustLengthForDistance(match.length, match.distance);
                    const length_encoding = slots.encodeLengthSlot(adjusted_length);
                    const match_symbol: usize = 262 + length_encoding.slot;
                    try bw.writeBits(ld_codes[match_symbol], @intCast(ld_lengths[match_symbol]));
                    if (length_encoding.extra_bits > 0) {
                        try bw.writeBits(length_encoding.extra, length_encoding.extra_bits);
                    }

                    const distance_encoding = slots.encodeDistanceSlot(match.distance);
                    try bw.writeBits(dd_codes[distance_encoding.dd_slot], @intCast(dd_lengths[distance_encoding.dd_slot]));
                    if (distance_encoding.dd_extra_bits > 0) {
                        try bw.writeBits(distance_encoding.dd_extra, distance_encoding.dd_extra_bits);
                    }
                    if (distance_encoding.use_ldd) {
                        try bw.writeBits(ldd_codes[distance_encoding.ldd_value], @intCast(ldd_lengths[distance_encoding.ldd_value]));
                    }

                    prev_distances[3] = prev_distances[2];
                    prev_distances[2] = prev_distances[1];
                    prev_distances[1] = prev_distances[0];
                    prev_distances[0] = match.distance;
                }
            },
        }
    }

    const block_total_bits = bw.totalBits();
    const block_bytes = try bw.flush();

    return try wrapBlockHeader(ws.staging[0..block_bytes], block_total_bits, is_last_block, out);
}

fn computeCanonicalCodes(lengths: []const u8, codes: []u32) void {
    var length_count: [16]u32 = @splat(0);
    var max_length: u8 = 0;
    for (lengths) |code_length| {
        if (code_length > 0) {
            length_count[code_length] += 1;
            max_length = @max(max_length, code_length);
        }
    }

    var next_code: [16]u32 = @splat(0);
    var code: u32 = 0;
    for (1..@as(usize, max_length) + 1) |length_bits| {
        code = (code + length_count[length_bits - 1]) << 1;
        next_code[length_bits] = code;
    }

    for (lengths, 0..) |code_length, index| {
        if (code_length > 0) {
            codes[index] = next_code[code_length];
            next_code[code_length] += 1;
        } else {
            codes[index] = 0;
        }
    }
}

fn encodeCLSymbols(
    ld_lengths: *const [nc]u8,
    dd_lengths: *const [dc]u8,
    ldd_lengths: *const [ldc]u8,
    rd_lengths: *const [rc]u8,
    symbols: []CLSymbol,
    count: *usize,
) void {
    count.* = 0;
    var combined_lengths: [total_symbols]u8 = undefined;
    @memcpy(combined_lengths[0..nc], ld_lengths);
    @memcpy(combined_lengths[nc .. nc + dc], dd_lengths);
    @memcpy(combined_lengths[nc + dc .. nc + dc + ldc], ldd_lengths);
    @memcpy(combined_lengths[nc + dc + ldc .. total_symbols], rd_lengths);

    var i: usize = 0;
    while (i < combined_lengths.len) {
        const code_length = combined_lengths[i];

        if (code_length == 0) {
            var run: usize = 0;
            while (i + run < combined_lengths.len and combined_lengths[i + run] == 0) : (run += 1) {}
            while (run > 0) {
                if (run >= 11) {
                    // Symbol 19 encodes 11 to 138 zeros as 11 + readBits(7).
                    const emit_count = @min(run, 138);
                    symbols[count.*] = .{ .symbol = 19, .extra = @intCast(emit_count - 11), .extra_bits = 7 };
                    count.* += 1;
                    run -= emit_count;
                    i += emit_count;
                } else if (run >= 3) {
                    // Symbol 18 encodes 3 to 10 zeros as 3 + readBits(3).
                    const emit_count = @min(run, 10);
                    symbols[count.*] = .{ .symbol = 18, .extra = @intCast(emit_count - 3), .extra_bits = 3 };
                    count.* += 1;
                    run -= emit_count;
                    i += emit_count;
                } else {
                    symbols[count.*] = .{ .symbol = 0, .extra = 0, .extra_bits = 0 };
                    count.* += 1;
                    run -= 1;
                    i += 1;
                }
            }
        } else {
            symbols[count.*] = .{ .symbol = code_length, .extra = 0, .extra_bits = 0 };
            count.* += 1;
            i += 1;

            var run: usize = 0;
            while (i + run < combined_lengths.len and combined_lengths[i + run] == code_length) : (run += 1) {}
            while (run > 0) {
                if (run >= 11) {
                    // Symbol 17 repeats the previous length 11 to 138 times,
                    // as 11 + readBits(7).
                    const emit_count = @min(run, 138);
                    symbols[count.*] = .{ .symbol = 17, .extra = @intCast(emit_count - 11), .extra_bits = 7 };
                    count.* += 1;
                    run -= emit_count;
                    i += emit_count;
                } else if (run >= 3) {
                    // Symbol 16 repeats the previous length 3 to 10 times, as
                    // 3 + readBits(3).
                    const emit_count = @min(run, 10);
                    symbols[count.*] = .{ .symbol = 16, .extra = @intCast(emit_count - 3), .extra_bits = 3 };
                    count.* += 1;
                    run -= emit_count;
                    i += emit_count;
                } else {
                    symbols[count.*] = .{ .symbol = code_length, .extra = 0, .extra_bits = 0 };
                    count.* += 1;
                    run -= 1;
                    i += 1;
                }
            }
        }
    }
}

// Block header layout: a flags byte (valid-bits count, size width, last-block,
// table-present), the 0x5a XOR checksum, and the block size.
fn wrapBlockHeader(block_bytes: []const u8, total_bits: usize, is_last_block: bool, out: []u8) Failure!usize {
    const block_size: u32 = @intCast(block_bytes.len);
    const last_byte_bits: u8 = @intCast(if (total_bits % 8 == 0) 8 else total_bits % 8);
    const byte_count: u8 = if (block_size <= 0xFF) 1 else if (block_size <= 0xFFFF) 2 else 3;

    var flags: u8 = (last_byte_bits - 1) & 0x07;
    flags |= (byte_count - 1) << 3;
    if (is_last_block) flags |= 0x40;
    flags |= 0x80;

    var checksum: u8 = 0x5a ^ flags;
    checksum ^= @as(u8, @truncate(block_size));
    if (byte_count >= 2) checksum ^= @as(u8, @truncate(block_size >> 8));
    if (byte_count >= 3) checksum ^= @as(u8, @truncate(block_size >> 16));

    const header_size: usize = 2 + byte_count;
    const total_size = header_size + block_bytes.len;
    if (out.len < total_size) return error.InsufficientCapacity;

    out[0] = flags;
    out[1] = checksum;
    out[2] = @truncate(block_size);
    if (byte_count >= 2) out[3] = @truncate(block_size >> 8);
    if (byte_count >= 3) out[4] = @truncate(block_size >> 16);

    @memcpy(out[header_size..total_size], block_bytes);
    return total_size;
}

fn findRepeatDistance(prev_distances: [4]u32, distance: u32) ?usize {
    if (distance == 0) return null;
    for (prev_distances, 0..) |prev_distance, index| {
        if (prev_distance == distance) return index;
    }
    return null;
}

fn rotatePrevDistances(prev_distances: *[4]u32, index: usize) void {
    const distance = prev_distances[index];
    var i = index;
    while (i > 0) : (i -= 1) {
        prev_distances[i] = prev_distances[i - 1];
    }
    prev_distances[0] = distance;
}

fn ensureNonZeroFreq(freqs: anytype) void {
    for (freqs) |count| {
        if (count > 0) return;
    }
    freqs[0] = 1;
}

fn isAllZero(freqs: []const u32) bool {
    for (freqs) |count| {
        if (count > 0) return false;
    }
    return true;
}

test "compress block round-trips through the unpack50 decoder" {
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
    // space. The decoder slices the latter at max_filter_block.
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

test "block header checksum matches the flags and size bytes xor" {
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
