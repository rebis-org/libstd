const std = @import("std");
const builtin = @import("builtin");

const build_options = @import("options");

const huffman = @import("../common/primitive/huffman.zig");
const kernels = @import("kernels.zig");

// NEON is baseline on aarch64, so the wide match-copy path needs no extra
// target feature; other targets keep the portable word-at-a-time path.
const vector_match_copy = !build_options.portable and builtin.cpu.arch == .aarch64;

pub const history_size = 2 * window_size;
pub const measurement_buffer_size = 64;

pub const Options = struct {
    good: u16,
    nice: u16,
    lazy: u16,
    chain: u16,
    optimal: bool = false,
};

const window_size = 32768;
const min_match = 3;
const max_match = 258;
const min_lookahead = max_match + min_match + 1;
const max_code_bits = 15;
const lit_alphabet = 288;
const dist_alphabet = 32;
const cl_alphabet = 19;
const block_tokens = 16384;
const staging_size = 4096;
const hash_bits = 15;
const hash_size = 1 << hash_bits;
// Minimum-length matches farther back than this are demoted to literals.
const too_far = 4096;
const no_position = std.math.maxInt(u32);
const token_literal: u64 = 1 << 63;

// Optimal parse: one forward pass plus frozen-price backward DP; no second price
// iteration (costs ~30% speed for ~0.3% ratio). Span cap preserves the reread invariant.
const optimal_span = window_size - min_lookahead;
const optimal_stride = 4;
const optimal_price_shift = 6;
// 4-byte chain cannot surface exactly-3 matches; side table recovers those for short distances.
const hash3_bits = 15;
const hash3_size = 1 << hash3_bits;

const OptimalScratch = struct {
    tokens: [optimal_span]u64,
    cost: [optimal_span + 1]u32,
    choice: [optimal_span]u32,
    candidates: [optimal_span * optimal_stride]u32,
    candidate_count: [optimal_span]u8,
};

pub const optimal_workspace_size = @sizeOf(OptimalScratch) + @alignOf(OptimalScratch);

// Bound by token-cap flushes, not 64 KiB stored blocks: at most n/block_tokens + 1 blocks.
pub fn encodedSizeBound(input_len: usize) usize {
    return input_len +| 6 *| (input_len / block_tokens + 1) +| 8;
}
const codegen_order: [cl_alphabet]u8 = .{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
const length_base: [29]u16 = .{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
const length_extra: [29]u5 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
const dist_base: [30]u16 = .{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
const dist_extra: [30]u5 = .{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

// Deflate64 widens length/distance alphabets, so separate base/extra tables.
const deflate64_window_size = 2 * window_size;
const deflate64_max_match = 65538;
const deflate64_length_base: [29]u16 = length_base[0..28].* ++ .{3};
const deflate64_length_extra: [29]u5 = length_extra[0..28].* ++ .{16};
const deflate64_dist_base: [32]u16 = dist_base ++ .{ 0x8001, 0xC001 };
const deflate64_dist_extra: [32]u5 = dist_extra ++ .{ 14, 14 };
pub const deflate64_history_size = 2 * deflate64_window_size + deflate64_max_match + min_match + 1;
pub const deflate64_decode_history_size = deflate64_window_size + deflate64_max_match + 1;

// Packed base|extra in one u32: one load per match code in the hot loop.
const length_info = infoTable(&length_base, &length_extra);
const dist_info = infoTable(&dist_base, &dist_extra);
const deflate64_length_info = infoTable(&deflate64_length_base, &deflate64_length_extra);
const deflate64_dist_info = infoTable(&deflate64_dist_base, &deflate64_dist_extra);

fn infoTable(comptime bases: []const u16, comptime extras: []const u5) [bases.len]u32 {
    var out: [bases.len]u32 = undefined;
    for (bases, extras, 0..) |base, extra, i| out[i] = @as(u32, base) | @as(u32, extra) << 16;
    return out;
}

const fixed_lit_lengths = blk: {
    var lengths: [lit_alphabet]u8 = undefined;
    for (0..144) |i| lengths[i] = 8;
    for (144..256) |i| lengths[i] = 9;
    for (256..280) |i| lengths[i] = 7;
    for (280..288) |i| lengths[i] = 8;
    break :blk lengths;
};

const fixed_dist_lengths: [dist_alphabet]u8 = @splat(5);

const fixed_lit_codes = blk: {
    var codes: [lit_alphabet]u16 = undefined;
    for (0..144) |i| codes[i] = reverseBits(@intCast(0x30 + i), 8);
    for (144..256) |i| codes[i] = reverseBits(@intCast(0x190 + i - 144), 9);
    for (256..280) |i| codes[i] = reverseBits(@intCast(i - 256), 7);
    for (280..288) |i| codes[i] = reverseBits(@intCast(0xC0 + i - 280), 8);
    break :blk codes;
};

const fixed_dist_codes = blk: {
    var codes: [dist_alphabet]u16 = undefined;
    for (0..dist_alphabet) |i| codes[i] = reverseBits(@intCast(i), 5);
    break :blk codes;
};

fn reverseBits(value: u16, bits: u8) u16 {
    return @bitReverse(value) >> @intCast(16 - bits);
}

fn completeTree(freqs: []const u32, lengths: []u8) void {
    var used_count: usize = 0;
    var only: usize = 0;
    for (freqs, 0..) |freq, symbol| {
        if (freq != 0) {
            used_count += 1;
            only = symbol;
        }
    }
    // Strict decoders reject incomplete trees, so a zero-frequency sibling keeps trees complete.
    if (used_count == 0) {
        lengths[0] = 1;
        lengths[1] = 1;
    } else if (used_count == 1) {
        lengths[only] = 1;
        lengths[if (only == 0) 1 else 0] = 1;
    }
}

fn canonicalCodes(lengths: []const u8, codes: []u16) void {
    var counts: [max_code_bits + 1]u16 = @splat(0);
    for (lengths) |length| {
        if (length != 0) counts[length] += 1;
    }
    var next: [max_code_bits + 1]u16 = undefined;
    var code: u16 = 0;
    for (1..max_code_bits + 1) |bits| {
        code = (code + counts[bits - 1]) << 1;
        next[bits] = code;
    }
    for (lengths, 0..) |length, symbol| {
        if (length == 0) continue;
        codes[symbol] = reverseBits(next[length], length);
        next[length] += 1;
    }
}

fn Tree(comptime max_root_bits: u5, comptime max_sub: usize) type {
    return struct {
        root: [1 << max_root_bits]u32,
        sub: [max_sub]u32,
        root_bits: u5 = 0,
        sub_len: u32 = 0,
        max_len: u5 = 0,
        empty: bool = false,
    };
}

fn buildTree(lengths: []const u8, tree: anytype, comptime max_root_bits: u5, allow_single: bool, allow_empty: bool) error{InvalidData}!void {
    tree.empty = false;
    tree.root_bits = 0;
    tree.sub_len = 0;
    tree.max_len = 0;

    var counts: [max_code_bits + 1]u16 = @splat(0);
    for (lengths) |length| {
        if (length > max_code_bits) return error.InvalidData;
        counts[length] += 1;
    }
    counts[0] = 0;
    var total: u32 = 0;
    for (1..max_code_bits + 1) |bits| {
        total += counts[bits];
        if (counts[bits] != 0) tree.max_len = @intCast(bits);
    }
    if (total == 0) {
        if (!allow_empty) return error.InvalidData;
        tree.empty = true;
        return;
    }
    var left: i32 = 1;
    for (1..max_code_bits + 1) |bits| {
        left = (left << 1) - counts[bits];
        if (left < 0) return error.InvalidData;
    }
    // A lone one-bit code is the only incomplete tree the format permits.
    if (left > 0 and !(allow_single and tree.max_len == 1)) return error.InvalidData;

    const root_bits: u5 = @min(tree.max_len, max_root_bits);
    const root_size = @as(usize, 1) << root_bits;
    const root_mask = root_size - 1;
    tree.root_bits = root_bits;

    var first_code: [max_code_bits + 1]u16 = undefined;
    var code: u16 = 0;
    for (1..max_code_bits + 1) |bits| {
        code = (code + counts[bits - 1]) << 1;
        first_code[bits] = code;
    }
    var next_code = first_code;

    var max_extra: [1 << max_root_bits]u8 = @splat(0);
    for (lengths) |len| {
        if (len == 0 or len <= root_bits) continue;
        const c = reverseBits(next_code[len], len);
        next_code[len] += 1;
        const prefix = c & root_mask;
        const extra = len - root_bits;
        if (extra > max_extra[prefix]) max_extra[prefix] = @intCast(extra);
    }

    next_code = first_code;

    var sub_offset: [1 << max_root_bits]u32 = undefined;
    var sub_len: u32 = 0;
    for (0..root_size) |prefix| {
        if (max_extra[prefix] > 0) {
            sub_offset[prefix] = sub_len;
            sub_len += @as(u32, 1) << @intCast(max_extra[prefix]);
        } else {
            sub_offset[prefix] = 0;
        }
    }
    if (sub_len > tree.sub.len) return error.InvalidData;
    tree.sub_len = sub_len;

    // Only the live span needs clearing; complete trees tile every slot.
    @memset(tree.root[0..root_size], 0);
    @memset(tree.sub[0..sub_len], 0);

    for (lengths, 0..) |len, symbol| {
        if (len == 0 or len > root_bits) continue;
        const c = reverseBits(next_code[len], len);
        next_code[len] += 1;
        const entry = (@as(u32, @intCast(symbol)) << 16) | len;
        var slot: usize = c;
        while (slot < root_size) : (slot += @as(usize, 1) << @intCast(len)) tree.root[slot] = entry;
    }

    for (lengths, 0..) |len, symbol| {
        if (len == 0 or len <= root_bits) continue;
        const c = reverseBits(next_code[len], len);
        next_code[len] += 1;
        const prefix = c & root_mask;
        const extra = len - root_bits;
        const sub_bits = max_extra[prefix];
        const lower = (c >> @intCast(root_bits)) & ((@as(u16, 1) << @intCast(extra)) - 1);
        const base = sub_offset[prefix];
        const entry = (@as(u32, @intCast(symbol)) << 16) | @as(u32, extra);
        const start = base + @as(usize, lower);
        const step = @as(usize, 1) << @intCast(extra);
        const end = base + (@as(usize, 1) << @intCast(sub_bits));
        var slot = start;
        while (slot < end) : (slot += step) tree.sub[slot] = entry;
        if (tree.root[prefix] == 0) {
            tree.root[prefix] = (sub_offset[prefix] << 16) | (@as(u32, sub_bits) << 8);
        }
    }
}

pub fn CompressOf(comptime variant: enum { deflate, deflate64 }) type {
    return struct {
        const Config = struct {
            window_size: usize,
            max_match: usize,
            min_lookahead: usize,
            history_size: usize,
            hdist_max: u16,
            length_base: []const u16,
            length_extra: []const u5,
            dist_base: []const u16,
            dist_extra: []const u5,
        };

        const config: Config = switch (variant) {
            .deflate => .{ .window_size = 32768, .max_match = 258, .min_lookahead = 258 + min_match + 1, .history_size = 2 * 32768, .hdist_max = 30, .length_base = &length_base, .length_extra = &length_extra, .dist_base = &dist_base, .dist_extra = &dist_extra },
            .deflate64 => .{ .window_size = deflate64_window_size, .max_match = deflate64_max_match, .min_lookahead = deflate64_max_match + min_match + 1, .history_size = deflate64_history_size, .hdist_max = 32, .length_base = &deflate64_length_base, .length_extra = &deflate64_length_extra, .dist_base = &deflate64_dist_base, .dist_extra = &deflate64_dist_extra },
        };

        writer: std.Io.Writer,
        downstream: *std.Io.Writer,
        options: Options,
        history: []u8,
        base: u64,
        end: usize,
        cursor: usize,
        finalized: usize,
        block_start: usize,
        pending_len: usize,
        pending_dist: u32,
        deferred: bool,
        tokens_len: usize,
        bits: u64,
        bit_count: u7,
        staging: [staging_size]u8,
        staging_len: usize,
        head: [hash_size]u32,
        prev: [config.window_size]u32,
        tokens: [block_tokens]u64,
        head3: [hash3_size]u32,
        failed: bool,
        finished: bool,
        optimal: ?*OptimalScratch,
        opt_pending_len: usize,

        pub fn init(downstream: *std.Io.Writer, history: []u8, options: Options) error{ InvalidCall, InsufficientCapacity }!@This() {
            if (history.len < config.history_size) return error.InsufficientCapacity;
            if (options.good < min_match or options.good > config.max_match) return error.InvalidCall;
            if (options.nice < min_match or options.nice > config.max_match) return error.InvalidCall;
            if (options.lazy > options.nice) return error.InvalidCall;
            if (options.chain == 0) return error.InvalidCall;
            var optimal: ?*OptimalScratch = null;
            if (options.optimal) {
                const base = @intFromPtr(history.ptr) + config.history_size;
                const aligned = std.mem.alignForward(usize, base, @alignOf(OptimalScratch));
                const start = aligned - @intFromPtr(history.ptr);
                if (history.len < start + @sizeOf(OptimalScratch)) return error.InsufficientCapacity;
                optimal = @ptrFromInt(aligned);
            }
            // Encoder state below is filled by the block loop before any read.
            return .{
                .writer = .{ .buffer = history[0..config.history_size], .vtable = &.{ .drain = drain, .flush = flush, .rebase = writerRebase } },
                .downstream = downstream,
                .options = options,
                .history = history[0..config.history_size],
                .base = 0,
                .end = 0,
                .cursor = 0,
                .finalized = 0,
                .block_start = 0,
                .pending_len = min_match - 1,
                .pending_dist = 0,
                .deferred = false,
                .tokens_len = 0,
                .bits = 0,
                .bit_count = 0,
                .staging = undefined,
                .staging_len = 0,
                .head = @splat(no_position),
                .prev = undefined,
                .tokens = undefined,
                // Filled only for optimal mode; the lazy path never reads it.
                .head3 = if (options.optimal) @splat(no_position) else undefined,
                .failed = false,
                .finished = false,
                .optimal = optimal,
                .opt_pending_len = 0,
            };
        }

        pub fn finish(c: *@This()) std.Io.Writer.Error!void {
            if (c.failed or c.finished) return error.WriteFailed;
            errdefer c.writer = .failing;
            c.end = c.writer.end;
            try c.tokenize(true);
            if (c.options.optimal) {
                if (c.opt_pending_len != 0) {
                    try c.emitBlock(true, c.optimal.?.tokens[0..c.opt_pending_len]);
                    c.opt_pending_len = 0;
                } else {
                    // Final flag still needs a block on empty/boundary input.
                    c.finalized = c.cursor;
                    try c.emitBlock(true, c.tokens[0..0]);
                }
            } else {
                if (c.pending_len >= min_match) {
                    c.tallyMatch(c.pending_len, c.pending_dist);
                } else if (c.deferred) {
                    c.tallyLiteral(c.history[c.cursor - 1]);
                }
                c.pending_len = min_match - 1;
                c.finalized = c.cursor;
                try c.emitBlock(true, c.tokens[0..c.tokens_len]);
            }
            const pad: u6 = @intCast((8 - c.bit_count % 8) % 8);
            try c.writeBits(0, pad);
            try c.flushStaging();
            c.finished = true;
        }

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const compressor: *@This() = @alignCast(@fieldParentPtr("writer", w));
            if (compressor.failed or compressor.finished) return error.WriteFailed;
            errdefer compressor.writer = .failing;
            compressor.end = w.end;
            try compressor.tokenize(false);
            for (data[0 .. data.len - 1]) |part| try compressor.consume(part);
            const last = data[data.len - 1];
            for (0..splat) |_| try compressor.consume(last);
            w.end = compressor.end;
            return last.len * splat;
        }

        fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
            const compressor: *@This() = @alignCast(@fieldParentPtr("writer", w));
            if (compressor.failed or compressor.finished) return error.WriteFailed;
            errdefer compressor.writer = .failing;
            compressor.end = w.end;
            try compressor.tokenize(true);
            try compressor.flushStaging();
            w.end = compressor.end;
        }

        fn writerRebase(w: *std.Io.Writer, preserve: usize, capacity: usize) std.Io.Writer.Error!void {
            const compressor: *@This() = @alignCast(@fieldParentPtr("writer", w));
            if (compressor.failed or compressor.finished) return error.WriteFailed;
            errdefer compressor.writer = .failing;
            compressor.end = w.end;
            try compressor.tokenize(false);
            const need = (compressor.end + capacity) -| w.buffer.len;
            const history_limit = compressor.cursor -| config.window_size;
            const preserve_limit = compressor.end -| preserve;
            if (need > history_limit or need > preserve_limit) return error.WriteFailed;
            if ((compressor.tokens_len != 0 or compressor.opt_pending_len != 0) and need > compressor.block_start) return error.WriteFailed;
            compressor.slide(need);
            w.end = compressor.end;
        }

        fn consume(compressor: *@This(), bytes: []const u8) std.Io.Writer.Error!void {
            var rest = bytes;
            while (rest.len != 0) {
                if (compressor.end == compressor.history.len) compressor.slide(compressor.cursor -| config.window_size);
                const count = @min(rest.len, compressor.history.len - compressor.end);
                @memcpy(compressor.history[compressor.end..][0..count], rest[0..count]);
                compressor.end += count;
                rest = rest[count..];
                try compressor.tokenize(false);
            }
        }

        fn slide(c: *@This(), keep_from: usize) void {
            if (keep_from == 0) return;
            if ((c.tokens_len != 0 or c.opt_pending_len != 0) and c.block_start < keep_from) {
                // Span cap keeps this unreachable; retaining block start is defensive only.
                c.slide(c.block_start);
                return;
            }
            const kept = c.end - keep_from;
            @memmove(c.history[0..kept], c.history[keep_from..c.end]);
            c.end = kept;
            c.cursor -= keep_from;
            c.finalized -= keep_from;
            c.block_start -= keep_from;
            c.base += keep_from;
        }

        fn tokenize(c: *@This(), finishing: bool) std.Io.Writer.Error!void {
            if (c.options.optimal) return c.tokenizeOptimal(finishing);
            while (c.cursor < c.end) {
                if (!finishing and c.end - c.cursor < config.min_lookahead) break;
                try c.step();
                // Deflate64 matches can exceed the window; subtracting lookahead would stall the slide forever.
                const span_cap = if (config.window_size > config.min_lookahead) config.window_size - config.min_lookahead else config.window_size;
                if (c.tokens_len == block_tokens or c.finalized - c.block_start >= span_cap) try c.emitBlock(false, c.tokens[0..c.tokens_len]);
            }
        }

        fn tokenizeOptimal(c: *@This(), finishing: bool) std.Io.Writer.Error!void {
            // Pending block pins its span; emit non-final to keep block_start == cursor.
            if (c.opt_pending_len != 0) {
                try c.emitBlock(false, c.optimal.?.tokens[0..c.opt_pending_len]);
                c.opt_pending_len = 0;
            }
            while (c.cursor < c.end) {
                if (!finishing and c.end - c.cursor < config.min_lookahead) break;
                const limit = if (finishing) c.end - c.cursor else c.end - c.cursor - config.min_lookahead + 1;
                // Non-final sliver waits for more input; buffer-full path leaves room for a full span.
                if (!finishing and limit < 4096) break;
                const span = @min(optimal_span, limit);
                try c.encodeBlockOptimal(c.cursor + span, finishing);
            }
        }

        fn encodeBlockOptimal(c: *@This(), span_end: usize, finishing: bool) std.Io.Writer.Error!void {
            const scratch = c.optimal.?;
            const start = c.block_start;
            const span = span_end - start;
            var lit_freq: [lit_alphabet]u32 = @splat(0);
            var dist_freq: [dist_alphabet]u32 = @splat(0);
            lit_freq[256] = 1;
            // Replay lazy decisions exactly so frozen prices start from the accepted distribution.
            var stats_tokens: u64 = 0;
            var stats_at = start;
            var stats_pending_len: usize = min_match - 1;
            var stats_pending_dist: u32 = 0;
            var stats_deferred = false;
            var prev_best: usize = 0;
            var p = start;
            while (p < span_end) : (p += 1) {
                var best_length: usize = min_match - 1;
                var best_distance: u32 = 0;
                var count: u8 = 0;
                const candidates = scratch.candidates[(p - start) * optimal_stride ..][0..optimal_stride];
                if (c.end - p >= min_match + 1) {
                    const head = c.insert(p);
                    var chain_list: [optimal_stride]u32 = undefined;
                    var chain_count: u8 = 0;
                    // Deep walk runs only where the previous position found nothing long.
                    if (head != no_position and prev_best < 32) {
                        const found = c.searchImproving(p, head, span_end, &chain_list);
                        chain_count = found.count;
                        best_length = found.length;
                        best_distance = found.distance;
                    }
                    // Nearest 3-byte hit recovers what the 4-byte chain cannot surface.
                    const position: u32 = @truncate(c.base + p);
                    var side_length: usize = 0;
                    var side_distance: u32 = 0;
                    if (position != no_position) {
                        const h3 = hash3(c.history[p..]);
                        const cand3 = c.head3[h3];
                        c.head3[h3] = position;
                        if (cand3 != no_position) {
                            const distance = position -% cand3;
                            if (distance != 0 and distance <= config.window_size) {
                                const l = matchLength(c.history, p - distance, p, @min(@min(config.max_match, c.end - p), span_end - p));
                                if (l >= min_match) {
                                    side_length = l;
                                    side_distance = distance;
                                }
                            }
                        }
                    }
                    count = mergeCandidates(candidates, chain_list[0..chain_count], side_length, side_distance);
                    if (side_length > best_length and side_length >= min_match) {
                        best_length = side_length;
                        best_distance = side_distance;
                    }
                }
                prev_best = best_length;
                scratch.candidate_count[p - start] = count;
                if (p != stats_at) continue;
                var current_length = best_length;
                const current_distance = best_distance;
                if (stats_pending_len >= c.options.lazy and stats_pending_len >= min_match) current_length = min_match - 1;
                if (current_length == min_match and current_distance > too_far) current_length = min_match - 1;
                if (stats_pending_len >= min_match and current_length <= stats_pending_len) {
                    lit_freq[257 + @as(usize, lengthIndexFor(stats_pending_len))] += 1;
                    dist_freq[distIndexFor(stats_pending_dist)] += 1;
                    stats_tokens += 1;
                    stats_at = p + stats_pending_len - 1;
                    stats_pending_len = min_match - 1;
                    stats_deferred = false;
                } else {
                    if (stats_deferred) {
                        lit_freq[c.history[p - 1]] += 1;
                        stats_tokens += 1;
                    }
                    stats_deferred = true;
                    stats_pending_len = current_length;
                    stats_pending_dist = current_distance;
                    stats_at = p + 1;
                }
            }
            if (stats_pending_len >= min_match) {
                lit_freq[257 + @as(usize, lengthIndexFor(stats_pending_len))] += 1;
                dist_freq[distIndexFor(stats_pending_dist)] += 1;
                stats_tokens += 1;
            } else if (stats_deferred) {
                lit_freq[c.history[span_end - 1]] += 1;
                stats_tokens += 1;
            }
            const token_count = c.planBlock(span, &lit_freq, &dist_freq, stats_tokens);
            c.cursor = span_end;
            c.finalized = span_end;
            if (finishing and span_end == c.end) {
                // Final flag belongs to finish(); block waits tallied.
                c.opt_pending_len = token_count;
                return;
            }
            try c.emitBlock(false, scratch.tokens[0..token_count]);
        }

        fn planBlock(c: *@This(), span: usize, lit_freq: *[lit_alphabet]u32, dist_freq: *[dist_alphabet]u32, stats_tokens: u64) usize {
            var lit_lengths: [lit_alphabet]u8 = undefined;
            var dist_lengths: [dist_alphabet]u8 = undefined;
            huffman.limitedLengths(lit_freq, &lit_lengths, max_code_bits);
            huffman.limitedLengths(dist_freq, &dist_lengths, max_code_bits);
            completeTree(lit_freq, &lit_lengths);
            completeTree(dist_freq, &dist_lengths);
            // Header cost spreads over tokens, so a match is charged one share per replaced literal.
            const header_bits = dynamicHeaderBits(&lit_lengths, &dist_lengths);
            const overhead: u32 = @intCast((header_bits << optimal_price_shift) / @max(1, stats_tokens));
            var lit_price: [256]u32 = undefined;
            for (0..256) |symbol| lit_price[symbol] = @as(u32, lit_lengths[symbol]) << optimal_price_shift;
            return c.optimalParse(span, &lit_price, &lit_lengths, &dist_lengths, overhead);
        }

        const Improving = struct { count: u8, length: usize, distance: u32 };

        // Ascending improving pairs let the DP price against the cheapest covering distance.
        // Budget collapses past good length: the chain tail dominates encode cost.
        fn searchImproving(c: *@This(), s: usize, head_candidate: u32, span_end: usize, output: []u32) Improving {
            const position: u32 = @truncate(c.base + s);
            const available = @min(config.max_match, c.end - s);
            const clip = @min(available, span_end - s);
            const nice = @min(c.options.nice, available);
            var budget: u32 = c.options.chain;
            const good_budget: u32 = @max(1, c.options.chain / 4);
            var best: usize = min_match - 1;
            var best_dist: u32 = 0;
            var count: u8 = 0;
            var candidate = head_candidate;
            const history = c.history;
            const prev: []const u32 = c.prev[0..];
            const good = c.options.good;
            while (candidate != no_position and budget > 0) : (budget -= 1) {
                const distance = position -% candidate;
                if (distance == 0 or distance > config.window_size) break;
                const at = s - distance;
                if (best < available and history[at + best] == history[s + best] and history[at + best - 1] == history[s + best - 1]) {
                    const len = matchLength(history, at, s, available);
                    if (len > best) {
                        best = len;
                        best_dist = distance;
                        if (best >= good and budget > good_budget) budget = good_budget;
                        const l = @min(len, clip);
                        if (l >= min_match) {
                            const entry = (@as(u32, @intCast(l - 1)) << 16) | (distance - 1);
                            if (count < optimal_stride) {
                                output[count] = entry;
                                count += 1;
                            } else {
                                output[optimal_stride - 1] = entry;
                            }
                        }
                        if (best >= nice) break;
                    }
                }
                candidate = prev[at & (config.window_size - 1)];
            }
            return .{ .count = count, .length = @min(best, clip), .distance = best_dist };
        }

        // Backward DP on frozen prices; suffix minima give each length its cheapest covering distance.
        fn optimalParse(c: *@This(), span: usize, lit_price: []const u32, lit_lengths: []const u8, dist_lengths: []const u8, overhead: u32) usize {
            const scratch = c.optimal.?;
            const history = c.history[c.block_start..][0..span];
            scratch.cost[span] = 0;
            var i = span;
            while (i > 0) {
                i -= 1;
                var best = lit_price[history[i]] + overhead + scratch.cost[i + 1];
                var choice: u32 = 0;
                const count = scratch.candidate_count[i];
                if (count != 0) {
                    const entries = scratch.candidates[i * optimal_stride ..][0..count];
                    var sfx_price: [optimal_stride]u32 = undefined;
                    var sfx_dist: [optimal_stride]u32 = undefined;
                    var j: usize = count;
                    var sp: u32 = std.math.maxInt(u32);
                    var sd: u32 = 0;
                    while (j > 0) {
                        j -= 1;
                        const edist: u32 = (entries[j] & 0xFFFF) + 1;
                        const di = distIndexFor(edist);
                        const dp = (@as(u32, dist_lengths[di]) + config.dist_extra[di]) << optimal_price_shift;
                        if (dp < sp) {
                            sp = dp;
                            sd = edist;
                        }
                        sfx_price[j] = sp;
                        sfx_dist[j] = sd;
                    }
                    // Prices are slot-constant, so only slot-first lengths plus the longest need trying.
                    const lmax: usize = @as(usize, entries[count - 1] >> 16) + 1;
                    var seg: usize = 0;
                    var l: usize = min_match;
                    while (true) {
                        while (@as(usize, entries[seg] >> 16) + 1 < l) seg += 1;
                        const li = lengthIndexFor(l);
                        const price = ((@as(u32, lit_lengths[257 + @as(usize, li)]) + config.length_extra[li]) << optimal_price_shift) + sfx_price[seg] + overhead + scratch.cost[i + l];
                        if (price < best) {
                            best = price;
                            choice = (@as(u32, @intCast(l - 1)) << 16) | (sfx_dist[seg] - 1);
                        }
                        if (l >= lmax) break;
                        l = @min(config.length_base[li] + (@as(usize, 1) << config.length_extra[li]), lmax);
                    }
                }
                scratch.cost[i] = best;
                scratch.choice[i] = choice;
            }
            var token_count: usize = 0;
            var pos: usize = 0;
            while (pos < span) {
                const entry = scratch.choice[pos];
                const elen: usize = @as(usize, entry >> 16) + 1;
                if (elen == 1) {
                    scratch.tokens[token_count] = token_literal | history[pos];
                    pos += 1;
                } else {
                    scratch.tokens[token_count] = @as(u64, @intCast(elen - min_match)) << 16 | (entry & 0xFFFF);
                    pos += elen;
                }
                token_count += 1;
            }
            return token_count;
        }

        fn step(c: *@This()) std.Io.Writer.Error!void {
            const s = c.cursor;
            var head_candidate: u32 = no_position;
            if (c.end - s >= min_match + 1) head_candidate = c.insert(s);
            var current_length: usize = min_match - 1;
            var current_distance: u32 = 0;
            if (head_candidate != no_position and (c.pending_len < c.options.lazy or c.pending_len < min_match)) {
                const found = c.search(s, head_candidate);
                current_length = found.length;
                current_distance = found.distance;
                // Too-far minimum match costs more than literals; demote before lazy.
                if (current_length == min_match and current_distance > too_far) {
                    current_length = min_match - 1;
                    current_distance = 0;
                }
            }
            if (c.pending_len >= min_match and current_length <= c.pending_len) {
                c.tallyMatch(c.pending_len, c.pending_dist);
                var p = s + 1;
                const last = s + c.pending_len - 1;
                while (p < last) : (p += 1) {
                    if (c.end - p >= min_match + 1) _ = c.insert(p);
                }
                c.cursor = last;
                c.finalized = c.cursor;
                c.pending_len = min_match - 1;
                c.deferred = false;
            } else {
                if (c.deferred) c.tallyLiteral(c.history[s - 1]);
                c.deferred = true;
                c.pending_len = current_length;
                c.pending_dist = current_distance;
                c.finalized = s;
                c.cursor = s + 1;
            }
        }

        fn insert(c: *@This(), s: usize) u32 {
            const position: u32 = @truncate(c.base + s);
            // Sentinel collides once per 4 GiB; that position forfeits its slot.
            if (position == no_position) return no_position;
            const h = hash4(c.history[s..]);
            const candidate = c.head[h];
            c.prev[s & (config.window_size - 1)] = candidate;
            c.head[h] = position;
            return candidate;
        }

        fn search(c: *@This(), s: usize, head_candidate: u32) Match {
            const position: u32 = @truncate(c.base + s);
            const available = @min(config.max_match, c.end - s);
            const nice = @min(c.options.nice, available);
            var budget: u32 = c.options.chain;
            if (c.pending_len >= c.options.good) budget >>= 2;
            var best_length: usize = min_match - 1;
            var best_distance: u32 = 0;
            var candidate = head_candidate;
            const history = c.history;
            const prev: []const u32 = c.prev[0..];
            while (candidate != no_position and budget > 0) : (budget -= 1) {
                const distance = position -% candidate;
                if (distance == 0 or distance > config.window_size) break;
                const at = s - distance;
                if (best_length < available and history[at + best_length] == history[s + best_length] and history[at + best_length - 1] == history[s + best_length - 1]) {
                    const match_length = matchLength(history, at, s, available);
                    if (match_length > best_length) {
                        best_length = match_length;
                        best_distance = distance;
                        if (best_length >= nice) break;
                    }
                }
                candidate = prev[at & (config.window_size - 1)];
            }
            return .{ .length = best_length, .distance = best_distance };
        }

        fn tallyLiteral(c: *@This(), byte: u8) void {
            c.tokens[c.tokens_len] = token_literal | byte;
            c.tokens_len += 1;
        }

        fn tallyMatch(c: *@This(), length: usize, distance: u32) void {
            c.tokens[c.tokens_len] = @as(u64, @intCast(length - min_match)) << 16 | (distance - 1);
            c.tokens_len += 1;
        }

        fn lengthIndexFor(length: usize) u5 {
            if (variant == .deflate64) {
                // Remapped code 285 covers every length from 258 up.
                if (length >= 258) return 28;
            } else if (length == 258) {
                return 28;
            }
            const value: u32 = @intCast(length - min_match);
            if (value < 8) return @intCast(value);
            const top: u5 = @intCast(31 - @clz(value));
            return 4 * top - 8 + @as(u5, @intCast(value >> @intCast(top - 2)));
        }

        fn distIndexFor(distance: usize) u5 {
            if (distance <= 2) return @intCast(distance - 1);
            const value: u32 = @intCast(distance - 1);
            const top: u5 = @intCast(31 - @clz(value));
            return 2 * top - 2 + @as(u5, @intCast(value >> @intCast(top - 1)));
        }

        fn emitBlock(c: *@This(), final: bool, tokens: []const u64) std.Io.Writer.Error!void {
            const span = c.finalized - c.block_start;
            var lit_freq: [lit_alphabet]u32 = @splat(0);
            var dist_freq: [dist_alphabet]u32 = @splat(0);
            var extra_sum: u64 = 0;
            lit_freq[256] = 1;
            for (tokens) |token| {
                if (token & token_literal != 0) {
                    lit_freq[token & 0xFF] += 1;
                } else {
                    const li = lengthIndexFor(((token >> 16) & 0xFFFF) + min_match);
                    const di = distIndexFor((token & 0xFFFF) + 1);
                    lit_freq[257 + @as(usize, li)] += 1;
                    dist_freq[di] += 1;
                    extra_sum += config.length_extra[li] + config.dist_extra[di];
                }
            }
            var lit_lengths: [lit_alphabet]u8 = undefined;
            var dist_lengths: [dist_alphabet]u8 = undefined;
            huffman.limitedLengths(&lit_freq, &lit_lengths, max_code_bits);
            huffman.limitedLengths(&dist_freq, &dist_lengths, max_code_bits);
            completeTree(&lit_freq, &lit_lengths);
            completeTree(&dist_freq, &dist_lengths);
            var hlit: usize = lit_alphabet;
            while (hlit > 257 and lit_lengths[hlit - 1] == 0) hlit -= 1;
            var hdist: usize = dist_alphabet;
            while (hdist > 1 and dist_lengths[hdist - 1] == 0) hdist -= 1;
            var combined: [286 + dist_alphabet]u8 = undefined;
            @memcpy(combined[0..hlit], lit_lengths[0..hlit]);
            @memcpy(combined[hlit..][0..hdist], dist_lengths[0..hdist]);
            var rle_symbol: [combined.len]u8 = undefined;
            var rle_value: [combined.len]u8 = undefined;
            var cl_freq: [cl_alphabet]u32 = @splat(0);
            var cl_extra: u64 = 0;
            const rle_count = runLengthEncode(combined[0 .. hlit + hdist], &rle_symbol, &rle_value, &cl_freq, &cl_extra);
            var cl_lengths: [cl_alphabet]u8 = undefined;
            huffman.limitedLengths(&cl_freq, &cl_lengths, 7);
            completeTree(&cl_freq, &cl_lengths);
            var hclen: usize = cl_alphabet;
            while (hclen > 4 and cl_lengths[codegen_order[hclen - 1]] == 0) hclen -= 1;
            var fixed_bits: u64 = 3 + extra_sum;
            for (0..286) |symbol| fixed_bits += lit_freq[symbol] * fixed_lit_lengths[symbol];
            for (0..config.hdist_max) |symbol| fixed_bits += dist_freq[symbol] * 5;
            var dynamic_bits: u64 = 3 + 14 + 3 * hclen + cl_extra + extra_sum;
            for (0..lit_alphabet) |symbol| dynamic_bits += lit_freq[symbol] * lit_lengths[symbol];
            for (0..dist_alphabet) |symbol| dynamic_bits += dist_freq[symbol] * dist_lengths[symbol];
            for (0..cl_alphabet) |symbol| dynamic_bits += cl_freq[symbol] * cl_lengths[symbol];
            const stored_bits = 3 + (8 - (c.bit_count + 3) % 8) % 8 + 32 + 8 * span;
            if (stored_bits < fixed_bits and stored_bits < dynamic_bits) {
                try c.writeBits(@intFromBool(final), 1);
                try c.writeBits(0, 2);
                const pad: u6 = @intCast((8 - c.bit_count % 8) % 8);
                try c.writeBits(0, pad);
                try c.writeBits(@intCast(span), 16);
                try c.writeBits(~@as(u32, @intCast(span)) & 0xFFFF, 16);
                try c.flushStaging();
                c.downstream.writeAll(c.history[c.block_start..c.finalized]) catch {
                    c.failed = true;
                    return error.WriteFailed;
                };
            } else if (fixed_bits <= dynamic_bits) {
                try c.writeBits(@intFromBool(final), 1);
                try c.writeBits(1, 2);
                try c.emitTokens(tokens, &fixed_lit_codes, &fixed_lit_lengths, &fixed_dist_codes, &fixed_dist_lengths);
            } else {
                var lit_codes: [lit_alphabet]u16 = undefined;
                var dist_codes: [dist_alphabet]u16 = undefined;
                var cl_codes: [cl_alphabet]u16 = undefined;
                canonicalCodes(&lit_lengths, &lit_codes);
                canonicalCodes(&dist_lengths, &dist_codes);
                canonicalCodes(&cl_lengths, &cl_codes);
                try c.writeBits(@intFromBool(final), 1);
                try c.writeBits(2, 2);
                try c.writeBits(@intCast(hlit - 257), 5);
                try c.writeBits(@intCast(hdist - 1), 5);
                try c.writeBits(@intCast(hclen - 4), 4);
                for (0..hclen) |i| try c.writeBits(cl_lengths[codegen_order[i]], 3);
                for (rle_symbol[0..rle_count], rle_value[0..rle_count]) |symbol, value| {
                    try c.writeBits(cl_codes[symbol], cl_lengths[symbol]);
                    switch (symbol) {
                        16 => try c.writeBits(value, 2),
                        17 => try c.writeBits(value, 3),
                        18 => try c.writeBits(value, 7),
                        else => {},
                    }
                }
                try c.emitTokens(tokens, &lit_codes, &lit_lengths, &dist_codes, &dist_lengths);
            }
            c.tokens_len = 0;
            c.block_start = c.finalized;
        }

        fn emitTokens(c: *@This(), tokens: []const u64, lit_codes: []const u16, lit_lengths: []const u8, dist_codes: []const u16, dist_lengths: []const u8) std.Io.Writer.Error!void {
            for (tokens) |token| {
                if (token & token_literal != 0) {
                    const symbol: usize = token & 0xFF;
                    try c.writeBits(lit_codes[symbol], lit_lengths[symbol]);
                } else {
                    const length = ((token >> 16) & 0xFFFF) + min_match;
                    const distance = (token & 0xFFFF) + 1;
                    const li = lengthIndexFor(length);
                    const di = distIndexFor(distance);
                    try c.writeBits(lit_codes[257 + @as(usize, li)], lit_lengths[257 + @as(usize, li)]);
                    try c.writeBits(@intCast(length - config.length_base[li]), config.length_extra[li]);
                    try c.writeBits(dist_codes[di], dist_lengths[di]);
                    try c.writeBits(@intCast(distance - config.dist_base[di]), config.dist_extra[di]);
                }
            }
            try c.writeBits(lit_codes[256], lit_lengths[256]);
        }

        fn writeBits(c: *@This(), value: u32, count: u8) std.Io.Writer.Error!void {
            c.bits |= @as(u64, value) << @intCast(c.bit_count);
            c.bit_count += @intCast(count);
            if (c.bit_count < 8) return;
            if (c.staging_len + 8 > staging_size) try c.flushStaging();
            // Wide store covers pending bytes; tail bytes are overwritten next call.
            std.mem.writeInt(u64, c.staging[c.staging_len..][0..8], c.bits, .little);
            const written: u7 = c.bit_count >> 3;
            c.staging_len += written;
            c.bits >>= @intCast(written * 8);
            c.bit_count &= 7;
        }

        fn flushStaging(c: *@This()) std.Io.Writer.Error!void {
            if (c.staging_len == 0) return;
            c.downstream.writeAll(c.staging[0..c.staging_len]) catch {
                c.failed = true;
                return error.WriteFailed;
            };
            c.staging_len = 0;
        }
    };
}

pub const Compress = CompressOf(.deflate);
pub const Compress64 = CompressOf(.deflate64);
const Match = struct { length: usize, distance: u32 };

fn hash4(bytes: []const u8) u32 {
    const word = @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 24);
    var h = word *% 0x9E37_79B1;
    h ^= h >> 16;
    return h & (hash_size - 1);
}

fn hash3(bytes: []const u8) u32 {
    const word = @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16);
    var h = word *% 0x9E37_79B1;
    h ^= h >> 16;
    return h & (hash3_size - 1);
}

// Keep ascending order with nearer distance on ties; over capacity keep ends for cheap shorts and coverage.
fn mergeCandidates(output: []u32, chain: []const u32, side_length: usize, side_distance: u32) u8 {
    if (side_length < min_match) {
        @memcpy(output[0..chain.len], chain);
        return @intCast(chain.len);
    }
    var buffer: [optimal_stride + 1]u32 = undefined;
    var count: usize = 0;
    var side_taken = false;
    for (chain) |entry| {
        const entry_length: usize = @as(usize, entry >> 16) + 1;
        if (!side_taken and side_length <= entry_length) {
            side_taken = true;
            if (side_length == entry_length) {
                const entry_distance = (entry & 0xFFFF) + 1;
                buffer[count] = (@as(u32, @intCast(entry_length - 1)) << 16) | (@min(side_distance, entry_distance) - 1);
                count += 1;
                continue;
            }
            buffer[count] = (@as(u32, @intCast(side_length - 1)) << 16) | (side_distance - 1);
            count += 1;
        }
        buffer[count] = entry;
        count += 1;
    }
    if (!side_taken) {
        buffer[count] = (@as(u32, @intCast(side_length - 1)) << 16) | (side_distance - 1);
        count += 1;
    }
    if (count > optimal_stride) {
        @memcpy(output, buffer[0 .. optimal_stride - 1]);
        output[optimal_stride - 1] = buffer[count - 1];
        return optimal_stride;
    }
    @memcpy(output[0..count], buffer[0..count]);
    return @intCast(count);
}

inline fn matchLength(history: []const u8, at: usize, s: usize, available: usize) usize {
    var length: usize = 0;
    if (builtin.target.cpu.arch.endian() == .little) {
        while (length + 8 <= available) {
            const back = std.mem.readInt(u64, history[at + length ..][0..8], .little);
            const front = std.mem.readInt(u64, history[s + length ..][0..8], .little);
            if (back != front) return length + (@ctz(back ^ front) >> 3);
            length += 8;
        }
    }
    while (length < available and history[at + length] == history[s + length]) length += 1;
    return length;
}

// Local bit buffer keeps the hot loop in registers.
const SliceBits = struct {
    data: []const u8,
    pos: usize,
    bits: u64,
    count: u7,

    inline fn refill(b: *SliceBits, need: u7) void {
        while (b.count < need) {
            if (b.pos + 8 <= b.data.len) {
                const word = std.mem.readInt(u64, b.data[b.pos..][0..8], .little);
                const advance: u7 = @min((64 - b.count) >> 3, 8);
                const mask = ~@as(u64, 0) >> @intCast(64 - @as(u8, advance) * 8);
                b.bits |= (word & mask) << @intCast(b.count);
                b.pos += advance;
                b.count += advance * 8;
            } else if (b.pos < b.data.len and b.count <= 56) {
                b.bits |= @as(u64, b.data[b.pos]) << @intCast(b.count);
                b.count += 8;
                b.pos += 1;
            } else return;
        }
    }

    inline fn take(b: *SliceBits, n: u7) InflateError!u32 {
        if (n == 0) return 0;
        b.refill(n);
        if (b.count < n) return error.Truncated;
        const value: u32 = @truncate(b.bits & ((@as(u64, 1) << @intCast(n)) - 1));
        b.bits >>= @intCast(n);
        b.count -= n;
        return value;
    }

    inline fn decode(b: *SliceBits, tree: anytype, root_bits: u7) InflateError!u16 {
        b.refill(max_code_bits);
        // Zero-padded tail is exact via tiled tables; fail only past real buffered bits.
        const entry = tree.root[@intCast(b.bits & ((@as(u64, 1) << @intCast(root_bits)) - 1))];
        if (entry == 0) return error.InvalidData;
        const len: u7 = @intCast(entry & 0xFF);
        if (len != 0) {
            if (len > b.count) return error.Truncated;
            b.bits >>= @intCast(len);
            b.count -= len;
            return @intCast(entry >> 16);
        }
        const sub_bits: u7 = @intCast((entry >> 8) & 0xFF);
        const sub_entry = tree.sub[@intCast((entry >> 16) + ((b.bits >> @intCast(root_bits)) & ((@as(u64, 1) << @intCast(sub_bits)) - 1)))];
        const sub_len: u7 = @intCast(sub_entry & 0xFF);
        const consumed = @as(u7, root_bits) + sub_len;
        if (consumed > b.count) return error.Truncated;
        b.bits >>= @intCast(consumed);
        b.count -= consumed;
        return @intCast(sub_entry >> 16);
    }
};

// Short copies dominate, so inline ladders avoid per-call memcpy overhead.
inline fn copyMatchBuf(buf: []u8, end: usize, distance: u32, length: u32) usize {
    const len: usize = length;
    if (comptime vector_match_copy) {
        if (len <= 512) {
            return kernels.copyMatchCore(.{
                .Ret = usize,
                .short_one = .byte_widen,
            }, buf, end, distance, len);
        }
    }

    const src = end - distance;
    var rest = len;
    if (distance >= rest) {
        @memcpy(buf[end..][0..rest], buf[src..][0..rest]);
        return end + rest;
    }

    if (distance == 1) {
        @memset(buf[end..][0..rest], buf[src]);
        return end + rest;
    }

    var out = end;
    if (distance <= 16) {
        var pat: [16]u8 = undefined;
        @memcpy(pat[0..distance], buf[src..][0..distance]);
        while (rest >= distance) {
            @memcpy(buf[out..][0..distance], pat[0..distance]);
            out += distance;
            rest -= distance;
        }
        if (rest > 0) {
            @memcpy(buf[out..][0..rest], pat[0..rest]);
            out += rest;
        }
        return out;
    }

    var covered: usize = distance;
    while (rest > 0) {
        const chunk = @min(covered, rest);
        @memcpy(buf[out..][0..chunk], buf[out - covered ..][0..chunk]);
        out += chunk;
        rest -= chunk;
        covered += chunk;
    }
    return out;
}

// Mirrors emitBlock's header cost so frozen prices carry the same per-token overhead.
fn dynamicHeaderBits(lit_lengths: []const u8, dist_lengths: []const u8) u64 {
    var hlit: usize = lit_alphabet;
    while (hlit > 257 and lit_lengths[hlit - 1] == 0) hlit -= 1;
    var hdist: usize = dist_alphabet;
    while (hdist > 1 and dist_lengths[hdist - 1] == 0) hdist -= 1;
    var combined: [lit_alphabet + dist_alphabet]u8 = undefined;
    @memcpy(combined[0..hlit], lit_lengths[0..hlit]);
    @memcpy(combined[hlit..][0..hdist], dist_lengths[0..hdist]);
    var rle_symbol: [combined.len]u8 = undefined;
    var rle_value: [combined.len]u8 = undefined;
    var cl_freq: [cl_alphabet]u32 = @splat(0);
    var cl_extra: u64 = 0;
    _ = runLengthEncode(combined[0 .. hlit + hdist], &rle_symbol, &rle_value, &cl_freq, &cl_extra);
    var cl_lengths: [cl_alphabet]u8 = undefined;
    huffman.limitedLengths(&cl_freq, &cl_lengths, 7);
    completeTree(&cl_freq, &cl_lengths);
    var hclen: usize = cl_alphabet;
    while (hclen > 4 and cl_lengths[codegen_order[hclen - 1]] == 0) hclen -= 1;
    var bits: u64 = 3 + 14 + 3 * hclen + cl_extra;
    for (0..cl_alphabet) |symbol| bits += cl_freq[symbol] * cl_lengths[symbol];
    return bits;
}

fn runLengthEncode(lengths: []const u8, symbols: []u8, values: []u8, cl_freq: *[cl_alphabet]u32, cl_extra: *u64) usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < lengths.len) {
        const value = lengths[i];
        var run: usize = 1;
        while (i + run < lengths.len and lengths[i + run] == value) run += 1;
        i += run;
        if (value == 0) {
            while (run >= 11) {
                const n = @min(run, 138);
                symbols[count] = 18;
                values[count] = @intCast(n - 11);
                cl_freq[18] += 1;
                cl_extra.* += 7;
                count += 1;
                run -= n;
            }
            if (run >= 3) {
                symbols[count] = 17;
                values[count] = @intCast(run - 3);
                cl_freq[17] += 1;
                cl_extra.* += 3;
                count += 1;
                run = 0;
            }
            for (0..run) |_| {
                symbols[count] = 0;
                cl_freq[0] += 1;
                count += 1;
            }
        } else {
            symbols[count] = value;
            cl_freq[value] += 1;
            count += 1;
            run -= 1;
            while (run >= 3) {
                const n = @min(run, 6);
                symbols[count] = 16;
                values[count] = @intCast(n - 3);
                cl_freq[16] += 1;
                cl_extra.* += 2;
                count += 1;
                run -= n;
            }
            for (0..run) |_| {
                symbols[count] = value;
                cl_freq[value] += 1;
                count += 1;
            }
        }
    }
    return count;
}

const InflateError = error{ InvalidData, Truncated, ReadFailed };

pub fn DecompressOf(comptime variant: enum { deflate, deflate64 }) type {
    return struct {
        const InflateConfig = struct {
            window_size: usize,
            max_match: usize,
            dist_max: u16,
            hdist_max: u16,
            length_base: []const u16,
            length_extra: []const u5,
            dist_base: []const u16,
            dist_extra: []const u5,
            length_info: []const u32,
            dist_info: []const u32,
        };

        const config: InflateConfig = switch (variant) {
            .deflate => .{ .window_size = 32768, .max_match = 258, .dist_max = 29, .hdist_max = 30, .length_base = &length_base, .length_extra = &length_extra, .dist_base = &dist_base, .dist_extra = &dist_extra, .length_info = &length_info, .dist_info = &dist_info },
            .deflate64 => .{ .window_size = deflate64_window_size, .max_match = deflate64_max_match, .dist_max = 31, .hdist_max = 32, .length_base = &deflate64_length_base, .length_extra = &deflate64_length_extra, .dist_base = &deflate64_dist_base, .dist_extra = &deflate64_dist_extra, .length_info = &deflate64_length_info, .dist_info = &deflate64_dist_info },
        };

        reader: std.Io.Reader,
        input: Input,
        bits: u64,
        bit_count: u7,
        state: State,
        final: bool,
        fixed: bool,
        stored_remaining: u16,
        lit: Tree(10, 9216),
        distance_tree: Tree(8, 4096),
        failed: bool,

        const State = enum { header, stored_copy, tables, data, end };

        const Input = union(enum) {
            reader: *std.Io.Reader,
            slice: struct { data: []const u8, pos: usize },
        };

        pub fn init(input: *std.Io.Reader, history: []u8) @This() {
            std.debug.assert(history.len >= config.window_size + config.max_match + 1);
            // Rebuilt per block before any decode, so `undefined` is safe.
            return .{
                .reader = .{ .buffer = history, .seek = 0, .end = 0, .vtable = &.{ .stream = stream, .discard = discard, .rebase = readerRebase } },
                .input = .{ .reader = input },
                .bits = 0,
                .bit_count = 0,
                .state = .header,
                .final = false,
                .fixed = false,
                .stored_remaining = 0,
                .lit = undefined,
                .distance_tree = undefined,
                .failed = false,
            };
        }

        pub fn initSlice(data: []const u8, history: []u8) @This() {
            std.debug.assert(history.len >= config.window_size + config.max_match + 1);
            // Rebuilt per block before any decode, so `undefined` is safe.
            return .{
                .reader = .{ .buffer = history, .seek = 0, .end = 0, .vtable = &.{ .stream = stream, .discard = discard, .rebase = readerRebase } },
                .input = .{ .slice = .{ .data = data, .pos = 0 } },
                .bits = 0,
                .bit_count = 0,
                .state = .header,
                .final = false,
                .fixed = false,
                .stored_remaining = 0,
                .lit = undefined,
                .distance_tree = undefined,
                .failed = false,
            };
        }

        pub fn inputBitsConsumed(self: *const @This()) usize {
            // Whole-byte pulls leave unconsumed bits; subtract for the logical position.
            return switch (self.input) {
                .reader => |r| r.seek * 8 - self.bit_count,
                .slice => |s| s.pos * 8 - self.bit_count,
            };
        }

        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const decompressor: *@This() = @alignCast(@fieldParentPtr("reader", r));
            if (decompressor.failed) return error.ReadFailed;
            var remaining: usize = @intFromEnum(limit);
            var produced: usize = 0;
            while (remaining > 0) {
                if (decompressor.state == .end) break;
                if (r.end + config.max_match > r.buffer.len) {
                    const keep = @min(config.window_size, r.end);
                    const flush_to = r.end - keep;
                    if (flush_to > r.seek) {
                        const count = @min(flush_to - r.seek, remaining);
                        w.writeAll(r.buffer[r.seek..][0..count]) catch return error.WriteFailed;
                        r.seek += count;
                        remaining -= count;
                        produced += count;
                        if (r.seek < flush_to) break;
                    }
                    @memmove(r.buffer[0..keep], r.buffer[flush_to..r.end]);
                    r.end = keep;
                    r.seek = 0;
                }
                if (r.end == r.buffer.len) break;
                decompressor.step() catch {
                    decompressor.failed = true;
                    return error.ReadFailed;
                };
            }
            if (decompressor.state == .end and r.seek < r.end) {
                const count = @min(r.end - r.seek, remaining);
                if (count > 0) {
                    w.writeAll(r.buffer[r.seek..][0..count]) catch return error.WriteFailed;
                    r.seek += count;
                    remaining -= count;
                    produced += count;
                }
            }
            if (produced == 0 and decompressor.state == .end) return error.EndOfStream;
            return produced;
        }

        fn discard(r: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
            var sink_buffer: [0]u8 = .{};
            var discarding: std.Io.Writer.Discarding = .init(&sink_buffer);
            return stream(r, &discarding.writer, limit) catch |failure| switch (failure) {
                error.WriteFailed => unreachable,
                else => |other_failure| return other_failure,
            };
        }

        fn readerRebase(r: *std.Io.Reader, capacity: usize) std.Io.Reader.RebaseError!void {
            const keep_floor = @min(config.window_size, r.end);
            const discard_n = @min(r.seek, r.end - keep_floor);
            const kept = r.end - discard_n;
            @memmove(r.buffer[0..kept], r.buffer[discard_n..r.end]);
            r.end = kept;
            r.seek -= discard_n;
            if (capacity > r.buffer.len - r.end) return error.EndOfStream;
        }

        fn step(d: *@This()) InflateError!void {
            switch (d.state) {
                .header => try d.readHeader(),
                .tables => try d.readTables(),
                .data => try d.decodeData(),
                .stored_copy => try d.copyStored(),
                .end => {},
            }
        }

        fn readHeader(d: *@This()) InflateError!void {
            d.final = try d.take(1) != 0;
            switch (try d.take(2)) {
                0 => {
                    const pad = d.bit_count % 8;
                    _ = try d.take(pad);
                    const len = try d.take(16);
                    const nlen = try d.take(16);
                    if (len + nlen != 0xFFFF) return error.InvalidData;
                    d.stored_remaining = @intCast(len);
                    d.state = .stored_copy;
                },
                1 => {
                    // Point at comptime tables; dynamic trees stay for the next dynamic block.
                    d.fixed = true;
                    d.state = .data;
                },
                2 => d.state = .tables,
                else => return error.InvalidData,
            }
        }

        fn readTables(d: *@This()) InflateError!void {
            const hlit = (try d.take(5)) + 257;
            if (hlit > 286) return error.InvalidData;
            const hdist = (try d.take(5)) + 1;
            if (hdist > config.hdist_max) return error.InvalidData;
            const hclen = (try d.take(4)) + 4;
            var cl_lengths: [cl_alphabet]u8 = @splat(0);
            for (0..hclen) |i| cl_lengths[codegen_order[i]] = @intCast(try d.take(3));
            // Filled before any decode, so `undefined` is safe.
            var cl_tree: Tree(7, 1) = undefined;
            try buildTree(&cl_lengths, &cl_tree, 7, false, false);
            // Sized for the largest legal hlit+hdist (deflate64 allows hdist 32).
            var lengths: [286 + 32]u8 = undefined;
            const total = hlit + hdist;
            var i: usize = 0;
            while (i < total) {
                const symbol = try d.decode(&cl_tree);
                if (symbol < 16) {
                    lengths[i] = @intCast(symbol);
                    i += 1;
                    continue;
                }
                const repeat = switch (symbol) {
                    16 => 3 + (try d.take(2)),
                    17 => 3 + (try d.take(3)),
                    else => 11 + (try d.take(7)),
                };
                if (symbol == 16 and i == 0) return error.InvalidData;
                if (i + repeat > total) return error.InvalidData;
                const fill: u8 = if (symbol == 16) lengths[i - 1] else 0;
                for (0..repeat) |_| {
                    lengths[i] = fill;
                    i += 1;
                }
            }
            try buildTree(lengths[0..hlit], &d.lit, 10, true, false);
            try buildTree(lengths[hlit..total], &d.distance_tree, 8, true, true);
            d.fixed = false;
            d.state = .data;
        }

        fn decodeData(d: *@This()) InflateError!void {
            const r = &d.reader;
            const lit = if (d.fixed) &fixed_lit_tree else &d.lit;
            const distance_tree = if (d.fixed) &fixed_dist_tree else &d.distance_tree;
            if (d.input == .slice) return d.decodeDataSlice(lit, distance_tree);
            while (r.end + config.max_match <= r.buffer.len) {
                const symbol = try d.decode(lit);
                if (symbol < 256) {
                    r.buffer[r.end] = @intCast(symbol);
                    r.end += 1;
                    continue;
                }
                if (symbol == 256) {
                    d.state = if (d.final) .end else .header;
                    return;
                }
                if (symbol > 285) return error.InvalidData;
                const li = symbol - 257;
                const length = config.length_base[li] + try d.take(config.length_extra[li]);
                const dsym = try d.decode(distance_tree);
                if (dsym > config.dist_max) return error.InvalidData;
                const distance = config.dist_base[dsym] + try d.take(config.dist_extra[dsym]);
                if (distance > r.end) return error.InvalidData;
                r.end = copyMatchBuf(r.buffer, r.end, distance, length);
            }
        }

        // Locals keep per-symbol work in registers; state writes back on exit.
        fn decodeDataSlice(d: *@This(), lit: anytype, distance_tree: anytype) InflateError!void {
            const r = &d.reader;
            if (lit.empty) return error.InvalidData;
            var b: SliceBits = .{ .data = d.input.slice.data, .pos = d.input.slice.pos, .bits = d.bits, .count = d.bit_count };
            var end = r.end;
            const buf = r.buffer;
            const lit_root_bits = lit.root_bits;
            const distance_root_bits = distance_tree.root_bits;
            defer {
                d.input.slice.pos = b.pos;
                d.bits = b.bits;
                d.bit_count = b.count;
                r.end = end;
            }
            while (end + config.max_match <= buf.len) {
                const symbol = try b.decode(lit, lit_root_bits);
                if (symbol < 256) {
                    buf[end] = @intCast(symbol);
                    end += 1;
                    continue;
                }
                if (symbol == 256) {
                    d.state = if (d.final) .end else .header;
                    return;
                }
                if (symbol > 285) return error.InvalidData;
                const linfo = config.length_info[symbol - 257];
                const length = (linfo & 0xFFFF) + try b.take(@intCast(linfo >> 16));
                if (distance_tree.empty) return error.InvalidData;
                const dsym = try b.decode(distance_tree, distance_root_bits);
                if (dsym > config.dist_max) return error.InvalidData;
                const dinfo = config.dist_info[dsym];
                const distance = (dinfo & 0xFFFF) + try b.take(@intCast(dinfo >> 16));
                if (distance > end) return error.InvalidData;
                end = copyMatchBuf(buf, end, distance, length);
            }
        }

        fn copyStored(d: *@This()) InflateError!void {
            const r = &d.reader;
            while (d.stored_remaining != 0) {
                if (r.end == r.buffer.len) return;
                if (d.bit_count >= 8) {
                    r.buffer[r.end] = @intCast(try d.take(8));
                    r.end += 1;
                    d.stored_remaining -= 1;
                    continue;
                }
                const available = switch (d.input) {
                    .reader => |rd| rd.peekGreedy(1) catch |err| switch (err) {
                        error.EndOfStream => return error.Truncated,
                        error.ReadFailed => return error.ReadFailed,
                    },
                    .slice => |*s| blk: {
                        if (s.pos >= s.data.len) return error.Truncated;
                        break :blk s.data[s.pos..];
                    },
                };
                const count = @min(@min(available.len, d.stored_remaining), r.buffer.len - r.end);
                @memcpy(r.buffer[r.end..][0..count], available[0..count]);
                switch (d.input) {
                    .reader => |rd| rd.seek += count,
                    .slice => |*s| s.pos += count,
                }
                r.end += count;
                d.stored_remaining -= @intCast(count);
            }
            if (d.stored_remaining == 0) d.state = if (d.final) .end else .header;
        }

        inline fn refill(d: *@This(), need: u7) InflateError!void {
            while (d.bit_count < need) {
                const before = d.bit_count;
                try d.refillOnce();
                if (d.bit_count == before) return;
            }
        }

        inline fn refillOnce(d: *@This()) InflateError!void {
            switch (d.input) {
                .reader => |rd| {
                    const space = 64 - d.bit_count;
                    if (space < 8) return;
                    const available = rd.peekGreedy(1) catch |err| switch (err) {
                        error.EndOfStream => return,
                        error.ReadFailed => return error.ReadFailed,
                    };
                    const want_bytes = @min(@as(usize, space >> 3), available.len);
                    if (want_bytes == 0) return;
                    var i: usize = 0;
                    while (i < want_bytes) : (i += 1) {
                        d.bits |= @as(u64, available[i]) << @intCast(d.bit_count);
                        d.bit_count += 8;
                    }
                    rd.seek += want_bytes;
                },
                .slice => |*s| {
                    // Mask the wide load to consumed bytes so upper bits stay zero; drain tail byte-wise.
                    if (s.pos + 8 <= s.data.len) {
                        const word = std.mem.readInt(u64, s.data[s.pos..][0..8], .little);
                        const advance: u7 = @min((64 - d.bit_count) >> 3, 8);
                        const mask = ~@as(u64, 0) >> @intCast(64 - @as(u8, advance) * 8);
                        d.bits |= (word & mask) << @intCast(d.bit_count);
                        s.pos += advance;
                        d.bit_count += advance * 8;
                        return;
                    }
                    while (d.bit_count <= 56 and s.pos < s.data.len) {
                        d.bits |= @as(u64, s.data[s.pos]) << @intCast(d.bit_count);
                        d.bit_count += 8;
                        s.pos += 1;
                    }
                },
            }
        }

        inline fn take(d: *@This(), count: u7) InflateError!u32 {
            if (count == 0) return 0;
            try d.refill(count);
            if (d.bit_count < count) return error.Truncated;
            const value: u32 = @truncate(d.bits & ((@as(u64, 1) << @intCast(count)) - 1));
            d.bits >>= @intCast(count);
            d.bit_count -= count;
            return value;
        }

        inline fn decode(d: *@This(), tree: anytype) InflateError!u16 {
            if (tree.empty) return error.InvalidData;
            // One refill covers the longest code in the common case.
            try d.refill(max_code_bits);
            const root_bits = tree.root_bits;
            // Zero-padded tail is exact via tiled tables; fail only past real buffered bits.
            const entry = tree.root[@intCast(d.bits & ((@as(u64, 1) << @intCast(root_bits)) - 1))];
            if (entry == 0) return error.InvalidData;
            const len: u7 = @intCast(entry & 0xFF);
            if (len != 0) {
                if (len > d.bit_count) return error.Truncated;
                d.bits >>= @intCast(len);
                d.bit_count -= len;
                return @intCast(entry >> 16);
            }
            const sub_bits: u7 = @intCast((entry >> 8) & 0xFF);
            const sub_entry = tree.sub[@intCast((entry >> 16) + ((d.bits >> @intCast(root_bits)) & ((@as(u64, 1) << @intCast(sub_bits)) - 1)))];
            const sub_len: u7 = @intCast(sub_entry & 0xFF);
            const consumed = @as(u7, root_bits) + sub_len;
            if (consumed > d.bit_count) return error.Truncated;
            d.bits >>= @intCast(consumed);
            d.bit_count -= consumed;
            return @intCast(sub_entry >> 16);
        }
    };
}

pub const Decompress = DecompressOf(.deflate);
pub const Decompress64 = DecompressOf(.deflate64);
const fixed_lit_tree = buildTreeValue(10, 9216, &fixed_lit_lengths, false, false) catch @compileError("The fixed literal table failed to build.");
const fixed_dist_tree = buildTreeValue(8, 4096, &fixed_dist_lengths, false, false) catch @compileError("The fixed distance table failed to build.");

fn buildTreeValue(comptime max_root_bits: u5, comptime max_sub: usize, lengths: []const u8, allow_single: bool, allow_empty: bool) error{InvalidData}!Tree(max_root_bits, max_sub) {
    @setEvalBranchQuota(1_000_000);
    // Filled before the caller reads it, so `undefined` is safe.
    var tree: Tree(max_root_bits, max_sub) = undefined;
    try buildTree(lengths, &tree, max_root_bits, allow_single, allow_empty);
    return tree;
}
