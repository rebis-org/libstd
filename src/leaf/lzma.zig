const std = @import("std");

const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");
const kernels = @import("kernels.zig");

pub const dictionary_min = 1 << 12;
pub const dictionary_max = 1 << 30; // 1 GiB for 64-bit workspace sizing.

pub const Properties = struct {
    lc: u4,
    lp: u4,
    pb: u4,
    dictionary_size: u32,

    pub fn encode(self: Properties) u8 {
        return @intCast((@as(u32, self.pb) * 5 + self.lp) * 9 + self.lc);
    }

    pub fn decode(byte: u8, dictionary_size: u32) Failure!Properties {
        if (byte >= 9 * 5 * 5) return error.InvalidData;
        const lc: u4 = @intCast(byte % 9);
        const d = byte / 9;
        const pb: u4 = @intCast(d / 5);
        const lp: u4 = @intCast(d % 5);
        return .{
            .lc = lc,
            .lp = lp,
            .pb = pb,
            .dictionary_size = dictionary_size,
        };
    }

    pub fn literalContextCount(self: Properties) usize {
        return @as(usize, 1) << @intCast(self.lp + self.lc);
    }
};

pub const Options = struct {
    properties: Properties,
    unpack_size: ?u64 = null,
    marker_required: bool = false,
    max_work: u64 = std.math.maxInt(u64),
    match_finder_depth: u32 = 32,
    lazy: bool = false,
    nice_len: u32 = 273,
    match_finder: MatchFinder = .bt4,
};

pub const MatchFinder = enum { hash_chain, bt4 };

const Prob = u16;
const prob_init: Prob = 1 << 10;
const prob_total_bits = 11;
const prob_move_bits = 5;
const top_value = 1 << 24;
const num_states = 12;
const num_pos_bits_max = 4;
const num_len_to_pos_states = 4;
const match_min_len = 2;

// Match finders (reference-style): a 4-byte hash table (head) whose buckets
// drive either a position chain (hash_chain) or a content-ordered binary tree
// over the cyclic slot pairs (bt4). Both walks are bounded by a fixed depth
// cap so per-position work is O(depth) instead of O(dictionary_size), which
// is what keeps encoding of large inputs near-linear rather than the earlier
// brute-force O(n * dict) scan.
const match_finder_hash_min_bits: u5 = 12;
const match_finder_hash_max_bits: u5 = 20;
// Side tables for short matches: a 4-byte hash can never pair positions whose
// fourth byte differs, so 2- and 3-byte matches need their own indices (the
// reference bt4 carries the same hash2/hash3 side tables).
const match_finder_hash2_bits: u5 = 16;
const match_finder_hash3_bits: u5 = 17;
const end_pos_model_index = 14;
const num_full_distances = 1 << (end_pos_model_index >> 1);
const num_align_bits = 4;
const align_size = 1 << num_align_bits;
const is_match_count = num_states << num_pos_bits_max;
const is_rep0_long_count = num_states << num_pos_bits_max;
const pos_slot_decoder_count = num_len_to_pos_states;
const pos_decoders_count = 1 + num_full_distances - end_pos_model_index;
const low_coder_count = 1 << num_pos_bits_max;
const mid_coder_count = 1 << num_pos_bits_max;
const literal_probs_count = 0x300;

// No copy fallback exists, so the bound rests on the probability model: the
// >>prob_move_bits update keeps every probability inside [32, 2016] of 2048,
// so a single bit decision never exceeds 6 bits and a converged context costs
// ~1 bit; a literal byte costs the is-match decision plus 8 tree decisions.
// 5/4 (= 10 bits per byte) covers the sustained converged cost (~9 bits per
// literal byte) plus transient model wrongness; the constant absorbs the
// range-coder cache byte, the 5-byte flush, and the end marker. Verified
// against corpus and pathological inputs by the oracle suite; the strict
// per-decision clamp bound would be ~7x and useless as a planning size.
pub fn encodedSizeBound(input_len: usize) usize {
    return input_len +| (input_len / 4) +| 64;
}

// Fixed-point bit-price table used by the encoder's parser.  One bit costs
// price_scale units; the table is indexed by probability >> 4 so it holds
// 128 entries covering the full 11-bit probability range.
const price_scale_shift = 10;
const price_scale = 1 << price_scale_shift;
const kBitPrice = blk: {
    @setEvalBranchQuota(10000);
    var table: [128]u16 = undefined;
    for (0..128) |i| {
        var p = (i << 4) + 8;
        if (p > 2047) p = 2047;
        const f = @log2(2048.0 / @as(f64, p));
        table[i] = @intFromFloat(@round(f * price_scale));
    }
    break :blk table;
};

// Optimal-parsing window: the encoder plans up to opt_window positions ahead
// against the frozen probability model, then emits the cheapest decision
// sequence. 8192 measured best on the corpus: smaller windows cut long-range
// decisions at the boundary, larger windows let the frozen prices go stale on
// evolving distributions before the next rebuild.
const max_match_len = 273;
const opt_window = 8192;

const back_literal: u32 = 0xFFFFFFFF;
const back_short_rep: u32 = 0xFFFFFFFE;
const back_rep_base: u32 = 0xF0000000; // | rep index; dist-1 never reaches 2^30.

const Opt = struct {
    price: u32,
    pos_prev: u16,
    back: u32,
    state: u8,
    backs: [4]u32,
};

const Decision = struct { back: u32, len: u32 };

// One improving match candidate from the finder: strictly increasing lengths,
// dist is 1-based (a stored dist of 1 means the previous byte).
const MatchPair = struct { len: u16, dist: u32 };
const match_list_max = 64;

// Per-window bit prices derived from the frozen probability model. Indexed by
// the same shapes the encoder tables use so the planner never touches Prob
// state directly.
const PriceTables = struct {
    is_match: [is_match_count][2]u32,
    is_rep: [num_states][2]u32,
    is_rep_g0: [num_states][2]u32,
    is_rep_g1: [num_states][2]u32,
    is_rep_g2: [num_states][2]u32,
    is_rep0_long: [is_rep0_long_count][2]u32,
    len: [low_coder_count][max_match_len + 1]u32,
    rep_len: [low_coder_count][max_match_len + 1]u32,
    slot: [num_len_to_pos_states][64]u32,
    dist: [num_len_to_pos_states][num_full_distances]u32,
    align_prices: [align_size]u32,
};

// The probability tables are a single layout shared by sizing, both init
// paths, and reset; the field order here is the workspace order.
const ProbTables = struct {
    literal_probs: []Prob,
    is_match: []Prob,
    is_rep: []Prob,
    is_rep_g0: []Prob,
    is_rep_g1: []Prob,
    is_rep_g2: []Prob,
    is_rep0_long: []Prob,
    pos_slot_decoders: []Prob,
    pos_decoders: []Prob,
    align_decoder: []Prob,
    len_choice: []Prob,
    len_low: []Prob,
    len_mid: []Prob,
    len_high: []Prob,
    rep_len_choice: []Prob,
    rep_len_low: []Prob,
    rep_len_mid: []Prob,
    rep_len_high: []Prob,
};

fn probCount(comptime name: []const u8, properties: Properties) usize {
    if (std.mem.eql(u8, name, "literal_probs")) return literal_probs_count * properties.literalContextCount();
    if (std.mem.eql(u8, name, "is_match")) return is_match_count;
    if (std.mem.eql(u8, name, "is_rep")) return num_states;
    if (std.mem.eql(u8, name, "is_rep_g0")) return num_states;
    if (std.mem.eql(u8, name, "is_rep_g1")) return num_states;
    if (std.mem.eql(u8, name, "is_rep_g2")) return num_states;
    if (std.mem.eql(u8, name, "is_rep0_long")) return is_rep0_long_count;
    if (std.mem.eql(u8, name, "pos_slot_decoders")) return pos_slot_decoder_count * (1 << 6);
    if (std.mem.eql(u8, name, "pos_decoders")) return pos_decoders_count;
    if (std.mem.eql(u8, name, "align_decoder")) return align_size;
    if (std.mem.eql(u8, name, "len_choice")) return 2;
    if (std.mem.eql(u8, name, "len_low")) return low_coder_count * (1 << 3);
    if (std.mem.eql(u8, name, "len_mid")) return mid_coder_count * (1 << 3);
    if (std.mem.eql(u8, name, "len_high")) return 1 << 8;
    if (std.mem.eql(u8, name, "rep_len_choice")) return 2;
    if (std.mem.eql(u8, name, "rep_len_low")) return low_coder_count * (1 << 3);
    if (std.mem.eql(u8, name, "rep_len_mid")) return mid_coder_count * (1 << 3);
    if (std.mem.eql(u8, name, "rep_len_high")) return 1 << 8;
    unreachable;
}

pub fn modelProbCount(properties: Properties) usize {
    var total: usize = 0;
    inline for (std.meta.fields(ProbTables)) |field| {
        total += probCount(field.name, properties);
    }
    return total;
}

pub fn modelSize(properties: Properties) usize {
    return modelProbCount(properties) * @sizeOf(Prob);
}

fn takeTables(self: anytype, workspace: *io.Workspace, properties: Properties) Failure!void {
    inline for (std.meta.fields(ProbTables)) |field| {
        @field(self, field.name) = try workspace.take(Prob, probCount(field.name, properties));
    }
}

fn planTables(plan: *io.WorkspacePlan, properties: Properties) Failure!void {
    inline for (std.meta.fields(ProbTables)) |field| {
        try plan.take(Prob, probCount(field.name, properties));
    }
}

fn resetTables(self: anytype) void {
    inline for (std.meta.fields(ProbTables)) |field| {
        initProbs(@field(self, field.name));
    }
}

pub fn decodeWorkspaceSize(properties: Properties) usize {
    var plan = io.WorkspacePlan.init(null);
    plan.take(u8, properties.dictionary_size) catch return 0;
    planTables(&plan, properties) catch return 0;
    // Account for worst-case alignment padding when the scratch slice is not
    // ideally aligned for the u16 probability arrays taken by Decoder.init.
    return std.mem.alignForward(usize, plan.required() + (@alignOf(u32) - 1) + (@alignOf(u16) - 1), @alignOf(u64));
}

pub fn decodeInPlaceWorkspaceSize(properties: Properties) usize {
    return std.mem.alignForward(usize, modelSize(properties) + (@alignOf(u32) - 1) + (@alignOf(u16) - 1), @alignOf(u64));
}

fn matchFinderHashBits(dictionary_size: u32) u5 {
    var bits: u5 = 0;
    var size: u32 = dictionary_size;
    while (size > 1) : (size >>= 1) {
        bits += 1;
    }
    // About half as many buckets as window positions, within hard bounds.
    if (bits > 0) bits -= 1;
    if (bits < match_finder_hash_min_bits) bits = match_finder_hash_min_bits;
    if (bits > match_finder_hash_max_bits) bits = match_finder_hash_max_bits;
    return bits;
}

fn matchFinderHashSize(dictionary_size: u32) usize {
    return @as(usize, 1) << matchFinderHashBits(dictionary_size);
}

fn matchFinderChainSize(dictionary_size: u32) usize {
    return @as(usize, dictionary_size) + 1;
}
pub fn encodeWorkspaceSize(properties: Properties) usize {
    return encodeWorkspaceSizeFor(properties, false);
}

pub fn encodeWorkspaceSizeBt(properties: Properties) usize {
    return encodeWorkspaceSizeFor(properties, true);
}

fn encodeWorkspaceSizeFor(properties: Properties, bt: bool) usize {
    var plan = io.WorkspacePlan.init(null);
    plan.take(u8, properties.dictionary_size) catch return 0;
    plan.take(u32, matchFinderChainSize(properties.dictionary_size)) catch return 0;
    if (bt) {
        plan.take(u32, matchFinderChainSize(properties.dictionary_size)) catch return 0;
        plan.take(u32, matchFinderChainSize(properties.dictionary_size)) catch return 0;
    }
    plan.take(u32, matchFinderHashSize(properties.dictionary_size)) catch return 0;
    plan.take(u32, @as(usize, 1) << match_finder_hash2_bits) catch return 0;
    plan.take(u32, @as(usize, 1) << match_finder_hash3_bits) catch return 0;
    planTables(&plan, properties) catch return 0;
    plan.take(Opt, opt_window + 1) catch return 0;
    plan.take(Decision, opt_window) catch return 0;
    plan.take(PriceTables, 1) catch return 0;
    plan.take(u32, properties.literalContextCount() << 8) catch return 0;
    // The plan above is computed from an idealized aligned base. Callers may
    // pass a slice whose base is only partially aligned (LZMA2's per-chunk
    // estimate slice is offset into the main workspace), which adds a few bytes
    // of alignment padding at the u32/u16 boundaries. Reserve the worst case so
    // any caller-provided base alignment works.
    return std.mem.alignForward(usize, plan.required() + (@alignOf(u32) - 1) + (@alignOf(u16) - 1), @alignOf(u64));
}

// Stream-shaped range decoder: reads through a std.Io.Reader or a caller
// slice; per-bit calls can fail mid-symbol. The buffer-to-buffer decode path
// uses RangeDecoderFast instead.
const RangeDecoder = struct {
    const E = Failure;

    input: Input,
    range: u32,
    code: u32,
    corrupted: bool,

    const Input = union(enum) {
        reader: *std.Io.Reader,
        slice: struct { data: []const u8, pos: usize },
    };

    fn init(reader: *std.Io.Reader) Failure!RangeDecoder {
        var self = RangeDecoder{
            .input = .{ .reader = reader },
            .range = 0xFFFFFFFF,
            .code = 0,
            .corrupted = false,
        };
        const first = try self.readByte();
        if (first != 0) return error.InvalidData;
        for (0..4) |_| {
            self.code = (self.code << 8) | try self.readByte();
        }
        if (self.code == self.range) self.corrupted = true;
        return self;
    }

    fn initSlice(data: []const u8) Failure!RangeDecoder {
        var self = RangeDecoder{
            .input = .{ .slice = .{ .data = data, .pos = 0 } },
            .range = 0xFFFFFFFF,
            .code = 0,
            .corrupted = false,
        };
        const first = try self.readByte();
        if (first != 0) return error.InvalidData;
        for (0..4) |_| {
            self.code = (self.code << 8) | try self.readByte();
        }
        if (self.code == self.range) self.corrupted = true;
        return self;
    }

    fn readByte(self: *RangeDecoder) E!u8 {
        return switch (self.input) {
            .reader => |reader| io.readByte(reader),
            .slice => |*s| blk: {
                if (s.pos >= s.data.len) {
                    return error.InvalidData;
                }
                const byte = s.data[s.pos];
                s.pos += 1;
                break :blk byte;
            },
        };
    }

    inline fn normalize(self: *RangeDecoder) E!void {
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | try self.readByte();
        }
    }

    inline fn decodeBit(self: *RangeDecoder, prob: *Prob) E!u1 {
        const p: u32 = prob.*;
        const bound = (self.range >> prob_total_bits) * p;
        // Branchless update: mask is all-ones when the decoded bit is 1.
        // The range identity holds mod 2^32: bound + (range - 2*bound) ==
        // range - bound, and the & 0 case leaves bound.
        const mask: u32 = 0 -% @as(u32, @intFromBool(self.code >= bound));
        self.code -%= bound & mask;
        self.range = bound +% ((self.range -% bound -% bound) & mask);
        const up = (((@as(u32, 1) << prob_total_bits) - p) >> prob_move_bits) & ~mask;
        const down = (p >> prob_move_bits) & mask;
        prob.* = @intCast(p + up - down);
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | try self.readByte();
        }
        return @intCast(mask & 1);
    }

    inline fn decodeDirectBits(self: *RangeDecoder, num_bits: u5) E!u32 {
        var res: u32 = 0;
        var remaining = num_bits;
        while (remaining > 0) {
            if (self.range < top_value) {
                self.range <<= 8;
                self.code = (self.code << 8) | try self.readByte();
            }
            // Direct bits halve range each step. After normalizing,
            // range >= top_value, so we can decode up to
            // 7 - @clz(range) bits while keeping range >= top_value.
            const leading_zeros = @clz(self.range);
            const max_batch: u32 = @max(1, 7 - leading_zeros);
            const batch: u5 = @intCast(@min(@as(u32, remaining), max_batch));
            var i: u5 = 0;
            while (i < batch) : (i += 1) {
                self.range >>= 1;
                self.code -%= self.range;
                const t: u32 = 0 -% (self.code >> 31);
                self.code +%= self.range & t;
                if (self.code == self.range) self.corrupted = true;
                res = (res << 1) +% t +% 1;
            }
            remaining -= batch;
        }
        // Match the per-bit form's final normalization so callers see the
        // same range/code state.
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | try self.readByte();
        }
        return res;
    }

    fn isFinishedOk(self: RangeDecoder) bool {
        return self.code == 0;
    }
};

// Slice-only range decoder used by the buffer-to-buffer decode path. Removing
// the per-bit error union lets the compiler keep the hot decode loop registers
// in fast storage instead of shuffling error-payload state for every symbol.
const RangeDecoderFast = struct {
    input: struct { data: []const u8, pos: usize },
    range: u32,
    code: u32,
    corrupted: bool,

    fn initSlice(data: []const u8) Failure!RangeDecoderFast {
        var self = RangeDecoderFast{
            .input = .{ .data = data, .pos = 0 },
            .range = 0xFFFFFFFF,
            .code = 0,
            .corrupted = false,
        };
        const first = self.readByte();
        if (first != 0) return error.InvalidData;
        for (0..4) |_| {
            self.code = (self.code << 8) | self.readByte();
        }
        if (self.code == self.range) self.corrupted = true;
        return self;
    }

    inline fn readByte(self: *RangeDecoderFast) u8 {
        const s = &self.input;
        if (s.pos >= s.data.len) {
            self.corrupted = true;
            return 0;
        }
        const byte = s.data[s.pos];
        s.pos += 1;
        return byte;
    }

    inline fn normalize(self: *RangeDecoderFast) void {
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | self.readByte();
        }
    }

    inline fn decodeBit(self: *RangeDecoderFast, prob: *Prob) u1 {
        const p: u32 = prob.*;
        const bound = (self.range >> prob_total_bits) * p;
        // Branchless update: mask is all-ones when the decoded bit is 1. The
        // range identity holds mod 2^32: bound + (range - 2*bound) == range -
        // bound, and the & 0 case leaves bound.
        const mask: u32 = 0 -% @as(u32, @intFromBool(self.code >= bound));
        self.code -%= bound & mask;
        self.range = bound +% ((self.range -% bound -% bound) & mask);
        const up = (((@as(u32, 1) << prob_total_bits) - p) >> prob_move_bits) & ~mask;
        const down = (p >> prob_move_bits) & mask;
        prob.* = @intCast(p + up - down);
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | self.readByte();
        }
        return @intCast(mask & 1);
    }

    inline fn decodeDirectBits(self: *RangeDecoderFast, num_bits: u5) u32 {
        var res: u32 = 0;
        var remaining = num_bits;
        while (remaining > 0) {
            if (self.range < top_value) {
                self.range <<= 8;
                self.code = (self.code << 8) | self.readByte();
            }
            const leading_zeros = @clz(self.range);
            const max_batch: u32 = @max(1, 7 - leading_zeros);
            const batch: u5 = @intCast(@min(@as(u32, remaining), max_batch));
            var i: u5 = 0;
            while (i < batch) : (i += 1) {
                self.range >>= 1;
                self.code -%= self.range;
                const t: u32 = 0 -% (self.code >> 31);
                self.code +%= self.range & t;
                if (self.code == self.range) self.corrupted = true;
                res = (res << 1) +% t +% 1;
            }
            remaining -= batch;
        }
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | self.readByte();
        }
        return res;
    }

    fn isFinishedOk(self: RangeDecoderFast) bool {
        return self.code == 0;
    }
};

pub const RangeEncoder = struct {
    writer: *std.Io.Writer,
    range: u32,
    low: u64,
    cache: u8,
    cache_size: u32,

    pub fn init(writer: *std.Io.Writer) RangeEncoder {
        return .{
            .writer = writer,
            .range = 0xFFFFFFFF,
            .low = 0,
            .cache = 0,
            .cache_size = 0,
        };
    }

    fn shiftLow(self: *RangeEncoder) Failure!void {
        const low32: u32 = @intCast(self.low & 0xFFFFFFFF);
        const high: u32 = @intCast(self.low >> 32);
        self.low = @as(u64, std.math.shl(u32, low32, 8));
        if (low32 < 0xFF000000 or high != 0) {
            try io.writeByte(self.writer, self.cache +% @as(u8, @intCast(high)));
            self.cache = @intCast((low32 >> 24) & 0xFF);
            if (self.cache_size == 0) return;
            const fill: u8 = @intCast((high + 0xFF) & 0xFF);
            var remaining = self.cache_size;
            while (remaining > 0) : (remaining -= 1) {
                try io.writeByte(self.writer, fill);
            }
            self.cache_size = 0;
        } else {
            self.cache_size += 1;
        }
    }

    fn normalize(self: *RangeEncoder) Failure!void {
        if (self.range < top_value) {
            self.range <<= 8;
            try self.shiftLow();
        }
    }

    fn encodeBit(self: *RangeEncoder, prob: *Prob, symbol: u1) Failure!void {
        const p: u32 = prob.*;
        const bound = (self.range >> prob_total_bits) * p;
        updateProb(prob, symbol);
        if (symbol == 0) {
            self.range = bound;
        } else {
            self.low += bound;
            self.range -= bound;
        }
        try self.normalize();
    }

    fn encodeDirectBits(self: *RangeEncoder, value: u32, num_bits: u5) Failure!void {
        var remaining = num_bits;
        while (remaining > 0) : (remaining -= 1) {
            self.range >>= 1;
            if (((value >> @intCast(remaining - 1)) & 1) == 1) {
                self.low += self.range;
            }
            try self.normalize();
        }
    }

    pub fn finish(self: *RangeEncoder) Failure!void {
        var i: u32 = 0;
        while (i < 5) : (i += 1) {
            try self.shiftLow();
        }
    }
};

// The adaptive model update every encodeBit shares: RangeEncoder applies it
// while emitting bits, PriceCounter while pricing a parse.
inline fn updateProb(prob: *Prob, symbol: u1) void {
    const p: u32 = prob.*;
    if (symbol == 0) {
        prob.* = @intCast(p + (((@as(u32, 1) << prob_total_bits) - p) >> prob_move_bits));
    } else {
        prob.* = @intCast(p - (p >> prob_move_bits));
    }
}

// RangeEncoder-shaped price accumulator: charges the fixed-point bit price of
// every coded decision against the live model without emitting a bitstream.
const PriceCounter = struct {
    price: u64 = 0,

    inline fn encodeBit(self: *PriceCounter, prob: *Prob, symbol: u1) Failure!void {
        self.price += Encoder.priceBit(prob.*, symbol);
        updateProb(prob, symbol);
    }

    inline fn encodeDirectBits(self: *PriceCounter, value: u32, num_bits: u5) Failure!void {
        _ = value;
        self.price += @as(u64, num_bits) << price_scale_shift;
    }
};

inline fn bitTreeDecode(rc: anytype, probs: []Prob, comptime num_bits: u5) Failure!u32 {
    var m: u32 = 1;
    inline for (0..num_bits) |_| {
        const bit = try rc.decodeBit(&probs[m]);
        m = (m << 1) + bit;
    }
    return m - (@as(u32, 1) << num_bits);
}

inline fn bitTreeReverseDecode(rc: anytype, probs: []Prob, num_bits: u5) Failure!u32 {
    var m: u32 = 1;
    var symbol: u32 = 0;
    var i: u32 = 0;
    while (i < num_bits) : (i += 1) {
        const bit = try rc.decodeBit(&probs[m]);
        m = (m << 1) + bit;
        symbol |= @as(u32, bit) << @intCast(i);
    }
    return symbol;
}

inline fn bitTreeDecodeFast(rc: *RangeDecoderFast, probs: []Prob, comptime num_bits: u5) u32 {
    var m: u32 = 1;
    inline for (0..num_bits) |_| {
        const bit = rc.decodeBit(&probs[m]);
        m = (m << 1) + bit;
    }
    return m - (@as(u32, 1) << num_bits);
}

inline fn bitTreeReverseDecodeFast(rc: *RangeDecoderFast, probs: []Prob, num_bits: u5) u32 {
    var m: u32 = 1;
    var symbol: u32 = 0;
    var i: u32 = 0;
    while (i < num_bits) : (i += 1) {
        const bit = rc.decodeBit(&probs[m]);
        m = (m << 1) + bit;
        symbol |= @as(u32, bit) << @intCast(i);
    }
    return symbol;
}

fn bitTreeEncode(rc: anytype, probs: []Prob, num_bits: u5, symbol: u32) Failure!void {
    var m: u32 = 1;
    var i = num_bits;
    while (i > 0) : (i -= 1) {
        const bit: u1 = @intCast((symbol >> @intCast(i - 1)) & 1);
        try rc.encodeBit(&probs[m], bit);
        m = (m << 1) + bit;
    }
}

fn bitTreeReverseEncode(rc: anytype, probs: []Prob, num_bits: u5, symbol: u32) Failure!void {
    var m: u32 = 1;
    var i: u32 = 0;
    while (i < num_bits) : (i += 1) {
        const bit: u1 = @intCast((symbol >> @intCast(i)) & 1);
        try rc.encodeBit(&probs[m], bit);
        m = (m << 1) + bit;
    }
}

pub fn DecoderOf(comptime slice_input: bool) type {
    const RC = if (slice_input) RangeDecoderFast else RangeDecoder;
    return struct {
        const Self = @This();

        properties: Properties,
        dictionary: []u8,
        dict_pos: u32,
        dict_full: bool,
        // In-place decode only: the dictionary position of the most recent
        // format-level dictionary reset. The output buffer is the dictionary,
        // so a reset cannot rewind the write position; it is a logical floor
        // that distance validation enforces instead.
        dict_floor: u32,
        total_pos: u32,
        rc: RC,
        is_match: []Prob,
        is_rep: []Prob,
        is_rep_g0: []Prob,
        is_rep_g1: []Prob,
        is_rep_g2: []Prob,
        is_rep0_long: []Prob,
        pos_slot_decoders: []Prob,
        pos_decoders: []Prob,
        align_decoder: []Prob,
        len_choice: []Prob,
        len_low: []Prob,
        len_mid: []Prob,
        len_high: []Prob,
        rep_len_choice: []Prob,
        rep_len_low: []Prob,
        rep_len_mid: []Prob,
        rep_len_high: []Prob,
        literal_probs: []Prob,
        rep0: u32,
        rep1: u32,
        rep2: u32,
        rep3: u32,
        state: u32,
        output_buffer: ?[]u8,
        output_pos: usize,
        output_writer: ?*std.Io.Writer,
        out_buf: [4096]u8,
        out_len: usize,
        clear_dictionary: bool,

        pub fn setWriter(self: *Self, writer: *std.Io.Writer) void {
            self.output_writer = writer;
        }

        pub fn setProperties(self: *Self, properties: Properties) void {
            self.properties = properties;
        }

        pub fn initProperties(properties: Properties, scratch: []u8) Failure!Self {
            var workspace = try io.Workspace.init(scratch.ptr, scratch.len);
            const dictionary = try workspace.take(u8, properties.dictionary_size);
            var self = Self{
                .properties = properties,
                .dictionary = dictionary,
                .dict_pos = 0,
                .dict_full = false,
                .dict_floor = 0,
                .total_pos = 0,
                .rc = undefined,
                .is_match = undefined,
                .is_rep = undefined,
                .is_rep_g0 = undefined,
                .is_rep_g1 = undefined,
                .is_rep_g2 = undefined,
                .is_rep0_long = undefined,
                .pos_slot_decoders = undefined,
                .pos_decoders = undefined,
                .align_decoder = undefined,
                .len_choice = undefined,
                .len_low = undefined,
                .len_mid = undefined,
                .len_high = undefined,
                .rep_len_choice = undefined,
                .rep_len_low = undefined,
                .rep_len_mid = undefined,
                .rep_len_high = undefined,
                .literal_probs = undefined,
                .rep0 = 0,
                .rep1 = 0,
                .rep2 = 0,
                .rep3 = 0,
                .state = 0,
                .output_buffer = null,
                .output_pos = 0,
                .output_writer = null,
                .out_buf = undefined,
                .out_len = 0,
                .clear_dictionary = true,
            };
            try takeTables(&self, &workspace, properties);
            self.resetDictionary();
            self.resetState();
            self.resetProbabilities();
            return self;
        }

        pub fn initPropertiesInPlace(properties: Properties, output: []u8, scratch: []u8) Failure!Self {
            var workspace = try io.Workspace.init(scratch.ptr, scratch.len);
            var self = Self{
                .properties = properties,
                .dictionary = output,
                .dict_pos = 0,
                .dict_full = false,
                .dict_floor = 0,
                .total_pos = 0,
                .rc = undefined,
                .is_match = undefined,
                .is_rep = undefined,
                .is_rep_g0 = undefined,
                .is_rep_g1 = undefined,
                .is_rep_g2 = undefined,
                .is_rep0_long = undefined,
                .pos_slot_decoders = undefined,
                .pos_decoders = undefined,
                .align_decoder = undefined,
                .len_choice = undefined,
                .len_low = undefined,
                .len_mid = undefined,
                .len_high = undefined,
                .rep_len_choice = undefined,
                .rep_len_low = undefined,
                .rep_len_mid = undefined,
                .rep_len_high = undefined,
                .literal_probs = undefined,
                .rep0 = 0,
                .rep1 = 0,
                .rep2 = 0,
                .rep3 = 0,
                .state = 0,
                .output_buffer = null,
                .output_pos = 0,
                .output_writer = null,
                .out_buf = undefined,
                .out_len = 0,
                .clear_dictionary = false,
            };
            try takeTables(&self, &workspace, properties);
            self.resetDictionary();
            self.resetState();
            self.resetProbabilities();
            return self;
        }

        pub fn init(properties: Properties, reader: *std.Io.Reader, scratch: []u8) Failure!Self {
            var self = try initProperties(properties, scratch);
            try self.resetReader(reader);
            return self;
        }

        pub fn resetReader(self: *Self, _reader: *std.Io.Reader) Failure!void {
            if (comptime slice_input) {
                return error.Unsupported;
            }
            self.rc = try RC.init(_reader);
        }

        pub fn resetReaderSlice(self: *Self, data: []const u8) Failure!void {
            self.rc = try RC.initSlice(data);
        }

        pub fn resetState(self: *Self) void {
            self.state = 0;
            self.rep0 = 0;
            self.rep1 = 0;
            self.rep2 = 0;
            self.rep3 = 0;
        }

        pub fn resetDictionary(self: *Self) void {
            if (self.clear_dictionary) {
                @memset(self.dictionary, 0);
                self.dict_pos = 0;
                self.dict_full = false;
            } else {
                // In-place decode: the output buffer is the dictionary, so a
                // format-level reset cannot rewind the write position without
                // corrupting already-produced output. Record it as a floor.
                self.dict_floor = self.dict_pos;
            }
        }

        pub fn resetProbabilities(self: *Self) void {
            resetTables(self);
        }

        pub fn feedByte(self: *Self, byte: u8) void {
            self.dictionary[self.dict_pos] = byte;
            self.dict_pos += 1;
            self.total_pos +%= 1;
            if (self.dict_pos == self.dictionary.len) {
                if (self.clear_dictionary) {
                    self.dict_pos = 0;
                    self.dict_full = true;
                }
            }
        }

        pub fn decodeToOutput(self: *Self, output: ?[]u8, unpack_size: ?u64, marker_required: bool) Failure!void {
            self.output_buffer = output;
            self.output_pos = 0;
            var remaining: ?u64 = unpack_size;
            if (comptime slice_input) {
                // Local range-coder state: keeping range/code/input position out
                // of the shared struct lets the compiler hold them in registers
                // across the hot loop instead of round-tripping memory per bit.
                var rc = self.rc;
                defer self.rc = rc;
                var prev_byte: u32 = if (self.dict_pos == 0 and !self.dict_full) 0 else self.getByte(1);
                while (true) {
                    if (rc.corrupted) return error.InvalidData;
                    if (remaining) |*r| {
                        if (r.* == 0) {
                            if (!marker_required) {
                                if (rc.isFinishedOk()) {
                                    try self.finishOutput();
                                    return;
                                }
                                try self.finishOutput();
                                return;
                            }
                        }
                    }
                    const pos_state = self.total_pos & ((@as(u32, 1) << @intCast(self.properties.pb)) - 1);
                    const state2 = (self.state << num_pos_bits_max) + pos_state;
                    if (rc.decodeBit(&self.is_match[state2]) == 0) {
                        // Literal
                        prev_byte = try self.decodeLiteral(&rc, prev_byte);
                        self.state = updateStateLiteral(self.state);
                        if (remaining) |*r| r.* -= 1;
                        continue;
                    }
                    var len: u32 = undefined;
                    if (rc.decodeBit(&self.is_rep[self.state]) == 0) {
                        // Simple match
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.state = updateStateMatch(self.state);
                        len = try self.decodeLength(&rc, pos_state, false);
                        self.rep0 = try self.decodeDistance(&rc, len);
                        if (self.rep0 == 0xFFFFFFFF) {
                            if (!rc.isFinishedOk()) return error.InvalidData;
                            if (marker_required and remaining != null and remaining.? != 0) return error.InvalidData;
                            try self.finishOutput();
                            return;
                        }
                        if (self.rep0 >= self.properties.dictionary_size or !self.checkDistance(self.rep0)) return error.InvalidData;
                    } else {
                        // Rep match
                        if (self.dict_pos == 0 and !self.dict_full) return error.InvalidData;
                        if (rc.decodeBit(&self.is_rep_g0[self.state]) == 0) {
                            if (rc.decodeBit(&self.is_rep0_long[state2]) == 0) {
                                // Short rep
                                self.state = updateStateShortRep(self.state);
                                const byte = self.getByte(self.rep0 + 1);
                                try self.putByte(byte);
                                prev_byte = byte;
                                if (remaining) |*r| r.* -= 1;
                                continue;
                            }
                            // Rep match 0: no distance history change.
                        } else {
                            if (rc.decodeBit(&self.is_rep_g1[self.state]) == 0) {
                                const dist = self.rep1;
                                self.rep1 = self.rep0;
                                self.rep0 = dist;
                            } else {
                                if (rc.decodeBit(&self.is_rep_g2[self.state]) == 0) {
                                    const dist = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = dist;
                                } else {
                                    const dist = self.rep3;
                                    self.rep3 = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = dist;
                                }
                            }
                        }
                        len = try self.decodeLength(&rc, pos_state, true);
                        self.state = updateStateRep(self.state);
                    }
                    len += match_min_len;
                    var is_error = false;
                    if (remaining) |*r| {
                        if (r.* < len) {
                            len = @intCast(r.*);
                            is_error = true;
                        }
                        r.* -= len;
                    }
                    try self.copyMatch(self.rep0 + 1, len);
                    if (is_error) return error.InvalidData;
                    prev_byte = self.getByte(1);
                }
            } else {
                var prev_byte: u32 = if (self.dict_pos == 0 and !self.dict_full) 0 else self.getByte(1);
                while (true) {
                    if (remaining) |*r| {
                        if (r.* == 0) {
                            if (!marker_required) {
                                if (self.rc.isFinishedOk()) {
                                    try self.finishOutput();
                                    return;
                                }
                                try self.finishOutput();
                                return;
                            }
                        }
                    }
                    const pos_state = self.total_pos & ((@as(u32, 1) << @intCast(self.properties.pb)) - 1);
                    const state2 = (self.state << num_pos_bits_max) + pos_state;
                    if (try self.rc.decodeBit(&self.is_match[state2]) == 0) {
                        // Literal
                        prev_byte = try self.decodeLiteral(&self.rc, prev_byte);
                        self.state = updateStateLiteral(self.state);
                        if (remaining) |*r| r.* -= 1;
                        continue;
                    }
                    var len: u32 = undefined;
                    if (try self.rc.decodeBit(&self.is_rep[self.state]) == 0) {
                        // Simple match
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.state = updateStateMatch(self.state);
                        len = try self.decodeLength(&self.rc, pos_state, false);
                        self.rep0 = try self.decodeDistance(&self.rc, len);
                        if (self.rep0 == 0xFFFFFFFF) {
                            if (!self.rc.isFinishedOk()) return error.InvalidData;
                            if (marker_required and remaining != null and remaining.? != 0) return error.InvalidData;
                            try self.finishOutput();
                            return;
                        }
                        if (self.rep0 >= self.properties.dictionary_size or !self.checkDistance(self.rep0)) return error.InvalidData;
                    } else {
                        // Rep match
                        if (self.dict_pos == 0 and !self.dict_full) return error.InvalidData;
                        if (try self.rc.decodeBit(&self.is_rep_g0[self.state]) == 0) {
                            if (try self.rc.decodeBit(&self.is_rep0_long[state2]) == 0) {
                                // Short rep
                                self.state = updateStateShortRep(self.state);
                                const byte = self.getByte(self.rep0 + 1);
                                try self.putByte(byte);
                                prev_byte = byte;
                                if (remaining) |*r| r.* -= 1;
                                continue;
                            }
                            // Rep match 0: no distance history change.
                        } else {
                            if (try self.rc.decodeBit(&self.is_rep_g1[self.state]) == 0) {
                                const dist = self.rep1;
                                self.rep1 = self.rep0;
                                self.rep0 = dist;
                            } else {
                                if (try self.rc.decodeBit(&self.is_rep_g2[self.state]) == 0) {
                                    const dist = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = dist;
                                } else {
                                    const dist = self.rep3;
                                    self.rep3 = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = dist;
                                }
                            }
                        }
                        len = try self.decodeLength(&self.rc, pos_state, true);
                        self.state = updateStateRep(self.state);
                    }
                    len += match_min_len;
                    var is_error = false;
                    if (remaining) |*r| {
                        if (r.* < len) {
                            len = @intCast(r.*);
                            is_error = true;
                        }
                        r.* -= len;
                    }
                    try self.copyMatch(self.rep0 + 1, len);
                    if (is_error) return error.InvalidData;
                    prev_byte = self.getByte(1);
                }
            }
        }

        fn decodeLiteral(self: *Self, rc: *RC, prev_byte: u32) Failure!u8 {
            const lit_state = ((self.total_pos & ((@as(u32, 1) << @intCast(self.properties.lp)) - 1)) << @intCast(self.properties.lc)) +
                (prev_byte >> @intCast(8 - self.properties.lc));
            const probs = self.literal_probs[lit_state * literal_probs_count ..][0..literal_probs_count];
            var symbol: u32 = 1;
            if (comptime slice_input) {
                if (self.state >= 7) {
                    var match = self.getByte(self.rep0 + 1);
                    var use_match = true;
                    // The tree walk always runs exactly 8 bits: symbol stays
                    // below 0x100 before the last shift.
                    inline for (0..8) |_| {
                        if (use_match) {
                            const match_bit: u32 = (match >> 7) & 1;
                            match <<= 1;
                            const bit = rc.decodeBit(&probs[((1 + match_bit) << 8) + symbol]);
                            symbol = (symbol << 1) | bit;
                            if (match_bit != bit) use_match = false;
                        } else {
                            const bit = rc.decodeBit(&probs[symbol]);
                            symbol = (symbol << 1) | bit;
                        }
                    }
                } else {
                    inline for (0..8) |_| {
                        const bit = rc.decodeBit(&probs[symbol]);
                        symbol = (symbol << 1) | bit;
                    }
                }
                if (rc.corrupted) return error.InvalidData;
                const byte: u8 = @intCast(symbol - 0x100);
                try self.putByte(byte);
                return byte;
            } else {
                if (self.state >= 7) {
                    var match = self.getByte(self.rep0 + 1);
                    var use_match = true;
                    inline for (0..8) |_| {
                        if (use_match) {
                            const match_bit: u32 = (match >> 7) & 1;
                            match <<= 1;
                            const bit = try rc.decodeBit(&probs[((1 + match_bit) << 8) + symbol]);
                            symbol = (symbol << 1) | bit;
                            if (match_bit != bit) use_match = false;
                        } else {
                            const bit = try rc.decodeBit(&probs[symbol]);
                            symbol = (symbol << 1) | bit;
                        }
                    }
                } else {
                    inline for (0..8) |_| {
                        const bit = try rc.decodeBit(&probs[symbol]);
                        symbol = (symbol << 1) | bit;
                    }
                }
                const byte: u8 = @intCast(symbol - 0x100);
                try self.putByte(byte);
                return byte;
            }
        }

        fn decodeLength(self: *Self, rc: *RC, pos_state: u32, comptime is_rep: bool) Failure!u32 {
            const choice = if (is_rep) &self.rep_len_choice[0] else &self.len_choice[0];
            const choice2 = if (is_rep) &self.rep_len_choice[1] else &self.len_choice[1];
            const low = if (is_rep) self.rep_len_low else self.len_low;
            const mid = if (is_rep) self.rep_len_mid else self.len_mid;
            const high = if (is_rep) self.rep_len_high else self.len_high;
            if (comptime slice_input) {
                if (rc.decodeBit(choice) == 0) {
                    const res = bitTreeDecodeFast(rc, low[pos_state * (1 << 3) ..][0..(1 << 3)], 3);
                    if (rc.corrupted) return error.InvalidData;
                    return res;
                }
                if (rc.decodeBit(choice2) == 0) {
                    const res = 8 + bitTreeDecodeFast(rc, mid[pos_state * (1 << 3) ..][0..(1 << 3)], 3);
                    if (rc.corrupted) return error.InvalidData;
                    return res;
                }
                const res = 16 + bitTreeDecodeFast(rc, high, 8);
                if (rc.corrupted) return error.InvalidData;
                return res;
            }
            if (try rc.decodeBit(choice) == 0) {
                return try bitTreeDecode(rc, low[pos_state * (1 << 3) ..][0..(1 << 3)], 3);
            }
            if (try rc.decodeBit(choice2) == 0) {
                return 8 + try bitTreeDecode(rc, mid[pos_state * (1 << 3) ..][0..(1 << 3)], 3);
            }
            return 16 + try bitTreeDecode(rc, high, 8);
        }

        fn decodeDistance(self: *Self, rc: *RC, len: u32) Failure!u32 {
            var len_state = len;
            if (len_state > num_len_to_pos_states - 1) len_state = num_len_to_pos_states - 1;
            if (comptime slice_input) {
                const pos_slot = bitTreeDecodeFast(rc, self.pos_slot_decoders[len_state * (1 << 6) ..][0..(1 << 6)], 6);
                if (rc.corrupted) return error.InvalidData;
                if (pos_slot < 4) return pos_slot;
                const num_direct_bits = (pos_slot >> 1) - 1;
                var dist: u32 = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
                if (pos_slot < end_pos_model_index) {
                    dist += bitTreeReverseDecodeFast(rc, self.pos_decoders[dist - pos_slot ..], @intCast(num_direct_bits));
                } else {
                    dist += (rc.decodeDirectBits(@intCast(num_direct_bits - num_align_bits))) << num_align_bits;
                    dist += bitTreeReverseDecodeFast(rc, self.align_decoder, num_align_bits);
                }
                if (rc.corrupted) return error.InvalidData;
                return dist;
            }
            const pos_slot = try bitTreeDecode(rc, self.pos_slot_decoders[len_state * (1 << 6) ..][0..(1 << 6)], 6);
            if (pos_slot < 4) return pos_slot;
            const num_direct_bits = (pos_slot >> 1) - 1;
            var dist: u32 = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
            if (pos_slot < end_pos_model_index) {
                dist += try bitTreeReverseDecode(rc, self.pos_decoders[dist - pos_slot ..], @intCast(num_direct_bits));
            } else {
                dist += (try rc.decodeDirectBits(@intCast(num_direct_bits - num_align_bits))) << num_align_bits;
                dist += try bitTreeReverseDecode(rc, self.align_decoder, num_align_bits);
            }
            return dist;
        }

        fn putByte(self: *Self, byte: u8) Failure!void {
            if (!self.clear_dictionary and self.dict_pos >= self.dictionary.len) return error.InsufficientCapacity;
            self.dictionary[self.dict_pos] = byte;
            self.dict_pos += 1;
            self.total_pos +%= 1;
            if (self.dict_pos == self.dictionary.len) {
                self.dict_pos = 0;
                self.dict_full = true;
            }
            if (self.output_buffer) |output| {
                if (self.output_pos >= output.len) return error.InsufficientCapacity;
                output[self.output_pos] = byte;
                self.output_pos += 1;
            } else if (self.output_writer) |writer| {
                self.out_buf[self.out_len] = byte;
                self.out_len += 1;
                self.output_pos += 1;
                if (self.out_len == self.out_buf.len) try self.flushOutput(writer);
            } else {
                self.output_pos += 1;
            }
        }

        fn flushOutput(self: *Self, writer: *std.Io.Writer) Failure!void {
            try io.writeBytes(writer, self.out_buf[0..self.out_len]);
            self.out_len = 0;
        }

        fn finishOutput(self: *Self) Failure!void {
            if (self.output_writer) |writer| {
                if (self.out_len > 0) try self.flushOutput(writer);
            }
        }

        fn getByte(self: Self, dist: u32) u8 {
            const pos = if (dist <= self.dict_pos) self.dict_pos - dist else @as(u32, @intCast(self.dictionary.len)) - dist + self.dict_pos;
            return self.dictionary[pos];
        }

        fn checkDistance(self: Self, dist: u32) bool {
            // dist is 0-based: it reaches dist + 1 bytes back, so a full
            // dictionary of dict_pos bytes only covers dist < dict_pos.
            // In-place decode enforces the reset floor instead: matches may
            // not reach before the most recent dictionary reset.
            if (!self.clear_dictionary) return dist < self.dict_pos - self.dict_floor;
            return dist < self.dict_pos or self.dict_full;
        }

        fn copyMatch(self: *Self, dist: u32, len: u32) Failure!void {
            // decodeInPlace uses the output buffer as a linear dictionary. A
            // single forward copy covers the match because the source window is
            // contiguous and the destination is past the source.
            if (!self.clear_dictionary) {
                if (self.dict_pos + len > self.dictionary.len) return error.InsufficientCapacity;
                kernels.copyMatch(self.dictionary, self.dict_pos, dist, len);
                self.dict_pos += len;
                self.total_pos +%= len;
                return;
            }
            var remaining = len;
            while (remaining > 0) {
                if (self.dict_pos >= self.dictionary.len) return error.InsufficientCapacity;
                const src = if (dist <= self.dict_pos)
                    self.dict_pos - dist
                else
                    self.dictionary.len - dist + self.dict_pos;
                var chunk = @min(@as(usize, remaining), self.dictionary.len - self.dict_pos);
                if (src > self.dict_pos) chunk = @min(chunk, self.dictionary.len - src);
                if (self.output_buffer) |output| {
                    chunk = @min(chunk, output.len - self.output_pos);
                    if (chunk == 0) return error.InsufficientCapacity;
                }
                if (src < self.dict_pos) {
                    var covered: usize = dist;
                    var done: usize = 0;
                    while (done < chunk) {
                        const take = @min(covered, chunk - done);
                        @memcpy(self.dictionary[self.dict_pos + done ..][0..take], self.dictionary[self.dict_pos + done - covered ..][0..take]);
                        done += take;
                        covered += take;
                    }
                } else {
                    @memmove(self.dictionary[self.dict_pos..][0..chunk], self.dictionary[src..][0..chunk]);
                }
                if (self.output_buffer) |output| {
                    @memcpy(output[self.output_pos..][0..chunk], self.dictionary[self.dict_pos..][0..chunk]);
                    self.output_pos += chunk;
                } else if (self.output_writer) |writer| {
                    var offset: usize = 0;
                    while (offset < chunk) {
                        const take = @min(chunk - offset, self.out_buf.len - self.out_len);
                        @memcpy(self.out_buf[self.out_len..][0..take], self.dictionary[self.dict_pos + offset ..][0..take]);
                        self.out_len += take;
                        offset += take;
                        if (self.out_len == self.out_buf.len) try self.flushOutput(writer);
                    }
                    self.output_pos += chunk;
                } else {
                    self.output_pos += chunk;
                }
                self.dict_pos += @intCast(chunk);
                if (self.dict_pos == self.dictionary.len) {
                    self.dict_pos = 0;
                    self.dict_full = true;
                }
                self.total_pos +%= @intCast(chunk);
                remaining -= @intCast(chunk);
            }
        }
    };
}

pub const Decoder = DecoderOf(false);

fn updateStateLiteral(state: u32) u32 {
    if (state < 4) return 0;
    if (state < 10) return state - 3;
    return state - 6;
}

fn updateStateMatch(state: u32) u32 {
    return if (state < 7) 7 else 10;
}

fn updateStateRep(state: u32) u32 {
    return if (state < 7) 8 else 11;
}

fn updateStateShortRep(state: u32) u32 {
    return if (state < 7) 9 else 11;
}

fn initProbs(probs: []Prob) void {
    @memset(std.mem.sliceAsBytes(probs), 0);
    for (probs) |*p| p.* = prob_init;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    const needed = decodeWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    if (input.len + output.len > options.max_work) return error.ResourceLimit;
    // Use the in-place dictionary path: the output buffer is large enough to
    // hold the decoded stream, so it can serve as the dictionary window and
    // avoid a per-byte copy to a separate output buffer.
    var decoder = try DecoderOf(true).initPropertiesInPlace(options.properties, output, scratch);
    try decoder.resetReaderSlice(input);
    try decoder.decodeToOutput(null, options.unpack_size, options.marker_required);
    return decoder.total_pos;
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    const needed = decodeInPlaceWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    if (input.len + output.len > options.max_work) return error.ResourceLimit;
    var decoder = try DecoderOf(true).initPropertiesInPlace(options.properties, output, scratch);
    try decoder.resetReaderSlice(input);
    try decoder.decodeToOutput(null, options.unpack_size, options.marker_required);
    return decoder.total_pos;
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    const needed = decodeWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    if (input.len > options.max_work) return error.ResourceLimit;
    var decoder = try DecoderOf(true).initProperties(options.properties, scratch);
    try decoder.resetReaderSlice(input);
    try decoder.decodeToOutput(null, options.unpack_size, options.marker_required);
    return decoder.output_pos;
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    var source = std.Io.Reader.fixed(input);
    try decodeStream(&source, writer, scratch, options);
}

pub fn decodeStream(reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    const needed = decodeWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    var decoder = try Decoder.init(options.properties, reader, scratch);
    decoder.output_writer = writer;
    try decoder.decodeToOutput(null, options.unpack_size, options.marker_required);
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeInner(input, &counter.writer, scratch, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

// Sizing estimate for the LZMA2 chunk probe: one greedy forward pass with the
// live model (no DP window, no range coder) priced through kBitPrice. The
// dictionary clamps to the next power of two >= the chunk length (floored at
// dictionary_min) — every match distance is bounded by the chunk anyway — so
// the per-probe finder-table clears scale with the chunk, not the profile
// dictionary. The estimate errs high by construction
// (price-aware greedy acceptance, insert-only finder advance); the measured
// divergence and margin calibration are documented at the probe in lzma2.zig.
pub fn estimatedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var props = options.properties;
    if (input.len < props.dictionary_size) {
        var clamp: u32 = dictionary_min;
        while (clamp < input.len) clamp <<= 1;
        if (clamp < props.dictionary_size) props.dictionary_size = clamp;
    }
    const needed = if (options.match_finder == .bt4) encodeWorkspaceSizeBt(props) else encodeWorkspaceSize(props);
    if (scratch.len < needed) return error.InsufficientCapacity;
    var probe_options = options;
    probe_options.properties = props;
    var drain = std.Io.Writer.fixed(&.{});
    var encoder = try Encoder.init(props, &drain, scratch, probe_options);
    const price = try encoder.estimateInput(input);
    // price_scale units per bit, 8 bits per byte: >> (price_scale_shift + 3).
    const payload = std.math.cast(usize, (price + (1 << 13) - 1) >> 13) orelse return error.ResourceLimit;
    // 5 range-coder flush bytes plus the cache byte.
    return payload + 6;
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    if (input.len + output.len > options.max_work) return error.ResourceLimit;
    var dest = std.Io.Writer.fixed(output);
    try encodeInner(input, &dest, scratch, options);
    return dest.end;
}

pub fn encodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (input.len > options.max_work) return error.ResourceLimit;
    try encodeInner(input, writer, scratch, options);
}

pub const Encoder = struct {
    properties: Properties,
    dictionary: []u8,
    dict_pos: u32,
    dict_full: bool,
    total_pos: u32,
    // Hash-chain match finder state. head[bucket] stores the most recent
    // position (offset by one so zero means empty) for each 4-byte hash;
    // chain[slot] stores the previous same-hash position, one slot per window
    // position. chain_window is dictionary_size + 1.
    head: []u32,
    chain: []u32,
    left: []u32,
    right: []u32,
    hash2: []u32,
    hash3: []u32,
    hash_mask: u32,
    dict_mask: u32,
    chain_window: usize,
    rc: RangeEncoder,
    is_match: []Prob,
    is_rep: []Prob,
    is_rep_g0: []Prob,
    is_rep_g1: []Prob,
    is_rep_g2: []Prob,
    is_rep0_long: []Prob,
    pos_slot_decoders: []Prob,
    pos_decoders: []Prob,
    align_decoder: []Prob,
    len_choice: []Prob,
    len_low: []Prob,
    len_mid: []Prob,
    len_high: []Prob,
    rep_len_choice: []Prob,
    rep_len_low: []Prob,
    rep_len_mid: []Prob,
    rep_len_high: []Prob,
    literal_probs: []Prob,
    match_finder_depth: u32,
    nice_len: u32,
    match_finder: MatchFinder,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
    state: u32,
    input: []const u8,
    input_base: usize,
    // Optimal-parsing scratch (workspace-owned): the per-window optimum nodes,
    // the extraction stack, and the derived price tables.
    opt: []Opt,
    decisions: []Decision,
    prices: *PriceTables,
    literal_prices: []u32,

    pub fn init(properties: Properties, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!Encoder {
        var workspace = try io.Workspace.init(scratch.ptr, scratch.len);
        const dictionary = try workspace.take(u8, properties.dictionary_size);
        const chain = try workspace.take(u32, matchFinderChainSize(properties.dictionary_size));
        const left = if (options.match_finder == .bt4) try workspace.take(u32, matchFinderChainSize(properties.dictionary_size)) else @constCast(&.{});
        const right = if (options.match_finder == .bt4) try workspace.take(u32, matchFinderChainSize(properties.dictionary_size)) else @constCast(&.{});
        const head = try workspace.take(u32, matchFinderHashSize(properties.dictionary_size));
        const hash2 = try workspace.take(u32, @as(usize, 1) << match_finder_hash2_bits);
        const hash3 = try workspace.take(u32, @as(usize, 1) << match_finder_hash3_bits);
        const opt = try workspace.take(Opt, opt_window + 1);
        const decisions = try workspace.take(Decision, opt_window);
        const prices = &(try workspace.take(PriceTables, 1))[0];
        const literal_prices = try workspace.take(u32, properties.literalContextCount() << 8);
        var self = Encoder{
            .properties = properties,
            .dictionary = dictionary,
            .dict_pos = 0,
            .dict_full = false,
            .total_pos = 0,
            .head = head,
            .chain = chain,
            .left = left,
            .right = right,
            .hash2 = hash2,
            .hash3 = hash3,
            .hash_mask = @intCast(matchFinderHashSize(properties.dictionary_size) - 1),
            .dict_mask = if (properties.dictionary_size & (properties.dictionary_size - 1) == 0) properties.dictionary_size - 1 else 0,
            .chain_window = matchFinderChainSize(properties.dictionary_size),
            .rc = RangeEncoder.init(writer),
            .is_match = undefined,
            .is_rep = undefined,
            .is_rep_g0 = undefined,
            .is_rep_g1 = undefined,
            .is_rep_g2 = undefined,
            .is_rep0_long = undefined,
            .pos_slot_decoders = undefined,
            .pos_decoders = undefined,
            .align_decoder = undefined,
            .len_choice = undefined,
            .len_low = undefined,
            .len_mid = undefined,
            .len_high = undefined,
            .rep_len_choice = undefined,
            .rep_len_low = undefined,
            .rep_len_mid = undefined,
            .rep_len_high = undefined,
            .literal_probs = undefined,
            .match_finder_depth = options.match_finder_depth,
            .nice_len = options.nice_len,
            .match_finder = options.match_finder,
            .rep0 = 0,
            .rep1 = 0,
            .rep2 = 0,
            .rep3 = 0,
            .state = 0,
            .input = &.{},
            .input_base = 0,
            .opt = opt,
            .decisions = decisions,
            .prices = prices,
            .literal_prices = literal_prices,
        };
        try takeTables(&self, &workspace, properties);
        resetTables(&self);
        @memset(self.head, 0);
        @memset(self.hash2, 0);
        @memset(self.hash3, 0);
        return self;
    }

    inline fn priceBit(prob: Prob, bit: u1) u32 {
        const idx = prob >> 4;
        if (bit == 0) return kBitPrice[idx];
        const q = 2048 - @as(u32, prob);
        const idx1 = if (q > 2047) 127 else q >> 4;
        return kBitPrice[idx1];
    }

    inline fn bitTreePrice(comptime num_bits: u5, probs: []const Prob, symbol: u32) u32 {
        var price: u32 = 0;
        var m: u32 = 1;
        inline for (0..num_bits) |i| {
            const bit = (symbol >> @intCast(num_bits - 1 - i)) & 1;
            price += priceBit(probs[m], @intCast(bit));
            m = (m << 1) | bit;
        }
        return price;
    }

    inline fn bitTreeReversePrice(num_bits: u5, probs: []const Prob, symbol: u32) u32 {
        var price: u32 = 0;
        var m: u32 = 1;
        var i: u5 = 0;
        while (i < num_bits) : (i += 1) {
            const bit = (symbol >> i) & 1;
            price += priceBit(probs[m], @intCast(bit));
            m = (m << 1) | bit;
        }
        return price;
    }

    // Matched-literal price: walks the actual byte against the match byte,
    // mirroring encodeLiteral's tree indexing (match-context rows until the
    // first differing bit, then the plain tree).
    inline fn matchedLiteralPrice(probs: []const Prob, literal: u8, match_byte: u8) u32 {
        var price: u32 = 0;
        var symbol: u32 = 1;
        var lit: u32 = literal;
        var mb: u32 = match_byte;
        var use_match = true;
        inline for (0..8) |_| {
            if (symbol >= 0x100) break;
            const match_bit = (mb >> 7) & 1;
            mb <<= 1;
            const bit = (lit >> 7) & 1;
            lit <<= 1;
            const idx = if (use_match) ((1 + match_bit) << 8) + symbol else symbol;
            price += priceBit(probs[idx], @intCast(bit));
            symbol = (symbol << 1) | bit;
            if (match_bit != bit) use_match = false;
        }
        return price;
    }

    // Refresh every price table from the live probability model. Runs once per
    // optimum window; the model stays frozen while the window is planned.
    fn buildPrices(self: *Encoder) void {
        const prices = self.prices;
        for (self.is_match, 0..) |p, i| {
            prices.is_match[i][0] = priceBit(p, 0);
            prices.is_match[i][1] = priceBit(p, 1);
        }
        for (self.is_rep, 0..) |p, i| {
            prices.is_rep[i][0] = priceBit(p, 0);
            prices.is_rep[i][1] = priceBit(p, 1);
        }
        for (self.is_rep_g0, 0..) |p, i| {
            prices.is_rep_g0[i][0] = priceBit(p, 0);
            prices.is_rep_g0[i][1] = priceBit(p, 1);
        }
        for (self.is_rep_g1, 0..) |p, i| {
            prices.is_rep_g1[i][0] = priceBit(p, 0);
            prices.is_rep_g1[i][1] = priceBit(p, 1);
        }
        for (self.is_rep_g2, 0..) |p, i| {
            prices.is_rep_g2[i][0] = priceBit(p, 0);
            prices.is_rep_g2[i][1] = priceBit(p, 1);
        }
        for (self.is_rep0_long, 0..) |p, i| {
            prices.is_rep0_long[i][0] = priceBit(p, 0);
            prices.is_rep0_long[i][1] = priceBit(p, 1);
        }
        const pos_states: usize = @as(usize, 1) << @intCast(self.properties.pb);
        for (0..pos_states) |ps| {
            const low = self.len_low[ps * (1 << 3) ..][0..(1 << 3)];
            const mid = self.len_mid[ps * (1 << 3) ..][0..(1 << 3)];
            const low_rep = self.rep_len_low[ps * (1 << 3) ..][0..(1 << 3)];
            const mid_rep = self.rep_len_mid[ps * (1 << 3) ..][0..(1 << 3)];
            const c0 = priceBit(self.len_choice[0], 0);
            const c10 = priceBit(self.len_choice[0], 1) + priceBit(self.len_choice[1], 0);
            const c11 = priceBit(self.len_choice[0], 1) + priceBit(self.len_choice[1], 1);
            const r0 = priceBit(self.rep_len_choice[0], 0);
            const r10 = priceBit(self.rep_len_choice[0], 1) + priceBit(self.rep_len_choice[1], 0);
            const r11 = priceBit(self.rep_len_choice[0], 1) + priceBit(self.rep_len_choice[1], 1);
            var raw: u32 = 0;
            while (raw <= max_match_len - match_min_len) : (raw += 1) {
                const len = raw + match_min_len;
                if (raw < 8) {
                    prices.len[ps][len] = c0 + bitTreePrice(3, low, raw);
                    prices.rep_len[ps][len] = r0 + bitTreePrice(3, low_rep, raw);
                } else if (raw < 16) {
                    prices.len[ps][len] = c10 + bitTreePrice(3, mid, raw - 8);
                    prices.rep_len[ps][len] = r10 + bitTreePrice(3, mid_rep, raw - 8);
                } else {
                    prices.len[ps][len] = c11 + bitTreePrice(8, self.len_high, raw - 16);
                    prices.rep_len[ps][len] = r11 + bitTreePrice(8, self.rep_len_high, raw - 16);
                }
            }
        }
        for (0..num_len_to_pos_states) |len_state| {
            const slot_probs = self.pos_slot_decoders[len_state * (1 << 6) ..][0..(1 << 6)];
            var slot: u32 = 0;
            while (slot < 64) : (slot += 1) {
                prices.slot[len_state][slot] = bitTreePrice(6, slot_probs, slot);
            }
            var d: u32 = 0;
            while (d < num_full_distances) : (d += 1) {
                if (d < 4) {
                    prices.dist[len_state][d] = prices.slot[len_state][d];
                    continue;
                }
                const s = encodePosSlot(d);
                const nd: u5 = @intCast((s >> 1) - 1);
                const base_dist = (@as(u32, 2) | (s & 1)) << nd;
                prices.dist[len_state][d] = prices.slot[len_state][s] +
                    bitTreeReversePrice(nd, self.pos_decoders[base_dist - s ..], d - base_dist);
            }
        }
        var a: u32 = 0;
        while (a < align_size) : (a += 1) {
            prices.align_prices[a] = bitTreeReversePrice(num_align_bits, self.align_decoder, a);
        }
        const contexts = self.properties.literalContextCount();
        for (0..contexts) |ctx| {
            const probs = self.literal_probs[ctx * literal_probs_count ..][0..literal_probs_count];
            var sym: u32 = 0;
            while (sym < 256) : (sym += 1) {
                var price: u32 = 0;
                var m: u32 = 1;
                inline for (0..8) |i| {
                    const bit = (sym >> @intCast(7 - i)) & 1;
                    price += priceBit(probs[m], @intCast(bit));
                    m = (m << 1) | bit;
                }
                self.literal_prices[ctx * 256 + sym] = price;
            }
        }
    }

    inline fn distPrice(self: *const Encoder, len_state: u32, dist0: u32) u32 {
        if (dist0 < num_full_distances) return self.prices.dist[len_state][dist0];
        const slot = encodePosSlot(dist0);
        const nd = (slot >> 1) - 1;
        return self.prices.slot[len_state][slot] +
            (nd - num_align_bits) * price_scale +
            self.prices.align_prices[dist0 & (align_size - 1)];
    }

    pub fn encodeInput(self: *Encoder, input: []const u8, marker_required: bool) Failure!void {
        self.input = input;
        self.input_base = self.total_pos;
        var pos: usize = 0;
        while (pos < input.len) {
            const w_len = @min(opt_window, input.len - pos);
            self.buildPrices();
            const count = self.planWindow(pos, w_len);
            try self.encodeWindow(pos, count);
            pos += w_len;
        }
        if (marker_required) {
            const pos_state = self.total_pos & ((@as(u32, 1) << @intCast(self.properties.pb)) - 1);
            const state2 = (self.state << num_pos_bits_max) + pos_state;
            try self.rc.encodeBit(&self.is_match[state2], 1);
            try self.rc.encodeBit(&self.is_rep[self.state], 0);
            self.rep3 = self.rep2;
            self.rep2 = self.rep1;
            self.rep1 = self.rep0;
            self.state = updateStateMatch(self.state);
            try self.encodeLength(&self.rc, pos_state, 0);
            try self.encodeEndMarker(&self.rc);
        }
        try self.rc.finish();
        self.input = &.{};
    }

    // Live-model prices for the estimator's greedy acceptance test: a match
    // is taken only when its coded price beats the literal run it replaces,
    // so sparse far matches on binary data cannot inflate the estimate past
    // the LZMA2 pack-field boundary.
    fn literalLivePrice(self: *const Encoder, byte: u8) u32 {
        const prev_byte: u32 = if (self.dict_pos == 0 and !self.dict_full) 0 else self.getByte(1);
        const lit_state = ((self.total_pos & ((@as(u32, 1) << @intCast(self.properties.lp)) - 1)) << @intCast(self.properties.lc)) +
            (prev_byte >> @intCast(8 - self.properties.lc));
        const probs = self.literal_probs[lit_state * literal_probs_count ..][0..literal_probs_count];
        if (self.state >= 7) return matchedLiteralPrice(probs, byte, self.getByte(self.rep0 + 1));
        var price: u32 = 0;
        var symbol: u32 = 1;
        var lit: u32 = byte;
        inline for (0..8) |_| {
            const bit: u1 = @intCast((lit >> 7) & 1);
            lit <<= 1;
            price += priceBit(probs[symbol], bit);
            symbol = (symbol << 1) | bit;
        }
        return price;
    }

    fn lenLivePrice(choice: []const Prob, low: []const Prob, mid: []const Prob, high: []const Prob, pos_state: u32, raw_len: u32) u32 {
        if (raw_len < 8) return priceBit(choice[0], 0) + bitTreePrice(3, low[pos_state * (1 << 3) ..][0..(1 << 3)], raw_len);
        if (raw_len < 16) return priceBit(choice[0], 1) + priceBit(choice[1], 0) + bitTreePrice(3, mid[pos_state * (1 << 3) ..][0..(1 << 3)], raw_len - 8);
        return priceBit(choice[0], 1) + priceBit(choice[1], 1) + bitTreePrice(8, high, raw_len - 16);
    }

    fn distLivePrice(self: *const Encoder, raw_len: u32, dist0: u32) u32 {
        const pos_slot = encodePosSlot(dist0);
        const len_state: u32 = @min(raw_len, num_len_to_pos_states - 1);
        const price = bitTreePrice(6, self.pos_slot_decoders[len_state * (1 << 6) ..][0..(1 << 6)], pos_slot);
        if (pos_slot < 4) return price;
        const num_direct_bits: u5 = @intCast((pos_slot >> 1) - 1);
        const base_dist = (@as(u32, 2) | (pos_slot & 1)) << num_direct_bits;
        const offset = dist0 - base_dist;
        if (pos_slot < end_pos_model_index) {
            return price + bitTreeReversePrice(num_direct_bits, self.pos_decoders[base_dist - pos_slot ..], offset);
        }
        return price + @as(u32, num_direct_bits - num_align_bits) * price_scale +
            bitTreeReversePrice(num_align_bits, self.align_decoder, offset & (align_size - 1));
    }

    fn matchLivePrice(self: *const Encoder, state2: u32, pos_state: u32, dist: u32, len: usize) u32 {
        const raw_len: u32 = @intCast(len - match_min_len);
        return priceBit(self.is_match[state2], 1) + priceBit(self.is_rep[self.state], 0) +
            lenLivePrice(self.len_choice, self.len_low, self.len_mid, self.len_high, pos_state, raw_len) +
            self.distLivePrice(raw_len, dist - 1);
    }

    fn repLivePrice(self: *const Encoder, state2: u32, pos_state: u32, rep: usize, len: usize) u32 {
        var price = priceBit(self.is_match[state2], 1) + priceBit(self.is_rep[self.state], 1);
        price += switch (rep) {
            0 => priceBit(self.is_rep_g0[self.state], 0) + priceBit(self.is_rep0_long[state2], 1),
            1 => priceBit(self.is_rep_g0[self.state], 1) + priceBit(self.is_rep_g1[self.state], 0),
            2 => priceBit(self.is_rep_g0[self.state], 1) + priceBit(self.is_rep_g1[self.state], 1) + priceBit(self.is_rep_g2[self.state], 0),
            else => priceBit(self.is_rep_g0[self.state], 1) + priceBit(self.is_rep_g1[self.state], 1) + priceBit(self.is_rep_g2[self.state], 1),
        };
        const raw_len: u32 = @intCast(len - match_min_len);
        return price + lenLivePrice(self.rep_len_choice, self.rep_len_low, self.rep_len_mid, self.rep_len_high, pos_state, raw_len);
    }

    // Insert-only advance for the estimator: positions covered by a taken
    // match still feed the hash-chain finder tables so later positions see
    // the same match offers the DP probe would; only the chain walk is
    // skipped. Hash-chain only — the bt4 tree ordering cannot be maintained
    // without the walk, so a bt4 probe just sees fewer offers (looser but
    // still safe).
    fn insertSkipped(self: *Encoder, pos: usize, len: usize) void {
        if (self.match_finder != .hash_chain) return;
        var p = pos + 1;
        const end = pos + len;
        while (p < end) : (p += 1) {
            if (p + 4 > self.input.len) return;
            const abs_pos = self.input_base + p;
            if (abs_pos >= std.math.maxInt(u32)) return;
            const hash = self.hash4(p);
            const slot = abs_pos % self.chain_window;
            self.chain[slot] = self.head[hash];
            self.head[hash] = @intCast(abs_pos + 1);
            const b = self.input[p..];
            const h2 = @as(u32, b[0]) | (@as(u32, b[1]) << 8);
            self.hash2[h2] = @intCast(abs_pos + 1);
            const w3 = h2 | (@as(u32, b[2]) << 16);
            const h3 = (w3 *% 0x9E3779B1) >> @as(u5, @intCast(32 - @as(u6, match_finder_hash3_bits)));
            self.hash3[h3] = @intCast(abs_pos + 1);
        }
    }

    // One greedy forward pass charging fixed-point prices against the live
    // model instead of emitting a bitstream: the LZMA2 sizing probe shape (no
    // DP window, no range coder). Match-covered positions still enter the
    // finder (insert-only, no chain walk) so the estimate stays tight on
    // sparse-match data.
    fn estimateInput(self: *Encoder, input: []const u8) Failure!u64 {
        self.input = input;
        self.input_base = self.total_pos;
        var pc = PriceCounter{};
        const pb_mask = (@as(u32, 1) << @intCast(self.properties.pb)) - 1;
        var matches: [match_list_max]MatchPair = undefined;
        var pos: usize = 0;
        while (pos < input.len) {
            const abs = self.input_base + pos;
            const pos_state = @as(u32, @truncate(abs)) & pb_mask;
            const state2 = (self.state << num_pos_bits_max) + pos_state;
            const max_len = @min(max_match_len, input.len - pos);
            var rep_len: [4]usize = .{ 0, 0, 0, 0 };
            var best_rep: usize = 0;
            var best_rep_len: usize = 0;
            if (abs > 0) {
                const backs = [4]u32{ self.rep0, self.rep1, self.rep2, self.rep3 };
                for (0..4) |r| {
                    const dist = @as(usize, backs[r]) + 1;
                    if (dist > abs) continue;
                    const l = self.matchLen(abs - dist, abs, max_len);
                    rep_len[r] = l;
                    if (l > best_rep_len) {
                        best_rep_len = l;
                        best_rep = r;
                    }
                }
            }
            const count = self.findMatches(pos, &matches);
            const found_len: usize = if (count > 0) matches[count - 1].len else 0;
            const lit_price = priceBit(self.is_match[state2], 0) + self.literalLivePrice(input[pos]);
            const rep_ok = best_rep_len >= match_min_len and
                self.repLivePrice(state2, pos_state, best_rep, best_rep_len) < best_rep_len * lit_price;
            const match_ok = found_len >= match_min_len and
                self.matchLivePrice(state2, pos_state, matches[count - 1].dist, found_len) < found_len * lit_price;
            if ((rep_ok and best_rep_len >= found_len) or (rep_ok and !match_ok)) {
                try pc.encodeBit(&self.is_match[state2], 1);
                try pc.encodeBit(&self.is_rep[self.state], 1);
                switch (best_rep) {
                    0 => {
                        try pc.encodeBit(&self.is_rep_g0[self.state], 0);
                        try pc.encodeBit(&self.is_rep0_long[state2], 1);
                    },
                    1 => {
                        try pc.encodeBit(&self.is_rep_g0[self.state], 1);
                        try pc.encodeBit(&self.is_rep_g1[self.state], 0);
                        const dist = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = dist;
                    },
                    2 => {
                        try pc.encodeBit(&self.is_rep_g0[self.state], 1);
                        try pc.encodeBit(&self.is_rep_g1[self.state], 1);
                        try pc.encodeBit(&self.is_rep_g2[self.state], 0);
                        const dist = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = dist;
                    },
                    else => {
                        try pc.encodeBit(&self.is_rep_g0[self.state], 1);
                        try pc.encodeBit(&self.is_rep_g1[self.state], 1);
                        try pc.encodeBit(&self.is_rep_g2[self.state], 1);
                        const dist = self.rep3;
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = dist;
                    },
                }
                try self.encodeRepLength(&pc, pos_state, @intCast(best_rep_len - match_min_len));
                self.state = updateStateRep(self.state);
                self.copyBytes(pos, @intCast(best_rep_len));
                self.insertSkipped(pos, best_rep_len);
                pos += best_rep_len;
            } else if (match_ok) {
                const dist = matches[count - 1].dist;
                try pc.encodeBit(&self.is_match[state2], 1);
                try pc.encodeBit(&self.is_rep[self.state], 0);
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = dist - 1;
                self.state = updateStateMatch(self.state);
                const raw_len: u32 = @intCast(found_len - match_min_len);
                try self.encodeLength(&pc, pos_state, raw_len);
                try self.encodeDistance(&pc, raw_len, dist - 1);
                self.copyBytes(pos, @intCast(found_len));
                self.insertSkipped(pos, found_len);
                pos += found_len;
            } else if (rep_len[0] >= 1 and
                priceBit(self.is_match[state2], 1) + priceBit(self.is_rep[self.state], 1) +
                    priceBit(self.is_rep_g0[self.state], 0) + priceBit(self.is_rep0_long[state2], 0) < lit_price)
            {
                try pc.encodeBit(&self.is_match[state2], 1);
                try pc.encodeBit(&self.is_rep[self.state], 1);
                try pc.encodeBit(&self.is_rep_g0[self.state], 0);
                try pc.encodeBit(&self.is_rep0_long[state2], 0);
                self.state = updateStateShortRep(self.state);
                self.putByte(self.getByte(self.rep0 + 1));
                pos += 1;
            } else {
                try pc.encodeBit(&self.is_match[state2], 0);
                try self.encodeLiteral(&pc, input[pos]);
                self.state = updateStateLiteral(self.state);
                self.putByte(input[pos]);
                pos += 1;
            }
        }
        self.input = &.{};
        return pc.price;
    }

    inline fn relax(self: *Encoder, j: usize, price: u32, prev: u16, back: u32, state: u32, backs: *const [4]u32) void {
        const o = &self.opt[j];
        if (price < o.price) {
            o.price = price;
            o.pos_prev = prev;
            o.back = back;
            o.state = @intCast(state);
            o.backs = backs.*;
        }
    }

    // Dynamic-programming pass over one window: every position is inserted into
    // the match finder and relaxed against literal, short-rep, rep, and finder
    // matches using the frozen per-window prices. Fills self.decisions in
    // reverse order and returns the decision count.
    fn planWindow(self: *Encoder, w_start: usize, w_len: usize) usize {
        const opt = self.opt;
        const prices = self.prices;
        const pb_mask = (@as(u32, 1) << @intCast(self.properties.pb)) - 1;
        const lp_mask = (@as(u32, 1) << @intCast(self.properties.lp)) - 1;
        const lc_shift: u5 = @intCast(8 - self.properties.lc);
        opt[0] = .{
            .price = 0,
            .pos_prev = 0,
            .back = back_literal,
            .state = @intCast(self.state),
            .backs = .{ self.rep0, self.rep1, self.rep2, self.rep3 },
        };
        for (opt[1 .. w_len + 1]) |*o| o.price = std.math.maxInt(u32);
        var matches: [match_list_max]MatchPair = undefined;
        var i: usize = 0;
        while (i < w_len) : (i += 1) {
            const node = opt[i];
            const base = node.price;
            const abs = self.input_base + w_start + i;
            const abs32: u32 = @truncate(abs);
            const pos_state = abs32 & pb_mask;
            const state = node.state;
            const state2 = (@as(u32, state) << num_pos_bits_max) + pos_state;
            // Literal: exact tree price from the frozen model.
            const prev_byte: u32 = if (abs == 0) 0 else self.byteAt(abs - 1);
            const lit_state = ((abs32 & lp_mask) << @intCast(self.properties.lc)) + (prev_byte >> lc_shift);
            const lit_row = self.literal_probs[lit_state * literal_probs_count ..][0..literal_probs_count];
            var lit_price = prices.is_match[state2][0];
            if (state < 7) {
                lit_price += self.literal_prices[lit_state * 256 + self.input[w_start + i]];
            } else {
                lit_price += matchedLiteralPrice(lit_row, self.input[w_start + i], self.byteAt(abs - node.backs[0] - 1));
            }
            self.relax(i + 1, base + lit_price, @intCast(i), back_literal, updateStateLiteral(state), &node.backs);
            if (abs > 0) {
                const dist0 = node.backs[0];
                if (dist0 < abs) {
                    // Short rep: one byte copied from rep0.
                    if (self.byteAt(abs) == self.byteAt(abs - dist0 - 1)) {
                        const price = base + prices.is_match[state2][1] + prices.is_rep[state][1] +
                            prices.is_rep_g0[state][0] + prices.is_rep0_long[state2][0];
                        self.relax(i + 1, price, @intCast(i), back_short_rep, updateStateShortRep(state), &node.backs);
                    }
                    // Rep matches: every length of every live rep distance.
                    const rep_base = base + prices.is_match[state2][1] + prices.is_rep[state][1];
                    const max_len = @min(max_match_len, w_len - i);
                    for (0..4) |r| {
                        const dist = node.backs[r] +% 1;
                        // Equal rep distances price identically except for the
                        // index bits, so only the lowest duplicate index matters.
                        if (r > 0 and node.backs[r] == node.backs[r - 1]) continue;
                        if (dist <= abs) {
                            const len_r = self.matchLen(abs - dist, abs, max_len);
                            if (len_r >= match_min_len) {
                                const rb = rep_base + switch (r) {
                                    0 => prices.is_rep_g0[state][0] + prices.is_rep0_long[state2][1],
                                    1 => prices.is_rep_g0[state][1] + prices.is_rep_g1[state][0],
                                    2 => prices.is_rep_g0[state][1] + prices.is_rep_g1[state][1] + prices.is_rep_g2[state][0],
                                    else => prices.is_rep_g0[state][1] + prices.is_rep_g1[state][1] + prices.is_rep_g2[state][1],
                                };
                                var nb: [4]u32 = undefined;
                                nb[0] = node.backs[r];
                                var k: usize = 1;
                                for (0..4) |j| {
                                    if (j != r) {
                                        nb[k] = node.backs[j];
                                        k += 1;
                                    }
                                }
                                const rep_state = updateStateRep(state);
                                var l: usize = match_min_len;
                                while (l <= len_r) : (l += 1) {
                                    self.relax(i + l, rb + prices.rep_len[pos_state][l], @intCast(i), back_rep_base | @as(u32, @intCast(r)), rep_state, &nb);
                                }
                            }
                        }
                    }
                }
            }
            // Normal matches from the finder (also inserts the position).
            const count = self.findMatches(w_start + i, &matches);
            if (count > 0) {
                const mb = base + prices.is_match[state2][1] + prices.is_rep[state][0];
                const match_state = updateStateMatch(state);
                var prev_len: u32 = match_min_len - 1;
                for (matches[0..count]) |mp| {
                    const clip = @min(@as(usize, mp.len), w_len - i);
                    if (clip <= prev_len) break;
                    var nb: [4]u32 = .{ mp.dist - 1, node.backs[0], node.backs[1], node.backs[2] };
                    var l: usize = prev_len + 1;
                    while (l <= clip) : (l += 1) {
                        const len_state = @min(@as(u32, @intCast(l - match_min_len)), num_len_to_pos_states - 1);
                        self.relax(i + l, mb + prices.len[pos_state][l] + self.distPrice(len_state, mp.dist - 1), @intCast(i), mp.dist - 1, match_state, &nb);
                    }
                    prev_len = @intCast(clip);
                }
            }
        }
        var e: usize = w_len;
        var n: usize = 0;
        while (e > 0) {
            const o = opt[e];
            self.decisions[n] = .{ .back = o.back, .len = @intCast(e - o.pos_prev) };
            e = o.pos_prev;
            n += 1;
        }
        return n;
    }

    fn encodeWindow(self: *Encoder, w_start: usize, count: usize) Failure!void {
        const pb_mask = (@as(u32, 1) << @intCast(self.properties.pb)) - 1;
        var d = count;
        var pos = w_start;
        while (d > 0) {
            d -= 1;
            const dec = self.decisions[d];
            const pos_state = self.total_pos & pb_mask;
            const state2 = (self.state << num_pos_bits_max) + pos_state;
            if (dec.back == back_literal) {
                try self.rc.encodeBit(&self.is_match[state2], 0);
                try self.encodeLiteral(&self.rc, self.input[pos]);
                self.state = updateStateLiteral(self.state);
                self.putByte(self.input[pos]);
                pos += 1;
            } else if (dec.back == back_short_rep) {
                try self.rc.encodeBit(&self.is_match[state2], 1);
                try self.rc.encodeBit(&self.is_rep[self.state], 1);
                try self.rc.encodeBit(&self.is_rep_g0[self.state], 0);
                try self.rc.encodeBit(&self.is_rep0_long[state2], 0);
                self.state = updateStateShortRep(self.state);
                self.putByte(self.getByte(self.rep0 + 1));
                pos += 1;
            } else if (dec.back >= back_rep_base) {
                const index: u4 = @intCast(dec.back - back_rep_base);
                try self.rc.encodeBit(&self.is_match[state2], 1);
                try self.rc.encodeBit(&self.is_rep[self.state], 1);
                switch (index) {
                    0 => {
                        try self.rc.encodeBit(&self.is_rep_g0[self.state], 0);
                        try self.rc.encodeBit(&self.is_rep0_long[state2], 1);
                    },
                    1 => {
                        try self.rc.encodeBit(&self.is_rep_g0[self.state], 1);
                        try self.rc.encodeBit(&self.is_rep_g1[self.state], 0);
                        const dist = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = dist;
                    },
                    2 => {
                        try self.rc.encodeBit(&self.is_rep_g0[self.state], 1);
                        try self.rc.encodeBit(&self.is_rep_g1[self.state], 1);
                        try self.rc.encodeBit(&self.is_rep_g2[self.state], 0);
                        const dist = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = dist;
                    },
                    else => {
                        try self.rc.encodeBit(&self.is_rep_g0[self.state], 1);
                        try self.rc.encodeBit(&self.is_rep_g1[self.state], 1);
                        try self.rc.encodeBit(&self.is_rep_g2[self.state], 1);
                        const dist = self.rep3;
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = dist;
                    },
                }
                try self.encodeRepLength(&self.rc, pos_state, dec.len - match_min_len);
                self.state = updateStateRep(self.state);
                self.copyBytes(pos, dec.len);
                pos += dec.len;
            } else {
                const dist = dec.back + 1;
                try self.rc.encodeBit(&self.is_match[state2], 1);
                try self.rc.encodeBit(&self.is_rep[self.state], 0);
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = dist - 1;
                self.state = updateStateMatch(self.state);
                const raw_len = dec.len - match_min_len;
                try self.encodeLength(&self.rc, pos_state, raw_len);
                try self.encodeDistance(&self.rc, raw_len, dist - 1);
                self.copyBytes(pos, dec.len);
                pos += dec.len;
            }
        }
    }

    fn encodeLiteral(self: *Encoder, rc: anytype, byte: u8) Failure!void {
        const prev_byte: u32 = if (self.dict_pos == 0 and !self.dict_full) 0 else self.getByte(1);
        const lit_state = ((self.total_pos & ((@as(u32, 1) << @intCast(self.properties.lp)) - 1)) << @intCast(self.properties.lc)) +
            (prev_byte >> @intCast(8 - self.properties.lc));
        const probs = self.literal_probs[lit_state * literal_probs_count ..][0..literal_probs_count];
        var symbol: u32 = 1;
        var literal = byte;
        if (self.state >= 7) {
            var match_byte = self.getByte(self.rep0 + 1);
            while (symbol < 0x100) {
                const match_bit: u1 = @intCast((match_byte >> 7) & 1);
                match_byte <<= 1;
                const bit: u1 = @intCast((literal >> 7) & 1);
                literal <<= 1;
                try rc.encodeBit(&probs[((@as(u32, 1) + match_bit) << 8) + symbol], bit);
                symbol = (symbol << 1) | bit;
                if (match_bit != bit) break;
            }
        }
        while (symbol < 0x100) {
            const bit: u1 = @intCast((literal >> 7) & 1);
            literal <<= 1;
            try rc.encodeBit(&probs[symbol], bit);
            symbol = (symbol << 1) | bit;
        }
    }

    fn encodeLength(self: *Encoder, rc: anytype, pos_state: u32, len: u32) Failure!void {
        if (len < 8) {
            try rc.encodeBit(&self.len_choice[0], 0);
            try bitTreeEncode(rc, self.len_low[pos_state * (1 << 3) ..][0..(1 << 3)], 3, len);
        } else if (len < 16) {
            try rc.encodeBit(&self.len_choice[0], 1);
            try rc.encodeBit(&self.len_choice[1], 0);
            try bitTreeEncode(rc, self.len_mid[pos_state * (1 << 3) ..][0..(1 << 3)], 3, len - 8);
        } else {
            try rc.encodeBit(&self.len_choice[0], 1);
            try rc.encodeBit(&self.len_choice[1], 1);
            try bitTreeEncode(rc, self.len_high, 8, len - 16);
        }
    }

    fn encodeRepLength(self: *Encoder, rc: anytype, pos_state: u32, len: u32) Failure!void {
        if (len < 8) {
            try rc.encodeBit(&self.rep_len_choice[0], 0);
            try bitTreeEncode(rc, self.rep_len_low[pos_state * (1 << 3) ..][0..(1 << 3)], 3, len);
        } else if (len < 16) {
            try rc.encodeBit(&self.rep_len_choice[0], 1);
            try rc.encodeBit(&self.rep_len_choice[1], 0);
            try bitTreeEncode(rc, self.rep_len_mid[pos_state * (1 << 3) ..][0..(1 << 3)], 3, len - 8);
        } else {
            try rc.encodeBit(&self.rep_len_choice[0], 1);
            try rc.encodeBit(&self.rep_len_choice[1], 1);
            try bitTreeEncode(rc, self.rep_len_high, 8, len - 16);
        }
    }

    fn encodeDistance(self: *Encoder, rc: anytype, raw_len: u32, dist: u32) Failure!void {
        const pos_slot = encodePosSlot(dist);
        var len_state = raw_len;
        if (len_state > num_len_to_pos_states - 1) len_state = num_len_to_pos_states - 1;
        try bitTreeEncode(rc, self.pos_slot_decoders[len_state * (1 << 6) ..][0..(1 << 6)], 6, pos_slot);
        if (pos_slot < 4) return;
        const num_direct_bits = (pos_slot >> 1) - 1;
        const base_dist = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
        const offset = dist - base_dist;
        if (pos_slot < end_pos_model_index) {
            try bitTreeReverseEncode(rc, self.pos_decoders[base_dist - pos_slot ..], @intCast(num_direct_bits), offset);
        } else {
            try rc.encodeDirectBits(offset >> num_align_bits, @intCast(num_direct_bits - num_align_bits));
            try bitTreeReverseEncode(rc, self.align_decoder, num_align_bits, offset & ((@as(u32, 1) << num_align_bits) - 1));
        }
    }

    fn encodeEndMarker(self: *Encoder, rc: anytype) Failure!void {
        const pos_slot: u32 = 63;
        const len_state: u32 = 0;
        try bitTreeEncode(rc, self.pos_slot_decoders[len_state * (1 << 6) ..][0..(1 << 6)], 6, pos_slot);
        const num_direct_bits = (pos_slot >> 1) - 1; // 30
        const base_dist: u32 = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits); // 0xC0000000
        const offset: u32 = 0xFFFFFFFF - base_dist; // 0x3FFFFFFF
        try rc.encodeDirectBits(offset >> num_align_bits, @intCast(num_direct_bits - num_align_bits)); // 0x03FFFFFF, 26 bits
        try bitTreeReverseEncode(rc, self.align_decoder, num_align_bits, offset & ((@as(u32, 1) << num_align_bits) - 1)); // 15
    }

    inline fn byteAt(self: *const Encoder, abs_pos: usize) u8 {
        if (abs_pos >= self.input_base) return self.input[abs_pos - self.input_base];
        return self.dictionary[if (self.dict_mask != 0) abs_pos & self.dict_mask else abs_pos % self.dictionary.len];
    }

    inline fn matchLen(self: *const Encoder, a: usize, b: usize, max_len: usize) usize {
        if (a >= self.input_base) {
            return kernels.matchLen8(self.input, a - self.input_base, b - self.input_base, max_len);
        }
        var len: usize = 0;
        const da = if (self.dict_mask != 0) a & self.dict_mask else a % self.dictionary.len;
        const first_span = @min(@min(self.input_base - a, max_len), self.dictionary.len - da);
        if (first_span > 0) {
            const input_offset = b - self.input_base;
            var l: usize = 0;
            while (l + 8 <= first_span and std.mem.readInt(u64, self.dictionary[da + l ..][0..8], .little) == std.mem.readInt(u64, self.input[input_offset + l ..][0..8], .little)) l += 8;
            while (l < first_span and self.dictionary[da + l] == self.input[input_offset + l]) l += 1;
            len += l;
            if (l < first_span) return len;
        }
        if (len < max_len) {
            const p = a + len;
            if (p >= self.input_base) {
                return len + kernels.matchLen8(self.input, p - self.input_base, b - self.input_base + len, max_len - len);
            }
            while (len < max_len and self.byteAt(a + len) == self.byteAt(b + len)) len += 1;
        }
        return len;
    }

    // Fill `matches` with the improving (len, dist) candidates at pos and
    // insert the position into the finder. Returns the entry count.
    fn findMatches(self: *Encoder, pos: usize, matches: []MatchPair) usize {
        if (self.match_finder == .bt4) return self.btFindMatches(pos, matches);
        return self.hcFindMatches(pos, matches);
    }

    // The bt4 walk records only lengths whose bytes were compared during the
    // descent (the min(len0, len1) prefix is the tree invariant and each step
    // beyond it is byte-checked), so list entries need no re-verification.
    // hash2/hash3 side tables: most recent position for each 2-byte value and
    // each mixed 3-byte key. Covers matches shorter than 4 bytes, which the
    // 4-byte main index structurally cannot pair. Returns entries appended to
    // matches (strictly increasing lengths).
    fn shortMatches(self: *Encoder, pos: usize, matches: []MatchPair) usize {
        const abs_pos = self.input_base + pos;
        if (abs_pos >= std.math.maxInt(u32)) return 0;
        const b = self.input[pos..];
        var count: usize = 0;
        const h2 = @as(u32, b[0]) | (@as(u32, b[1]) << 8);
        const cand2 = self.hash2[h2];
        self.hash2[h2] = @intCast(abs_pos + 1);
        if (cand2 != 0) {
            const delta = abs_pos - (cand2 - 1);
            // The 2-byte value is the index itself, so equality is free.
            if (delta < self.chain_window) {
                matches[count] = .{ .len = 2, .dist = @intCast(delta) };
                count += 1;
            }
        }
        const w3 = h2 | (@as(u32, b[2]) << 16);
        const h3 = (w3 *% 0x9E3779B1) >> @as(u5, @intCast(32 - @as(u6, match_finder_hash3_bits)));
        const cand3 = self.hash3[h3];
        self.hash3[h3] = @intCast(abs_pos + 1);
        if (cand3 != 0) {
            const prev = cand3 - 1;
            const delta = abs_pos - prev;
            if (delta < self.chain_window) {
                // Mixed hash: a collision can share only a prefix, so verify.
                var l: u32 = 0;
                while (l < 3 and self.byteAt(prev + l) == self.byteAt(abs_pos + l)) l += 1;
                if (l >= match_min_len and (count == 0 or l > matches[0].len)) {
                    matches[count] = .{ .len = @intCast(l), .dist = @intCast(delta) };
                    count += 1;
                }
            }
        }
        return count;
    }

    fn btFindMatches(self: *Encoder, pos: usize, matches: []MatchPair) usize {
        const abs_pos = self.input_base + pos;
        // Stored positions are u32; past that boundary there is no window to
        // match against within profile limits, so fall back to the bounded
        // tail scan rather than wrapping the position arithmetic (the same
        // guard the hash-chain and short-match paths carry).
        if (abs_pos >= std.math.maxInt(u32)) return self.tailMatches(pos, matches);
        // Positions without a full max_match_len lookahead never enter the
        // tree: the len == len_limit splice grafts a node on a verified prefix
        // of len_limit bytes, which is only order-safe when len_limit is the
        // format maximum; a chunk tail would splice on a weak prefix and
        // corrupt the ordering every later insert relies on. It also keeps
        // every probe inside the chunk slice.
        if (pos + max_match_len >= self.input.len) return self.tailMatches(pos, matches);
        const len_limit: usize = @min(self.input.len - pos, max_match_len);
        const hash = self.hash4(pos);
        const cyc = abs_pos % self.chain_window;
        var ptr0: *u32 = &self.right[cyc];
        var ptr1: *u32 = &self.left[cyc];
        ptr0.* = 0;
        ptr1.* = 0;
        var cur = self.head[hash];
        self.head[hash] = @intCast(abs_pos);
        var len0: usize = 0;
        var len1: usize = 0;
        var count: usize = self.shortMatches(pos, matches);
        var best_len: usize = if (count > 0) matches[count - 1].len else 0;
        const cm_check = if (abs_pos < self.chain_window) 0 else abs_pos - self.chain_window;
        var depth: u32 = self.match_finder_depth;
        const input = self.input;
        const input_base = self.input_base;
        while (cur != 0 and depth != 0 and cm_check < cur) : (depth -= 1) {
            if (cur == abs_pos) break;
            const delta = abs_pos - cur;
            const pair_slot = if (cyc >= delta) cyc - delta else self.chain_window + cyc - delta;
            const pb = cur;
            var len = @min(len0, len1);
            if (pb >= input_base) {
                const pb_off = @as(usize, pb) - input_base;
                if (input[pb_off + len] == input[pos + len]) {
                    len += 1;
                    if (len != len_limit and input[pb_off + len] == input[pos + len]) {
                        len = self.matchLen(pb, abs_pos, len_limit);
                    }
                    if (best_len < len) {
                        best_len = len;
                        if (count < matches.len) {
                            matches[count] = .{ .len = @intCast(len), .dist = @intCast(delta) };
                            count += 1;
                        }
                        if (len == len_limit) {
                            ptr1.* = self.left[pair_slot];
                            ptr0.* = self.right[pair_slot];
                            return count;
                        }
                    }
                }
                if (input[pb_off + len] < input[pos + len]) {
                    ptr1.* = cur;
                    cur = self.right[pair_slot];
                    ptr1 = &self.right[pair_slot];
                    len1 = len;
                } else {
                    ptr0.* = cur;
                    cur = self.left[pair_slot];
                    ptr0 = &self.left[pair_slot];
                    len0 = len;
                }
                continue;
            }
            const abs_b0 = input[pos + len];
            if (self.byteAt(pb + len) == abs_b0) {
                len += 1;
                if (len != len_limit) {
                    const abs_b1 = input[pos + len];
                    if (self.byteAt(pb + len) == abs_b1) {
                        len = self.matchLen(pb, abs_pos, len_limit);
                    }
                }
                if (best_len < len) {
                    best_len = len;
                    if (count < matches.len) {
                        matches[count] = .{ .len = @intCast(len), .dist = @intCast(delta) };
                        count += 1;
                    }
                    if (len == len_limit) {
                        ptr1.* = self.left[pair_slot];
                        ptr0.* = self.right[pair_slot];
                        return count;
                    }
                }
            }
            const abs_b = input[pos + len];
            if (self.byteAt(pb + len) < abs_b) {
                ptr1.* = cur;
                cur = self.right[pair_slot];
                ptr1 = &self.right[pair_slot];
                len1 = len;
            } else {
                ptr0.* = cur;
                cur = self.left[pair_slot];
                ptr0 = &self.left[pair_slot];
                len0 = len;
            }
        }
        ptr0.* = 0;
        ptr1.* = 0;
        return count;
    }

    fn hcFindMatches(self: *Encoder, pos: usize, matches: []MatchPair) usize {
        // The 4-byte hash key needs four bytes ahead; the last few positions
        // fall back to a bounded scan (at most a couple of positions, so the
        // direct dictionary walk stays cheap).
        if (pos + 4 > self.input.len) return self.tailMatches(pos, matches);
        const abs_pos = self.input_base + pos;
        // Stored positions are u32; beyond that boundary there is no window to
        // match against within profile limits, so emit no match rather than
        // letting the position offset wrap.
        if (abs_pos >= std.math.maxInt(u32)) return 0;
        const max_len: usize = @min(self.input.len - pos, max_match_len);
        const hash = self.hash4(pos);
        const window = self.chain_window;
        const slot = abs_pos % window;
        var prev_stored = self.head[hash];
        self.head[hash] = @intCast(abs_pos + 1);
        self.chain[slot] = prev_stored;
        var count: usize = self.shortMatches(pos, matches);
        var best_len: usize = if (count > 0) matches[count - 1].len else 0;
        var depth: u32 = self.match_finder_depth;
        while (prev_stored != 0 and depth != 0) : (depth -= 1) {
            const prev = @as(usize, prev_stored - 1);
            const delta = abs_pos - prev;
            if (delta >= window) break;
            const len = self.matchLen(prev, abs_pos, max_len);
            if (len > best_len) {
                best_len = len;
                if (count < matches.len) {
                    matches[count] = .{ .len = @intCast(len), .dist = @intCast(delta) };
                    count += 1;
                }
                if (len == max_len or len >= self.nice_len) break;
            }
            const prev_slot = if (slot >= delta) slot - delta else window + slot - delta;
            prev_stored = self.chain[prev_slot];
        }
        return count;
    }

    fn tailMatches(self: *const Encoder, pos: usize, matches: []MatchPair) usize {
        if (pos + 2 > self.input.len) return 0;
        const abs_pos = self.input_base + pos;
        // Tail positions only carry a couple of bytes; cap the direct scan so
        // per-chunk tail work stays bounded regardless of dictionary size.
        const max_dist = @min(@min(@as(usize, abs_pos), @as(usize, self.properties.dictionary_size)), 1 << 12);
        const max_len: usize = @min(self.input.len - pos, max_match_len);
        var best_len: usize = 0;
        var count: usize = 0;
        var dist: usize = 1;
        while (dist <= max_dist) : (dist += 1) {
            const prev = abs_pos - dist;
            if (self.byteAt(abs_pos) != self.byteAt(prev)) continue;
            const len = self.matchLen(prev, abs_pos, max_len);
            if (len > best_len) {
                best_len = len;
                matches[count] = .{ .len = @intCast(len), .dist = @intCast(dist) };
                count += 1;
                if (len >= max_len or count == matches.len) break;
            }
        }
        return count;
    }

    fn hash4(self: *const Encoder, pos: usize) u32 {
        const b = self.input[pos..][0..4];
        const word = @as(u32, b[0]) | (@as(u32, b[1]) << 8) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 24);
        var h = word *% 0x9E3779B1;
        h ^= h >> 16;
        return h & self.hash_mask;
    }

    fn copyBytes(self: *Encoder, pos: usize, len: u32) void {
        var p: usize = pos;
        var remaining: usize = len;
        while (remaining > 0) {
            const n = @min(remaining, self.dictionary.len - self.dict_pos);
            @memcpy(self.dictionary[self.dict_pos..][0..n], self.input[p..][0..n]);
            self.dict_pos += @intCast(n);
            self.total_pos +%= @intCast(n);
            if (self.dict_pos == self.dictionary.len) {
                self.dict_pos = 0;
                self.dict_full = true;
            }
            p += n;
            remaining -= n;
        }
    }

    pub fn putByte(self: *Encoder, byte: u8) void {
        self.dictionary[self.dict_pos] = byte;
        self.dict_pos += 1;
        self.total_pos +%= 1;
        if (self.dict_pos == self.dictionary.len) {
            self.dict_pos = 0;
            self.dict_full = true;
        }
    }

    pub fn setRangeEncoder(self: *Encoder, rc: RangeEncoder) void {
        self.rc = rc;
    }

    // LZMA2 state reset without a dictionary reset (control 0xC0): the model,
    // state, and rep distances return to initial values while the dictionary,
    // finder tables, and position counters continue across the chunk boundary.
    pub fn resetModelKeepDictionary(self: *Encoder) void {
        resetTables(self);
        self.state = 0;
        self.rep0 = 0;
        self.rep1 = 0;
        self.rep2 = 0;
        self.rep3 = 0;
    }

    pub fn snapshotModel(self: *const Encoder, dst: []Prob) void {
        var offset: usize = 0;
        inline for (std.meta.fields(ProbTables)) |field| {
            const slice = @field(self, field.name);
            @memcpy(dst[offset..][0..slice.len], slice);
            offset += slice.len;
        }
    }

    pub fn restoreModel(self: *Encoder, src: []const Prob) void {
        var offset: usize = 0;
        inline for (std.meta.fields(ProbTables)) |field| {
            const slice = @field(self, field.name);
            @memcpy(slice, src[offset..][0..slice.len]);
            offset += slice.len;
        }
    }

    fn getByte(self: *const Encoder, dist: u32) u8 {
        const pos = if (dist <= self.dict_pos) self.dict_pos - dist else @as(u32, @intCast(self.dictionary.len)) - dist + self.dict_pos;
        return self.dictionary[pos];
    }
};

fn encodeInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    const needed = if (options.match_finder == .bt4) encodeWorkspaceSizeBt(options.properties) else encodeWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    var encoder = try Encoder.init(options.properties, writer, scratch, options);
    try encoder.encodeInput(input, options.marker_required);
}

fn encodePosSlot(dist: u32) u32 {
    const d: u64 = dist;
    if (d < 4) return dist;
    const k = 63 - @clz(d);
    const slot_offset = (d - (@as(u64, 1) << @intCast(k))) >> @intCast(k - 1);
    return 2 * @as(u32, @intCast(k)) + @as(u32, @intCast(slot_offset));
}
