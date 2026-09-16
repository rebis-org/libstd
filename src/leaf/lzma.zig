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
        const packed_pb_lp = byte / 9;
        const pb: u4 = @intCast(packed_pb_lp / 5);
        const lp: u4 = @intCast(packed_pb_lp % 5);
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

// Bounded O(depth) walks keep large-input encoding near-linear, not O(n*dictionary).
const match_finder_hash_min_bits: u5 = 12;
const match_finder_hash_max_bits: u5 = 20;
// 4-byte hash cannot pair short matches, so separate hash2/hash3 indices.
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

// No copy fallback: 10 bits/byte covers converged cost plus transient wrongness; strict clamp bound would be ~7x.
// Constant absorbs cache byte, flush, and end marker.
pub fn encodedSizeBound(input_len: usize) usize {
    return input_len +| (input_len / 4) +| 64;
}

const price_scale_shift = 10;
const price_scale = 1 << price_scale_shift;
const bit_price = blk: {
    @setEvalBranchQuota(10000);
    var table: [128]u16 = undefined;
    for (0..128) |i| {
        var probability = (i << 4) + 8;
        if (probability > 2047) probability = 2047;
        const f = @log2(2048.0 / @as(f64, probability));
        table[i] = @intFromFloat(@round(f * price_scale));
    }
    break :blk table;
};

// 8192 plans ahead on frozen prices; smaller cuts long decisions, larger goes stale.
const max_match_len = 273;
const opt_window = 8192;

const distance_literal: u32 = 0xFFFFFFFF;
const distance_short_rep: u32 = 0xFFFFFFFE;
const distance_rep_base: u32 = 0xF0000000; // | rep index; distance-1 never reaches 2^30.

const Opt = struct {
    price: u32,
    previous_position: u16,
    distance: u32,
    state: u8,
    rep_distances: [4]u32,
};

const Decision = struct { distance: u32, length: u32 };

const MatchPair = struct { length: u16, distance: u32 };
const match_list_max = 64;

const PriceTables = struct {
    is_match: [is_match_count][2]u32,
    is_rep: [num_states][2]u32,
    is_rep_g0: [num_states][2]u32,
    is_rep_g1: [num_states][2]u32,
    is_rep_g2: [num_states][2]u32,
    is_rep0_long: [is_rep0_long_count][2]u32,
    length_prices: [low_coder_count][max_match_len + 1]u32,
    repeat_length_prices: [low_coder_count][max_match_len + 1]u32,
    slot: [num_len_to_pos_states][64]u32,
    distance_prices: [num_len_to_pos_states][num_full_distances]u32,
    align_prices: [align_size]u32,
};

// Field order is the workspace order.
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
    // Worst-case padding when scratch is misaligned for u16 tables.
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
    // LZMA2 estimate slices offset into the workspace, so reserve worst-case padding for any base alignment.
    return std.mem.alignForward(usize, plan.required() + (@alignOf(u32) - 1) + (@alignOf(u16) - 1), @alignOf(u64));
}

const RangeDecoder = struct {
    const E = Failure;

    input: Input,
    range: u32,
    code: u32,
    corrupted: bool,

    const Input = union(enum) {
        reader: *std.Io.Reader,
        slice: struct { data: []const u8, position: usize },
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
            .input = .{ .slice = .{ .data = data, .position = 0 } },
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
            .slice => |*input_cursor| read_byte: {
                if (input_cursor.position >= input_cursor.data.len) {
                    return error.InvalidData;
                }
                const byte = input_cursor.data[input_cursor.position];
                input_cursor.position += 1;
                break :read_byte byte;
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
        const probability: u32 = prob.*;
        const bound = (self.range >> prob_total_bits) * probability;
        // Branchless: identity holds mod 2^32, so mask selects the bit-1 case.
        const mask: u32 = 0 -% @as(u32, @intFromBool(self.code >= bound));
        self.code -%= bound & mask;
        self.range = bound +% ((self.range -% bound -% bound) & mask);
        const increase = (((@as(u32, 1) << prob_total_bits) - probability) >> prob_move_bits) & ~mask;
        const decrease = (probability >> prob_move_bits) & mask;
        prob.* = @intCast(probability + increase - decrease);
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
            // Batch up to 7 - @clz(range) bits while keeping range >= top_value.
            const leading_zeros = @clz(self.range);
            const max_batch: u32 = @max(1, 7 - leading_zeros);
            const batch: u5 = @intCast(@min(@as(u32, remaining), max_batch));
            var i: u5 = 0;
            while (i < batch) : (i += 1) {
                self.range >>= 1;
                self.code -%= self.range;
                const top_bit_mask: u32 = 0 -% (self.code >> 31);
                self.code +%= self.range & top_bit_mask;
                if (self.code == self.range) self.corrupted = true;
                res = (res << 1) +% top_bit_mask +% 1;
            }
            remaining -= batch;
        }
        // Match per-bit final normalization so callers see the same state.
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

// Slice-only decoder drops the per-bit error union to keep the hot loop in registers.
const RangeDecoderFast = struct {
    input: struct { data: []const u8, position: usize },
    range: u32,
    code: u32,
    corrupted: bool,

    fn initSlice(data: []const u8) Failure!RangeDecoderFast {
        var self = RangeDecoderFast{
            .input = .{ .data = data, .position = 0 },
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
        const input_cursor = &self.input;
        if (input_cursor.position >= input_cursor.data.len) {
            self.corrupted = true;
            return 0;
        }
        const byte = input_cursor.data[input_cursor.position];
        input_cursor.position += 1;
        return byte;
    }

    inline fn normalize(self: *RangeDecoderFast) void {
        if (self.range < top_value) {
            self.range <<= 8;
            self.code = (self.code << 8) | self.readByte();
        }
    }

    inline fn decodeBit(self: *RangeDecoderFast, prob: *Prob) u1 {
        const probability: u32 = prob.*;
        const bound = (self.range >> prob_total_bits) * probability;
        // Branchless: identity holds mod 2^32, so mask selects the bit-1 case.
        const mask: u32 = 0 -% @as(u32, @intFromBool(self.code >= bound));
        self.code -%= bound & mask;
        self.range = bound +% ((self.range -% bound -% bound) & mask);
        const increase = (((@as(u32, 1) << prob_total_bits) - probability) >> prob_move_bits) & ~mask;
        const decrease = (probability >> prob_move_bits) & mask;
        prob.* = @intCast(probability + increase - decrease);
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
                const top_bit_mask: u32 = 0 -% (self.code >> 31);
                self.code +%= self.range & top_bit_mask;
                if (self.code == self.range) self.corrupted = true;
                res = (res << 1) +% top_bit_mask +% 1;
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
        const probability: u32 = prob.*;
        const bound = (self.range >> prob_total_bits) * probability;
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

inline fn updateProb(prob: *Prob, symbol: u1) void {
    const probability: u32 = prob.*;
    if (symbol == 0) {
        prob.* = @intCast(probability + (((@as(u32, 1) << prob_total_bits) - probability) >> prob_move_bits));
    } else {
        prob.* = @intCast(probability - (probability >> prob_move_bits));
    }
}

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

inline fn bitTreeDecode(range_coder: anytype, probs: []Prob, comptime num_bits: u5) Failure!u32 {
    var node: u32 = 1;
    inline for (0..num_bits) |_| {
        const bit = try range_coder.decodeBit(&probs[node]);
        node = (node << 1) + bit;
    }
    return node - (@as(u32, 1) << num_bits);
}

inline fn bitTreeReverseDecode(range_coder: anytype, probs: []Prob, num_bits: u5) Failure!u32 {
    var node: u32 = 1;
    var symbol: u32 = 0;
    var i: u32 = 0;
    while (i < num_bits) : (i += 1) {
        const bit = try range_coder.decodeBit(&probs[node]);
        node = (node << 1) + bit;
        symbol |= @as(u32, bit) << @intCast(i);
    }
    return symbol;
}

inline fn bitTreeDecodeFast(range_coder: *RangeDecoderFast, probs: []Prob, comptime num_bits: u5) u32 {
    var node: u32 = 1;
    inline for (0..num_bits) |_| {
        const bit = range_coder.decodeBit(&probs[node]);
        node = (node << 1) + bit;
    }
    return node - (@as(u32, 1) << num_bits);
}

inline fn bitTreeReverseDecodeFast(range_coder: *RangeDecoderFast, probs: []Prob, num_bits: u5) u32 {
    var node: u32 = 1;
    var symbol: u32 = 0;
    var i: u32 = 0;
    while (i < num_bits) : (i += 1) {
        const bit = range_coder.decodeBit(&probs[node]);
        node = (node << 1) + bit;
        symbol |= @as(u32, bit) << @intCast(i);
    }
    return symbol;
}

fn bitTreeEncode(range_coder: anytype, probs: []Prob, num_bits: u5, symbol: u32) Failure!void {
    var node: u32 = 1;
    var i = num_bits;
    while (i > 0) : (i -= 1) {
        const bit: u1 = @intCast((symbol >> @intCast(i - 1)) & 1);
        try range_coder.encodeBit(&probs[node], bit);
        node = (node << 1) + bit;
    }
}

fn bitTreeReverseEncode(range_coder: anytype, probs: []Prob, num_bits: u5, symbol: u32) Failure!void {
    var node: u32 = 1;
    var i: u32 = 0;
    while (i < num_bits) : (i += 1) {
        const bit: u1 = @intCast((symbol >> @intCast(i)) & 1);
        try range_coder.encodeBit(&probs[node], bit);
        node = (node << 1) + bit;
    }
}

pub fn DecoderOf(comptime slice_input: bool) type {
    const RC = if (slice_input) RangeDecoderFast else RangeDecoder;
    return struct {
        const Self = @This();

        properties: Properties,
        dictionary: []u8,
        dictionary_pos: u32,
        dictionary_full: bool,
        // Reset cannot rewind in-place output, so it acts as a distance-validation floor.
        dictionary_floor: u32,
        total_pos: u32,
        range_coder: RC,
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
        staging_buffer: [4096]u8,
        staging_length: usize,
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
            // Tables assigned and filled before the decoder runs, so `undefined` is safe.
            var self = Self{
                .properties = properties,
                .dictionary = dictionary,
                .dictionary_pos = 0,
                .dictionary_full = false,
                .dictionary_floor = 0,
                .total_pos = 0,
                .range_coder = undefined,
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
                .staging_buffer = undefined,
                .staging_length = 0,
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
            // Tables assigned and filled before the decoder runs, so `undefined` is safe.
            var self = Self{
                .properties = properties,
                .dictionary = output,
                .dictionary_pos = 0,
                .dictionary_full = false,
                .dictionary_floor = 0,
                .total_pos = 0,
                .range_coder = undefined,
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
                .staging_buffer = undefined,
                .staging_length = 0,
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
            self.range_coder = try RC.init(_reader);
        }

        pub fn resetReaderSlice(self: *Self, data: []const u8) Failure!void {
            self.range_coder = try RC.initSlice(data);
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
                self.dictionary_pos = 0;
                self.dictionary_full = false;
            } else {
                // Output is the dictionary, so record reset as a floor instead of rewinding.
                self.dictionary_floor = self.dictionary_pos;
            }
        }

        pub fn resetProbabilities(self: *Self) void {
            resetTables(self);
        }

        pub fn feedByte(self: *Self, byte: u8) void {
            self.dictionary[self.dictionary_pos] = byte;
            self.dictionary_pos += 1;
            self.total_pos +%= 1;
            if (self.dictionary_pos == self.dictionary.len) {
                if (self.clear_dictionary) {
                    self.dictionary_pos = 0;
                    self.dictionary_full = true;
                }
            }
        }

        pub fn decodeToOutput(self: *Self, output: ?[]u8, unpack_size: ?u64, marker_required: bool) Failure!void {
            self.output_buffer = output;
            self.output_pos = 0;
            var remaining: ?u64 = unpack_size;
            if (comptime slice_input) {
                // Locals keep per-bit work in registers, not round-tripping memory.
                var range_coder = self.range_coder;
                defer self.range_coder = range_coder;
                var prev_byte: u32 = if (self.dictionary_pos == 0 and !self.dictionary_full) 0 else self.getByte(1);
                while (true) {
                    if (range_coder.corrupted) return error.InvalidData;
                    if (remaining) |*remaining_count| {
                        if (remaining_count.* == 0) {
                            if (!marker_required) {
                                if (range_coder.isFinishedOk()) {
                                    try self.finishOutput();
                                    return;
                                }
                                try self.finishOutput();
                                return;
                            }
                        }
                    }
                    const position_state = self.total_pos & ((@as(u32, 1) << @intCast(self.properties.pb)) - 1);
                    const state2 = (self.state << num_pos_bits_max) + position_state;
                    if (range_coder.decodeBit(&self.is_match[state2]) == 0) {
                        prev_byte = try self.decodeLiteral(&range_coder, prev_byte);
                        self.state = updateStateLiteral(self.state);
                        if (remaining) |*remaining_count| remaining_count.* -= 1;
                        continue;
                    }
                    // Assigned on both match branches, so `undefined` is safe.
                    var length: u32 = undefined;
                    if (range_coder.decodeBit(&self.is_rep[self.state]) == 0) {
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.state = updateStateMatch(self.state);
                        length = try self.decodeLength(&range_coder, position_state, false);
                        self.rep0 = try self.decodeDistance(&range_coder, length);
                        if (self.rep0 == 0xFFFFFFFF) {
                            if (!range_coder.isFinishedOk()) return error.InvalidData;
                            if (marker_required and remaining != null and remaining.? != 0) return error.InvalidData;
                            try self.finishOutput();
                            return;
                        }
                        if (self.rep0 >= self.properties.dictionary_size or !self.checkDistance(self.rep0)) return error.InvalidData;
                    } else {
                        if (self.dictionary_pos == 0 and !self.dictionary_full) return error.InvalidData;
                        if (range_coder.decodeBit(&self.is_rep_g0[self.state]) == 0) {
                            if (range_coder.decodeBit(&self.is_rep0_long[state2]) == 0) {
                                self.state = updateStateShortRep(self.state);
                                const byte = self.getByte(self.rep0 + 1);
                                try self.putByte(byte);
                                prev_byte = byte;
                                if (remaining) |*remaining_count| remaining_count.* -= 1;
                                continue;
                            }
                        } else {
                            if (range_coder.decodeBit(&self.is_rep_g1[self.state]) == 0) {
                                const distance = self.rep1;
                                self.rep1 = self.rep0;
                                self.rep0 = distance;
                            } else {
                                if (range_coder.decodeBit(&self.is_rep_g2[self.state]) == 0) {
                                    const distance = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = distance;
                                } else {
                                    const distance = self.rep3;
                                    self.rep3 = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = distance;
                                }
                            }
                        }
                        length = try self.decodeLength(&range_coder, position_state, true);
                        self.state = updateStateRep(self.state);
                    }
                    length += match_min_len;
                    var is_error = false;
                    if (remaining) |*remaining_count| {
                        if (remaining_count.* < length) {
                            length = @intCast(remaining_count.*);
                            is_error = true;
                        }
                        remaining_count.* -= length;
                    }
                    try self.copyMatch(self.rep0 + 1, length);
                    if (is_error) return error.InvalidData;
                    prev_byte = self.getByte(1);
                }
            } else {
                var prev_byte: u32 = if (self.dictionary_pos == 0 and !self.dictionary_full) 0 else self.getByte(1);
                while (true) {
                    if (remaining) |*remaining_count| {
                        if (remaining_count.* == 0) {
                            if (!marker_required) {
                                if (self.range_coder.isFinishedOk()) {
                                    try self.finishOutput();
                                    return;
                                }
                                try self.finishOutput();
                                return;
                            }
                        }
                    }
                    const position_state = self.total_pos & ((@as(u32, 1) << @intCast(self.properties.pb)) - 1);
                    const state2 = (self.state << num_pos_bits_max) + position_state;
                    if (try self.range_coder.decodeBit(&self.is_match[state2]) == 0) {
                        prev_byte = try self.decodeLiteral(&self.range_coder, prev_byte);
                        self.state = updateStateLiteral(self.state);
                        if (remaining) |*remaining_count| remaining_count.* -= 1;
                        continue;
                    }
                    // Assigned on both match branches, so `undefined` is safe.
                    var length: u32 = undefined;
                    if (try self.range_coder.decodeBit(&self.is_rep[self.state]) == 0) {
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.state = updateStateMatch(self.state);
                        length = try self.decodeLength(&self.range_coder, position_state, false);
                        self.rep0 = try self.decodeDistance(&self.range_coder, length);
                        if (self.rep0 == 0xFFFFFFFF) {
                            if (!self.range_coder.isFinishedOk()) return error.InvalidData;
                            if (marker_required and remaining != null and remaining.? != 0) return error.InvalidData;
                            try self.finishOutput();
                            return;
                        }
                        if (self.rep0 >= self.properties.dictionary_size or !self.checkDistance(self.rep0)) return error.InvalidData;
                    } else {
                        if (self.dictionary_pos == 0 and !self.dictionary_full) return error.InvalidData;
                        if (try self.range_coder.decodeBit(&self.is_rep_g0[self.state]) == 0) {
                            if (try self.range_coder.decodeBit(&self.is_rep0_long[state2]) == 0) {
                                self.state = updateStateShortRep(self.state);
                                const byte = self.getByte(self.rep0 + 1);
                                try self.putByte(byte);
                                prev_byte = byte;
                                if (remaining) |*remaining_count| remaining_count.* -= 1;
                                continue;
                            }
                        } else {
                            if (try self.range_coder.decodeBit(&self.is_rep_g1[self.state]) == 0) {
                                const distance = self.rep1;
                                self.rep1 = self.rep0;
                                self.rep0 = distance;
                            } else {
                                if (try self.range_coder.decodeBit(&self.is_rep_g2[self.state]) == 0) {
                                    const distance = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = distance;
                                } else {
                                    const distance = self.rep3;
                                    self.rep3 = self.rep2;
                                    self.rep2 = self.rep1;
                                    self.rep1 = self.rep0;
                                    self.rep0 = distance;
                                }
                            }
                        }
                        length = try self.decodeLength(&self.range_coder, position_state, true);
                        self.state = updateStateRep(self.state);
                    }
                    length += match_min_len;
                    var is_error = false;
                    if (remaining) |*remaining_count| {
                        if (remaining_count.* < length) {
                            length = @intCast(remaining_count.*);
                            is_error = true;
                        }
                        remaining_count.* -= length;
                    }
                    try self.copyMatch(self.rep0 + 1, length);
                    if (is_error) return error.InvalidData;
                    prev_byte = self.getByte(1);
                }
            }
        }

        fn decodeLiteral(self: *Self, range_coder: *RC, prev_byte: u32) Failure!u8 {
            const lit_state = ((self.total_pos & ((@as(u32, 1) << @intCast(self.properties.lp)) - 1)) << @intCast(self.properties.lc)) +
                (prev_byte >> @intCast(8 - self.properties.lc));
            const probs = self.literal_probs[lit_state * literal_probs_count ..][0..literal_probs_count];
            var symbol: u32 = 1;
            if (comptime slice_input) {
                if (self.state >= 7) {
                    var match = self.getByte(self.rep0 + 1);
                    var use_match = true;
                    // Exactly 8 steps: symbol stays below 0x100 until the last shift.
                    inline for (0..8) |_| {
                        if (use_match) {
                            const match_bit: u32 = (match >> 7) & 1;
                            match <<= 1;
                            const bit = range_coder.decodeBit(&probs[((1 + match_bit) << 8) + symbol]);
                            symbol = (symbol << 1) | bit;
                            if (match_bit != bit) use_match = false;
                        } else {
                            const bit = range_coder.decodeBit(&probs[symbol]);
                            symbol = (symbol << 1) | bit;
                        }
                    }
                } else {
                    inline for (0..8) |_| {
                        const bit = range_coder.decodeBit(&probs[symbol]);
                        symbol = (symbol << 1) | bit;
                    }
                }
                if (range_coder.corrupted) return error.InvalidData;
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
                            const bit = try range_coder.decodeBit(&probs[((1 + match_bit) << 8) + symbol]);
                            symbol = (symbol << 1) | bit;
                            if (match_bit != bit) use_match = false;
                        } else {
                            const bit = try range_coder.decodeBit(&probs[symbol]);
                            symbol = (symbol << 1) | bit;
                        }
                    }
                } else {
                    inline for (0..8) |_| {
                        const bit = try range_coder.decodeBit(&probs[symbol]);
                        symbol = (symbol << 1) | bit;
                    }
                }
                const byte: u8 = @intCast(symbol - 0x100);
                try self.putByte(byte);
                return byte;
            }
        }

        fn decodeLength(self: *Self, range_coder: *RC, position_state: u32, comptime is_rep: bool) Failure!u32 {
            const choice = if (is_rep) &self.rep_len_choice[0] else &self.len_choice[0];
            const choice2 = if (is_rep) &self.rep_len_choice[1] else &self.len_choice[1];
            const low = if (is_rep) self.rep_len_low else self.len_low;
            const mid = if (is_rep) self.rep_len_mid else self.len_mid;
            const high = if (is_rep) self.rep_len_high else self.len_high;
            if (comptime slice_input) {
                if (range_coder.decodeBit(choice) == 0) {
                    const res = bitTreeDecodeFast(range_coder, low[position_state * (1 << 3) ..][0..(1 << 3)], 3);
                    if (range_coder.corrupted) return error.InvalidData;
                    return res;
                }
                if (range_coder.decodeBit(choice2) == 0) {
                    const res = 8 + bitTreeDecodeFast(range_coder, mid[position_state * (1 << 3) ..][0..(1 << 3)], 3);
                    if (range_coder.corrupted) return error.InvalidData;
                    return res;
                }
                const res = 16 + bitTreeDecodeFast(range_coder, high, 8);
                if (range_coder.corrupted) return error.InvalidData;
                return res;
            }
            if (try range_coder.decodeBit(choice) == 0) {
                return try bitTreeDecode(range_coder, low[position_state * (1 << 3) ..][0..(1 << 3)], 3);
            }
            if (try range_coder.decodeBit(choice2) == 0) {
                return 8 + try bitTreeDecode(range_coder, mid[position_state * (1 << 3) ..][0..(1 << 3)], 3);
            }
            return 16 + try bitTreeDecode(range_coder, high, 8);
        }

        fn decodeDistance(self: *Self, range_coder: *RC, length: u32) Failure!u32 {
            var length_state = length;
            if (length_state > num_len_to_pos_states - 1) length_state = num_len_to_pos_states - 1;
            if (comptime slice_input) {
                const pos_slot = bitTreeDecodeFast(range_coder, self.pos_slot_decoders[length_state * (1 << 6) ..][0..(1 << 6)], 6);
                if (range_coder.corrupted) return error.InvalidData;
                if (pos_slot < 4) return pos_slot;
                const num_direct_bits = (pos_slot >> 1) - 1;
                var distance: u32 = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
                if (pos_slot < end_pos_model_index) {
                    distance += bitTreeReverseDecodeFast(range_coder, self.pos_decoders[distance - pos_slot ..], @intCast(num_direct_bits));
                } else {
                    distance += (range_coder.decodeDirectBits(@intCast(num_direct_bits - num_align_bits))) << num_align_bits;
                    distance += bitTreeReverseDecodeFast(range_coder, self.align_decoder, num_align_bits);
                }
                if (range_coder.corrupted) return error.InvalidData;
                return distance;
            }
            const pos_slot = try bitTreeDecode(range_coder, self.pos_slot_decoders[length_state * (1 << 6) ..][0..(1 << 6)], 6);
            if (pos_slot < 4) return pos_slot;
            const num_direct_bits = (pos_slot >> 1) - 1;
            var distance: u32 = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
            if (pos_slot < end_pos_model_index) {
                distance += try bitTreeReverseDecode(range_coder, self.pos_decoders[distance - pos_slot ..], @intCast(num_direct_bits));
            } else {
                distance += (try range_coder.decodeDirectBits(@intCast(num_direct_bits - num_align_bits))) << num_align_bits;
                distance += try bitTreeReverseDecode(range_coder, self.align_decoder, num_align_bits);
            }
            return distance;
        }

        fn putByte(self: *Self, byte: u8) Failure!void {
            if (!self.clear_dictionary and self.dictionary_pos >= self.dictionary.len) return error.InsufficientCapacity;
            self.dictionary[self.dictionary_pos] = byte;
            self.dictionary_pos += 1;
            self.total_pos +%= 1;
            if (self.dictionary_pos == self.dictionary.len) {
                self.dictionary_pos = 0;
                self.dictionary_full = true;
            }
            if (self.output_buffer) |output| {
                if (self.output_pos >= output.len) return error.InsufficientCapacity;
                output[self.output_pos] = byte;
                self.output_pos += 1;
            } else if (self.output_writer) |writer| {
                self.staging_buffer[self.staging_length] = byte;
                self.staging_length += 1;
                self.output_pos += 1;
                if (self.staging_length == self.staging_buffer.len) try self.flushOutput(writer);
            } else {
                self.output_pos += 1;
            }
        }

        fn flushOutput(self: *Self, writer: *std.Io.Writer) Failure!void {
            try io.writeBytes(writer, self.staging_buffer[0..self.staging_length]);
            self.staging_length = 0;
        }

        fn finishOutput(self: *Self) Failure!void {
            if (self.output_writer) |writer| {
                if (self.staging_length > 0) try self.flushOutput(writer);
            }
        }

        fn getByte(self: Self, distance: u32) u8 {
            const position = if (distance <= self.dictionary_pos) self.dictionary_pos - distance else @as(u32, @intCast(self.dictionary.len)) - distance + self.dictionary_pos;
            return self.dictionary[position];
        }

        fn checkDistance(self: Self, distance: u32) bool {
            // 0-based distance reaches distance+1 distance; in-place matches may not cross the reset floor.
            if (!self.clear_dictionary) return distance < self.dictionary_pos - self.dictionary_floor;
            return distance < self.dictionary_pos or self.dictionary_full;
        }

        fn copyMatch(self: *Self, distance: u32, length: u32) Failure!void {
            // Linear dictionary: source is contiguous and before dest, so one forward copy covers it.
            if (!self.clear_dictionary) {
                if (self.dictionary_pos + length > self.dictionary.len) return error.InsufficientCapacity;
                kernels.copyMatch(self.dictionary, self.dictionary_pos, distance, length);
                self.dictionary_pos += length;
                self.total_pos +%= length;
                return;
            }
            var remaining = length;
            while (remaining > 0) {
                if (self.dictionary_pos >= self.dictionary.len) return error.InsufficientCapacity;
                const source = if (distance <= self.dictionary_pos)
                    self.dictionary_pos - distance
                else
                    self.dictionary.len - distance + self.dictionary_pos;
                var chunk = @min(@as(usize, remaining), self.dictionary.len - self.dictionary_pos);
                if (source > self.dictionary_pos) chunk = @min(chunk, self.dictionary.len - source);
                if (self.output_buffer) |output| {
                    chunk = @min(chunk, output.len - self.output_pos);
                    if (chunk == 0) return error.InsufficientCapacity;
                }
                if (source < self.dictionary_pos) {
                    var covered: usize = distance;
                    var done: usize = 0;
                    while (done < chunk) {
                        const take = @min(covered, chunk - done);
                        @memcpy(self.dictionary[self.dictionary_pos + done ..][0..take], self.dictionary[self.dictionary_pos + done - covered ..][0..take]);
                        done += take;
                        covered += take;
                    }
                } else {
                    @memmove(self.dictionary[self.dictionary_pos..][0..chunk], self.dictionary[source..][0..chunk]);
                }
                if (self.output_buffer) |output| {
                    @memcpy(output[self.output_pos..][0..chunk], self.dictionary[self.dictionary_pos..][0..chunk]);
                    self.output_pos += chunk;
                } else if (self.output_writer) |writer| {
                    var offset: usize = 0;
                    while (offset < chunk) {
                        const take = @min(chunk - offset, self.staging_buffer.len - self.staging_length);
                        @memcpy(self.staging_buffer[self.staging_length..][0..take], self.dictionary[self.dictionary_pos + offset ..][0..take]);
                        self.staging_length += take;
                        offset += take;
                        if (self.staging_length == self.staging_buffer.len) try self.flushOutput(writer);
                    }
                    self.output_pos += chunk;
                } else {
                    self.output_pos += chunk;
                }
                self.dictionary_pos += @intCast(chunk);
                if (self.dictionary_pos == self.dictionary.len) {
                    self.dictionary_pos = 0;
                    self.dictionary_full = true;
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
    for (probs) |*prob_entry| prob_entry.* = prob_init;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    const needed = decodeWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    if (input.len + output.len > options.max_work) return error.ResourceLimit;
    // Output doubles as dictionary window, avoiding a separate copy.
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

// Greedy live-model pass for the LZMA2 probe; dictionary clamps to chunk size so clears scale with chunk.
// Calibration documented at the lzma2 probe.
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
    const payload = std.math.cast(usize, (price + (1 << 13) - 1) >> 13) orelse return error.ResourceLimit;
    // 5 flush bytes plus the cache byte.
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
    dictionary_pos: u32,
    dictionary_full: bool,
    total_pos: u32,
    head: []u32,
    chain: []u32,
    left: []u32,
    right: []u32,
    hash2: []u32,
    hash3: []u32,
    hash_mask: u32,
    dictionary_mask: u32,
    chain_window: usize,
    range_coder: RangeEncoder,
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
        // Tables assigned and filled before the encoder runs, so `undefined` is safe.
        var self = Encoder{
            .properties = properties,
            .dictionary = dictionary,
            .dictionary_pos = 0,
            .dictionary_full = false,
            .total_pos = 0,
            .head = head,
            .chain = chain,
            .left = left,
            .right = right,
            .hash2 = hash2,
            .hash3 = hash3,
            .hash_mask = @intCast(matchFinderHashSize(properties.dictionary_size) - 1),
            .dictionary_mask = if (properties.dictionary_size & (properties.dictionary_size - 1) == 0) properties.dictionary_size - 1 else 0,
            .chain_window = matchFinderChainSize(properties.dictionary_size),
            .range_coder = RangeEncoder.init(writer),
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
        if (bit == 0) return bit_price[idx];
        const complement = 2048 - @as(u32, prob);
        const idx1 = if (complement > 2047) 127 else complement >> 4;
        return bit_price[idx1];
    }

    inline fn bitTreePrice(comptime num_bits: u5, probs: []const Prob, symbol: u32) u32 {
        var price: u32 = 0;
        var node: u32 = 1;
        inline for (0..num_bits) |i| {
            const bit = (symbol >> @intCast(num_bits - 1 - i)) & 1;
            price += priceBit(probs[node], @intCast(bit));
            node = (node << 1) | bit;
        }
        return price;
    }

    inline fn bitTreeReversePrice(num_bits: u5, probs: []const Prob, symbol: u32) u32 {
        var price: u32 = 0;
        var node: u32 = 1;
        var i: u5 = 0;
        while (i < num_bits) : (i += 1) {
            const bit = (symbol >> i) & 1;
            price += priceBit(probs[node], @intCast(bit));
            node = (node << 1) | bit;
        }
        return price;
    }

    inline fn matchedLiteralPrice(probs: []const Prob, literal: u8, match_byte: u8) u32 {
        var price: u32 = 0;
        var symbol: u32 = 1;
        var lit: u32 = literal;
        var match_bits: u32 = match_byte;
        var use_match = true;
        inline for (0..8) |_| {
            if (symbol >= 0x100) break;
            const match_bit = (match_bits >> 7) & 1;
            match_bits <<= 1;
            const bit = (lit >> 7) & 1;
            lit <<= 1;
            const idx = if (use_match) ((1 + match_bit) << 8) + symbol else symbol;
            price += priceBit(probs[idx], @intCast(bit));
            symbol = (symbol << 1) | bit;
            if (match_bit != bit) use_match = false;
        }
        return price;
    }

    fn buildPrices(self: *Encoder) void {
        const prices = self.prices;
        for (self.is_match, 0..) |probability, i| {
            prices.is_match[i][0] = priceBit(probability, 0);
            prices.is_match[i][1] = priceBit(probability, 1);
        }
        for (self.is_rep, 0..) |probability, i| {
            prices.is_rep[i][0] = priceBit(probability, 0);
            prices.is_rep[i][1] = priceBit(probability, 1);
        }
        for (self.is_rep_g0, 0..) |probability, i| {
            prices.is_rep_g0[i][0] = priceBit(probability, 0);
            prices.is_rep_g0[i][1] = priceBit(probability, 1);
        }
        for (self.is_rep_g1, 0..) |probability, i| {
            prices.is_rep_g1[i][0] = priceBit(probability, 0);
            prices.is_rep_g1[i][1] = priceBit(probability, 1);
        }
        for (self.is_rep_g2, 0..) |probability, i| {
            prices.is_rep_g2[i][0] = priceBit(probability, 0);
            prices.is_rep_g2[i][1] = priceBit(probability, 1);
        }
        for (self.is_rep0_long, 0..) |probability, i| {
            prices.is_rep0_long[i][0] = priceBit(probability, 0);
            prices.is_rep0_long[i][1] = priceBit(probability, 1);
        }
        const pos_states: usize = @as(usize, 1) << @intCast(self.properties.pb);
        for (0..pos_states) |position_state| {
            const low = self.len_low[position_state * (1 << 3) ..][0..(1 << 3)];
            const mid = self.len_mid[position_state * (1 << 3) ..][0..(1 << 3)];
            const low_rep = self.rep_len_low[position_state * (1 << 3) ..][0..(1 << 3)];
            const mid_rep = self.rep_len_mid[position_state * (1 << 3) ..][0..(1 << 3)];
            const c0 = priceBit(self.len_choice[0], 0);
            const c10 = priceBit(self.len_choice[0], 1) + priceBit(self.len_choice[1], 0);
            const c11 = priceBit(self.len_choice[0], 1) + priceBit(self.len_choice[1], 1);
            const r0 = priceBit(self.rep_len_choice[0], 0);
            const r10 = priceBit(self.rep_len_choice[0], 1) + priceBit(self.rep_len_choice[1], 0);
            const r11 = priceBit(self.rep_len_choice[0], 1) + priceBit(self.rep_len_choice[1], 1);
            var raw: u32 = 0;
            while (raw <= max_match_len - match_min_len) : (raw += 1) {
                const length = raw + match_min_len;
                if (raw < 8) {
                    prices.length_prices[position_state][length] = c0 + bitTreePrice(3, low, raw);
                    prices.repeat_length_prices[position_state][length] = r0 + bitTreePrice(3, low_rep, raw);
                } else if (raw < 16) {
                    prices.length_prices[position_state][length] = c10 + bitTreePrice(3, mid, raw - 8);
                    prices.repeat_length_prices[position_state][length] = r10 + bitTreePrice(3, mid_rep, raw - 8);
                } else {
                    prices.length_prices[position_state][length] = c11 + bitTreePrice(8, self.len_high, raw - 16);
                    prices.repeat_length_prices[position_state][length] = r11 + bitTreePrice(8, self.rep_len_high, raw - 16);
                }
            }
        }
        for (0..num_len_to_pos_states) |length_state| {
            const slot_probs = self.pos_slot_decoders[length_state * (1 << 6) ..][0..(1 << 6)];
            var slot: u32 = 0;
            while (slot < 64) : (slot += 1) {
                prices.slot[length_state][slot] = bitTreePrice(6, slot_probs, slot);
            }
            var distance: u32 = 0;
            while (distance < num_full_distances) : (distance += 1) {
                if (distance < 4) {
                    prices.distance_prices[length_state][distance] = prices.slot[length_state][distance];
                    continue;
                }
                const pos_slot = encodePosSlot(distance);
                const direct_count: u5 = @intCast((pos_slot >> 1) - 1);
                const base_dist = (@as(u32, 2) | (pos_slot & 1)) << direct_count;
                prices.distance_prices[length_state][distance] = prices.slot[length_state][pos_slot] +
                    bitTreeReversePrice(direct_count, self.pos_decoders[base_dist - pos_slot ..], distance - base_dist);
            }
        }
        var align_index: u32 = 0;
        while (align_index < align_size) : (align_index += 1) {
            prices.align_prices[align_index] = bitTreeReversePrice(num_align_bits, self.align_decoder, align_index);
        }
        const contexts = self.properties.literalContextCount();
        for (0..contexts) |ctx| {
            const probs = self.literal_probs[ctx * literal_probs_count ..][0..literal_probs_count];
            var sym: u32 = 0;
            while (sym < 256) : (sym += 1) {
                var price: u32 = 0;
                var node: u32 = 1;
                inline for (0..8) |i| {
                    const bit = (sym >> @intCast(7 - i)) & 1;
                    price += priceBit(probs[node], @intCast(bit));
                    node = (node << 1) | bit;
                }
                self.literal_prices[ctx * 256 + sym] = price;
            }
        }
    }

    inline fn distancePrice(self: *const Encoder, length_state: u32, distance: u32) u32 {
        if (distance < num_full_distances) return self.prices.distance_prices[length_state][distance];
        const slot = encodePosSlot(distance);
        const direct_count = (slot >> 1) - 1;
        return self.prices.slot[length_state][slot] +
            (direct_count - num_align_bits) * price_scale +
            self.prices.align_prices[distance & (align_size - 1)];
    }

    pub fn encodeInput(self: *Encoder, input: []const u8, marker_required: bool) Failure!void {
        self.input = input;
        self.input_base = self.total_pos;
        var position: usize = 0;
        while (position < input.len) {
            const window_length = @min(opt_window, input.len - position);
            self.buildPrices();
            const count = self.planWindow(position, window_length);
            try self.encodeWindow(position, count);
            position += window_length;
        }
        if (marker_required) {
            const position_state = self.total_pos & ((@as(u32, 1) << @intCast(self.properties.pb)) - 1);
            const state2 = (self.state << num_pos_bits_max) + position_state;
            try self.range_coder.encodeBit(&self.is_match[state2], 1);
            try self.range_coder.encodeBit(&self.is_rep[self.state], 0);
            self.rep3 = self.rep2;
            self.rep2 = self.rep1;
            self.rep1 = self.rep0;
            self.state = updateStateMatch(self.state);
            try self.encodeLength(&self.range_coder, position_state, 0);
            try self.encodeEndMarker(&self.range_coder);
        }
        try self.range_coder.finish();
        self.input = &.{};
    }

    // Price-aware acceptance stops sparse far matches inflating past the pack boundary.
    fn literalLivePrice(self: *const Encoder, byte: u8) u32 {
        const prev_byte: u32 = if (self.dictionary_pos == 0 and !self.dictionary_full) 0 else self.getByte(1);
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

    fn lengthLivePrice(choice: []const Prob, low: []const Prob, mid: []const Prob, high: []const Prob, position_state: u32, raw_length: u32) u32 {
        if (raw_length < 8) return priceBit(choice[0], 0) + bitTreePrice(3, low[position_state * (1 << 3) ..][0..(1 << 3)], raw_length);
        if (raw_length < 16) return priceBit(choice[0], 1) + priceBit(choice[1], 0) + bitTreePrice(3, mid[position_state * (1 << 3) ..][0..(1 << 3)], raw_length - 8);
        return priceBit(choice[0], 1) + priceBit(choice[1], 1) + bitTreePrice(8, high, raw_length - 16);
    }

    fn distanceLivePrice(self: *const Encoder, raw_length: u32, distance: u32) u32 {
        const pos_slot = encodePosSlot(distance);
        const length_state: u32 = @min(raw_length, num_len_to_pos_states - 1);
        const price = bitTreePrice(6, self.pos_slot_decoders[length_state * (1 << 6) ..][0..(1 << 6)], pos_slot);
        if (pos_slot < 4) return price;
        const num_direct_bits: u5 = @intCast((pos_slot >> 1) - 1);
        const base_dist = (@as(u32, 2) | (pos_slot & 1)) << num_direct_bits;
        const offset = distance - base_dist;
        if (pos_slot < end_pos_model_index) {
            return price + bitTreeReversePrice(num_direct_bits, self.pos_decoders[base_dist - pos_slot ..], offset);
        }
        return price + @as(u32, num_direct_bits - num_align_bits) * price_scale +
            bitTreeReversePrice(num_align_bits, self.align_decoder, offset & (align_size - 1));
    }

    fn matchLivePrice(self: *const Encoder, state2: u32, position_state: u32, distance: u32, length: usize) u32 {
        const raw_length: u32 = @intCast(length - match_min_len);
        return priceBit(self.is_match[state2], 1) + priceBit(self.is_rep[self.state], 0) +
            lengthLivePrice(self.len_choice, self.len_low, self.len_mid, self.len_high, position_state, raw_length) +
            self.distanceLivePrice(raw_length, distance - 1);
    }

    fn repLivePrice(self: *const Encoder, state2: u32, position_state: u32, rep_index: usize, length: usize) u32 {
        var price = priceBit(self.is_match[state2], 1) + priceBit(self.is_rep[self.state], 1);
        price += switch (rep_index) {
            0 => priceBit(self.is_rep_g0[self.state], 0) + priceBit(self.is_rep0_long[state2], 1),
            1 => priceBit(self.is_rep_g0[self.state], 1) + priceBit(self.is_rep_g1[self.state], 0),
            2 => priceBit(self.is_rep_g0[self.state], 1) + priceBit(self.is_rep_g1[self.state], 1) + priceBit(self.is_rep_g2[self.state], 0),
            else => priceBit(self.is_rep_g0[self.state], 1) + priceBit(self.is_rep_g1[self.state], 1) + priceBit(self.is_rep_g2[self.state], 1),
        };
        const raw_length: u32 = @intCast(length - match_min_len);
        return price + lengthLivePrice(self.rep_len_choice, self.rep_len_low, self.rep_len_mid, self.rep_len_high, position_state, raw_length);
    }

    // Insert-only: covered positions feed tables without the chain walk; bt4 sees fewer offers but stays safe.
    fn insertSkipped(self: *Encoder, position: usize, length: usize) void {
        if (self.match_finder != .hash_chain) return;
        var cursor = position + 1;
        const span_end = position + length;
        while (cursor < span_end) : (cursor += 1) {
            if (cursor + 4 > self.input.len) return;
            const abs_pos = self.input_base + cursor;
            if (abs_pos >= std.math.maxInt(u32)) return;
            const hash = self.hash4(cursor);
            const slot = abs_pos % self.chain_window;
            self.chain[slot] = self.head[hash];
            self.head[hash] = @intCast(abs_pos + 1);
            const remaining_input = self.input[cursor..];
            const h2 = @as(u32, remaining_input[0]) | (@as(u32, remaining_input[1]) << 8);
            self.hash2[h2] = @intCast(abs_pos + 1);
            const w3 = h2 | (@as(u32, remaining_input[2]) << 16);
            const h3 = (w3 *% 0x9E3779B1) >> @as(u5, @intCast(32 - @as(u6, match_finder_hash3_bits)));
            self.hash3[h3] = @intCast(abs_pos + 1);
        }
    }

    fn estimateInput(self: *Encoder, input: []const u8) Failure!u64 {
        self.input = input;
        self.input_base = self.total_pos;
        var price_counter = PriceCounter{};
        const pb_mask = (@as(u32, 1) << @intCast(self.properties.pb)) - 1;
        var matches: [match_list_max]MatchPair = undefined;
        var position: usize = 0;
        while (position < input.len) {
            const abs = self.input_base + position;
            const position_state = @as(u32, @truncate(abs)) & pb_mask;
            const state2 = (self.state << num_pos_bits_max) + position_state;
            const max_length = @min(max_match_len, input.len - position);
            var rep_lengths: [4]usize = .{ 0, 0, 0, 0 };
            var best_rep_index: usize = 0;
            var best_rep_length: usize = 0;
            if (abs > 0) {
                const rep_distances = [4]u32{ self.rep0, self.rep1, self.rep2, self.rep3 };
                for (0..4) |rep_index| {
                    const distance = @as(usize, rep_distances[rep_index]) + 1;
                    if (distance > abs) continue;
                    const match_length = self.matchLen(abs - distance, abs, max_length);
                    rep_lengths[rep_index] = match_length;
                    if (match_length > best_rep_length) {
                        best_rep_length = match_length;
                        best_rep_index = rep_index;
                    }
                }
            }
            const count = self.findMatches(position, &matches);
            const found_length: usize = if (count > 0) matches[count - 1].length else 0;
            const lit_price = priceBit(self.is_match[state2], 0) + self.literalLivePrice(input[position]);
            const rep_ok = best_rep_length >= match_min_len and
                self.repLivePrice(state2, position_state, best_rep_index, best_rep_length) < best_rep_length * lit_price;
            const match_ok = found_length >= match_min_len and
                self.matchLivePrice(state2, position_state, matches[count - 1].distance, found_length) < found_length * lit_price;
            if ((rep_ok and best_rep_length >= found_length) or (rep_ok and !match_ok)) {
                try price_counter.encodeBit(&self.is_match[state2], 1);
                try price_counter.encodeBit(&self.is_rep[self.state], 1);
                switch (best_rep_index) {
                    0 => {
                        try price_counter.encodeBit(&self.is_rep_g0[self.state], 0);
                        try price_counter.encodeBit(&self.is_rep0_long[state2], 1);
                    },
                    1 => {
                        try price_counter.encodeBit(&self.is_rep_g0[self.state], 1);
                        try price_counter.encodeBit(&self.is_rep_g1[self.state], 0);
                        const distance = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = distance;
                    },
                    2 => {
                        try price_counter.encodeBit(&self.is_rep_g0[self.state], 1);
                        try price_counter.encodeBit(&self.is_rep_g1[self.state], 1);
                        try price_counter.encodeBit(&self.is_rep_g2[self.state], 0);
                        const distance = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = distance;
                    },
                    else => {
                        try price_counter.encodeBit(&self.is_rep_g0[self.state], 1);
                        try price_counter.encodeBit(&self.is_rep_g1[self.state], 1);
                        try price_counter.encodeBit(&self.is_rep_g2[self.state], 1);
                        const distance = self.rep3;
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = distance;
                    },
                }
                try self.encodeRepLength(&price_counter, position_state, @intCast(best_rep_length - match_min_len));
                self.state = updateStateRep(self.state);
                self.copyBytes(position, @intCast(best_rep_length));
                self.insertSkipped(position, best_rep_length);
                position += best_rep_length;
            } else if (match_ok) {
                const distance = matches[count - 1].distance;
                try price_counter.encodeBit(&self.is_match[state2], 1);
                try price_counter.encodeBit(&self.is_rep[self.state], 0);
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = distance - 1;
                self.state = updateStateMatch(self.state);
                const raw_length: u32 = @intCast(found_length - match_min_len);
                try self.encodeLength(&price_counter, position_state, raw_length);
                try self.encodeDistance(&price_counter, raw_length, distance - 1);
                self.copyBytes(position, @intCast(found_length));
                self.insertSkipped(position, found_length);
                position += found_length;
            } else if (rep_lengths[0] >= 1 and
                priceBit(self.is_match[state2], 1) + priceBit(self.is_rep[self.state], 1) +
                    priceBit(self.is_rep_g0[self.state], 0) + priceBit(self.is_rep0_long[state2], 0) < lit_price)
            {
                try price_counter.encodeBit(&self.is_match[state2], 1);
                try price_counter.encodeBit(&self.is_rep[self.state], 1);
                try price_counter.encodeBit(&self.is_rep_g0[self.state], 0);
                try price_counter.encodeBit(&self.is_rep0_long[state2], 0);
                self.state = updateStateShortRep(self.state);
                self.putByte(self.getByte(self.rep0 + 1));
                position += 1;
            } else {
                try price_counter.encodeBit(&self.is_match[state2], 0);
                try self.encodeLiteral(&price_counter, input[position]);
                self.state = updateStateLiteral(self.state);
                self.putByte(input[position]);
                position += 1;
            }
        }
        self.input = &.{};
        return price_counter.price;
    }

    inline fn relax(self: *Encoder, node_index: usize, price: u32, previous_position: u16, distance: u32, state: u32, rep_distances: *const [4]u32) void {
        const node = &self.opt[node_index];
        if (price < node.price) {
            node.price = price;
            node.previous_position = previous_position;
            node.distance = distance;
            node.state = @intCast(state);
            node.rep_distances = rep_distances.*;
        }
    }

    fn planWindow(self: *Encoder, w_start: usize, window_length: usize) usize {
        const opt = self.opt;
        const prices = self.prices;
        const pb_mask = (@as(u32, 1) << @intCast(self.properties.pb)) - 1;
        const lp_mask = (@as(u32, 1) << @intCast(self.properties.lp)) - 1;
        const lc_shift: u5 = @intCast(8 - self.properties.lc);
        opt[0] = .{
            .price = 0,
            .previous_position = 0,
            .distance = distance_literal,
            .state = @intCast(self.state),
            .rep_distances = .{ self.rep0, self.rep1, self.rep2, self.rep3 },
        };
        for (opt[1 .. window_length + 1]) |*opt_entry| opt_entry.price = std.math.maxInt(u32);
        var matches: [match_list_max]MatchPair = undefined;
        var i: usize = 0;
        while (i < window_length) : (i += 1) {
            const node = opt[i];
            const base = node.price;
            const abs = self.input_base + w_start + i;
            const abs32: u32 = @truncate(abs);
            const position_state = abs32 & pb_mask;
            const state = node.state;
            const state2 = (@as(u32, state) << num_pos_bits_max) + position_state;
            const prev_byte: u32 = if (abs == 0) 0 else self.byteAt(abs - 1);
            const lit_state = ((abs32 & lp_mask) << @intCast(self.properties.lc)) + (prev_byte >> lc_shift);
            const lit_row = self.literal_probs[lit_state * literal_probs_count ..][0..literal_probs_count];
            var lit_price = prices.is_match[state2][0];
            if (state < 7) {
                lit_price += self.literal_prices[lit_state * 256 + self.input[w_start + i]];
            } else {
                lit_price += matchedLiteralPrice(lit_row, self.input[w_start + i], self.byteAt(abs - node.rep_distances[0] - 1));
            }
            self.relax(i + 1, base + lit_price, @intCast(i), distance_literal, updateStateLiteral(state), &node.rep_distances);
            if (abs > 0) {
                const rep_distance = node.rep_distances[0];
                if (rep_distance < abs) {
                    if (self.byteAt(abs) == self.byteAt(abs - rep_distance - 1)) {
                        const price = base + prices.is_match[state2][1] + prices.is_rep[state][1] +
                            prices.is_rep_g0[state][0] + prices.is_rep0_long[state2][0];
                        self.relax(i + 1, price, @intCast(i), distance_short_rep, updateStateShortRep(state), &node.rep_distances);
                    }
                    const rep_base = base + prices.is_match[state2][1] + prices.is_rep[state][1];
                    const max_length = @min(max_match_len, window_length - i);
                    for (0..4) |rep_index| {
                        const distance = node.rep_distances[rep_index] +% 1;
                        // Duplicate rep distances price identically but for index bits; keep the lowest.
                        if (rep_index > 0 and node.rep_distances[rep_index] == node.rep_distances[rep_index - 1]) continue;
                        if (distance <= abs) {
                            const rep_length = self.matchLen(abs - distance, abs, max_length);
                            if (rep_length >= match_min_len) {
                                const rep_price = rep_base + switch (rep_index) {
                                    0 => prices.is_rep_g0[state][0] + prices.is_rep0_long[state2][1],
                                    1 => prices.is_rep_g0[state][1] + prices.is_rep_g1[state][0],
                                    2 => prices.is_rep_g0[state][1] + prices.is_rep_g1[state][1] + prices.is_rep_g2[state][0],
                                    else => prices.is_rep_g0[state][1] + prices.is_rep_g1[state][1] + prices.is_rep_g2[state][1],
                                };
                                var next_distances: [4]u32 = undefined;
                                next_distances[0] = node.rep_distances[rep_index];
                                var write_index: usize = 1;
                                for (0..4) |read_index| {
                                    if (read_index != rep_index) {
                                        next_distances[write_index] = node.rep_distances[read_index];
                                        write_index += 1;
                                    }
                                }
                                const rep_state = updateStateRep(state);
                                var candidate_length: usize = match_min_len;
                                while (candidate_length <= rep_length) : (candidate_length += 1) {
                                    self.relax(i + candidate_length, rep_price + prices.repeat_length_prices[position_state][candidate_length], @intCast(i), distance_rep_base | @as(u32, @intCast(rep_index)), rep_state, &next_distances);
                                }
                            }
                        }
                    }
                }
            }
            const count = self.findMatches(w_start + i, &matches);
            if (count > 0) {
                const match_base = base + prices.is_match[state2][1] + prices.is_rep[state][0];
                const match_state = updateStateMatch(state);
                var previous_length: u32 = match_min_len - 1;
                for (matches[0..count]) |match_pair| {
                    const clipped_length = @min(@as(usize, match_pair.length), window_length - i);
                    if (clipped_length <= previous_length) break;
                    var next_distances: [4]u32 = .{ match_pair.distance - 1, node.rep_distances[0], node.rep_distances[1], node.rep_distances[2] };
                    var candidate_length: usize = previous_length + 1;
                    while (candidate_length <= clipped_length) : (candidate_length += 1) {
                        const length_state = @min(@as(u32, @intCast(candidate_length - match_min_len)), num_len_to_pos_states - 1);
                        self.relax(i + candidate_length, match_base + prices.length_prices[position_state][candidate_length] + self.distancePrice(length_state, match_pair.distance - 1), @intCast(i), match_pair.distance - 1, match_state, &next_distances);
                    }
                    previous_length = @intCast(clipped_length);
                }
            }
        }
        var end_position: usize = window_length;
        var decision_count: usize = 0;
        while (end_position > 0) {
            const node = opt[end_position];
            self.decisions[decision_count] = .{ .distance = node.distance, .length = @intCast(end_position - node.previous_position) };
            end_position = node.previous_position;
            decision_count += 1;
        }
        return decision_count;
    }

    fn encodeWindow(self: *Encoder, w_start: usize, count: usize) Failure!void {
        const pb_mask = (@as(u32, 1) << @intCast(self.properties.pb)) - 1;
        var pending_decisions = count;
        var position = w_start;
        while (pending_decisions > 0) {
            pending_decisions -= 1;
            const dec = self.decisions[pending_decisions];
            const position_state = self.total_pos & pb_mask;
            const state2 = (self.state << num_pos_bits_max) + position_state;
            if (dec.distance == distance_literal) {
                try self.range_coder.encodeBit(&self.is_match[state2], 0);
                try self.encodeLiteral(&self.range_coder, self.input[position]);
                self.state = updateStateLiteral(self.state);
                self.putByte(self.input[position]);
                position += 1;
            } else if (dec.distance == distance_short_rep) {
                try self.range_coder.encodeBit(&self.is_match[state2], 1);
                try self.range_coder.encodeBit(&self.is_rep[self.state], 1);
                try self.range_coder.encodeBit(&self.is_rep_g0[self.state], 0);
                try self.range_coder.encodeBit(&self.is_rep0_long[state2], 0);
                self.state = updateStateShortRep(self.state);
                self.putByte(self.getByte(self.rep0 + 1));
                position += 1;
            } else if (dec.distance >= distance_rep_base) {
                const index: u4 = @intCast(dec.distance - distance_rep_base);
                try self.range_coder.encodeBit(&self.is_match[state2], 1);
                try self.range_coder.encodeBit(&self.is_rep[self.state], 1);
                switch (index) {
                    0 => {
                        try self.range_coder.encodeBit(&self.is_rep_g0[self.state], 0);
                        try self.range_coder.encodeBit(&self.is_rep0_long[state2], 1);
                    },
                    1 => {
                        try self.range_coder.encodeBit(&self.is_rep_g0[self.state], 1);
                        try self.range_coder.encodeBit(&self.is_rep_g1[self.state], 0);
                        const distance = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = distance;
                    },
                    2 => {
                        try self.range_coder.encodeBit(&self.is_rep_g0[self.state], 1);
                        try self.range_coder.encodeBit(&self.is_rep_g1[self.state], 1);
                        try self.range_coder.encodeBit(&self.is_rep_g2[self.state], 0);
                        const distance = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = distance;
                    },
                    else => {
                        try self.range_coder.encodeBit(&self.is_rep_g0[self.state], 1);
                        try self.range_coder.encodeBit(&self.is_rep_g1[self.state], 1);
                        try self.range_coder.encodeBit(&self.is_rep_g2[self.state], 1);
                        const distance = self.rep3;
                        self.rep3 = self.rep2;
                        self.rep2 = self.rep1;
                        self.rep1 = self.rep0;
                        self.rep0 = distance;
                    },
                }
                try self.encodeRepLength(&self.range_coder, position_state, dec.length - match_min_len);
                self.state = updateStateRep(self.state);
                self.copyBytes(position, dec.length);
                position += dec.length;
            } else {
                const distance = dec.distance + 1;
                try self.range_coder.encodeBit(&self.is_match[state2], 1);
                try self.range_coder.encodeBit(&self.is_rep[self.state], 0);
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                self.rep0 = distance - 1;
                self.state = updateStateMatch(self.state);
                const raw_length = dec.length - match_min_len;
                try self.encodeLength(&self.range_coder, position_state, raw_length);
                try self.encodeDistance(&self.range_coder, raw_length, distance - 1);
                self.copyBytes(position, dec.length);
                position += dec.length;
            }
        }
    }

    fn encodeLiteral(self: *Encoder, range_coder: anytype, byte: u8) Failure!void {
        const prev_byte: u32 = if (self.dictionary_pos == 0 and !self.dictionary_full) 0 else self.getByte(1);
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
                try range_coder.encodeBit(&probs[((@as(u32, 1) + match_bit) << 8) + symbol], bit);
                symbol = (symbol << 1) | bit;
                if (match_bit != bit) break;
            }
        }
        while (symbol < 0x100) {
            const bit: u1 = @intCast((literal >> 7) & 1);
            literal <<= 1;
            try range_coder.encodeBit(&probs[symbol], bit);
            symbol = (symbol << 1) | bit;
        }
    }

    fn encodeLength(self: *Encoder, range_coder: anytype, position_state: u32, length: u32) Failure!void {
        if (length < 8) {
            try range_coder.encodeBit(&self.len_choice[0], 0);
            try bitTreeEncode(range_coder, self.len_low[position_state * (1 << 3) ..][0..(1 << 3)], 3, length);
        } else if (length < 16) {
            try range_coder.encodeBit(&self.len_choice[0], 1);
            try range_coder.encodeBit(&self.len_choice[1], 0);
            try bitTreeEncode(range_coder, self.len_mid[position_state * (1 << 3) ..][0..(1 << 3)], 3, length - 8);
        } else {
            try range_coder.encodeBit(&self.len_choice[0], 1);
            try range_coder.encodeBit(&self.len_choice[1], 1);
            try bitTreeEncode(range_coder, self.len_high, 8, length - 16);
        }
    }

    fn encodeRepLength(self: *Encoder, range_coder: anytype, position_state: u32, length: u32) Failure!void {
        if (length < 8) {
            try range_coder.encodeBit(&self.rep_len_choice[0], 0);
            try bitTreeEncode(range_coder, self.rep_len_low[position_state * (1 << 3) ..][0..(1 << 3)], 3, length);
        } else if (length < 16) {
            try range_coder.encodeBit(&self.rep_len_choice[0], 1);
            try range_coder.encodeBit(&self.rep_len_choice[1], 0);
            try bitTreeEncode(range_coder, self.rep_len_mid[position_state * (1 << 3) ..][0..(1 << 3)], 3, length - 8);
        } else {
            try range_coder.encodeBit(&self.rep_len_choice[0], 1);
            try range_coder.encodeBit(&self.rep_len_choice[1], 1);
            try bitTreeEncode(range_coder, self.rep_len_high, 8, length - 16);
        }
    }

    fn encodeDistance(self: *Encoder, range_coder: anytype, raw_length: u32, distance: u32) Failure!void {
        const pos_slot = encodePosSlot(distance);
        var length_state = raw_length;
        if (length_state > num_len_to_pos_states - 1) length_state = num_len_to_pos_states - 1;
        try bitTreeEncode(range_coder, self.pos_slot_decoders[length_state * (1 << 6) ..][0..(1 << 6)], 6, pos_slot);
        if (pos_slot < 4) return;
        const num_direct_bits = (pos_slot >> 1) - 1;
        const base_dist = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
        const offset = distance - base_dist;
        if (pos_slot < end_pos_model_index) {
            try bitTreeReverseEncode(range_coder, self.pos_decoders[base_dist - pos_slot ..], @intCast(num_direct_bits), offset);
        } else {
            try range_coder.encodeDirectBits(offset >> num_align_bits, @intCast(num_direct_bits - num_align_bits));
            try bitTreeReverseEncode(range_coder, self.align_decoder, num_align_bits, offset & ((@as(u32, 1) << num_align_bits) - 1));
        }
    }

    fn encodeEndMarker(self: *Encoder, range_coder: anytype) Failure!void {
        const pos_slot: u32 = 63;
        const length_state: u32 = 0;
        try bitTreeEncode(range_coder, self.pos_slot_decoders[length_state * (1 << 6) ..][0..(1 << 6)], 6, pos_slot);
        const num_direct_bits = (pos_slot >> 1) - 1;
        const base_dist: u32 = (@as(u32, 2) | (pos_slot & 1)) << @intCast(num_direct_bits);
        const offset: u32 = 0xFFFFFFFF - base_dist;
        try range_coder.encodeDirectBits(offset >> num_align_bits, @intCast(num_direct_bits - num_align_bits));
        try bitTreeReverseEncode(range_coder, self.align_decoder, num_align_bits, offset & ((@as(u32, 1) << num_align_bits) - 1));
    }

    inline fn byteAt(self: *const Encoder, abs_pos: usize) u8 {
        if (abs_pos >= self.input_base) return self.input[abs_pos - self.input_base];
        return self.dictionary[if (self.dictionary_mask != 0) abs_pos & self.dictionary_mask else abs_pos % self.dictionary.len];
    }

    inline fn matchLen(self: *const Encoder, first: usize, second: usize, max_length: usize) usize {
        if (first >= self.input_base) {
            return kernels.matchLen8(self.input, first - self.input_base, second - self.input_base, max_length);
        }
        var length: usize = 0;
        const dictionary_index = if (self.dictionary_mask != 0) first & self.dictionary_mask else first % self.dictionary.len;
        const first_span = @min(@min(self.input_base - first, max_length), self.dictionary.len - dictionary_index);
        if (first_span > 0) {
            const input_offset = second - self.input_base;
            var offset: usize = 0;
            while (offset + 8 <= first_span and std.mem.readInt(u64, self.dictionary[dictionary_index + offset ..][0..8], .little) == std.mem.readInt(u64, self.input[input_offset + offset ..][0..8], .little)) offset += 8;
            while (offset < first_span and self.dictionary[dictionary_index + offset] == self.input[input_offset + offset]) offset += 1;
            length += offset;
            if (offset < first_span) return length;
        }
        if (length < max_length) {
            const position = first + length;
            if (position >= self.input_base) {
                return length + kernels.matchLen8(self.input, position - self.input_base, second - self.input_base + length, max_length - length);
            }
            while (length < max_length and self.byteAt(first + length) == self.byteAt(second + length)) length += 1;
        }
        return length;
    }

    fn findMatches(self: *Encoder, position: usize, matches: []MatchPair) usize {
        if (self.match_finder == .bt4) return self.btFindMatches(position, matches);
        return self.hcFindMatches(position, matches);
    }

    // Walk records only byte-compared lengths, so entries need no re-verification.
    // Side tables cover sub-4-byte matches the main index cannot pair.
    fn shortMatches(self: *Encoder, position: usize, matches: []MatchPair) usize {
        const abs_pos = self.input_base + position;
        if (abs_pos >= std.math.maxInt(u32)) return 0;
        const key_bytes = self.input[position..];
        var count: usize = 0;
        const h2 = @as(u32, key_bytes[0]) | (@as(u32, key_bytes[1]) << 8);
        const cand2 = self.hash2[h2];
        self.hash2[h2] = @intCast(abs_pos + 1);
        if (cand2 != 0) {
            const distance = abs_pos - (cand2 - 1);
            // Index is the 2-byte value itself, so equality is free.
            if (distance < self.chain_window) {
                matches[count] = .{ .length = 2, .distance = @intCast(distance) };
                count += 1;
            }
        }
        const w3 = h2 | (@as(u32, key_bytes[2]) << 16);
        const h3 = (w3 *% 0x9E3779B1) >> @as(u5, @intCast(32 - @as(u6, match_finder_hash3_bits)));
        const cand3 = self.hash3[h3];
        self.hash3[h3] = @intCast(abs_pos + 1);
        if (cand3 != 0) {
            const previous_position = cand3 - 1;
            const distance = abs_pos - previous_position;
            if (distance < self.chain_window) {
                // Mixed hash may collide on a prefix only, so verify.
                var verify_length: u32 = 0;
                while (verify_length < 3 and self.byteAt(previous_position + verify_length) == self.byteAt(abs_pos + verify_length)) verify_length += 1;
                if (verify_length >= match_min_len and (count == 0 or verify_length > matches[0].length)) {
                    matches[count] = .{ .length = @intCast(verify_length), .distance = @intCast(distance) };
                    count += 1;
                }
            }
        }
        return count;
    }

    fn btFindMatches(self: *Encoder, position: usize, matches: []MatchPair) usize {
        const abs_pos = self.input_base + position;
        // u32 positions cannot wrap; fall distance to the bounded tail scan past the boundary.
        if (abs_pos >= std.math.maxInt(u32)) return self.tailMatches(position, matches);
        // Splice is order-safe only at the format maximum; chunk tails stay out of the tree.
        if (position + max_match_len >= self.input.len) return self.tailMatches(position, matches);
        const length_limit: usize = @min(self.input.len - position, max_match_len);
        const hash = self.hash4(position);
        const cyc = abs_pos % self.chain_window;
        var ptr0: *u32 = &self.right[cyc];
        var ptr1: *u32 = &self.left[cyc];
        ptr0.* = 0;
        ptr1.* = 0;
        var cur = self.head[hash];
        self.head[hash] = @intCast(abs_pos);
        var length0: usize = 0;
        var length1: usize = 0;
        var count: usize = self.shortMatches(position, matches);
        var best_length: usize = if (count > 0) matches[count - 1].length else 0;
        const cm_check = if (abs_pos < self.chain_window) 0 else abs_pos - self.chain_window;
        var depth: u32 = self.match_finder_depth;
        const input = self.input;
        const input_base = self.input_base;
        while (cur != 0 and depth != 0 and cm_check < cur) : (depth -= 1) {
            if (cur == abs_pos) break;
            const distance = abs_pos - cur;
            const pair_slot = if (cyc >= distance) cyc - distance else self.chain_window + cyc - distance;
            const pb = cur;
            var length = @min(length0, length1);
            if (pb >= input_base) {
                const pb_off = @as(usize, pb) - input_base;
                if (input[pb_off + length] == input[position + length]) {
                    length += 1;
                    if (length != length_limit and input[pb_off + length] == input[position + length]) {
                        length = self.matchLen(pb, abs_pos, length_limit);
                    }
                    if (best_length < length) {
                        best_length = length;
                        if (count < matches.len) {
                            matches[count] = .{ .length = @intCast(length), .distance = @intCast(distance) };
                            count += 1;
                        }
                        if (length == length_limit) {
                            ptr1.* = self.left[pair_slot];
                            ptr0.* = self.right[pair_slot];
                            return count;
                        }
                    }
                }
                if (input[pb_off + length] < input[position + length]) {
                    ptr1.* = cur;
                    cur = self.right[pair_slot];
                    ptr1 = &self.right[pair_slot];
                    length1 = length;
                } else {
                    ptr0.* = cur;
                    cur = self.left[pair_slot];
                    ptr0 = &self.left[pair_slot];
                    length0 = length;
                }
                continue;
            }
            const input_byte0 = input[position + length];
            if (self.byteAt(pb + length) == input_byte0) {
                length += 1;
                if (length != length_limit) {
                    const input_byte1 = input[position + length];
                    if (self.byteAt(pb + length) == input_byte1) {
                        length = self.matchLen(pb, abs_pos, length_limit);
                    }
                }
                if (best_length < length) {
                    best_length = length;
                    if (count < matches.len) {
                        matches[count] = .{ .length = @intCast(length), .distance = @intCast(distance) };
                        count += 1;
                    }
                    if (length == length_limit) {
                        ptr1.* = self.left[pair_slot];
                        ptr0.* = self.right[pair_slot];
                        return count;
                    }
                }
            }
            const input_byte = input[position + length];
            if (self.byteAt(pb + length) < input_byte) {
                ptr1.* = cur;
                cur = self.right[pair_slot];
                ptr1 = &self.right[pair_slot];
                length1 = length;
            } else {
                ptr0.* = cur;
                cur = self.left[pair_slot];
                ptr0 = &self.left[pair_slot];
                length0 = length;
            }
        }
        ptr0.* = 0;
        ptr1.* = 0;
        return count;
    }

    fn hcFindMatches(self: *Encoder, position: usize, matches: []MatchPair) usize {
        // Last positions lack a full key; bounded scan stays cheap there.
        if (position + 4 > self.input.len) return self.tailMatches(position, matches);
        const abs_pos = self.input_base + position;
        // u32 positions cannot wrap; emit no match past the boundary.
        if (abs_pos >= std.math.maxInt(u32)) return 0;
        const max_length: usize = @min(self.input.len - position, max_match_len);
        const hash = self.hash4(position);
        const window = self.chain_window;
        const slot = abs_pos % window;
        var prev_stored = self.head[hash];
        self.head[hash] = @intCast(abs_pos + 1);
        self.chain[slot] = prev_stored;
        var count: usize = self.shortMatches(position, matches);
        var best_length: usize = if (count > 0) matches[count - 1].length else 0;
        var depth: u32 = self.match_finder_depth;
        while (prev_stored != 0 and depth != 0) : (depth -= 1) {
            const previous_position: usize = prev_stored - 1;
            const distance = abs_pos - previous_position;
            if (distance >= window) break;
            const length = self.matchLen(previous_position, abs_pos, max_length);
            if (length > best_length) {
                best_length = length;
                if (count < matches.len) {
                    matches[count] = .{ .length = @intCast(length), .distance = @intCast(distance) };
                    count += 1;
                }
                if (length == max_length or length >= self.nice_len) break;
            }
            const prev_slot = if (slot >= distance) slot - distance else window + slot - distance;
            prev_stored = self.chain[prev_slot];
        }
        return count;
    }

    fn tailMatches(self: *const Encoder, position: usize, matches: []MatchPair) usize {
        if (position + 2 > self.input.len) return 0;
        const abs_pos = self.input_base + position;
        // Cap the scan so tail work stays bounded regardless of dictionary size.
        const max_distance = @min(@min(@as(usize, abs_pos), @as(usize, self.properties.dictionary_size)), 1 << 12);
        const max_length: usize = @min(self.input.len - position, max_match_len);
        var best_length: usize = 0;
        var count: usize = 0;
        var distance: usize = 1;
        while (distance <= max_distance) : (distance += 1) {
            const previous_position = abs_pos - distance;
            if (self.byteAt(abs_pos) != self.byteAt(previous_position)) continue;
            const length = self.matchLen(previous_position, abs_pos, max_length);
            if (length > best_length) {
                best_length = length;
                matches[count] = .{ .length = @intCast(length), .distance = @intCast(distance) };
                count += 1;
                if (length >= max_length or count == matches.len) break;
            }
        }
        return count;
    }

    fn hash4(self: *const Encoder, position: usize) u32 {
        const key_bytes = self.input[position..][0..4];
        const word = @as(u32, key_bytes[0]) | (@as(u32, key_bytes[1]) << 8) | (@as(u32, key_bytes[2]) << 16) | (@as(u32, key_bytes[3]) << 24);
        var hash = word *% 0x9E3779B1;
        hash ^= hash >> 16;
        return hash & self.hash_mask;
    }

    fn copyBytes(self: *Encoder, position: usize, length: u32) void {
        var cursor: usize = position;
        var remaining: usize = length;
        while (remaining > 0) {
            const chunk = @min(remaining, self.dictionary.len - self.dictionary_pos);
            @memcpy(self.dictionary[self.dictionary_pos..][0..chunk], self.input[cursor..][0..chunk]);
            self.dictionary_pos += @intCast(chunk);
            self.total_pos +%= @intCast(chunk);
            if (self.dictionary_pos == self.dictionary.len) {
                self.dictionary_pos = 0;
                self.dictionary_full = true;
            }
            cursor += chunk;
            remaining -= chunk;
        }
    }

    pub fn putByte(self: *Encoder, byte: u8) void {
        self.dictionary[self.dictionary_pos] = byte;
        self.dictionary_pos += 1;
        self.total_pos +%= 1;
        if (self.dictionary_pos == self.dictionary.len) {
            self.dictionary_pos = 0;
            self.dictionary_full = true;
        }
    }

    pub fn setRangeEncoder(self: *Encoder, range_coder: RangeEncoder) void {
        self.range_coder = range_coder;
    }

    // Control 0xC0 resets model/state/reps while dictionary and finder continue.
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

    pub fn restoreModel(self: *Encoder, probabilities: []const Prob) void {
        var offset: usize = 0;
        inline for (std.meta.fields(ProbTables)) |field| {
            const slice = @field(self, field.name);
            @memcpy(slice, probabilities[offset..][0..slice.len]);
            offset += slice.len;
        }
    }

    fn getByte(self: *const Encoder, distance: u32) u8 {
        const position = if (distance <= self.dictionary_pos) self.dictionary_pos - distance else @as(u32, @intCast(self.dictionary.len)) - distance + self.dictionary_pos;
        return self.dictionary[position];
    }
};

fn encodeInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    const needed = if (options.match_finder == .bt4) encodeWorkspaceSizeBt(options.properties) else encodeWorkspaceSize(options.properties);
    if (scratch.len < needed) return error.InsufficientCapacity;
    var encoder = try Encoder.init(options.properties, writer, scratch, options);
    try encoder.encodeInput(input, options.marker_required);
}

fn encodePosSlot(distance: u32) u32 {
    const wide_distance: u64 = distance;
    if (wide_distance < 4) return distance;
    const bit_index = 63 - @clz(wide_distance);
    const slot_offset = (wide_distance - (@as(u64, 1) << @intCast(bit_index))) >> @intCast(bit_index - 1);
    return 2 * @as(u32, @intCast(bit_index)) + @as(u32, @intCast(slot_offset));
}
