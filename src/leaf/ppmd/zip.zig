const std = @import("std");

const failure_prim = @import("../../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../../common/primitive/io.zig");
const measurement = @import("../../common/primitive/measurement.zig");

pub const order_min = 2;
pub const order_max = 16;
pub const mem_mb_min = 1;
pub const mem_mb_max = 256;
pub const restore_restart = 0;
pub const restore_cut_off = 1;
const unit_size = 12;
const num_indexes = 38;
const int_bits = 7;
const period_bits = 7;
const bin_scale = 1 << (int_bits + period_bits);
const bin_shift = int_bits + period_bits;
const top_value = 1 << 24;
const bot_value = 1 << 15;
const max_freq = 124;
const empty_node = 0xFFFFFFFF;
const flag_rescaled: u8 = 1 << 2;
const flag_prev_high: u8 = 1 << 4;
const init_bin_esc = [_]u16{ 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };
const exp_escape = [_]u8{ 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };

const State = extern struct {
    symbol: u8,
    freq: u8,
    successor_low: u16,
    successor_high: u16,
};

const Context = extern struct {
    num_stats: u8,
    flags: u8,
    summ_freq: u16,
    stats: u32,
    suffix: u32,
};

const See = extern struct {
    summ: u16,
    shift: u8,
    count: u8,
};

const Node = extern struct {
    stamp: u32,
    next: u32,
    nu: u32,
};

pub const Options = struct {
    order: u32,
    mem_size: u32,
    restore_method: u32,
    max_work: u64 = std.math.maxInt(u64),
};

pub const DecodeResult = struct {
    decoded: usize,
    consumed: usize,
};

pub fn decodeWorkspaceSize(mem_size: u32) usize {
    return std.mem.alignForward(usize, @sizeOf(Model) + 4, 8) + mem_size + unit_size + 8;
}

pub const encodeWorkspaceSize = decodeWorkspaceSize;

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!DecodeResult {
    try validateOptions(options);
    const model = try Model.prepare(scratch, options.mem_size);
    model.restart(options.order, options.restore_method);
    var rc = RangeDecoder.init(input);
    try rc.initStream();
    var count: usize = 0;
    var finished = false;
    while (count < output.len) {
        const symbol = model.decodeSymbol(&rc) catch return error.InvalidData;
        if (symbol == -1) {
            finished = true;
            break;
        }
        if (symbol < 0) return error.InvalidData;
        output[count] = @intCast(symbol);
        count += 1;
    }
    if (!finished) {
        const symbol = model.decodeSymbol(&rc) catch return error.InvalidData;
        if (symbol != -1) return error.InvalidData;
    }
    if (rc.code != 0) return error.InvalidData;
    if (rc.pos != input.len) return error.InvalidData;
    return .{ .decoded = count, .consumed = rc.pos };
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeInner(input, &counter.writer, scratch, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var writer = std.Io.Writer.fixed(output);
    try encodeInner(input, &writer, scratch, options);
    return writer.end;
}

fn encodeInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    try validateOptions(options);
    const model = try Model.prepare(scratch, options.mem_size);
    model.restart(options.order, options.restore_method);
    var rc = RangeEncoder.init(writer);
    for (input) |byte| {
        try model.encodeSymbol(&rc, byte);
    }
    try model.encodeSymbol(&rc, -1);
    try rc.flush();
}

fn validateOptions(options: Options) Failure!void {
    if (options.order < order_min or options.order > order_max) return error.Unsupported;
    if (options.mem_size < (mem_mb_min << 20) or options.mem_size > (mem_mb_max << 20)) return error.Unsupported;
    if (options.mem_size & 3 != 0) return error.Unsupported;
    if (options.restore_method != restore_restart and options.restore_method != restore_cut_off) return error.Unsupported;
}

const RangeDecoder = struct {
    input: []const u8,
    pos: usize,
    code: u32,
    range: u32,
    low: u32,

    fn init(input: []const u8) RangeDecoder {
        return .{ .input = input, .pos = 0, .code = 0, .range = 0xFFFFFFFF, .low = 0 };
    }

    fn readByte(self: *RangeDecoder) Failure!u8 {
        if (self.pos >= self.input.len) return error.InvalidData;
        const byte = self.input[self.pos];
        self.pos += 1;
        return byte;
    }

    fn initStream(self: *RangeDecoder) Failure!void {
        self.code = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            self.code = (self.code << 8) | try self.readByte();
        }
        if (self.code >= 0xFFFFFFFF) return error.InvalidData;
    }

    fn normalize(self: *RangeDecoder) Failure!void {
        while ((self.low ^ (self.low +% self.range)) < top_value or
            (self.range < bot_value and blk: {
                self.range = (0 -% self.low) & (bot_value - 1);
                break :blk true;
            }))
        {
            self.code = (self.code << 8) | try self.readByte();
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn getThreshold(self: *RangeDecoder, total: u32) Failure!u32 {
        self.range /= total;
        return self.code / self.range;
    }

    fn decode(self: *RangeDecoder, start: u32, size: u32) void {
        const scaled = start *% self.range;
        self.low +%= scaled;
        self.code -%= scaled;
        self.range *%= size;
    }

    fn decodeFinal(self: *RangeDecoder, start: u32, size: u32) Failure!void {
        self.decode(start, size);
        try self.normalize();
    }
};

const RangeEncoder = struct {
    writer: *std.Io.Writer,
    low: u32,
    range: u32,

    fn init(writer: *std.Io.Writer) RangeEncoder {
        return .{ .writer = writer, .low = 0, .range = 0xFFFFFFFF };
    }

    fn writeByte(self: *RangeEncoder) Failure!void {
        self.writer.writeByte(@truncate(self.low >> 24)) catch return error.InsufficientCapacity;
    }

    fn normalize(self: *RangeEncoder) Failure!void {
        while ((self.low ^ (self.low +% self.range)) < top_value or
            (self.range < bot_value and blk: {
                self.range = (0 -% self.low) & (bot_value - 1);
                break :blk true;
            }))
        {
            try self.writeByte();
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn encode(self: *RangeEncoder, start: u32, size: u32, total: u32) void {
        self.range /= total;
        self.low +%= start * self.range;
        self.range *%= size;
    }

    fn encodeFinal(self: *RangeEncoder, start: u32, size: u32, total: u32) Failure!void {
        self.encode(start, size, total);
        try self.normalize();
    }

    fn flush(self: *RangeEncoder) Failure!void {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            try self.writeByte();
            self.low <<= 8;
        }
    }
};

fn updateProb1(prob: u32) u32 {
    const mean = (prob + (1 << (period_bits - 2))) >> period_bits;
    return prob - mean;
}

fn seeUpdate(see: *See) void {
    if (see.shift < period_bits) {
        see.count -= 1;
        if (see.count == 0) {
            see.summ <<= 1;
            see.count = @as(u8, 3) << @intCast(see.shift);
            see.shift += 1;
        }
    }
}

fn hiBitsFlag3(sym: u8) u8 {
    return @intCast(((@as(u16, sym) + 0xC0) >> 5) & 8);
}

fn hiBitsFlag4(sym: u8) u8 {
    return @intCast(((@as(u16, sym) + 0xC0) >> 4) & 16);
}

const Tables = struct {
    units2_indx: [128]u8 = undefined,
    indx2_units: [num_indexes]u8 = undefined,
    ns2_bs_indx: [256]u8 = undefined,
    ns2_indx: [260]u8 = undefined,
    exp_escape: [16]u8 = undefined,
    free_list: [num_indexes]u32 = undefined,
    stamps: [num_indexes]u32 = undefined,
    dummy_see: See = undefined,
    see: [24][32]See = undefined,
    bin_summ: [25][64]u16 = undefined,
};

const Model = struct {
    tables: Tables = .{},
    base: [*]u8 = undefined,
    size: u32 = 0,
    text: u32 = 0,
    lo_unit: u32 = 0,
    hi_unit: u32 = 0,
    units_start: u32 = 0,
    glue_count: u32 = 0,
    min_context: u32 = 0,
    max_context: u32 = 0,
    found_state: u32 = 0,
    order_fall: u32 = 0,
    init_esc: u32 = 0,
    prev_success: u32 = 0,
    max_order: u32 = 0,
    restore_method: u32 = 0,
    run_length: i32 = 0,
    init_rl: i32 = 0,

    fn prepare(scratch: []u8, mem_size: u32) Failure!*Model {
        if (scratch.len < decodeWorkspaceSize(mem_size)) return error.InsufficientCapacity;
        const model_addr = std.mem.alignForward(usize, @intFromPtr(scratch.ptr), @alignOf(Model));
        const model: *Model = @ptrFromInt(model_addr);
        const buf_addr = std.mem.alignForward(usize, model_addr + @sizeOf(Model), 4);
        if (buf_addr + mem_size + unit_size > @intFromPtr(scratch.ptr) + scratch.len) return error.InsufficientCapacity;
        model.base = @ptrFromInt(buf_addr);
        model.size = mem_size;
        model.construct();
        return model;
    }

    inline fn ptr(self: *Model, off: u32) [*]u8 {
        return self.base + off;
    }

    inline fn ref(self: *Model, p: anytype) u32 {
        return @intCast(@intFromPtr(p) - @intFromPtr(self.base));
    }

    inline fn ctx(self: *Model, off: u32) *Context {
        return @ptrFromInt(@intFromPtr(self.base) + off);
    }

    inline fn state(self: *Model, off: u32) *State {
        return @ptrFromInt(@intFromPtr(self.base) + off);
    }

    inline fn node(self: *Model, off: u32) *Node {
        return @ptrFromInt(@intFromPtr(self.base) + off);
    }

    inline fn statsOf(self: *Model, c: *Context) [*]State {
        return @ptrFromInt(@intFromPtr(self.base) + c.stats);
    }

    inline fn oneState(c: *Context) *State {
        return @ptrFromInt(@intFromPtr(c) + 2);
    }

    inline fn suffixOf(self: *Model, c: *Context) *Context {
        return self.ctx(c.suffix);
    }

    inline fn successor(s: *const State) u32 {
        return @as(u32, s.successor_low) | (@as(u32, s.successor_high) << 16);
    }

    inline fn setSuccessor(s: *State, value: u32) void {
        s.successor_low = @truncate(value);
        s.successor_high = @truncate(value >> 16);
    }

    inline fn i2u(self: *const Model, indx: usize) u32 {
        return self.tables.indx2_units[indx];
    }

    inline fn u2i(self: *const Model, nu: u32) usize {
        return self.tables.units2_indx[nu - 1];
    }

    fn construct(self: *Model) void {
        var i: usize = 0;
        var k: usize = 0;
        while (i < num_indexes) : (i += 1) {
            var step: usize = if (i >= 12) 4 else (i >> 2) + 1;
            while (step > 0) : (step -= 1) {
                self.tables.units2_indx[k] = @intCast(i);
                k += 1;
            }
            self.tables.indx2_units[i] = @intCast(k);
        }
        self.tables.ns2_bs_indx[0] = 0;
        self.tables.ns2_bs_indx[1] = 2;
        @memset(self.tables.ns2_bs_indx[2..11], 4);
        @memset(self.tables.ns2_bs_indx[11..], 6);
        i = 0;
        while (i < 5) : (i += 1) self.tables.ns2_indx[i] = @intCast(i);
        var m: usize = i;
        k = 1;
        while (i < 260) : (i += 1) {
            self.tables.ns2_indx[i] = @intCast(m);
            k -= 1;
            if (k == 0) {
                m += 1;
                k = m - 4;
            }
        }
        @memcpy(self.tables.exp_escape[0..], &exp_escape);
    }

    fn insertNode(self: *Model, node_off: u32, indx: usize) void {
        const nd = self.node(node_off);
        nd.stamp = empty_node;
        nd.next = self.tables.free_list[indx];
        nd.nu = self.i2u(indx);
        self.tables.free_list[indx] = node_off;
        self.tables.stamps[indx] += 1;
    }

    fn removeNode(self: *Model, indx: usize) u32 {
        const node_off = self.tables.free_list[indx];
        const nd = self.node(node_off);
        self.tables.free_list[indx] = nd.next;
        self.tables.stamps[indx] -= 1;
        return node_off;
    }

    fn splitBlock(self: *Model, ptr_off: u32, old_indx: usize, new_indx: usize) void {
        const nu = self.i2u(old_indx) - self.i2u(new_indx);
        const start = ptr_off + self.i2u(new_indx) * unit_size;
        var i = self.u2i(nu);
        if (self.i2u(i) != nu) {
            i -= 1;
            const k = self.i2u(i);
            self.insertNode(start + k * unit_size, nu - k - 1);
        }
        self.insertNode(start, i);
    }

    fn glueFreeBlocks(self: *Model) void {
        self.glue_count = 1 << 13;
        @memset(&self.tables.stamps, 0);
        if (self.lo_unit != self.hi_unit) self.node(self.lo_unit).stamp = 0;
        var head: u32 = 0;
        var next: u32 = undefined;
        var prev: *u32 = &head;
        var i: usize = 0;
        while (i < num_indexes) : (i += 1) {
            var n = self.tables.free_list[i];
            self.tables.free_list[i] = 0;
            while (n != 0) {
                const nd = self.node(n);
                var nu = nd.nu;
                prev.* = n;
                next = nd.next;
                if (nu != 0) {
                    prev = &nd.next;
                    while (self.node(n + nu * unit_size).stamp == empty_node) {
                        const node2 = self.node(n + nu * unit_size);
                        nu += node2.nu;
                        node2.nu = 0;
                        nd.nu = nu;
                    }
                }
                n = next;
            }
        }
        prev.* = 0;
        var n = head;
        while (n != 0) {
            const nd = self.node(n);
            var nu = nd.nu;
            const node_start = n;
            n = nd.next;
            if (nu == 0) continue;
            var node_off = node_start;
            while (nu > 128) : (nu -= 128) {
                self.insertNode(node_off, num_indexes - 1);
                node_off += 128 * unit_size;
            }
            var idx2 = self.u2i(nu);
            if (self.i2u(idx2) != nu) {
                idx2 -= 1;
                const k = self.i2u(idx2);
                self.insertNode(node_off + k * unit_size, nu - k - 1);
            }
            self.insertNode(node_off, idx2);
        }
    }

    fn allocUnitsRare(self: *Model, indx: usize) ?u32 {
        if (self.glue_count == 0) {
            self.glueFreeBlocks();
            if (self.tables.free_list[indx] != 0) return self.removeNode(indx);
        }
        var i = indx;
        while (true) {
            i += 1;
            if (i == num_indexes) {
                const num_bytes = self.i2u(indx) * unit_size;
                self.glue_count -= 1;
                if (self.units_start - self.text > num_bytes) {
                    self.units_start -= num_bytes;
                    return self.units_start;
                }
                return null;
            }
            if (self.tables.free_list[i] != 0) break;
        }
        const ret = self.removeNode(i);
        self.splitBlock(ret, i, indx);
        return ret;
    }

    fn allocUnits(self: *Model, indx: usize) ?u32 {
        if (self.tables.free_list[indx] != 0) return self.removeNode(indx);
        const num_bytes = self.i2u(indx) * unit_size;
        if (self.hi_unit - self.lo_unit >= num_bytes) {
            const ret = self.lo_unit;
            self.lo_unit += num_bytes;
            return ret;
        }
        return self.allocUnitsRare(indx);
    }

    fn copyUnits(self: *Model, dest: u32, source: u32, num: u32) void {
        const d = @as([*]u32, @ptrFromInt(@intFromPtr(self.base) + dest));
        const z = @as([*]const u32, @ptrFromInt(@intFromPtr(self.base) + source));
        var i: u32 = 0;
        while (i < num) : (i += 1) {
            d[i * 3] = z[i * 3];
            d[i * 3 + 1] = z[i * 3 + 1];
            d[i * 3 + 2] = z[i * 3 + 2];
        }
    }

    fn shrinkUnits(self: *Model, old_off: u32, old_nu: u32, new_nu: u32) u32 {
        const old_index = self.u2i(old_nu);
        const new_index = self.u2i(new_nu);
        if (old_index == new_index) return old_off;
        if (self.tables.free_list[new_index] != 0) {
            const ptr_off = self.removeNode(new_index);
            self.copyUnits(ptr_off, old_off, new_nu);
            self.insertNode(old_off, old_index);
            return ptr_off;
        }
        self.splitBlock(old_off, old_index, new_index);
        return old_off;
    }

    fn freeUnits(self: *Model, ptr_off: u32, nu: u32) void {
        self.insertNode(ptr_off, self.u2i(nu));
    }

    fn specialFreeUnit(self: *Model, ptr_off: u32) void {
        if (ptr_off != self.units_start) {
            self.insertNode(ptr_off, 0);
        } else {
            self.units_start += unit_size;
        }
    }

    fn expandTextArea(self: *Model) void {
        var count: [num_indexes]u32 = @splat(0);
        if (self.lo_unit != self.hi_unit) self.node(self.lo_unit).stamp = 0;
        var node_off = self.units_start;
        while (self.node(node_off).stamp == empty_node) {
            const nu = self.node(node_off).nu;
            self.node(node_off).stamp = 0;
            count[self.u2i(nu)] += 1;
            node_off += nu * unit_size;
        }
        self.units_start = node_off;
        var i: usize = 0;
        while (i < num_indexes) : (i += 1) {
            var cnt = count[i];
            if (cnt == 0) continue;
            var prev: *u32 = &self.tables.free_list[i];
            var n = prev.*;
            self.tables.stamps[i] -= cnt;
            while (true) {
                const nd = self.node(n);
                n = nd.next;
                if (nd.stamp != 0) {
                    prev = &nd.next;
                    continue;
                }
                prev.* = n;
                cnt -= 1;
                if (cnt == 0) break;
            }
        }
    }

    fn restart(self: *Model, max_order: u32, restore_method: u32) void {
        @memset(&self.tables.free_list, 0);
        @memset(&self.tables.stamps, 0);
        self.text = 0;
        self.hi_unit = self.size;
        const units_start = self.hi_unit - (self.size / 8 / unit_size) * 7 * unit_size;
        self.lo_unit = units_start;
        self.units_start = units_start;
        self.glue_count = 0;
        self.max_order = max_order;
        self.restore_method = restore_method;
        self.order_fall = max_order;
        const capped: i32 = @intCast(if (max_order < 12) max_order else 12);
        self.init_rl = -capped - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;
        self.hi_unit -= unit_size;
        self.min_context = self.hi_unit;
        self.max_context = self.hi_unit;
        const min_ctx = self.ctx(self.min_context);
        min_ctx.suffix = 0;
        min_ctx.flags = 0;
        min_ctx.num_stats = 256 - 1;
        min_ctx.summ_freq = 256 + 1;
        self.found_state = self.lo_unit;
        self.lo_unit += (256 / 2) * unit_size;
        min_ctx.stats = self.found_state;
        var i: usize = 0;
        while (i < 256) : (i += 1) {
            const s = self.state(self.found_state + @as(u32, @intCast(i)) * @sizeOf(State));
            s.symbol = @intCast(i);
            s.freq = 1;
            s.successor_low = 0;
            s.successor_high = 0;
        }
        i = 0;
        var m: usize = 0;
        while (m < 25) : (m += 1) {
            while (self.tables.ns2_indx[i] == m) i += 1;
            var k: usize = 0;
            while (k < 8) : (k += 1) {
                const val: u16 = @intCast(bin_scale - @as(u32, init_bin_esc[k]) / @as(u32, @intCast(i + 1)));
                var r: usize = k;
                while (r < 64) : (r += 8) self.tables.bin_summ[m][r] = val;
            }
        }
        i = 0;
        m = 0;
        while (m < 24) : (m += 1) {
            while (self.tables.ns2_indx[i + 3] == m + 3) i += 1;
            const summ: u16 = @intCast((2 * i + 5) << (period_bits - 4));
            for (0..32) |k| {
                self.tables.see[m][k].summ = summ;
                self.tables.see[m][k].shift = period_bits - 4;
                self.tables.see[m][k].count = 7;
            }
        }
        self.tables.dummy_see.summ = 0;
        self.tables.dummy_see.shift = period_bits;
        self.tables.dummy_see.count = 64;
    }

    fn binSumm(self: *Model) *u16 {
        const min_ctx = self.ctx(self.min_context);
        const s = Model.oneState(min_ctx);
        const row = self.tables.ns2_indx[@as(usize, s.freq) - 1];
        const col = self.prev_success +
            ((@as(u32, @bitCast(self.run_length)) >> 26) & 0x20) +
            self.tables.ns2_bs_indx[self.suffixOf(min_ctx).num_stats] +
            min_ctx.flags;
        return &self.tables.bin_summ[row][col];
    }

    fn makeEscFreq(self: *Model, num_masked: u32) struct { see: *See, esc_freq: u32 } {
        const min_ctx = self.ctx(self.min_context);
        const num_stats = @as(u32, min_ctx.num_stats);
        if (num_stats != 0xFF) {
            const row = self.tables.ns2_indx[@as(usize, num_stats) + 2] - 3;
            const col = @as(u32, @intFromBool(min_ctx.summ_freq > 11 * (num_stats + 1))) +
                2 * @as(u32, @intFromBool(2 * num_stats < @as(u32, self.suffixOf(min_ctx).num_stats) + num_masked)) +
                min_ctx.flags;
            const see = &self.tables.see[row][col];
            const r: u32 = see.summ >> @as(u4, @intCast(see.shift));
            see.summ = @intCast(see.summ - r);
            return .{ .see = see, .esc_freq = r + @as(u32, @intFromBool(r == 0)) };
        }
        return .{ .see = &self.tables.dummy_see, .esc_freq = 1 };
    }

    fn createSuccessors(self: *Model, skip: bool, s1: ?*State, c: *Context) ?u32 {
        const up_branch = Model.successor(self.state(self.found_state));
        var ps: [order_max + 1]u32 = undefined;
        var num_ps: usize = 0;
        if (!skip) {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }
        var cc = c;
        var s1_mut = s1;
        while (cc.suffix != 0) {
            var s: *State = undefined;
            cc = self.suffixOf(cc);
            if (s1_mut) |s1v| {
                s = s1v;
                s1_mut = null;
            } else if (cc.num_stats != 0) {
                const sym = self.state(self.found_state).symbol;
                var scan = self.statsOf(cc);
                while (scan[0].symbol != sym) scan += 1;
                s = &scan[0];
                if (s.freq < max_freq - 9) {
                    s.freq += 1;
                    cc.summ_freq +%= 1;
                }
            } else {
                s = Model.oneState(cc);
                s.freq +%= @intFromBool(self.suffixOf(cc).num_stats == 0 and s.freq < 24);
            }
            const succ = Model.successor(s);
            if (succ != up_branch) {
                if (num_ps == 0) return succ;
                cc = self.ctx(succ);
                break;
            }
            ps[num_ps] = self.ref(s);
            num_ps += 1;
        }
        const new_sym = self.ptr(up_branch)[0];
        const up_branch_next = up_branch + 1;
        const flags: u8 = hiBitsFlag4(self.state(self.found_state).symbol) + hiBitsFlag3(new_sym);
        var new_freq: u8 = undefined;
        if (cc.num_stats == 0) {
            new_freq = Model.oneState(cc).freq;
        } else {
            var scan = self.statsOf(cc);
            while (scan[0].symbol != new_sym) scan += 1;
            const cf = @as(u32, scan[0].freq) - 1;
            const s0 = @as(u32, cc.summ_freq) - cc.num_stats - cf;
            new_freq = @intCast(1 + if (2 * cf <= s0)
                @intFromBool(5 * cf > s0)
            else
                (cf + 2 * s0 - 3) / s0);
        }
        while (num_ps != 0) {
            var c1_off: u32 = undefined;
            if (self.hi_unit != self.lo_unit) {
                self.hi_unit -= unit_size;
                c1_off = self.hi_unit;
            } else if (self.tables.free_list[0] != 0) {
                c1_off = self.removeNode(0);
            } else {
                c1_off = self.allocUnitsRare(0) orelse return null;
            }
            const c1 = self.ctx(c1_off);
            c1.flags = flags;
            c1.num_stats = 0;
            Model.oneState(c1).symbol = new_sym;
            Model.oneState(c1).freq = new_freq;
            Model.setSuccessor(Model.oneState(c1), up_branch_next);
            c1.suffix = self.ref(cc);
            Model.setSuccessor(self.state(ps[num_ps - 1]), c1_off);
            num_ps -= 1;
            cc = c1;
        }
        return self.ref(cc);
    }

    fn reduceOrder(self: *Model, s1: ?*State, c: *Context) ?u32 {
        var s: ?*State = null;
        const c1 = c;
        const up_branch = self.text;
        Model.setSuccessor(self.state(self.found_state), up_branch);
        self.order_fall += 1;
        var cc = c;
        var s1_mut = s1;
        while (true) {
            if (s1_mut) |s1v| {
                cc = self.suffixOf(cc);
                s = s1v;
                s1_mut = null;
            } else {
                if (cc.suffix == 0) return self.ref(cc);
                cc = self.suffixOf(cc);
                if (cc.num_stats != 0) {
                    var scan = self.statsOf(cc);
                    if (scan[0].symbol != self.state(self.found_state).symbol) {
                        while (scan[0].symbol != self.state(self.found_state).symbol) scan += 1;
                    }
                    s = &scan[0];
                    if (s.?.freq < max_freq - 9) {
                        s.?.freq +%= 2;
                        cc.summ_freq +%= 2;
                    }
                } else {
                    const one = Model.oneState(cc);
                    one.freq +%= @intFromBool(one.freq < 32);
                    s = one;
                }
            }
            if (Model.successor(s.?) != 0) break;
            Model.setSuccessor(s.?, up_branch);
            self.order_fall += 1;
        }
        if (Model.successor(s.?) <= up_branch) {
            const s2 = self.state(self.found_state);
            self.found_state = self.ref(s.?);
            const created = self.createSuccessors(false, null, cc);
            if (created) |succ| {
                Model.setSuccessor(s.?, succ);
            } else {
                Model.setSuccessor(s.?, 0);
            }
            self.found_state = self.ref(s2);
        }
        const succ = Model.successor(s.?);
        if (self.order_fall == 1 and self.ref(c1) == self.max_context) {
            Model.setSuccessor(self.state(self.found_state), succ);
            self.text -= 1;
        }
        if (succ == 0) return null;
        return succ;
    }

    fn refresh(self: *Model, c: *Context, old_nu: u32, scale: u32) void {
        const i: u32 = c.num_stats;
        const stats_off = self.shrinkUnits(c.stats, old_nu, (i + 2) >> 1);
        c.stats = stats_off;
        var s = self.state(stats_off);
        var flags: u16 = @as(u16, s.symbol) + 0xC0;
        const scale_mut = scale | @as(u32, @intFromBool(c.summ_freq >= (1 << 15)));
        var esc_freq: u32 = c.summ_freq -% s.freq;
        var sum_freq: u32 = (s.freq + scale_mut) >> @as(u5, @intCast(scale_mut));
        s.freq = @intCast(sum_freq);
        var remaining = i;
        while (true) {
            s = self.state(self.ref(s) + @sizeOf(State));
            const freq: u32 = s.freq;
            esc_freq -%= freq;
            const halved = (freq + scale_mut) >> @as(u5, @intCast(scale_mut));
            sum_freq += halved;
            s.freq = @intCast(halved);
            flags |= @as(u16, s.symbol) + 0xC0;
            remaining -= 1;
            if (remaining == 0) break;
        }
        c.summ_freq = @intCast(sum_freq + ((esc_freq + scale_mut) >> @as(u5, @intCast(scale_mut))));
        c.flags = (c.flags & (flag_prev_high + flag_rescaled * @as(u8, @intCast(scale_mut & 1)))) + @as(u8, @intCast((flags >> 5) & 8));
    }

    fn usedMemory(self: *Model) u32 {
        var v: u32 = 0;
        for (0..num_indexes) |i| v +%= self.tables.stamps[i] * self.i2u(i);
        return self.size - (self.hi_unit - self.lo_unit) - (self.units_start - self.text) - v * unit_size;
    }

    fn cutOff(self: *Model, c: *Context, order: u32) u32 {
        var ns: i32 = c.num_stats;
        if (ns == 0) {
            const s = Model.oneState(c);
            var succ = Model.successor(s);
            if (succ >= self.units_start) {
                if (order < self.max_order) {
                    succ = self.cutOff(self.ctx(succ), order + 1);
                } else {
                    succ = 0;
                }
                Model.setSuccessor(s, succ);
                if (succ != 0 or order <= 9) return self.ref(c);
            }
            self.specialFreeUnit(self.ref(c));
            return 0;
        }
        const nu: u32 = @intCast((ns + 2) >> 1);
        var stats_off = c.stats;
        {
            const indx = self.u2i(nu);
            if (stats_off >= self.units_start and stats_off - self.units_start <= (1 << 14) and
                c.stats <= self.tables.free_list[indx])
            {
                const ptr_off = self.removeNode(indx);
                c.stats = ptr_off;
                self.copyUnits(ptr_off, stats_off, nu);
                if (stats_off != self.units_start) {
                    self.insertNode(stats_off, indx);
                } else {
                    self.units_start += self.i2u(indx) * unit_size;
                }
                stats_off = ptr_off;
            }
        }
        {
            var s = self.state(stats_off + @as(u32, @intCast(ns)) * @sizeOf(State));
            while (true) {
                const succ = Model.successor(s);
                if (succ < self.units_start) {
                    const s2 = self.state(stats_off + @as(u32, @intCast(ns)) * @sizeOf(State));
                    if (order != 0) {
                        if (self.ref(s) != self.ref(s2)) s.* = s2.*;
                    } else {
                        const tmp = s.*;
                        s.* = s2.*;
                        s2.* = tmp;
                        Model.setSuccessor(s2, 0);
                    }
                    ns -= 1;
                } else {
                    if (order < self.max_order) {
                        Model.setSuccessor(s, self.cutOff(self.ctx(succ), order + 1));
                    } else {
                        Model.setSuccessor(s, 0);
                    }
                }
                if (self.ref(s) == stats_off) break;
                s = self.state(self.ref(s) - @sizeOf(State));
            }
        }
        if (ns != c.num_stats and order != 0) {
            if (ns < 0) {
                self.freeUnits(stats_off, nu);
                self.specialFreeUnit(self.ref(c));
                return 0;
            }
            c.num_stats = @intCast(ns);
            if (ns == 0) {
                const sym = self.state(stats_off).symbol;
                c.flags = (c.flags & flag_prev_high) + hiBitsFlag3(sym);
                Model.oneState(c).symbol = sym;
                Model.oneState(c).freq = @intCast((@as(u32, self.state(stats_off).freq) + 11) >> 3);
                Model.setSuccessor(Model.oneState(c), Model.successor(self.state(stats_off)));
                self.freeUnits(stats_off, nu);
            } else {
                self.refresh(c, nu, @as(u32, @intFromBool(c.summ_freq > 16 * @as(u32, @intCast(ns)))));
            }
        }
        return self.ref(c);
    }

    fn restoreModel(self: *Model, ctx_error: *Context) void {
        self.text = 0;
        var c = self.ctx(self.max_context);
        while (self.ref(c) != self.ref(ctx_error)) {
            c.num_stats -%= 1;
            if (c.num_stats == 0) {
                const s = self.statsOf(c);
                c.flags = (c.flags & flag_prev_high) + hiBitsFlag3(s[0].symbol);
                Model.oneState(c).symbol = s[0].symbol;
                Model.oneState(c).freq = @intCast((@as(u32, s[0].freq) + 11) >> 3);
                Model.setSuccessor(Model.oneState(c), Model.successor(&s[0]));
                self.specialFreeUnit(self.ref(&s[0]));
            } else {
                self.refresh(c, (c.num_stats + 3) >> 1, 0);
            }
            c = self.suffixOf(c);
        }
        while (self.ref(c) != self.min_context) {
            if (c.num_stats == 0) {
                Model.oneState(c).freq = @intCast((@as(u32, Model.oneState(c).freq) + 1) >> 1);
            } else if (c.summ_freq +% 4 > 128 + 4 * c.num_stats) {
                c.summ_freq +%= 4;
                self.refresh(c, (c.num_stats + 2) >> 1, 1);
            } else {
                c.summ_freq +%= 4;
            }
            c = self.suffixOf(c);
        }
        if (self.restore_method == restore_restart or self.usedMemory() < (self.size >> 1)) {
            self.restart(self.max_order, self.restore_method);
        } else {
            while (self.ctx(self.max_context).suffix != 0) self.max_context = self.ctx(self.max_context).suffix;
            while (true) {
                _ = self.cutOff(self.ctx(self.max_context), 0);
                self.expandTextArea();
                if (self.usedMemory() <= 3 * (self.size >> 2)) break;
            }
            self.glue_count = 0;
            self.order_fall = self.max_order;
        }
        self.min_context = self.max_context;
    }

    fn updateModel(self: *Model) void {
        const f_symbol = self.state(self.found_state).symbol;
        const f_freq = @as(u32, self.state(self.found_state).freq);
        var min_successor = Model.successor(self.state(self.found_state));
        var s: ?*State = null;
        if (f_freq < max_freq / 4 and self.ctx(self.min_context).suffix != 0) {
            const c = self.suffixOf(self.ctx(self.min_context));
            if (c.num_stats == 0) {
                const one = Model.oneState(c);
                if (one.freq < 32) one.freq += 1;
                s = one;
            } else {
                var scan = self.statsOf(c);
                if (scan[0].symbol != f_symbol) {
                    while (scan[0].symbol != f_symbol) scan += 1;
                    if (scan[0].freq >= (scan - 1)[0].freq) {
                        const tmp = scan[0];
                        scan[0] = (scan - 1)[0];
                        (scan - 1)[0] = tmp;
                        scan -= 1;
                    }
                }
                s = &scan[0];
                if (scan[0].freq < max_freq - 9) {
                    scan[0].freq += 2;
                    c.summ_freq +%= 2;
                }
            }
        }
        const c0 = self.ctx(self.max_context);
        if (self.order_fall == 0 and min_successor != 0) {
            const cs = self.createSuccessors(true, s, self.ctx(self.min_context)) orelse {
                Model.setSuccessor(self.state(self.found_state), 0);
                self.restoreModel(c0);
                return;
            };
            Model.setSuccessor(self.state(self.found_state), cs);
            self.min_context = cs;
            self.max_context = cs;
            return;
        }
        const text_off = self.text;
        self.ptr(self.text)[0] = f_symbol;
        self.text += 1;
        if (self.text >= self.units_start) {
            self.restoreModel(c0);
            return;
        }
        var max_successor = self.text;
        if (min_successor == 0) {
            const cs = self.reduceOrder(s, self.ctx(self.min_context)) orelse {
                self.restoreModel(c0);
                return;
            };
            min_successor = cs;
        } else if (min_successor < self.units_start) {
            const cs = self.createSuccessors(false, s, self.ctx(self.min_context)) orelse {
                self.restoreModel(c0);
                return;
            };
            min_successor = cs;
        }
        self.order_fall -= 1;
        if (self.order_fall == 0) {
            max_successor = min_successor;
            if (self.max_context != self.min_context) self.text = text_off;
        }
        const flag: u8 = hiBitsFlag3(f_symbol);
        const ns: u32 = self.ctx(self.min_context).num_stats;
        const s0 = @as(u32, self.ctx(self.min_context).summ_freq) - ns - f_freq;
        var c = c0;
        while (self.ref(c) != self.min_context) {
            const ns1: u32 = c.num_stats;
            var sum: u32 = undefined;
            if (ns1 != 0) {
                if ((ns1 & 1) != 0) {
                    const old_nu = (ns1 + 1) >> 1;
                    const old_index = self.u2i(old_nu);
                    if (old_index != self.u2i(old_nu + 1)) {
                        const ptr_off = self.allocUnits(old_index + 1) orelse {
                            self.restoreModel(c);
                            return;
                        };
                        const old_off = c.stats;
                        self.copyUnits(ptr_off, old_off, old_nu);
                        self.insertNode(old_off, old_index);
                        c.stats = ptr_off;
                    }
                }
                sum = c.summ_freq;
                sum += @as(u32, @intFromBool(3 * ns1 + 1 < ns));
            } else {
                const st = self.state(self.allocUnits(0) orelse {
                    self.restoreModel(c);
                    return;
                });
                const one = Model.oneState(c);
                st.symbol = one.symbol;
                Model.setSuccessor(st, Model.successor(one));
                c.stats = self.ref(st);
                var freq: u32 = one.freq;
                if (freq < max_freq / 4 - 1) {
                    freq <<= 1;
                } else {
                    freq = max_freq - 4;
                }
                st.freq = @intCast(freq);
                sum = freq + self.init_esc + @as(u32, @intFromBool(ns > 2));
            }
            {
                const st = self.state(c.stats + (ns1 + 1) * @sizeOf(State));
                var cf = 2 * (sum + 6) * f_freq;
                const sf = s0 + sum;
                st.symbol = f_symbol;
                c.num_stats = @intCast(ns1 + 1);
                Model.setSuccessor(st, max_successor);
                c.flags |= flag;
                if (cf < 6 * sf) {
                    cf = 1 + @as(u32, @intFromBool(cf > sf)) + @as(u32, @intFromBool(cf >= 4 * sf));
                    sum += 4;
                } else {
                    cf = 4 + @as(u32, @intFromBool(cf > 9 * sf)) + @as(u32, @intFromBool(cf > 12 * sf)) +
                        @as(u32, @intFromBool(cf > 15 * sf));
                    sum += cf;
                }
                c.summ_freq = @intCast(sum);
                st.freq = @intCast(cf);
            }
            c = self.suffixOf(c);
        }
        self.max_context = min_successor;
        self.min_context = min_successor;
    }

    fn rescale(self: *Model) void {
        const min_ctx = self.ctx(self.min_context);
        const stats = self.statsOf(min_ctx);
        var s: [*]State = @ptrCast(self.state(self.found_state));
        if (self.ref(s) != self.ref(stats)) {
            const tmp = s[0];
            while (self.ref(s) != self.ref(stats)) {
                s[0] = (s - 1)[0];
                s -= 1;
            }
            s[0] = tmp;
        }
        var sum_freq: u32 = s[0].freq;
        var esc_freq: u32 = @as(u32, min_ctx.summ_freq) - sum_freq;
        const adder: u32 = @intFromBool(self.order_fall != 0);
        sum_freq = (sum_freq + 4 + adder) >> 1;
        s[0].freq = @intCast(sum_freq);
        var i: u32 = min_ctx.num_stats;
        while (true) {
            s += 1;
            const freq: u32 = s[0].freq;
            esc_freq -%= freq;
            const halved = (freq + adder) >> 1;
            sum_freq += halved;
            s[0].freq = @intCast(halved);
            if (halved > (s - 1)[0].freq) {
                const tmp = s[0];
                var s1 = s;
                while (self.ref(s1) != self.ref(stats)) {
                    if (tmp.freq <= (s1 - 1)[0].freq) break;
                    s1[0] = (s1 - 1)[0];
                    s1 -= 1;
                }
                s1[0] = tmp;
            }
            i -= 1;
            if (i == 0) break;
        }
        if (s[0].freq == 0) {
            var removed: u32 = 0;
            while (true) {
                removed += 1;
                s -= 1;
                if (s[0].freq != 0) break;
            }
            esc_freq += removed;
            const num_stats = @as(u32, min_ctx.num_stats);
            const num_stats_new = num_stats - removed;
            min_ctx.num_stats = @intCast(num_stats_new);
            const n0 = (num_stats + 2) >> 1;
            if (num_stats_new == 0) {
                var freq = (2 * @as(u32, stats[0].freq) + esc_freq - 1) / esc_freq;
                if (freq > max_freq / 3) freq = max_freq / 3;
                min_ctx.flags = (min_ctx.flags & flag_prev_high) + hiBitsFlag3(stats[0].symbol);
                const one = Model.oneState(min_ctx);
                one.* = stats[0];
                one.freq = @intCast(freq);
                self.found_state = self.ref(one);
                self.insertNode(self.ref(stats), self.u2i(n0));
                return;
            }
            const n1 = (num_stats_new + 2) >> 1;
            if (n0 != n1) min_ctx.stats = self.shrinkUnits(self.ref(stats), n0, n1);
        }
        min_ctx.summ_freq = @intCast(sum_freq + esc_freq - (esc_freq >> 1));
        min_ctx.flags |= flag_rescaled;
        self.found_state = min_ctx.stats;
    }

    fn update1(self: *Model) void {
        const s = self.state(self.found_state);
        const freq = @as(u32, s.freq) + 4;
        self.ctx(self.min_context).summ_freq +%= 4;
        s.freq = @intCast(freq);
        const prev = self.state(self.found_state - @sizeOf(State));
        if (freq > prev.freq) {
            const tmp = s.*;
            s.* = prev.*;
            prev.* = tmp;
            self.found_state = self.ref(prev);
            if (freq > max_freq) self.rescale();
        }
        self.nextContext();
    }

    fn update1_0(self: *Model) void {
        const s = self.state(self.found_state);
        const min_ctx = self.ctx(self.min_context);
        const freq = @as(u32, s.freq);
        self.prev_success = @intFromBool(2 * freq >= min_ctx.summ_freq);
        self.run_length += @intCast(self.prev_success);
        min_ctx.summ_freq +%= 4;
        s.freq = @intCast(freq + 4);
        if (freq + 4 > max_freq) self.rescale();
        self.nextContext();
    }

    fn update2(self: *Model) void {
        const s = self.state(self.found_state);
        const freq = @as(u32, s.freq) + 4;
        self.run_length = self.init_rl;
        self.ctx(self.min_context).summ_freq +%= 4;
        s.freq = @intCast(freq);
        if (freq > max_freq) self.rescale();
        self.updateModel();
    }

    fn nextContext(self: *Model) void {
        const c_off = Model.successor(self.state(self.found_state));
        if (self.order_fall == 0 and c_off >= self.units_start) {
            self.min_context = c_off;
            self.max_context = c_off;
        } else {
            self.updateModel();
        }
    }

    fn decodeSymbol(self: *Model, rc: *RangeDecoder) Failure!i32 {
        var mask: [256]u8 = undefined;
        const min_ctx = self.ctx(self.min_context);
        if (min_ctx.num_stats != 0) {
            var s = self.statsOf(min_ctx);
            var summ_freq: u32 = min_ctx.summ_freq;
            if (summ_freq > rc.range) summ_freq = rc.range;
            var count = try rc.getThreshold(summ_freq);
            const hi_cnt = count;
            count -%= s[0].freq;
            if (@as(i32, @bitCast(count)) < 0) {
                const symbol = s[0].symbol;
                try rc.decodeFinal(0, s[0].freq);
                self.found_state = self.ref(s);
                self.update1_0();
                return symbol;
            }
            self.prev_success = 0;
            var i: u32 = min_ctx.num_stats;
            while (true) {
                s += 1;
                count -%= s[0].freq;
                if (@as(i32, @bitCast(count)) < 0) {
                    const symbol = s[0].symbol;
                    try rc.decodeFinal((hi_cnt -% count) -% s[0].freq, s[0].freq);
                    self.found_state = self.ref(s);
                    self.update1();
                    return symbol;
                }
                i -= 1;
                if (i == 0) break;
            }
            if (hi_cnt >= summ_freq) return error.InvalidData;
            rc.decode(hi_cnt -% count, summ_freq - (hi_cnt -% count));
            @memset(&mask, 0xFF);
            var scan = self.statsOf(min_ctx);
            var n: usize = 0;
            while (n <= min_ctx.num_stats) : (n += 1) {
                mask[scan[0].symbol] = 0;
                scan += 1;
            }
        } else {
            const s = Model.oneState(min_ctx);
            const prob = self.binSumm();
            var pr: u32 = prob.*;
            const size0 = (rc.range >> bin_shift) * pr;
            pr = updateProb1(pr);
            if (rc.code < size0) {
                const symbol = s.symbol;
                prob.* = @intCast(pr + (1 << int_bits));
                rc.range = size0;
                try rc.normalize();
                const c_off = Model.successor(s);
                const freq = @as(u32, s.freq);
                self.found_state = self.ref(s);
                self.prev_success = 1;
                self.run_length += 1;
                s.freq = @intCast(freq + @as(u32, @intFromBool(freq < 196)));
                if (self.order_fall == 0 and c_off >= self.units_start) {
                    self.min_context = c_off;
                    self.max_context = c_off;
                } else {
                    self.updateModel();
                }
                return symbol;
            }
            prob.* = @intCast(pr);
            self.init_esc = self.tables.exp_escape[pr >> 10];
            rc.low +%= size0;
            rc.code -%= size0;
            rc.range = (rc.range & ~(@as(u32, bin_scale) - 1)) - size0;
            @memset(&mask, 0xFF);
            mask[Model.oneState(min_ctx).symbol] = 0;
            self.prev_success = 0;
        }
        while (true) {
            try rc.normalize();
            var mc = self.ctx(self.min_context);
            const num_masked: u32 = mc.num_stats;
            while (true) {
                self.order_fall += 1;
                if (mc.suffix == 0) return -1;
                mc = self.suffixOf(mc);
                if (mc.num_stats != num_masked) break;
            }
            self.min_context = self.ref(mc);
            var s = self.statsOf(mc);
            var hi_cnt: u32 = 0;
            var n: usize = 0;
            while (n <= mc.num_stats) : (n += 1) {
                if (mask[s[0].symbol] != 0) hi_cnt += s[0].freq;
                s += 1;
            }
            const esc = self.makeEscFreq(num_masked);
            const freq_sum = esc.esc_freq + hi_cnt;
            const freq_sum2 = if (freq_sum > rc.range) rc.range else freq_sum;
            var count = try rc.getThreshold(freq_sum2);
            if (count < hi_cnt) {
                s = self.statsOf(mc);
                hi_cnt = count;
                while (true) {
                    count -%= s[0].freq & @as(u32, mask[s[0].symbol]);
                    s += 1;
                    if (@as(i32, @bitCast(count)) < 0) break;
                }
                s -= 1;
                try rc.decodeFinal((hi_cnt -% count) -% s[0].freq, s[0].freq);
                seeUpdate(esc.see);
                self.found_state = self.ref(s);
                const symbol = s[0].symbol;
                self.update2();
                return symbol;
            }
            if (count >= freq_sum2) return error.InvalidData;
            rc.decode(hi_cnt, freq_sum2 - hi_cnt);
            esc.see.summ = @intCast(esc.see.summ + freq_sum);
            s = self.statsOf(mc);
            const s2 = s + mc.num_stats + 1;
            while (self.ref(s) != self.ref(s2)) {
                mask[s[0].symbol] = 0;
                s += 1;
            }
        }
    }

    fn encodeSymbol(self: *Model, rc: *RangeEncoder, symbol: i32) Failure!void {
        var mask: [256]u8 = undefined;
        const min_ctx = self.ctx(self.min_context);
        if (min_ctx.num_stats != 0) {
            var s = self.statsOf(min_ctx);
            var summ_freq: u32 = min_ctx.summ_freq;
            if (summ_freq > rc.range) summ_freq = rc.range;
            if (s[0].symbol == symbol) {
                try rc.encodeFinal(0, s[0].freq, summ_freq);
                self.found_state = self.ref(s);
                self.update1_0();
                return;
            }
            self.prev_success = 0;
            var sum: u32 = s[0].freq;
            var i: u32 = min_ctx.num_stats;
            while (true) {
                s += 1;
                if (s[0].symbol == symbol) {
                    try rc.encodeFinal(sum, s[0].freq, summ_freq);
                    self.found_state = self.ref(s);
                    self.update1();
                    return;
                }
                sum += s[0].freq;
                i -= 1;
                if (i == 0) break;
            }
            rc.encode(sum, summ_freq - sum, summ_freq);
            @memset(&mask, 0xFF);
            var scan = self.statsOf(min_ctx);
            var n: usize = 0;
            while (n <= min_ctx.num_stats) : (n += 1) {
                mask[scan[0].symbol] = 0;
                scan += 1;
            }
        } else {
            const s = Model.oneState(min_ctx);
            const prob = self.binSumm();
            var pr: u32 = prob.*;
            const bound = (rc.range >> bin_shift) * pr;
            pr = updateProb1(pr);
            if (s.symbol == symbol) {
                prob.* = @intCast(pr + (1 << int_bits));
                rc.range = bound;
                try rc.normalize();
                const c_off = Model.successor(s);
                const freq = @as(u32, s.freq);
                self.found_state = self.ref(s);
                self.prev_success = 1;
                self.run_length += 1;
                s.freq = @intCast(freq + @as(u32, @intFromBool(freq < 196)));
                if (self.order_fall == 0 and c_off >= self.units_start) {
                    self.min_context = c_off;
                    self.max_context = c_off;
                } else {
                    self.updateModel();
                }
                return;
            }
            prob.* = @intCast(pr);
            self.init_esc = self.tables.exp_escape[pr >> 10];
            rc.low +%= bound;
            rc.range = (rc.range & ~(@as(u32, bin_scale) - 1)) - bound;
            @memset(&mask, 0xFF);
            mask[Model.oneState(min_ctx).symbol] = 0;
            self.prev_success = 0;
        }
        while (true) {
            try rc.normalize();
            var mc = self.ctx(self.min_context);
            const num_masked: u32 = mc.num_stats;
            while (true) {
                self.order_fall += 1;
                if (mc.suffix == 0) return;
                mc = self.suffixOf(mc);
                if (mc.num_stats != num_masked) break;
            }
            self.min_context = self.ref(mc);
            const esc = self.makeEscFreq(num_masked);
            var s = self.statsOf(mc);
            var sum: u32 = 0;
            var i: u32 = @as(u32, mc.num_stats) + 1;
            while (true) {
                const cur = s[0].symbol;
                if (cur == symbol) {
                    const low = sum;
                    const freq = s[0].freq;
                    seeUpdate(esc.see);
                    self.found_state = self.ref(s);
                    var total = sum + esc.esc_freq + freq;
                    var scan = s + 1;
                    var remaining = i - 1;
                    while (remaining > 0) : (remaining -= 1) {
                        if (mask[scan[0].symbol] != 0) total += scan[0].freq;
                        scan += 1;
                    }
                    if (total > rc.range) total = rc.range;
                    try rc.encodeFinal(low, freq, total);
                    self.update2();
                    return;
                }
                sum += s[0].freq & @as(u32, mask[cur]);
                s += 1;
                i -= 1;
                if (i == 0) break;
            }
            var total = sum + esc.esc_freq;
            esc.see.summ = @intCast(esc.see.summ + total);
            if (total > rc.range) total = rc.range;
            rc.encode(sum, total - sum, total);
            var scan = self.statsOf(mc);
            var n: usize = 0;
            while (n <= mc.num_stats) : (n += 1) {
                mask[scan[0].symbol] = 0;
                scan += 1;
            }
        }
    }
};
