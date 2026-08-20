const std = @import("std");

const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");

pub const order_min = 2;
pub const order_max = 64;
pub const mem_min = 1 << 11;
pub const mem_max = 0x7FFFFFFF;
const unit_size = 12;
const num_indexes = 12;
const int_bits = 7;
const period_bits = 7;
const bin_scale = 1 << (int_bits + period_bits);
const top_value = 1 << 24;
const max_freq = 124;
const bit_shift = 14;
const init_bin_esc = [_]u16{ 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };
const exp_escape = [_]u8{ 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };

const State = extern struct {
    symbol: u8,
    freq: u8,
    successor_low: u16,
    successor_high: u16,
};

const Context = extern struct {
    num_stats: u16,
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
    stamp: u16,
    nu: u16,
    next: u32,
    prev: u32,
};

pub const Options = struct {
    order: u32,
    mem_size: u32,
    unpack_size: u64,
    max_work: u64 = std.math.maxInt(u64),
};

pub fn decodeWorkspaceSize(mem_size: u32) usize {
    return std.mem.alignForward(usize, @sizeOf(Model) + 4, 8) + mem_size + unit_size + 8;
}

pub const encodeWorkspaceSize = decodeWorkspaceSize;

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
    const unpack = std.math.cast(usize, options.unpack_size) orelse return error.ResourceLimit;
    if (input.len != unpack) return error.InvalidCall;
    try validateOptions(options, unpack);
    const model = try Model.prepare(scratch, options.mem_size);
    model.restart(options.order);
    var rc = RangeEncoder.init(writer);
    for (input) |byte| {
        try model.encodeSymbol(&rc, byte);
    }
    try rc.flush();
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    _ = input;
    _ = scratch;
    if (options.unpack_size > std.math.maxInt(usize)) return error.ResourceLimit;
    return std.math.cast(usize, options.unpack_size) orelse error.ResourceLimit;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    const unpack = std.math.cast(usize, options.unpack_size) orelse return error.ResourceLimit;
    if (output.len < unpack) return error.InsufficientCapacity;
    try validateOptions(options, unpack);
    const model = try Model.prepare(scratch, options.mem_size);
    model.restart(options.order);
    var rc = RangeDecoder.init(input);
    try rc.initStream();
    var dest = std.Io.Writer.fixed(output);
    var count: usize = 0;
    while (count < unpack) : (count += 1) {
        const symbol = model.decodeSymbol(&rc) catch return error.InvalidData;
        try io.writeByte(&dest, @intCast(symbol));
    }
    if (rc.code != 0) return error.InvalidData;
    return count;
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (options.unpack_size > std.math.maxInt(usize)) return error.ResourceLimit;
    const unpack = std.math.cast(usize, options.unpack_size) orelse return error.ResourceLimit;
    try validateOptions(options, unpack);
    const model = try Model.prepare(scratch, options.mem_size);
    model.restart(options.order);
    var rc = RangeDecoder.init(input);
    try rc.initStream();
    var count: usize = 0;
    while (count < unpack) : (count += 1) {
        const symbol = model.decodeSymbol(&rc) catch return error.InvalidData;
        try io.writeByte(writer, @intCast(symbol));
    }
    if (rc.code != 0) return error.InvalidData;
}

fn validateOptions(options: Options, unpack: usize) Failure!void {
    if (options.order < order_min or options.order > order_max) return error.Unsupported;
    if (options.mem_size < mem_min or options.mem_size > mem_max) return error.Unsupported;
    if (options.mem_size & 3 != 0) return error.Unsupported;
    if (options.max_work < unpack) return error.ResourceLimit;
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
        if (try self.readByte() != 0) return error.InvalidData;
        self.code = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            self.code = (self.code << 8) | try self.readByte();
        }
        if (self.code >= 0xFFFFFFFF) return error.InvalidData;
    }

    fn normalize(self: *RangeDecoder) Failure!void {
        while ((self.low ^ (self.low +% self.range)) < top_value) {
            self.code = (self.code << 8) | try self.readByte();
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn getThreshold(self: *RangeDecoder, total: u32) Failure!u32 {
        self.range = self.range / total;
        return (self.code -% self.low) / self.range;
    }

    fn decodeRange(self: *RangeDecoder, start: u32, size: u32) Failure!void {
        self.code -%= start *% self.range;
        self.range *%= size;
        try self.normalize();
    }

    fn decodeBit(self: *RangeDecoder, size0: u32) Failure!u32 {
        const new_bound = (self.range >> bit_shift) * size0;
        if (self.code < new_bound) {
            self.range = new_bound;
            try self.normalize();
            return 0;
        }
        self.code -= new_bound;
        self.range -= new_bound;
        try self.normalize();
        return 1;
    }
};

const RangeEncoder = struct {
    writer: *std.Io.Writer,
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,

    fn init(writer: *std.Io.Writer) RangeEncoder {
        return .{ .writer = writer, .low = 0, .range = 0xFFFFFFFF, .cache = 0, .cache_size = 1 };
    }

    fn shiftLow(self: *RangeEncoder) Failure!void {
        if (@as(u32, @truncate(self.low)) < 0xFF00_0000 or (self.low >> 32) != 0) {
            var temp = self.cache;
            while (true) {
                self.writer.writeByte(temp +% @as(u8, @truncate(self.low >> 32))) catch return error.InsufficientCapacity;
                temp = 0xFF;
                self.cache_size -= 1;
                if (self.cache_size == 0) break;
            }
            self.cache = @truncate(self.low >> 24);
        }
        self.cache_size += 1;
        self.low = @as(u32, @truncate(self.low)) << 8;
    }

    fn normalize(self: *RangeEncoder) Failure!void {
        if (self.range < top_value) {
            self.range <<= 8;
            try self.shiftLow();
            if (self.range < top_value) {
                self.range <<= 8;
                try self.shiftLow();
            }
        }
    }

    fn encode(self: *RangeEncoder, start: u32, size: u32) void {
        self.low += @as(u64, start *% self.range);
        self.range *%= size;
    }

    fn encodeFinal(self: *RangeEncoder, start: u32, size: u32) Failure!void {
        self.encode(start, size);
        try self.normalize();
    }

    fn flush(self: *RangeEncoder) Failure!void {
        var i: usize = 0;
        while (i < 5) : (i += 1) try self.shiftLow();
    }
};

const Tables = struct {
    indx2_units: [num_indexes]u8 = undefined,
    units2_indx: [128]u8 = undefined,
    ns2_indx: [256]u8 = undefined,
    ns2_bs_indx: [256]u8 = undefined,
    hb2_flag: [256]u8 = undefined,
    free_list: [num_indexes]u32 = undefined,
    dummy_see: See = undefined,
    see: [25][16]See = undefined,
    bin_summ: [128][64]u16 = undefined,
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
    hi_bits_flag: u32 = 0,
    run_length: i32 = 0,
    init_rl: i32 = 0,

    fn prepare(scratch: []u8, mem_size: u32) Failure!*Model {
        if (scratch.len < decodeWorkspaceSize(mem_size)) return error.InsufficientCapacity;
        const model_addr = std.mem.alignForward(usize, @intFromPtr(scratch.ptr), @alignOf(Model));
        const model: *Model = @ptrFromInt(model_addr);
        const buf_addr = std.mem.alignForward(usize, model_addr + @sizeOf(Model), 4);
        if (buf_addr + mem_size + unit_size > @intFromPtr(scratch.ptr) + scratch.len) return error.InsufficientCapacity;
        model.construct();
        model.base = @ptrFromInt(buf_addr);
        model.size = mem_size;
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
        return @ptrCast(&c.summ_freq);
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

    fn construct(self: *Model) void {
        var i: usize = 0;
        var k: usize = 0;
        while (i < num_indexes) : (i += 1) {
            var step: usize = (i >> 2) + 1;
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
        while (i < 3) : (i += 1) self.tables.ns2_indx[i] = @intCast(i);
        var m: usize = i;
        k = 1;
        while (i < 256) : (i += 1) {
            self.tables.ns2_indx[i] = @intCast(m);
            k -= 1;
            if (k == 0) {
                m += 1;
                k = m - 2;
            }
        }
        @memset(self.tables.hb2_flag[0..0x40], 0);
        @memset(self.tables.hb2_flag[0x40..], 8);
    }

    fn insertNode(self: *Model, node_off: u32, indx: usize) void {
        const link: *u32 = @ptrFromInt(@intFromPtr(self.base) + node_off);
        link.* = self.tables.free_list[indx];
        self.tables.free_list[indx] = node_off;
    }

    fn removeNode(self: *Model, indx: usize) u32 {
        const node_off = self.tables.free_list[indx];
        const link: *u32 = @ptrFromInt(@intFromPtr(self.base) + node_off);
        self.tables.free_list[indx] = link.*;
        return node_off;
    }

    inline fn i2u(self: *const Model, indx: usize) u32 {
        return self.tables.indx2_units[indx];
    }

    inline fn u2i(self: *const Model, nu: u32) usize {
        return self.tables.units2_indx[nu - 1];
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
        const head: u32 = self.size;
        var n: u32 = head;
        self.glue_count = 255;
        var i: usize = 0;
        while (i < num_indexes) : (i += 1) {
            const nu = self.i2u(i);
            var next = self.tables.free_list[i];
            self.tables.free_list[i] = 0;
            while (next != 0) {
                const nd = self.node(next);
                nd.next = n;
                self.node(n).prev = next;
                n = next;
                const link: *u32 = @ptrFromInt(@intFromPtr(nd));
                next = link.*;
                nd.stamp = 0;
                nd.nu = @intCast(nu);
            }
        }
        self.node(head).stamp = 1;
        self.node(head).next = n;
        self.node(n).prev = head;
        if (self.lo_unit != self.hi_unit) self.node(self.lo_unit).stamp = 1;
        while (n != head) {
            const nd = self.node(n);
            var nu: u32 = nd.nu;
            while (true) {
                const node2 = self.node(n + nu * unit_size);
                nu += node2.nu;
                if (node2.stamp != 0 or nu >= 0x10000) break;
                self.node(node2.prev).next = node2.next;
                self.node(node2.next).prev = node2.prev;
                nd.nu = @intCast(nu);
            }
            n = nd.next;
        }
        n = self.node(head).next;
        while (n != head) {
            const nd = self.node(n);
            var nu: u32 = nd.nu;
            const next = nd.next;
            var off = n;
            while (nu > 128) : (nu -= 128) {
                self.insertNode(off, num_indexes - 1);
                off += 128 * unit_size;
            }
            var idx2 = self.u2i(nu);
            if (self.i2u(idx2) != nu) {
                idx2 -= 1;
                const k = self.i2u(idx2);
                self.insertNode(off + k * unit_size, nu - k - 1);
            }
            self.insertNode(off, idx2);
            n = next;
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
        if (num_bytes <= self.hi_unit - self.lo_unit) {
            const ret = self.lo_unit;
            self.lo_unit += num_bytes;
            return ret;
        }
        return self.allocUnitsRare(indx);
    }

    fn shrinkUnits(self: *Model, old_off: u32, old_nu: u32, new_nu: u32) u32 {
        const old_index = self.u2i(old_nu);
        const new_index = self.u2i(new_nu);
        if (old_index == new_index) return old_off;
        if (self.tables.free_list[new_index] != 0) {
            const ptr_off = self.removeNode(new_index);
            @memcpy(self.ptr(ptr_off)[0 .. new_nu * unit_size], self.ptr(old_off)[0 .. new_nu * unit_size]);
            self.insertNode(old_off, old_index);
            return ptr_off;
        }
        self.splitBlock(old_off, old_index, new_index);
        return old_off;
    }

    fn restart(self: *Model, max_order: u32) void {
        @memset(self.tables.free_list[0..], 0);
        self.text = 0;
        self.hi_unit = self.size;
        self.lo_unit = self.hi_unit - (self.size / 8 / unit_size) * 7 * unit_size;
        self.units_start = self.lo_unit;
        self.glue_count = 0;
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
        min_ctx.num_stats = 256;
        min_ctx.summ_freq = 257;
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
        while (i < 128) : (i += 1) {
            var k: usize = 0;
            while (k < 8) : (k += 1) {
                const val: u16 = @intCast(bin_scale - @as(u32, init_bin_esc[k]) / (i + 2));
                var m: usize = 0;
                while (m < 64) : (m += 8) {
                    self.tables.bin_summ[i][m + k] = val;
                }
            }
        }
        i = 0;
        while (i < 25) : (i += 1) {
            var k: usize = 0;
            while (k < 16) : (k += 1) {
                const s = &self.tables.see[i][k];
                s.shift = period_bits - 4;
                s.summ = @intCast((5 * i + 10) << @as(u6, @intCast(s.shift)));
                s.count = 4;
            }
        }
        self.tables.dummy_see.shift = period_bits;
        self.tables.dummy_see.summ = 0;
        self.tables.dummy_see.count = 64;
        self.max_order = max_order;
        self.init_esc = 0;
        self.hi_bits_flag = 0;
    }

    fn binSumm(self: *Model) *u16 {
        const min_ctx = self.ctx(self.min_context);
        const freq = @as(u32, Model.oneState(min_ctx).freq) - 1;
        const sym = self.state(self.found_state).symbol;
        self.hi_bits_flag = self.tables.hb2_flag[sym];
        const idx: usize = self.prev_success +
            self.tables.ns2_bs_indx[self.suffixOf(min_ctx).num_stats - 1] +
            self.hi_bits_flag +
            2 * self.tables.hb2_flag[Model.oneState(min_ctx).symbol] +
            ((@as(u32, @bitCast(self.run_length)) >> 26) & 0x20);
        return &self.tables.bin_summ[freq][idx];
    }

    fn createSuccessors(self: *Model, skip: bool) ?u32 {
        var up_state: State = undefined;
        var c_off = self.min_context;
        var c = self.ctx(c_off);
        const up_branch = Model.successor(self.state(self.found_state));
        var ps: [64]u32 = undefined;
        var num_ps: usize = 0;
        if (!skip) {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }
        const found_symbol = self.state(self.found_state).symbol;
        while (c.suffix != 0) {
            var s: *State = undefined;
            c_off = c.suffix;
            c = self.ctx(c_off);
            if (c.num_stats != 1) {
                var scan = self.statsOf(c);
                while (scan[0].symbol != found_symbol) scan += 1;
                s = &scan[0];
            } else {
                s = Model.oneState(c);
            }
            const succ = Model.successor(s);
            if (succ != up_branch) {
                c_off = succ;
                c = self.ctx(c_off);
                if (num_ps == 0) return c_off;
                break;
            }
            ps[num_ps] = self.ref(s);
            num_ps += 1;
        }
        up_state.symbol = self.ptr(up_branch)[0];
        Model.setSuccessor(&up_state, up_branch + 1);
        if (c.num_stats == 1) {
            up_state.freq = Model.oneState(c).freq;
        } else {
            var scan = self.statsOf(c);
            while (scan[0].symbol != up_state.symbol) scan += 1;
            const cf = @as(u32, scan[0].freq - 1);
            const s0 = @as(u32, c.summ_freq) - c.num_stats - cf;
            up_state.freq = @intCast(1 + if (2 * cf <= s0)
                @intFromBool(5 * cf > s0)
            else
                (2 * cf + 3 * s0 - 1) / (2 * s0));
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
            c1.num_stats = 1;
            Model.oneState(c1).* = up_state;
            c1.suffix = c_off;
            num_ps -= 1;
            Model.setSuccessor(self.state(ps[num_ps]), c1_off);
            c_off = c1_off;
            c = c1;
        }
        return c_off;
    }

    fn updateModel(self: *Model) void {
        const f_successor0 = Model.successor(self.state(self.found_state));
        var f_successor = f_successor0;
        const found = self.state(self.found_state);
        if (found.freq < max_freq / 4 and self.ctx(self.min_context).suffix != 0) {
            var c = self.suffixOf(self.ctx(self.min_context));
            if (c.num_stats == 1) {
                const s = Model.oneState(c);
                if (s.freq < 32) s.freq += 1;
            } else {
                var s = self.statsOf(c);
                if (s[0].symbol != found.symbol) {
                    while (s[0].symbol != found.symbol) s += 1;
                    if (s[0].freq >= (s - 1)[0].freq) {
                        const tmp = s[0];
                        s[0] = (s - 1)[0];
                        (s - 1)[0] = tmp;
                        s -= 1;
                    }
                }
                if (s[0].freq < max_freq - 9) {
                    s[0].freq += 2;
                    c.summ_freq += 2;
                }
            }
        }
        if (self.order_fall == 0) {
            self.min_context = self.createSuccessors(true) orelse {
                self.restart(self.max_order);
                return;
            };
            self.max_context = self.min_context;
            Model.setSuccessor(self.state(self.found_state), self.min_context);
            return;
        }
        self.ptr(self.text)[0] = found.symbol;
        self.text += 1;
        var succ_off = self.text;
        if (self.text >= self.units_start) {
            self.restart(self.max_order);
            return;
        }
        if (f_successor != 0) {
            if (f_successor <= succ_off) {
                f_successor = self.createSuccessors(false) orelse {
                    self.restart(self.max_order);
                    return;
                };
            }
            if (self.order_fall == 1) {
                self.order_fall = 0;
                succ_off = f_successor;
                if (self.max_context != self.min_context) self.text -= 1;
            } else {
                self.order_fall -= 1;
            }
        } else {
            Model.setSuccessor(self.state(self.found_state), succ_off);
            f_successor = self.min_context;
        }
        const min_ctx = self.ctx(self.min_context);
        const ns = @as(u32, min_ctx.num_stats);
        const s0 = @as(u32, min_ctx.summ_freq) - ns - (@as(u32, found.freq) - 1);
        var c_off = self.max_context;
        while (c_off != self.min_context) {
            const c = self.ctx(c_off);
            const ns1 = @as(u32, c.num_stats);
            if (ns1 != 1) {
                if ((ns1 & 1) == 0) {
                    const old_nu = ns1 >> 1;
                    const i = self.u2i(old_nu);
                    if (i != self.u2i(old_nu + 1)) {
                        const ptr_off = self.allocUnits(i + 1) orelse {
                            self.restart(self.max_order);
                            return;
                        };
                        const old_off = c.stats;
                        @memcpy(self.ptr(ptr_off)[0 .. old_nu * unit_size], self.ptr(old_off)[0 .. old_nu * unit_size]);
                        self.insertNode(old_off, i);
                        c.stats = ptr_off;
                    }
                }
                const delta: u16 = @intCast(@as(u32, @intFromBool(2 * ns1 < ns)) +
                    2 * @as(u32, @intFromBool(4 * ns1 <= ns and @as(u32, c.summ_freq) <= 8 * ns1)));
                c.summ_freq += delta;
            } else {
                const s = self.state(self.allocUnits(0) orelse {
                    self.restart(self.max_order);
                    return;
                });
                s.* = Model.oneState(c).*;
                c.stats = self.ref(s);
                if (s.freq < max_freq / 4 - 1) {
                    s.freq <<= 1;
                } else {
                    s.freq = max_freq - 4;
                }
                c.summ_freq = @intCast(@as(u32, s.freq) + self.init_esc + @as(u32, @intFromBool(ns > 3)));
            }
            const found_freq = @as(u32, self.state(self.found_state).freq);
            var cf = 2 * found_freq * (@as(u32, c.summ_freq) + 6);
            const sf = s0 + @as(u32, c.summ_freq);
            if (cf < 6 * sf) {
                cf = 1 + @as(u32, @intFromBool(cf > sf)) + @as(u32, @intFromBool(cf >= 4 * sf));
                c.summ_freq += 3;
            } else {
                cf = 4 + @as(u32, @intFromBool(cf >= 9 * sf)) + @as(u32, @intFromBool(cf >= 12 * sf)) +
                    @as(u32, @intFromBool(cf >= 15 * sf));
                c.summ_freq += @intCast(cf);
            }
            const s = self.statsOf(c) + ns1;
            Model.setSuccessor(&s[0], succ_off);
            s[0].symbol = found.symbol;
            s[0].freq = @intCast(cf);
            c.num_stats = @intCast(ns1 + 1);
            c_off = c.suffix;
        }
        self.min_context = f_successor;
        self.max_context = f_successor;
    }

    fn rescale(self: *Model) void {
        const min_ctx = self.ctx(self.min_context);
        const stats = self.statsOf(min_ctx);
        var s: [*]State = @ptrCast(self.state(self.found_state));
        {
            const tmp = s[0];
            while (s != stats) {
                s[0] = (s - 1)[0];
                s -= 1;
            }
            s[0] = tmp;
        }
        var esc_freq: u32 = @as(u32, min_ctx.summ_freq) - s[0].freq;
        s[0].freq += 4;
        const adder: u32 = @intFromBool(self.order_fall != 0);
        s[0].freq = @intCast((@as(u32, s[0].freq) + adder) >> 1);
        var sum_freq: u32 = s[0].freq;
        var i: u32 = min_ctx.num_stats - 1;
        while (true) {
            s += 1;
            esc_freq -= s[0].freq;
            s[0].freq = @intCast((@as(u32, s[0].freq) + adder) >> 1);
            sum_freq += s[0].freq;
            if (s[0].freq > (s - 1)[0].freq) {
                var s1 = s;
                const tmp = s1[0];
                while (s1 != stats) {
                    if (tmp.freq <= (s1 - 1)[0].freq) break;
                    s1[0] = (s1 - 1)[0];
                    s1 -= 1;
                }
                s1[0] = tmp;
            }
            if (i == 1) break;
            i -= 1;
        }
        if (s[0].freq == 0) {
            const num_stats = min_ctx.num_stats;
            var removed: u32 = 0;
            while (true) {
                removed += 1;
                s -= 1;
                if (s[0].freq != 0) break;
            }
            esc_freq += removed;
            min_ctx.num_stats = @intCast(min_ctx.num_stats - removed);
            if (min_ctx.num_stats == 1) {
                var tmp = stats[0];
                while (true) {
                    tmp.freq = @intCast(@as(u32, tmp.freq) - (tmp.freq >> 1));
                    esc_freq >>= 1;
                    if (esc_freq <= 1) break;
                }
                self.insertNode(self.ref(stats), self.u2i((num_stats + 1) >> 1));
                const one = Model.oneState(min_ctx);
                one.* = tmp;
                self.found_state = self.ref(one);
                return;
            }
            const n0 = (num_stats + 1) >> 1;
            const n1 = (min_ctx.num_stats + 1) >> 1;
            if (n0 != n1) {
                min_ctx.stats = self.shrinkUnits(self.ref(stats), n0, n1);
            }
        }
        min_ctx.summ_freq = @intCast(sum_freq + esc_freq - (esc_freq >> 1));
        self.found_state = min_ctx.stats;
    }

    fn makeEscFreq(self: *Model, num_masked: u32) struct { see: *See, esc_freq: u32 } {
        const min_ctx = self.ctx(self.min_context);
        const non_masked = @as(u32, min_ctx.num_stats) - num_masked;
        if (min_ctx.num_stats != 256) {
            const see = &self.tables.see[self.tables.ns2_indx[non_masked - 1]][
                @as(u32, @intFromBool(non_masked < @as(u32, self.suffixOf(min_ctx).num_stats) - min_ctx.num_stats)) +
                    2 * @as(u32, @intFromBool(@as(u32, min_ctx.summ_freq) < 11 * min_ctx.num_stats)) +
                    4 * @as(u32, @intFromBool(num_masked > non_masked)) +
                    self.hi_bits_flag
            ];
            const r: u32 = see.summ >> @as(u4, @intCast(see.shift));
            see.summ = @intCast(see.summ - r);
            return .{ .see = see, .esc_freq = r + @as(u32, @intFromBool(r == 0)) };
        }
        return .{ .see = &self.tables.dummy_see, .esc_freq = 1 };
    }

    fn seeUpdate(see: *See) void {
        if (see.shift < period_bits) {
            if (see.count == 1) {
                see.summ <<= 1;
                see.count = @intCast(@as(u8, 3) << @as(u3, @intCast(see.shift)));
                see.shift += 1;
            } else {
                see.count -= 1;
            }
        }
    }

    fn update1(self: *Model) void {
        const s: [*]State = @ptrCast(self.state(self.found_state));
        s[0].freq += 4;
        self.ctx(self.min_context).summ_freq += 4;
        if (s[0].freq > (s - 1)[0].freq) {
            const tmp = s[0];
            s[0] = (s - 1)[0];
            (s - 1)[0] = tmp;
            self.found_state = self.ref(s) - @sizeOf(State);
            if (self.state(self.found_state).freq > max_freq) self.rescale();
        }
        self.nextContext();
    }

    fn update1_0(self: *Model) void {
        self.prev_success = @intFromBool(2 * @as(u32, self.state(self.found_state).freq) > self.ctx(self.min_context).summ_freq);
        self.run_length += @as(i32, @intCast(self.prev_success));
        self.ctx(self.min_context).summ_freq += 4;
        const s = self.state(self.found_state);
        s.freq += 4;
        if (s.freq > max_freq) self.rescale();
        self.nextContext();
    }

    fn updateBin(self: *Model) void {
        const s = self.state(self.found_state);
        if (s.freq < 128) s.freq += 1;
        self.prev_success = 1;
        self.run_length += 1;
        self.nextContext();
    }

    fn update2(self: *Model) void {
        self.ctx(self.min_context).summ_freq += 4;
        const s = self.state(self.found_state);
        s.freq += 4;
        if (s.freq > max_freq) self.rescale();
        self.run_length = self.init_rl;
        self.updateModel();
    }

    fn nextContext(self: *Model) void {
        const c_off = Model.successor(self.state(self.found_state));
        if (self.order_fall == 0 and c_off > self.text) {
            self.min_context = c_off;
            self.max_context = c_off;
        } else {
            self.updateModel();
        }
    }

    fn decodeSymbol(self: *Model, rc: *RangeDecoder) Failure!u32 {
        var mask: [256]u8 = undefined;
        var min_ctx = self.ctx(self.min_context);
        if (min_ctx.num_stats != 1) {
            var s = self.statsOf(min_ctx);
            const count = try rc.getThreshold(min_ctx.summ_freq);
            var hi_cnt: u32 = s[0].freq;
            if (count < hi_cnt) {
                const symbol = s[0].symbol;
                try rc.decodeRange(0, s[0].freq);
                self.found_state = self.ref(s);
                self.update1_0();
                return symbol;
            }
            self.prev_success = 0;
            var i: u32 = min_ctx.num_stats - 1;
            while (true) {
                s += 1;
                hi_cnt += s[0].freq;
                if (hi_cnt > count) {
                    const symbol = s[0].symbol;
                    try rc.decodeRange(hi_cnt - s[0].freq, s[0].freq);
                    self.found_state = self.ref(s);
                    self.update1();
                    return symbol;
                }
                if (i == 1) break;
                i -= 1;
            }
            if (count >= min_ctx.summ_freq) return error.InvalidData;
            self.hi_bits_flag = self.tables.hb2_flag[self.state(self.found_state).symbol];
            try rc.decodeRange(hi_cnt, @as(u32, min_ctx.summ_freq) - hi_cnt);
            @memset(&mask, 0xFF);
            mask[s[0].symbol] = 0;
            i = min_ctx.num_stats - 1;
            while (true) {
                s -= 1;
                mask[s[0].symbol] = 0;
                if (i == 1) break;
                i -= 1;
            }
        } else {
            const prob = self.binSumm();
            if (try rc.decodeBit(prob.*) == 0) {
                const symbol = Model.oneState(min_ctx).symbol;
                prob.* = updateProb0(prob.*);
                self.found_state = self.ref(Model.oneState(min_ctx));
                self.updateBin();
                return symbol;
            }
            prob.* = updateProb1(prob.*);
            self.init_esc = exp_escape[prob.* >> 10];
            @memset(&mask, 0xFF);
            mask[Model.oneState(min_ctx).symbol] = 0;
            self.prev_success = 0;
        }
        while (true) {
            var ps: [256]u32 = undefined;
            const num_masked = @as(u32, min_ctx.num_stats);
            while (true) {
                self.order_fall += 1;
                if (min_ctx.suffix == 0) return error.InvalidData;
                self.min_context = min_ctx.suffix;
                min_ctx = self.ctx(self.min_context);
                if (min_ctx.num_stats != num_masked) break;
            }
            var s = self.statsOf(min_ctx);
            var i: u32 = 0;
            const num = @as(u32, min_ctx.num_stats) - num_masked;
            var hi_cnt: u32 = 0;
            while (true) {
                if (mask[s[0].symbol] != 0) {
                    hi_cnt += s[0].freq;
                    ps[i] = self.ref(s);
                    i += 1;
                    if (i == num) break;
                }
                s += 1;
            }
            const esc = self.makeEscFreq(num_masked);
            const freq_sum = esc.esc_freq + hi_cnt;
            const count = try rc.getThreshold(freq_sum);
            if (count < hi_cnt) {
                var pps: usize = 0;
                hi_cnt = 0;
                while (true) {
                    hi_cnt += self.state(ps[pps]).freq;
                    if (hi_cnt > count) break;
                    pps += 1;
                }
                const s_off = ps[pps];
                const found = self.state(s_off);
                try rc.decodeRange(hi_cnt - found.freq, found.freq);
                Model.seeUpdate(esc.see);
                self.found_state = s_off;
                const symbol = found.symbol;
                self.update2();
                return symbol;
            }
            if (count >= freq_sum) return error.InvalidData;
            try rc.decodeRange(hi_cnt, freq_sum - hi_cnt);
            esc.see.summ = @intCast(esc.see.summ + freq_sum);
            while (i != 0) {
                i -= 1;
                mask[self.state(ps[i]).symbol] = 0;
            }
        }
    }

    fn encodeSymbol(self: *Model, rc: *RangeEncoder, symbol: i32) Failure!void {
        var mask: [256]u8 = undefined;
        const min_ctx = self.ctx(self.min_context);
        if (min_ctx.num_stats != 1) {
            var s = self.statsOf(min_ctx);
            rc.range /= min_ctx.summ_freq;
            if (s[0].symbol == symbol) {
                try rc.encodeFinal(0, s[0].freq);
                self.found_state = self.ref(s);
                self.update1_0();
                return;
            }
            self.prev_success = 0;
            var sum: u32 = s[0].freq;
            var i: u32 = min_ctx.num_stats - 1;
            while (true) {
                s += 1;
                if (s[0].symbol == symbol) {
                    try rc.encodeFinal(sum, s[0].freq);
                    self.found_state = self.ref(s);
                    self.update1();
                    return;
                }
                sum += s[0].freq;
                i -= 1;
                if (i == 0) break;
            }
            rc.encode(sum, min_ctx.summ_freq - sum);
            self.hi_bits_flag = self.tables.hb2_flag[self.state(self.found_state).symbol];
            @memset(&mask, 0xFF);
            var scan = self.statsOf(min_ctx);
            var n: usize = 0;
            while (n < min_ctx.num_stats) : (n += 1) {
                mask[scan[0].symbol] = 0;
                scan += 1;
            }
            mask[s[0].symbol] = 0;
        } else {
            const s = Model.oneState(min_ctx);
            const prob = self.binSumm();
            var pr: u32 = prob.*;
            const bound = (rc.range >> bit_shift) * pr;
            pr = updateProb1(@intCast(pr));
            if (s.symbol == symbol) {
                prob.* = @intCast(pr + (1 << int_bits));
                rc.range = bound;
                if (rc.range < top_value) {
                    rc.range <<= 8;
                    try rc.shiftLow();
                }
                const c_off = Model.successor(s);
                const freq = @as(u32, s.freq);
                self.found_state = self.ref(s);
                self.prev_success = 1;
                self.run_length += 1;
                s.freq = @intCast(freq + @as(u32, @intFromBool(freq < 128)));
                if (self.order_fall == 0 and c_off > self.text) {
                    self.min_context = c_off;
                    self.max_context = c_off;
                } else {
                    self.updateModel();
                }
                return;
            }
            prob.* = @intCast(pr);
            self.init_esc = exp_escape[pr >> 10];
            rc.low += @as(u64, bound);
            rc.range -= bound;
            @memset(&mask, 0xFF);
            mask[Model.oneState(min_ctx).symbol] = 0;
            self.prev_success = 0;
        }
        while (true) {
            try rc.normalize();
            var mc = self.ctx(self.min_context);
            const num_masked: u32 = mc.num_stats;
            var i: u32 = undefined;
            while (true) {
                self.order_fall += 1;
                if (mc.suffix == 0) return;
                mc = self.suffixOf(mc);
                i = mc.num_stats;
                if (i != num_masked) break;
            }
            self.min_context = self.ref(mc);
            const esc = self.makeEscFreq(num_masked);
            var s = self.statsOf(mc);
            var sum: u32 = 0;
            i = mc.num_stats;
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
                    rc.range /= total;
                    try rc.encodeFinal(low, freq);
                    self.update2();
                    return;
                }
                sum += s[0].freq & @as(u32, mask[cur]);
                s += 1;
                i -= 1;
                if (i == 0) break;
            }
            const total = sum + esc.esc_freq;
            esc.see.summ = @intCast(esc.see.summ + total);
            rc.range /= total;
            rc.encode(sum, esc.esc_freq);
            var scan = self.statsOf(mc);
            var n: usize = 0;
            while (n < mc.num_stats) : (n += 1) {
                mask[scan[0].symbol] = 0;
                scan += 1;
            }
            mask[(s - 1)[0].symbol] = 0;
        }
    }
};

fn updateProb0(prob: u16) u16 {
    const mean = (prob + (1 << (period_bits - 2))) >> period_bits;
    return prob + (1 << int_bits) - mean;
}

fn updateProb1(prob: u16) u16 {
    const mean = (prob + (1 << (period_bits - 2))) >> period_bits;
    return prob - mean;
}
