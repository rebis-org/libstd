const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;

// PPMd variant H, the model RAR3 "text compression" blocks use. Pointers are
// u32 offsets into a caller-provided heap slice, dereferenced through packed
// extern views (same technique as the 7z PPMd leaf). Offset 0 is unreachable
// — successor stubs are recorded after the pText increment — so it serves as
// NULL and the reference's `ptr <= pText` guards work verbatim on offsets.

const int_bits: u5 = 7;
const period_bits: u5 = 7;
const tot_bits: u5 = int_bits + period_bits;
const interval: u32 = 1 << int_bits;
const bin_scale: u32 = 1 << tot_bits;
const max_freq: u32 = 124;
const max_o: usize = 64;

const unit_size: u32 = 12;
const state_size: u32 = 6;

const null_off: u32 = 0;

const Ctx = extern struct {
    num_stats: u16,
    summ_freq: u16,
    stats: u32,
    suffix: u32,
};

const StateView = extern struct {
    sym: u8,
    freq: u8,
    succ_lo: u16,
    succ_hi: u16,

    // The successor is one u32 in the wire layout; the view splits it into
    // two u16 halves to keep the packed struct at the 6-byte PPMd stride.
    inline fn succ(self: *const StateView) u32 {
        return @as(u32, self.succ_hi) << 16 | self.succ_lo;
    }
    inline fn setSucc(self: *StateView, v: u32) void {
        self.succ_lo = @truncate(v);
        self.succ_hi = @truncate(v >> 16);
    }
};

const MemBlk = extern struct {
    stamp: u16,
    nu: u16,
    next: u32,
    prev: u32,
};

inline fn ctxAt(h: []u8, off: u32) *Ctx {
    return @ptrCast(@alignCast(h[off..][0..@sizeOf(Ctx)]));
}

inline fn stAt(h: []u8, off: u32) *StateView {
    return @ptrCast(@alignCast(h[off..][0..@sizeOf(StateView)]));
}

inline fn blkAt(h: []u8, off: u32) *MemBlk {
    return @ptrCast(@alignCast(h[off..][0..@sizeOf(MemBlk)]));
}

inline fn ctxOneState(c: u32) u32 {
    return c + 2;
}

// Held outside the heap like the reference's stack-local UpState.
const LocalState = struct {
    sym: u8,
    freq: u8,
    succ: u32,

    fn load(h: []const u8, s: u32) LocalState {
        const v = stAt(@constCast(h), s);
        return .{ .sym = v.sym, .freq = v.freq, .succ = @as(u32, v.succ_hi) << 16 | v.succ_lo };
    }
    fn store(self: LocalState, h: []u8, s: u32) void {
        const v = stAt(h, s);
        v.sym = self.sym;
        v.freq = self.freq;
        v.succ_lo = @truncate(self.succ);
        v.succ_hi = @truncate(self.succ >> 16);
    }
};

const RangeCoder = struct {
    low: u32,
    code: u32,
    range: u32,
    low_count: u32,
    high_count: u32,
    scale: u32,

    // The reference GetChar reads raw bytes from an over-allocated input
    // buffer and returns stale bytes at EOF, relying on the model's guards to
    // notice corruption. Returning 0 on exhaustion has the same property:
    // deterministic garbage the guards catch, never a panic.
    fn getByte(br: *BitReader) u32 {
        return br.readBits(8) catch 0;
    }

    fn initDecoder(self: *RangeCoder, br: *BitReader) void {
        self.low = 0;
        self.code = 0;
        self.range = 0xFFFFFFFF;
        for (0..4) |_| self.code = (self.code << 8) | getByte(br);
    }

    // (code-low)/(range /= scale). A zero divisor is corrupt-stream state the
    // C original would crash on; report corruption instead.
    fn currentCount(self: *RangeCoder) Failure!u32 {
        if (self.scale == 0) return error.InvalidData;
        self.range /= self.scale;
        if (self.range == 0) return error.InvalidData;
        return (self.code -% self.low) / self.range;
    }

    fn currentShiftCount(self: *RangeCoder, shift: u5) Failure!u32 {
        self.range >>= shift;
        if (self.range == 0) return error.InvalidData;
        return (self.code -% self.low) / self.range;
    }

    fn decodeUpdate(self: *RangeCoder) void {
        self.low +%= self.range *% self.low_count;
        self.range *%= self.high_count -% self.low_count;
    }

    // ARI_DEC_NORMALIZE. The `||` short-circuit matters: when the top bytes of
    // low and low+range already differ, range is NOT reset even if small.
    fn normalize(self: *RangeCoder, br: *BitReader) void {
        while (true) {
            if ((self.low ^ (self.low +% self.range)) >= (1 << 24)) {
                if (self.range >= (1 << 15)) break;
                self.range = (0 -% self.low) & ((1 << 15) - 1);
            }
            self.code = (self.code << 8) | getByte(br);
            self.range <<= 8;
            self.low <<= 8;
        }
    }
};

const n1 = 4;
const n2 = 4;
const n3 = 4;
const n4 = (128 + 3 - 1 * n1 - 2 * n2 - 3 * n3) / 4;
const n_indexes = n1 + n2 + n3 + n4;

const SubAllocator = struct {
    heap: []u8,
    sub_allocator_size: u32, // the ORIGINAL byte size requested
    glue_count: u8,
    indx2units: [n_indexes]u8,
    units2indx: [128]u8,
    free_list: [n_indexes]u32,
    ptext: u32,
    units_start: u32,
    fake_units_start: u32,
    heap_end: u32,
    lo_unit: u32,
    hi_unit: u32,

    fn initEmpty() SubAllocator {
        return .{
            .heap = &.{},
            .sub_allocator_size = 0,
            .glue_count = 0,
            .indx2units = undefined,
            .units2indx = undefined,
            .free_list = [_]u32{null_off} ** n_indexes,
            .ptext = 0,
            .units_start = 0,
            .fake_units_start = 0,
            .heap_end = 0,
            .lo_unit = 0,
            .hi_unit = 0,
        };
    }

    fn stop(self: *SubAllocator) void {
        self.heap = &.{};
        self.sub_allocator_size = 0;
    }

    // heap must be at least (sa_size_mb << 20) bytes; the caller sizes the
    // slice before the stream's requested model size is known, so a stream
    // asking for more than the caller provisioned is refused here. The pool
    // is 4-byte aligned inside the slice so u32 fields load directly.
    fn start(self: *SubAllocator, heap: []u8, sa_size_mb: u32) bool {
        const t: u32 = sa_size_mb << 20;
        if (self.sub_allocator_size == t) return true;
        const alloc_size: usize = @as(usize, t) / unit_size * unit_size + 2 * unit_size;
        if (heap.len < alloc_size + 8) return false;
        const base = std.mem.alignForward(usize, @intFromPtr(heap.ptr), 4) - @intFromPtr(heap.ptr);
        if (heap.len - base < alloc_size) return false;
        self.heap = heap[base .. base + alloc_size];
        self.heap_end = @intCast(alloc_size - unit_size);
        self.sub_allocator_size = t;
        return true;
    }

    fn initSubAllocator(self: *SubAllocator) void {
        @memset(&self.free_list, null_off);
        self.ptext = 0;

        const t = self.sub_allocator_size;
        // 7/8 of the pool for units, 1/8 for the text area; UNIT_SIZE ==
        // FIXED_UNIT_SIZE collapses the reference's Real*/Fake* split except
        // for the +UNIT_SIZE remainder compensation, kept verbatim.
        const size2: u32 = unit_size * (t / 8 / unit_size * 7);
        const size1: u32 = t - size2;
        const real_size1: u32 = size1 / unit_size * unit_size + unit_size;

        self.units_start = real_size1;
        self.lo_unit = real_size1;
        self.fake_units_start = size1;
        self.hi_unit = self.lo_unit + size2;

        var i: usize = 0;
        var k: u8 = 1;
        while (i < n1) : ({
            i += 1;
            k += 1;
        }) self.indx2units[i] = k;
        k += 1;
        while (i < n1 + n2) : ({
            i += 1;
            k += 2;
        }) self.indx2units[i] = k;
        k += 1;
        while (i < n1 + n2 + n3) : ({
            i += 1;
            k += 3;
        }) self.indx2units[i] = k;
        k += 1;
        while (i < n_indexes) : ({
            i += 1;
            k += 4;
        }) self.indx2units[i] = k;

        self.glue_count = 0;
        var ii: usize = 0;
        for (0..128) |kk| {
            if (self.indx2units[ii] < kk + 1) ii += 1;
            self.units2indx[kk] = @intCast(ii);
        }
    }

    inline fn u2b(nu: u32) u32 {
        return unit_size * nu;
    }

    inline fn insertNode(self: *SubAllocator, p: u32, indx: usize) void {
        std.mem.writeInt(u32, self.heap[p..][0..4], self.free_list[indx], .little);
        self.free_list[indx] = p;
    }

    inline fn removeNode(self: *SubAllocator, indx: usize) u32 {
        const r = self.free_list[indx];
        self.free_list[indx] = std.mem.readInt(u32, self.heap[r..][0..4], .little);
        return r;
    }

    fn splitBlock(self: *SubAllocator, pv: u32, old_indx: usize, new_indx: usize) void {
        var udiff: u32 = @as(u32, self.indx2units[old_indx]) - self.indx2units[new_indx];
        var p: u32 = pv + u2b(self.indx2units[new_indx]);
        var i: usize = self.units2indx[udiff - 1];
        if (self.indx2units[i] != udiff) {
            i -= 1;
            self.insertNode(p, i);
            const iu: u32 = self.indx2units[i];
            p += u2b(iu);
            udiff -= iu;
        }
        self.insertNode(p, self.units2indx[udiff - 1]);
    }

    // GlueFreeBlocks. The reference threads a stack-local sentinel node (s0)
    // into the doubly-linked list; the sentinel's links live in locals and
    // accesses route through S0 comparisons instead.
    const s0: u32 = 0xFFFFFFFF;

    fn glueFreeBlocks(self: *SubAllocator) void {
        var s0_next: u32 = s0;
        var s0_prev: u32 = s0;
        const h = self.heap;

        if (self.lo_unit != self.hi_unit) h[self.lo_unit] = 0;

        // Phase 1: drain the free lists into one stamped, doubly-linked list.
        for (0..n_indexes) |i| {
            while (self.free_list[i] != null_off) {
                const p = self.removeNode(i);
                const blk = blkAt(h, p);
                const next = s0_next;
                blk.prev = s0;
                blk.next = next;
                if (next == s0) s0_prev = p else blkAt(h, next).prev = p;
                s0_next = p;
                blk.stamp = 0xFFFF;
                blk.nu = self.indx2units[i];
            }
        }

        // Phase 2: merge physically adjacent stamped blocks.
        var p = s0_next;
        while (p != s0) : (p = blkAt(h, p).next) {
            while (true) {
                const p1 = p + u2b(blkAt(h, p).nu);
                if (p1 + unit_size > h.len) break; // guard; unreachable for valid states
                const blk1 = blkAt(h, p1);
                if (blk1.stamp != 0xFFFF) break;
                const total: u32 = @as(u32, blkAt(h, p).nu) + blk1.nu;
                if (total >= 0x10000) break;
                const pr = blk1.prev;
                const nx = blk1.next;
                if (pr == s0) s0_next = nx else blkAt(h, pr).next = nx;
                if (nx == s0) s0_prev = pr else blkAt(h, nx).prev = pr;
                blkAt(h, p).nu = @intCast(total);
            }
        }

        // Phase 3: re-insert, chopping >128-unit runs.
        while (s0_next != s0) {
            p = s0_next;
            {
                const nx = blkAt(h, p).next;
                if (nx == s0) s0_prev = s0 else blkAt(h, nx).prev = s0;
                s0_next = nx;
            }
            var sz: u32 = blkAt(h, p).nu;
            while (sz > 128) : (sz -= 128) {
                self.insertNode(p, n_indexes - 1);
                p += u2b(128);
            }
            var i: usize = self.units2indx[sz - 1];
            if (self.indx2units[i] != sz) {
                i -= 1;
                const k: u32 = sz - self.indx2units[i];
                self.insertNode(p + u2b(sz - k), @intCast(k - 1));
            }
            self.insertNode(p, i);
        }
    }

    fn allocUnitsRare(self: *SubAllocator, indx: usize) u32 {
        if (self.glue_count == 0) {
            self.glue_count = 255;
            self.glueFreeBlocks();
            if (self.free_list[indx] != null_off) return self.removeNode(indx);
        }
        var i = indx;
        while (true) {
            i += 1;
            if (i == n_indexes) {
                self.glue_count -%= 1;
                const bytes: u32 = u2b(self.indx2units[indx]);
                // FIXED_UNIT_SIZE == UNIT_SIZE, so the reference's separate
                // fake-units bookkeeping moves in lockstep with the real one.
                if (self.fake_units_start > self.ptext and
                    self.fake_units_start - self.ptext > bytes)
                {
                    self.fake_units_start -= bytes;
                    self.units_start -= bytes;
                    return self.units_start;
                }
                return null_off;
            }
            if (self.free_list[i] != null_off) break;
        }
        const ret = self.removeNode(i);
        self.splitBlock(ret, i, indx);
        return ret;
    }

    fn allocUnits(self: *SubAllocator, nu: u32) u32 {
        const indx: usize = self.units2indx[nu - 1];
        if (self.free_list[indx] != null_off) return self.removeNode(indx);
        const ret = self.lo_unit;
        self.lo_unit += u2b(self.indx2units[indx]);
        if (self.lo_unit <= self.hi_unit) return ret;
        self.lo_unit -= u2b(self.indx2units[indx]);
        return self.allocUnitsRare(indx);
    }

    fn allocContext(self: *SubAllocator) u32 {
        if (self.hi_unit != self.lo_unit) {
            self.hi_unit -= unit_size;
            return self.hi_unit;
        }
        if (self.free_list[0] != null_off) return self.removeNode(0);
        return self.allocUnitsRare(0);
    }

    fn expandUnits(self: *SubAllocator, old_ptr: u32, old_nu: u32) u32 {
        const idx_old: usize = self.units2indx[old_nu - 1];
        const idx_new: usize = self.units2indx[old_nu];
        if (idx_old == idx_new) return old_ptr;
        const ptr = self.allocUnits(old_nu + 1);
        if (ptr != null_off) {
            std.mem.copyForwards(u8, self.heap[ptr..][0..u2b(old_nu)], self.heap[old_ptr..][0..u2b(old_nu)]);
            self.insertNode(old_ptr, idx_old);
        }
        return ptr;
    }

    fn shrinkUnits(self: *SubAllocator, old_ptr: u32, old_nu: u32, new_nu: u32) u32 {
        const idx_old: usize = self.units2indx[old_nu - 1];
        const idx_new: usize = self.units2indx[new_nu - 1];
        if (idx_old == idx_new) return old_ptr;
        if (self.free_list[idx_new] != null_off) {
            const ptr = self.removeNode(idx_new);
            std.mem.copyForwards(u8, self.heap[ptr..][0..u2b(new_nu)], self.heap[old_ptr..][0..u2b(new_nu)]);
            self.insertNode(old_ptr, idx_old);
            return ptr;
        }
        self.splitBlock(old_ptr, idx_old, idx_new);
        return old_ptr;
    }

    fn freeUnits(self: *SubAllocator, ptr: u32, old_nu: u32) void {
        self.insertNode(ptr, self.units2indx[old_nu - 1]);
    }
};

const See2 = struct {
    summ: u16,
    shift: u8,
    count: u8,

    fn init(init_val: u32) See2 {
        const shift: u8 = period_bits - 4;
        return .{
            .summ = @truncate(init_val << @intCast(shift)),
            .shift = shift,
            .count = 4,
        };
    }

    // Signed arithmetic exactly as the reference: `short RetVal = (short)Summ
    // >> Shift` sign-extends, and the return converts through int to uint.
    fn getMean(self: *See2) u32 {
        const ret: i32 = @as(i16, @bitCast(self.summ)) >> @intCast(self.shift);
        self.summ -%= @bitCast(@as(i16, @truncate(ret)));
        return @bitCast(ret + @intFromBool(ret == 0));
    }

    fn update(self: *See2) void {
        if (self.shift < period_bits) {
            self.count -%= 1;
            if (self.count == 0) {
                self.summ +%= self.summ;
                self.count = @truncate(@as(u32, 3) << @intCast(self.shift));
                self.shift += 1;
            }
        }
    }
};

// GET_MEAN(SUMM,SHIFT,ROUND) from the reference.
inline fn getMeanSpread(summ: u32, comptime shift: u5, comptime round: u5) u32 {
    return (summ + (@as(u32, 1) << (shift - round))) >> shift;
}

const exp_escape = [16]u8{ 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };
const init_bin_esc = [8]u16{ 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };

pub const PpmModel = struct {
    coder: RangeCoder,
    sub: SubAllocator,

    see2: [25][16]See2,
    dummy_see2: See2,
    min_context: u32,
    max_context: u32,
    found_state: u32, // state offset, null_off when escaped
    num_masked: u32,
    init_esc: u32,
    order_fall: i32,
    max_order: u32,
    run_length: i32,
    init_rl: i32,
    char_mask: [256]u8,
    ns2indx: [256]u8,
    ns2bsindx: [256]u8,
    hb2flag: [256]u8,
    esc_count: u8,
    prev_success: u8,
    hi_bits_flag: u8,
    bin_summ: [128][64]u16,

    const Self = @This();

    pub fn init() Self {
        var m: Self = undefined;
        m.sub = SubAllocator.initEmpty();
        m.min_context = null_off;
        m.max_context = null_off;
        m.found_state = null_off;
        return m;
    }

    // heap: caller-provided pool; the stream names its model size in MiB and
    // anything up to heap.len is accepted, larger is refused.
    pub fn startModel(self: *Self, heap: []u8, max_order: u32, heap_mb: u32) Failure!void {
        self.esc_count = 1;
        self.max_order = max_order;
        if (!self.sub.start(heap, heap_mb)) return error.InsufficientCapacity;
        try self.restartModelRare();
        self.ns2bsindx[0] = 2 * 0;
        self.ns2bsindx[1] = 2 * 1;
        @memset(self.ns2bsindx[2..11], 2 * 2);
        @memset(self.ns2bsindx[11..256], 2 * 3);
        for (0..3) |i| self.ns2indx[i] = @intCast(i);
        {
            var m: u8 = 3;
            var k: u32 = 1;
            var step: u32 = 1;
            var i: usize = 3;
            while (i < 256) : (i += 1) {
                self.ns2indx[i] = m;
                k -= 1;
                if (k == 0) {
                    step += 1;
                    k = step;
                    m += 1;
                }
            }
        }
        @memset(self.hb2flag[0..0x40], 0);
        @memset(self.hb2flag[0x40..0x100], 0x08);
        self.dummy_see2 = .{ .summ = 0, .shift = period_bits, .count = 64 };
    }

    // ModelPPM::DecodeInit. The reference peeks the PPM-block flag without
    // consuming, so this first byte read must stay bit-aligned with it;
    // consuming even one flag bit desynchronises the whole stream.
    pub fn decodeInit(self: *Self, br: *BitReader, heap: []u8, esc_char: *u8) Failure!bool {
        var max_order: u32 = RangeCoder.getByte(br);
        const reset = (max_order & 0x20) != 0;
        var max_mb: u32 = 0;
        if (reset) {
            max_mb = RangeCoder.getByte(br);
        } else {
            if (self.sub.sub_allocator_size == 0) return false;
        }
        if (max_order & 0x40 != 0) esc_char.* = @intCast(RangeCoder.getByte(br));
        self.coder.initDecoder(br);
        if (reset) {
            max_order = (max_order & 0x1F) + 1;
            if (max_order > 16) max_order = 16 + (max_order - 16) * 3;
            if (max_order == 1) {
                self.sub.stop();
                return false;
            }
            try self.startModel(heap, max_order, max_mb + 1);
        }
        return self.min_context != null_off;
    }

    // ModelPPM::DecodeChar. Returns the decoded byte, or InvalidData on
    // corrupt data (the reference's -1).
    pub fn decodeChar(self: *Self, br: *BitReader) Failure!u32 {
        const h = self.sub.heap;
        if (self.min_context <= self.sub.ptext or self.min_context > self.sub.heap_end)
            return error.InvalidData;
        const min_ctx = ctxAt(h, self.min_context);
        if (min_ctx.num_stats != 1) {
            const stats = min_ctx.stats;
            if (stats <= self.sub.ptext or stats > self.sub.heap_end)
                return error.InvalidData;
            if (!try self.decodeSymbol1(self.min_context))
                return error.InvalidData;
        } else {
            self.decodeBinSymbol(self.min_context);
        }
        self.coder.decodeUpdate();
        while (self.found_state == null_off) {
            self.coder.normalize(br);
            while (true) {
                self.order_fall += 1;
                self.min_context = ctxAt(h, self.min_context).suffix;
                if (self.min_context <= self.sub.ptext or
                    self.min_context > self.sub.heap_end)
                    return error.InvalidData;
                if (ctxAt(h, self.min_context).num_stats != self.num_masked) break;
            }
            if (!try self.decodeSymbol2(self.min_context))
                return error.InvalidData;
            self.coder.decodeUpdate();
        }
        const symbol: u32 = stAt(h, self.found_state).sym;
        if (self.order_fall == 0 and stAt(h, self.found_state).succ() > self.sub.ptext) {
            const succ_off = stAt(h, self.found_state).succ();
            self.min_context = succ_off;
            self.max_context = succ_off;
        } else {
            try self.updateModel();
            if (self.esc_count == 0) self.clearMask();
        }
        self.coder.normalize(br);
        return symbol;
    }

    fn restartModelRare(self: *Self) Failure!void {
        @memset(&self.char_mask, 0);
        self.sub.initSubAllocator();
        self.init_rl = -@as(i32, @intCast(@min(self.max_order, 12))) - 1;
        const mc = self.sub.allocContext();
        if (mc == null_off) return error.InvalidData;
        self.min_context = mc;
        self.max_context = mc;
        const h = self.sub.heap;
        const root = ctxAt(h, mc);
        root.suffix = null_off;
        self.order_fall = @intCast(self.max_order);
        root.num_stats = 256;
        root.summ_freq = 256 + 1;
        const stats = self.sub.allocUnits(256 / 2);
        if (stats == null_off) return error.InvalidData;
        root.stats = stats;
        self.found_state = stats;
        self.run_length = self.init_rl;
        self.prev_success = 0;
        for (0..256) |i| {
            const s = stAt(h, stats + @as(u32, @intCast(i)) * state_size);
            s.sym = @intCast(i);
            s.freq = 1;
            s.setSucc(null_off);
        }

        for (0..128) |i| {
            for (0..8) |k| {
                var m: usize = 0;
                while (m < 64) : (m += 8) {
                    self.bin_summ[i][k + m] =
                        @truncate(bin_scale - init_bin_esc[k] / (@as(u32, @intCast(i)) + 2));
                }
            }
        }
        for (0..25) |i| {
            for (0..16) |k| {
                self.see2[i][k] = See2.init(5 * @as(u32, @intCast(i)) + 10);
            }
        }
    }

    // Reset after data error, allowing safe resuming (CleanUp).
    pub fn cleanUp(self: *Self, heap: []u8) void {
        self.sub.stop();
        self.startModel(heap, 2, 1) catch {};
    }

    fn createChild(self: *Self, c: u32, p_state: u32, first: LocalState) u32 {
        const pc = self.sub.allocContext();
        if (pc != null_off) {
            const h = self.sub.heap;
            const child = ctxAt(h, pc);
            child.num_stats = 1;
            first.store(h, ctxOneState(pc));
            child.suffix = c;
            stAt(h, p_state).setSucc(pc);
        }
        return pc;
    }

    fn rescale(self: *Self, c: u32) void {
        const h = self.sub.heap;
        const cctx = ctxAt(h, c);
        const old_ns: u32 = cctx.num_stats;
        if (old_ns == 0) return; // corrupt heap; guards will surface it
        var i: u32 = old_ns - 1;
        const stats = cctx.stats;

        {
            var p = self.found_state;
            while (p != stats) : (p -= state_size) {
                swapStates(h, p, p - state_size);
            }
        }
        const head = stAt(h, stats);
        head.freq = head.freq +| 4;
        cctx.summ_freq = cctx.summ_freq +% 4;
        var esc_freq: u32 = @as(u32, cctx.summ_freq) -% head.freq;
        const adder: u32 = @intFromBool(self.order_fall != 0);
        head.freq = @intCast((@as(u32, head.freq) + adder) >> 1);
        var summ_freq: u32 = head.freq;

        var p = stats;
        while (i != 0) : (i -= 1) {
            p += state_size;
            const sp = stAt(h, p);
            esc_freq -%= sp.freq;
            sp.freq = @intCast((@as(u32, sp.freq) + adder) >> 1);
            summ_freq += sp.freq;
            if (sp.freq > stAt(h, p - state_size).freq) {
                var p1 = p;
                var tmp: [state_size]u8 = undefined;
                @memcpy(&tmp, h[p1..][0..state_size]);
                const tmp_freq = tmp[1];
                while (p1 != stats and tmp_freq > stAt(h, p1 - state_size).freq) : (p1 -= state_size) {
                    copyState(h, p1, p1 - state_size);
                }
                @memcpy(h[p1..][0..state_size], &tmp);
            }
        }

        if (stAt(h, p).freq == 0) {
            var zeros: u32 = 0;
            while (stAt(h, p).freq == 0) {
                zeros += 1;
                p -= state_size;
            }
            esc_freq +%= zeros;
            const new_ns = old_ns - zeros;
            cctx.num_stats = @intCast(new_ns);
            if (new_ns == 1) {
                var tmp = LocalState.load(h, stats);
                var ef = esc_freq;
                while (true) {
                    tmp.freq -= tmp.freq >> 1;
                    ef >>= 1;
                    if (ef <= 1) break;
                }
                self.sub.freeUnits(stats, (old_ns + 1) >> 1);
                tmp.store(h, ctxOneState(c));
                self.found_state = ctxOneState(c);
                return;
            }
        }
        const ns: u32 = cctx.num_stats;
        esc_freq -%= esc_freq >> 1;
        cctx.summ_freq = @truncate(summ_freq + esc_freq);
        const half0 = (old_ns + 1) >> 1;
        const half1 = (ns + 1) >> 1;
        if (half0 != half1) {
            const moved = self.sub.shrinkUnits(stats, half0, half1);
            cctx.stats = moved;
        }
        self.found_state = cctx.stats;
    }

    fn createSuccessors(self: *Self, skip: bool, p1: u32) u32 {
        const h = self.sub.heap;
        var pc = self.min_context;
        const up_branch = stAt(h, self.found_state).succ();
        var ps: [max_o]u32 = undefined;
        var nps: usize = 0;
        var p: u32 = null_off;

        var goto_no_loop = false;
        var goto_loop_entry = false;
        if (!skip) {
            ps[nps] = self.found_state;
            nps += 1;
            if (ctxAt(h, pc).suffix == null_off) goto_no_loop = true;
        }
        if (!goto_no_loop and p1 != null_off) {
            p = p1;
            pc = ctxAt(h, pc).suffix;
            goto_loop_entry = true;
        }
        if (!goto_no_loop) {
            while (true) {
                if (!goto_loop_entry) {
                    pc = ctxAt(h, pc).suffix;
                    if (ctxAt(h, pc).num_stats != 1) {
                        p = ctxAt(h, pc).stats;
                        if (stAt(h, p).sym != stAt(h, self.found_state).sym) {
                            while (true) {
                                p += state_size;
                                if (p + state_size > h.len) return null_off; // guard
                                if (stAt(h, p).sym == stAt(h, self.found_state).sym) break;
                            }
                        }
                    } else {
                        p = ctxOneState(pc);
                    }
                }
                goto_loop_entry = false;
                if (stAt(h, p).succ() != up_branch) {
                    pc = stAt(h, p).succ();
                    break;
                }
                if (nps >= max_o) return null_off; // reference guard
                ps[nps] = p;
                nps += 1;
                if (ctxAt(h, pc).suffix == null_off) break;
            }
        }
        if (nps == 0) return pc;

        var up: LocalState = .{
            .sym = h[up_branch],
            .freq = 0,
            .succ = up_branch + 1,
        };
        if (ctxAt(h, pc).num_stats != 1) {
            if (pc <= self.sub.ptext) return null_off;
            var pp = ctxAt(h, pc).stats;
            if (stAt(h, pp).sym != up.sym) {
                while (true) {
                    pp += state_size;
                    if (pp + state_size > h.len) return null_off; // guard
                    if (stAt(h, pp).sym == up.sym) break;
                }
            }
            const cf: u32 = @as(u32, stAt(h, pp).freq) - 1;
            const s0: u32 = @as(u32, ctxAt(h, pc).summ_freq) -% ctxAt(h, pc).num_stats -% cf;
            up.freq = @intCast(1 + (if (2 * cf <= s0)
                @intFromBool(5 * cf > s0)
            else
                (2 * cf + 3 * s0 - 1) / (2 * s0)));
        } else {
            up.freq = stAt(h, ctxOneState(pc)).freq;
        }

        while (true) {
            nps -= 1;
            pc = self.createChild(pc, ps[nps], up);
            if (pc == null_off) return null_off;
            if (nps == 0) break;
        }
        return pc;
    }

    fn updateModel(self: *Self) Failure!void {
        const h = self.sub.heap;
        const fs = LocalState.load(h, self.found_state);
        var fs_succ = fs.succ;
        var p: u32 = null_off;

        const min_ctx = ctxAt(h, self.min_context);
        if (fs.freq < max_freq / 4 and min_ctx.suffix != null_off) {
            const pc_off = min_ctx.suffix;
            const pc = ctxAt(h, pc_off);
            if (pc.num_stats != 1) {
                p = pc.stats;
                if (stAt(h, p).sym != fs.sym) {
                    while (true) {
                        p += state_size;
                        if (p + state_size > h.len) return error.InvalidData;
                        if (stAt(h, p).sym == fs.sym) break;
                    }
                    if (stAt(h, p).freq >= stAt(h, p - state_size).freq) {
                        swapStates(h, p, p - state_size);
                        p -= state_size;
                    }
                }
                if (stAt(h, p).freq < max_freq - 9) {
                    stAt(h, p).freq += 2;
                    pc.summ_freq = pc.summ_freq +% 2;
                }
            } else {
                p = ctxOneState(pc_off);
                if (stAt(h, p).freq < 32) stAt(h, p).freq += 1;
            }
        }

        if (self.order_fall == 0) {
            const new_succ = self.createSuccessors(true, p);
            if (new_succ == null_off) {
                try self.restartModelRare();
                self.esc_count = 0;
                return;
            }
            stAt(h, self.found_state).setSucc(new_succ);
            self.min_context = new_succ;
            self.max_context = new_succ;
            return;
        }

        h[self.sub.ptext] = fs.sym;
        self.sub.ptext += 1;
        var successor: u32 = self.sub.ptext;
        if (self.sub.ptext >= self.sub.fake_units_start) {
            try self.restartModelRare();
            self.esc_count = 0;
            return;
        }

        if (fs_succ != null_off) {
            if (fs_succ <= self.sub.ptext) {
                fs_succ = self.createSuccessors(false, p);
                if (fs_succ == null_off) {
                    try self.restartModelRare();
                    self.esc_count = 0;
                    return;
                }
            }
            self.order_fall -= 1;
            if (self.order_fall == 0) {
                successor = fs_succ;
                if (self.max_context != self.min_context) self.sub.ptext -= 1;
            }
        } else {
            stAt(h, self.found_state).setSucc(successor);
            fs_succ = self.min_context;
        }

        const ns: u32 = min_ctx.num_stats;
        const s0: u32 = @as(u32, min_ctx.summ_freq) -% ns -% (@as(u32, fs.freq) - 1);
        var pc_off = self.max_context;
        while (pc_off != self.min_context) : (pc_off = ctxAt(h, pc_off).suffix) {
            const pc = ctxAt(h, pc_off);
            const ns1: u32 = pc.num_stats;
            if (ns1 != 1) {
                if ((ns1 & 1) == 0) {
                    const grown = self.sub.expandUnits(pc.stats, ns1 >> 1);
                    if (grown == null_off) {
                        try self.restartModelRare();
                        self.esc_count = 0;
                        return;
                    }
                    pc.stats = grown;
                }
                const bump: u32 = @as(u32, @intFromBool(2 * ns1 < ns)) +
                    2 * @as(u32, @intFromBool((4 * ns1 <= ns) and
                        (pc.summ_freq <= 8 * ns1)));
                pc.summ_freq = pc.summ_freq +% @as(u16, @truncate(bump));
            } else {
                const np = self.sub.allocUnits(1);
                if (np == null_off) {
                    try self.restartModelRare();
                    self.esc_count = 0;
                    return;
                }
                copyState(h, np, ctxOneState(pc_off));
                pc.stats = np;
                var f: u32 = stAt(h, np).freq;
                if (f < max_freq / 4 - 1) f += f else f = max_freq - 4;
                stAt(h, np).freq = @intCast(f);
                pc.summ_freq = @truncate(f + self.init_esc +
                    @intFromBool(ns > 3));
            }
            var cf: u32 = 2 * @as(u32, fs.freq) * (@as(u32, pc.summ_freq) + 6);
            const sf: u32 = s0 +% pc.summ_freq;
            if (cf < 6 * sf) {
                cf = 1 + @as(u32, @intFromBool(cf > sf)) + @intFromBool(cf >= 4 * sf);
                pc.summ_freq = pc.summ_freq +% 3;
            } else {
                cf = 4 + @as(u32, @intFromBool(cf >= 9 * sf)) +
                    @intFromBool(cf >= 12 * sf) + @intFromBool(cf >= 15 * sf);
                pc.summ_freq = pc.summ_freq +% @as(u16, @truncate(cf));
            }
            const np2 = pc.stats + ns1 * state_size;
            if (np2 + state_size > h.len) return error.InvalidData;
            const nstate = stAt(h, np2);
            nstate.setSucc(successor);
            nstate.sym = fs.sym;
            nstate.freq = @truncate(cf);
            pc.num_stats = @intCast(ns1 + 1);
        }
        self.min_context = fs_succ;
        self.max_context = fs_succ;
    }

    fn decodeBinSymbol(self: *Self, c: u32) void {
        const h = self.sub.heap;
        const rs = ctxOneState(c);
        const rs_state = stAt(h, rs);
        self.hi_bits_flag = self.hb2flag[stAt(h, self.found_state).sym];
        const cctx = ctxAt(h, c);
        const suffix_ns: usize = ctxAt(h, cctx.suffix).num_stats;
        // Saturating indexes: a corrupt heap can hold zero frequencies or a
        // zero-stats suffix; the C original would index garbage, we take the
        // escape path and let the guards/CRC surface it.
        const freq_idx: usize = @as(usize, rs_state.freq) -| 1;
        if (suffix_ns == 0) {
            self.found_state = null_off;
            self.coder.low_count = 0;
            self.coder.high_count = bin_scale;
            return;
        }
        const bs_idx: usize = @as(usize, self.prev_success) +
            self.ns2bsindx[suffix_ns - 1] +
            self.hi_bits_flag +
            2 * @as(usize, self.hb2flag[rs_state.sym]) +
            @as(usize, @intCast((self.run_length >> 26) & 0x20));
        const bs = &self.bin_summ[freq_idx][bs_idx];

        const shifted = self.coder.currentShiftCount(tot_bits) catch {
            // Range collapse: force the escape path; guards will surface it.
            self.found_state = null_off;
            self.coder.low_count = 0;
            self.coder.high_count = bin_scale;
            return;
        };
        if (shifted < bs.*) {
            self.found_state = rs;
            if (rs_state.freq < 128) rs_state.freq += 1;
            self.coder.low_count = 0;
            self.coder.high_count = bs.*;
            bs.* = @truncate(@as(u32, bs.*) + interval - getMeanSpread(bs.*, period_bits, 2));
            self.prev_success = 1;
            self.run_length += 1;
        } else {
            self.coder.low_count = bs.*;
            bs.* = @truncate(@as(u32, bs.*) - getMeanSpread(bs.*, period_bits, 2));
            self.coder.high_count = bin_scale;
            self.init_esc = exp_escape[bs.* >> 10];
            self.num_masked = 1;
            self.char_mask[rs_state.sym] = self.esc_count;
            self.prev_success = 0;
            self.found_state = null_off;
        }
    }

    fn update1(self: *Self, c: u32, p_in: u32) void {
        const h = self.sub.heap;
        var p = p_in;
        const cctx = ctxAt(h, c);
        self.found_state = p;
        var sp = stAt(h, p);
        sp.freq += 4;
        cctx.summ_freq = cctx.summ_freq +% 4;
        if (sp.freq > stAt(h, p - state_size).freq) {
            swapStates(h, p, p - state_size);
            p -= state_size;
            sp = stAt(h, p);
            self.found_state = p;
            if (sp.freq > max_freq) self.rescale(c);
        }
    }

    fn decodeSymbol1(self: *Self, c: u32) Failure!bool {
        const h = self.sub.heap;
        const cctx = ctxAt(h, c);
        if (cctx.num_stats == 0) return error.InvalidData;
        self.coder.scale = cctx.summ_freq;
        var p = cctx.stats;
        const count = try self.coder.currentCount();
        if (count >= self.coder.scale) return false;
        var hi_cnt: u32 = stAt(h, p).freq;
        if (count < hi_cnt) {
            self.coder.high_count = hi_cnt;
            self.prev_success = @intFromBool(2 * hi_cnt > self.coder.scale);
            self.run_length += self.prev_success;
            hi_cnt += 4;
            self.found_state = p;
            stAt(h, p).freq = @intCast(hi_cnt);
            cctx.summ_freq = cctx.summ_freq +% 4;
            if (hi_cnt > max_freq) self.rescale(c);
            self.coder.low_count = 0;
            return true;
        } else if (self.found_state == null_off) {
            return false;
        }
        self.prev_success = 0;
        var i: u32 = cctx.num_stats - 1;
        while (true) {
            p += state_size;
            if (p + state_size > h.len) return error.InvalidData;
            hi_cnt += stAt(h, p).freq;
            if (hi_cnt > count) break;
            i -= 1;
            if (i == 0) {
                self.hi_bits_flag = self.hb2flag[stAt(h, self.found_state).sym];
                self.coder.low_count = hi_cnt;
                const p_state = stAt(h, p);
                self.char_mask[p_state.sym] = self.esc_count;
                self.num_masked = cctx.num_stats;
                self.found_state = null_off;
                var j: u32 = self.num_masked - 1;
                var pp = p;
                while (j != 0) : (j -= 1) {
                    pp -= state_size;
                    self.char_mask[stAt(h, pp).sym] = self.esc_count;
                }
                self.coder.high_count = self.coder.scale;
                return true;
            }
        }
        self.coder.high_count = hi_cnt;
        self.coder.low_count = hi_cnt - stAt(h, p).freq;
        self.update1(c, p);
        return true;
    }

    fn update2(self: *Self, c: u32, p: u32) void {
        const h = self.sub.heap;
        self.found_state = p;
        const sp = stAt(h, p);
        sp.freq += 4;
        ctxAt(h, c).summ_freq = ctxAt(h, c).summ_freq +% 4;
        if (sp.freq > max_freq) self.rescale(c);
        self.esc_count +%= 1;
        self.run_length = self.init_rl;
    }

    fn makeEscFreq2(self: *Self, c: u32, diff: u32) *See2 {
        const h = self.sub.heap;
        const cctx = ctxAt(h, c);
        const num_stats: u32 = cctx.num_stats;
        if (diff == 0) {
            // Nothing left unmasked; the reference would index ns2indx[-1].
            self.coder.scale = 1;
            return &self.dummy_see2;
        }
        if (num_stats != 256) {
            const suffix_ns: u32 = ctxAt(h, cctx.suffix).num_stats;
            const idx1: usize = self.ns2indx[diff - 1];
            const idx2: usize = @as(usize, @intFromBool(diff < suffix_ns - num_stats)) +
                2 * @as(usize, @intFromBool(cctx.summ_freq < 11 * num_stats)) +
                4 * @as(usize, @intFromBool(self.num_masked > diff)) +
                self.hi_bits_flag;
            const psee = &self.see2[idx1][idx2];
            self.coder.scale = psee.getMean();
            return psee;
        }
        self.coder.scale = 1;
        return &self.dummy_see2;
    }

    fn decodeSymbol2(self: *Self, c: u32) Failure!bool {
        const h = self.sub.heap;
        const cctx = ctxAt(h, c);
        if (self.num_masked >= cctx.num_stats) return error.InvalidData;
        var i: u32 = cctx.num_stats - self.num_masked;
        const psee = self.makeEscFreq2(c, i);
        var ps: [256]u32 = undefined;
        var nps: usize = 0;
        var hi_cnt: u32 = 0;
        var p: u32 = cctx.stats -% state_size;
        while (true) {
            while (true) {
                p +%= state_size;
                if (p + state_size > h.len) return error.InvalidData;
                if (self.char_mask[stAt(h, p).sym] != self.esc_count) break;
            }
            hi_cnt += stAt(h, p).freq;
            if (nps >= 256) return error.InvalidData;
            ps[nps] = p;
            nps += 1;
            i -= 1;
            if (i == 0) break;
        }
        self.coder.scale +%= hi_cnt;
        const count = try self.coder.currentCount();
        if (count >= self.coder.scale) return false;

        var pi: usize = 0;
        p = ps[0];
        if (count < hi_cnt) {
            var acc: u32 = 0;
            while (true) {
                acc += stAt(h, p).freq;
                if (acc > count) break;
                pi += 1;
                if (pi >= nps) return error.InvalidData;
                p = ps[pi];
            }
            self.coder.high_count = acc;
            self.coder.low_count = acc - stAt(h, p).freq;
            psee.update();
            self.update2(c, p);
        } else {
            self.coder.low_count = hi_cnt;
            self.coder.high_count = self.coder.scale;
            for (ps[0..nps]) |sp| {
                self.char_mask[stAt(h, sp).sym] = self.esc_count;
            }
            psee.summ +%= @truncate(self.coder.scale);
            self.num_masked = cctx.num_stats;
        }
        return true;
    }

    fn clearMask(self: *Self) void {
        self.esc_count = 1;
        @memset(&self.char_mask, 0);
    }
};

inline fn copyState(h: []u8, dst: u32, src: u32) void {
    @memcpy(h[dst..][0..state_size], h[src..][0..state_size]);
}

inline fn swapStates(h: []u8, a: u32, b: u32) void {
    var tmp: [state_size]u8 = undefined;
    @memcpy(&tmp, h[a..][0..state_size]);
    @memcpy(h[a..][0..state_size], h[b..][0..state_size]);
    @memcpy(h[b..][0..state_size], &tmp);
}

test "suballocator unit tables match the reference construction" {
    var heap: [4 * 1024 * 1024]u8 = undefined;
    var m = PpmModel.init();
    try m.startModel(&heap, 4, 1);
    const sub = &m.sub;
    try std.testing.expectEqual(@as(u8, 1), sub.indx2units[0]);
    try std.testing.expectEqual(@as(u8, 4), sub.indx2units[3]);
    try std.testing.expectEqual(@as(u8, 6), sub.indx2units[4]);
    try std.testing.expectEqual(@as(u8, 12), sub.indx2units[7]);
    try std.testing.expectEqual(@as(u8, 15), sub.indx2units[8]);
    try std.testing.expectEqual(@as(u8, 24), sub.indx2units[11]);
    try std.testing.expectEqual(@as(u8, 28), sub.indx2units[12]);
    try std.testing.expectEqual(@as(u8, 128), sub.indx2units[n_indexes - 1]);
    for (0..128) |k| {
        const idx = sub.units2indx[k];
        try std.testing.expect(sub.indx2units[idx] >= k + 1);
        if (idx > 0) try std.testing.expect(sub.indx2units[idx - 1] < k + 1);
    }
}

test "suballocator alloc/free round-trips through the free list" {
    var heap: [4 * 1024 * 1024]u8 = undefined;
    var m = PpmModel.init();
    try m.startModel(&heap, 4, 1);
    const a = m.sub.allocUnits(2);
    try std.testing.expect(a != null_off);
    m.sub.freeUnits(a, 2);
    const b = m.sub.allocUnits(2);
    try std.testing.expectEqual(a, b);
    const c = m.sub.allocContext();
    try std.testing.expect(c != null_off);
    try std.testing.expect(c > b);
}

test "see2 getMean and update follow the reference arithmetic" {
    var s = See2.init(10);
    try std.testing.expectEqual(@as(u16, 80), s.summ);
    try std.testing.expectEqual(@as(u8, 3), s.shift);
    try std.testing.expectEqual(@as(u32, 10), s.getMean());
    try std.testing.expectEqual(@as(u16, 70), s.summ);
    s.update();
    s.update();
    s.update();
    const before = s.summ;
    s.update();
    try std.testing.expectEqual(before *% 2, s.summ);
    try std.testing.expectEqual(@as(u8, 4), s.shift);
    try std.testing.expectEqual(@as(u8, 3 << 3), s.count);
}

test "model restart builds the 256-symbol root" {
    var heap: [4 * 1024 * 1024]u8 = undefined;
    var m = PpmModel.init();
    try m.startModel(&heap, 4, 1);
    const h = m.sub.heap;
    try std.testing.expectEqual(@as(u16, 256), ctxAt(h, m.min_context).num_stats);
    try std.testing.expectEqual(@as(u16, 257), ctxAt(h, m.min_context).summ_freq);
    const stats = ctxAt(h, m.min_context).stats;
    try std.testing.expectEqual(@as(u8, 0), stAt(h, stats).sym);
    try std.testing.expectEqual(@as(u8, 255), stAt(h, stats + 255 * state_size).sym);
    try std.testing.expectEqual(@as(u16, @truncate(bin_scale - init_bin_esc[0] / 2)), m.bin_summ[0][0]);
    try std.testing.expectEqual(@as(u16, @truncate(bin_scale - init_bin_esc[3] / 7)), m.bin_summ[5][3]);
    try std.testing.expectEqual(m.bin_summ[5][3], m.bin_summ[5][3 + 8]);
    try std.testing.expectEqual(@as(u8, 2), m.ns2indx[2]);
    try std.testing.expectEqual(@as(u8, 3), m.ns2indx[3]);
    try std.testing.expectEqual(@as(u8, 4), m.ns2indx[4]);
    try std.testing.expectEqual(@as(u8, 4), m.ns2indx[5]);
    try std.testing.expectEqual(@as(u8, 5), m.ns2indx[8]);
}

test "startModel refuses a heap smaller than the requested model size" {
    var heap: [1024 * 1024]u8 = undefined;
    var m = PpmModel.init();
    try std.testing.expectError(error.InsufficientCapacity, m.startModel(&heap, 4, 4));
}

test "extern views preserve the packed six-byte state stride" {
    try std.testing.expectEqual(@as(usize, 6), @sizeOf(StateView));
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(Ctx));
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(MemBlk));
    var heap: [4 * 1024 * 1024]u8 = undefined;
    var m = PpmModel.init();
    try m.startModel(&heap, 4, 1);
    const h = m.sub.heap;
    const stats = ctxAt(h, m.min_context).stats;
    const s0 = stAt(h, stats);
    s0.setSucc(0x12345678);
    try std.testing.expectEqual(@as(u32, 0x12345678), s0.succ());
    try std.testing.expectEqual(@as(u32, 0x12345678), stAt(h, stats).succ());
}
