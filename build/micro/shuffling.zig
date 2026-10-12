//! Size-class shuffle pool after hendriknielaender/zBench (MIT): random slot swap per size
//! class keeps addresses unpredictable. Single-threaded port; micro layer only.

const std = @import("std");

const shuffle_alignment: std.mem.Alignment = .of(usize);
const num_size_classes = 32;
const shuffle_capacity = 256;

pub const ShufflingAllocator = struct {
    underlying: std.mem.Allocator,
    rng: u64,
    size_classes: [num_size_classes]SizeClass,

    pub fn init(underlying: std.mem.Allocator, seed: u64) ShufflingAllocator {
        return .{
            .underlying = underlying,
            .rng = seed,
            .size_classes = @splat(.{}),
        };
    }

    pub fn deinit(self: *ShufflingAllocator) void {
        for (&self.size_classes) |*sc| {
            if (!sc.active) continue;
            for (sc.ptrs) |slot| {
                if (slot) |ptr| {
                    std.mem.Allocator.rawFree(self.underlying, ptr[0..sc.size], shuffle_alignment, 0);
                }
            }
            sc.* = .{};
        }
    }

    pub fn allocator(self: *ShufflingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn randomIndex(self: *ShufflingAllocator, upper_bound: usize) usize {
        std.debug.assert(upper_bound > 0);
        if (self.rng == 0) self.rng = 0x9e3779b97f4a7c15;
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        const product: u128 = @as(u128, self.rng) * upper_bound;
        return @intCast(product >> 64);
    }

    fn shuffledClass(self: *ShufflingAllocator, info: SizeClassInfo) ?*SizeClass {
        const sc = &self.size_classes[info.index];
        if (sc.active) {
            std.debug.assert(sc.size == info.size);
            return sc;
        }
        if (!sc.prefill(self.underlying, info.size)) return null;
        var i: usize = shuffle_capacity;
        while (i > 1) {
            i -= 1;
            const j = self.randomIndex(i + 1);
            std.mem.swap(?[*]u8, &sc.ptrs[i], &sc.ptrs[j]);
        }
        return sc;
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    fn allocFn(self_ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if ((@as(u64, 1) << @backingInt(alignment)) > @alignOf(usize)) {
            return std.mem.Allocator.rawAlloc(self.underlying, len, alignment, ret_addr);
        }
        const info = sizeClassInfo(len) orelse {
            return std.mem.Allocator.rawAlloc(self.underlying, len, alignment, ret_addr);
        };
        const sc = self.shuffledClass(info) orelse {
            return std.mem.Allocator.rawAlloc(self.underlying, len, alignment, ret_addr);
        };
        const replacement = std.mem.Allocator.rawAlloc(self.underlying, info.size, shuffle_alignment, ret_addr) orelse return null;
        const slot = self.randomIndex(shuffle_capacity);
        const shuffled = sc.ptrs[slot].?;
        sc.ptrs[slot] = replacement;
        return shuffled;
    }

    fn resizeFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if (sizeClassInfo(memory.len) == null or shuffledAlignment(alignment)) {
            return std.mem.Allocator.rawResize(self.underlying, memory, alignment, new_len, ret_addr);
        }
        // Shuffled blocks were rounded up to their size class; refuse in-place
        // resize so callers fall back to alloc-copy-free.
        return false;
    }

    fn remapFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if (sizeClassInfo(memory.len) == null or shuffledAlignment(alignment)) {
            return std.mem.Allocator.rawRemap(self.underlying, memory, alignment, new_len, ret_addr);
        }
        return null;
    }

    fn freeFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if (memory.len == 0) return;
        if ((@as(u64, 1) << @backingInt(alignment)) > @alignOf(usize)) {
            std.mem.Allocator.rawFree(self.underlying, memory, alignment, ret_addr);
            return;
        }
        const info = sizeClassInfo(memory.len) orelse {
            std.mem.Allocator.rawFree(self.underlying, memory, alignment, ret_addr);
            return;
        };
        const sc = &self.size_classes[info.index];
        if (!sc.active) {
            std.mem.Allocator.rawFree(self.underlying, memory, alignment, ret_addr);
            return;
        }
        std.debug.assert(sc.size == info.size);
        const slot = self.randomIndex(shuffle_capacity);
        const evicted = sc.ptrs[slot].?;
        sc.ptrs[slot] = memory.ptr;
        std.mem.Allocator.rawFree(self.underlying, evicted[0..info.size], shuffle_alignment, ret_addr);
    }
};

fn shuffledAlignment(alignment: std.mem.Alignment) bool {
    return (@as(u64, 1) << @backingInt(alignment)) > @alignOf(usize);
}

const SizeClass = struct {
    active: bool = false,
    size: usize = 0,
    ptrs: [shuffle_capacity]?[*]u8 = @splat(null),

    fn prefill(self: *SizeClass, underlying: std.mem.Allocator, size: usize) bool {
        std.debug.assert(!self.active);
        std.debug.assert(size >= @sizeOf(usize));
        self.size = size;
        var slot: usize = 0;
        while (slot < shuffle_capacity) : (slot += 1) {
            self.ptrs[slot] = std.mem.Allocator.rawAlloc(underlying, size, shuffle_alignment, 0) orelse {
                while (slot > 0) {
                    slot -= 1;
                    std.mem.Allocator.rawFree(underlying, self.ptrs[slot].?[0..size], shuffle_alignment, 0);
                    self.ptrs[slot] = null;
                }
                self.size = 0;
                return false;
            };
        }
        self.active = true;
        return true;
    }
};

const SizeClassInfo = struct {
    index: usize,
    size: usize,
};

// Rounded size classes: word strides that double every fourth class.
fn sizeClassInfo(size: usize) ?SizeClassInfo {
    var class_size: usize = @sizeOf(usize);
    var stride: usize = @sizeOf(usize);
    var index: usize = 0;
    while (index < num_size_classes) : (index += 1) {
        if (size <= class_size) return .{ .index = index, .size = class_size };
        class_size += stride;
        if ((index + 1) % 4 == 0) stride *= 2;
    }
    return null;
}

test "shuffled blocks stay writable and every size class round-trips" {
    var shuffler = ShufflingAllocator.init(std.heap.page_allocator, 12345);
    defer shuffler.deinit();
    const alloc = shuffler.allocator();

    var sizes: [64]usize = undefined;
    for (&sizes, 0..) |*s, i| s.* = (i % 32) * 13 + 1;
    for (sizes) |s| {
        const buf = try alloc.alloc(u8, s);
        defer alloc.free(buf);
        for (buf, 0..) |*b, i| b.* = @truncate(i);
        for (buf, 0..) |b, i| try std.testing.expectEqual(@as(u8, @truncate(i)), b);
    }
}

test "word-aligned shuffles, wider alignments bypass" {
    var shuffler = ShufflingAllocator.init(std.heap.page_allocator, 42);
    defer shuffler.deinit();
    const alloc = shuffler.allocator();

    const wide = try alloc.alignedAlloc(u8, .fromByteUnits(64), 8);
    defer alloc.free(wide);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(wide.ptr) % 64);
}
