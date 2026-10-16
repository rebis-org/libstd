const std = @import("std");

const shuffle_alignment: std.mem.Alignment = .of(usize);
const size_class_count = 32;
const pool_slots_per_class = 256;

pub const ShufflingAllocator = struct {
    underlying: std.mem.Allocator,
    state: u64,
    size_classes: [size_class_count]SizeClass,

    pub fn init(underlying: std.mem.Allocator, seed: u64) ShufflingAllocator {
        return .{
            .underlying = underlying,
            .state = seed,
            .size_classes = @splat(.{}),
        };
    }

    pub fn deinit(self: *ShufflingAllocator) void {
        for (&self.size_classes) |*class| {
            if (!class.active) continue;
            for (class.ptrs) |slot| {
                if (slot) |ptr| {
                    std.mem.Allocator.rawFree(self.underlying, ptr[0..class.size], shuffle_alignment, 0);
                }
            }
            class.* = .{};
        }
    }

    pub fn allocator(self: *ShufflingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn randomIndex(self: *ShufflingAllocator, upper_bound: usize) usize {
        std.debug.assert(upper_bound > 0);
        if (self.state == 0) self.state = 0x9e3779b97f4a7c15;
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        const product: u128 = @as(u128, self.state) * upper_bound;
        return @intCast(product >> 64);
    }

    fn shuffledClass(self: *ShufflingAllocator, info: SizeClassInfo) ?*SizeClass {
        const class = &self.size_classes[info.index];
        if (class.active) {
            std.debug.assert(class.size == info.size);
            return class;
        }
        if (!class.prefill(self.underlying, info.size)) return null;
        var i: usize = pool_slots_per_class;
        while (i > 1) {
            i -= 1;
            const j = self.randomIndex(i + 1);
            std.mem.swap(?[*]u8, &class.ptrs[i], &class.ptrs[j]);
        }
        return class;
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    fn allocFn(self_ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        const info = poolableInfo(len, alignment) orelse {
            return std.mem.Allocator.rawAlloc(self.underlying, len, alignment, ret_addr);
        };
        const class = self.shuffledClass(info) orelse {
            return std.mem.Allocator.rawAlloc(self.underlying, len, alignment, ret_addr);
        };
        const replacement = std.mem.Allocator.rawAlloc(self.underlying, info.size, shuffle_alignment, ret_addr) orelse return null;
        const slot = self.randomIndex(pool_slots_per_class);
        const shuffled = class.ptrs[slot].?;
        class.ptrs[slot] = replacement;
        return shuffled;
    }

    fn resizeFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if (poolableInfo(memory.len, alignment) == null) {
            return std.mem.Allocator.rawResize(self.underlying, memory, alignment, new_len, ret_addr);
        }
        // Shuffled blocks were rounded up to their size class; refuse in-place
        // resize so callers fall back to alloc-copy-free.
        return false;
    }

    fn remapFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if (poolableInfo(memory.len, alignment) == null) {
            return std.mem.Allocator.rawRemap(self.underlying, memory, alignment, new_len, ret_addr);
        }
        return null;
    }

    fn freeFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ShufflingAllocator = @ptrCast(@alignCast(self_ptr));
        if (memory.len == 0) return;
        const info = poolableInfo(memory.len, alignment) orelse {
            std.mem.Allocator.rawFree(self.underlying, memory, alignment, ret_addr);
            return;
        };
        const class = &self.size_classes[info.index];
        if (!class.active) {
            std.mem.Allocator.rawFree(self.underlying, memory, alignment, ret_addr);
            return;
        }
        std.debug.assert(class.size == info.size);
        const slot = self.randomIndex(pool_slots_per_class);
        const evicted = class.ptrs[slot].?;
        class.ptrs[slot] = memory.ptr;
        std.mem.Allocator.rawFree(self.underlying, evicted[0..info.size], shuffle_alignment, ret_addr);
    }
};

fn exceedsWordAlignment(alignment: std.mem.Alignment) bool {
    return (@as(u64, 1) << @backingInt(alignment)) > @alignOf(usize);
}

fn poolableInfo(len: usize, alignment: std.mem.Alignment) ?SizeClassInfo {
    if (exceedsWordAlignment(alignment)) return null;
    return sizeClassInfo(len);
}

const SizeClass = struct {
    active: bool = false,
    size: usize = 0,
    ptrs: [pool_slots_per_class]?[*]u8 = @splat(null),

    fn prefill(self: *SizeClass, underlying: std.mem.Allocator, size: usize) bool {
        std.debug.assert(!self.active);
        std.debug.assert(size >= @sizeOf(usize));
        self.size = size;
        var slot: usize = 0;
        while (slot < pool_slots_per_class) : (slot += 1) {
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
    while (index < size_class_count) : (index += 1) {
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
    for (&sizes, 0..) |*size, i| size.* = (i % 32) * 13 + 1;
    for (sizes) |size| {
        const scratch = try alloc.alloc(u8, size);
        defer alloc.free(scratch);
        for (scratch, 0..) |*byte, i| byte.* = @truncate(i);
        for (scratch, 0..) |byte, i| try std.testing.expectEqual(@as(u8, @truncate(i)), byte);
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
