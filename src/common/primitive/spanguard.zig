const std = @import("std");

// Wraps a backing allocator so a caller-owned span can serve as a stdlib
// container's initial buffer, outside the allocator's ownership.
// The refusal lives at the raw vtable interface: stdlib containers free a
// moved buffer through rawFree (`Allocating`).
// The high-level `Allocator.free` poisons the freed bytes before this
// allocator runs, so keep the span out of high-level frees.
pub const SpanGuardAllocator = struct {
    backing: std.mem.Allocator,
    span: []const u8,

    fn isSpan(self: *SpanGuardAllocator, memory: []const u8) bool {
        return memory.ptr == self.span.ptr and memory.len == self.span.len;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *SpanGuardAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *SpanGuardAllocator = @ptrCast(@alignCast(ctx));
        if (self.isSpan(memory)) return false;
        return self.backing.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *SpanGuardAllocator = @ptrCast(@alignCast(ctx));
        if (self.isSpan(memory)) return null;
        return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *SpanGuardAllocator = @ptrCast(@alignCast(ctx));
        if (self.isSpan(memory)) return;
        self.backing.rawFree(memory, alignment, ret_addr);
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn allocator(self: *SpanGuardAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

test "span guard refuses span growth and drops span free" {
    var backing_buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    const span = try std.testing.allocator.alloc(u8, 64);
    defer std.testing.allocator.free(span);
    @memset(span, 0xa5);

    var guard = SpanGuardAllocator{ .backing = fba.allocator(), .span = span };
    const a = guard.allocator();

    // Ordinary allocations delegate to the backing allocator.
    const p = try a.alloc(u8, 32);
    a.free(p);

    // The span neither shrinks, grows in place, nor moves; its bytes stay put.
    try std.testing.expect(!a.rawResize(span, .of(u8), 32, @returnAddress()));
    try std.testing.expectEqual(@as(?[*]u8, null), a.rawRemap(span, .of(u8), 128, @returnAddress()));
    try std.testing.expect(std.mem.allEqual(u8, span, 0xa5));

    // A container deinit freeing its initial buffer with the raw interface
    // must not free the span.
    a.rawFree(span, .of(u8), @returnAddress());
    try std.testing.expect(std.mem.allEqual(u8, span, 0xa5));

    // The backing allocator still answers after the span operations.
    const q = try a.alloc(u8, 32);
    a.free(q);
}

test "span guard keeps the span intact when an allocating writer grows" {
    var backing_buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing_buffer);
    const span = try std.testing.allocator.alloc(u8, 64);
    defer std.testing.allocator.free(span);
    @memset(span, 0xa5);

    var guard = SpanGuardAllocator{ .backing = fba.allocator(), .span = span };
    var sink = std.Io.Writer.Allocating.initOwnedSlice(guard.allocator(), span);
    // sink.deinit is deliberately not called: the span is not an allocation.
    const data: [96]u8 = @splat(0x5a);
    try sink.writer.writeAll(&data);

    // Growth moved the writer off the span; the span itself never changed.
    try std.testing.expect(std.mem.allEqual(u8, span, 0xa5));
    try std.testing.expectEqual(96, sink.writer.end);
}
