const std = @import("std");
const span = @import("span.zig");

const Span = span.Span;
const Failure = span.Failure;

// Generation lives in a header prefix. Free bumps it and every access re-reads it.
pub const Block = struct {
    storage: []u8,
    generation: u64,

    pub const header_len: usize = @sizeOf(u64);

    fn loadGeneration(storage: []u8) u64 {
        return std.mem.readInt(u64, storage[0..header_len], .little);
    }

    fn storeGeneration(storage: []u8, generation: u64) void {
        std.mem.writeInt(u64, storage[0..header_len], generation, .little);
    }

    pub fn init(storage: []u8) Failure!Block {
        if (storage.len <= header_len) return error.ResourceLimit;
        // Incrementing the stored generation keeps a recycled buffer from reissuing a stale value.
        const generation = loadGeneration(storage) +% 1;
        storeGeneration(storage, generation);
        return .{ .storage = storage, .generation = generation };
    }

    pub fn free(self: *Block) void {
        self.generation +%= 1;
        storeGeneration(self.storage, self.generation);
    }

    pub fn acquire(self: *const Block) TrackedSpan {
        return .{
            .owner = self,
            .generation = self.generation,
            .span = .{ .ptr = self.storage.ptr + header_len, .len = self.storage.len - header_len },
        };
    }
};

pub const TrackedSpan = struct {
    owner: *const Block,
    generation: u64,
    span: Span,

    fn check(self: TrackedSpan) void {
        const current = std.mem.readInt(u64, self.owner.storage[0..Block.header_len], .little);
        if (current != self.generation) span.trap(.use_after_free, "tracked span is stale: the block was freed or reused.");
    }

    pub fn read(self: TrackedSpan, offset: usize, length: usize) []u8 {
        self.check();
        return self.span.read(offset, length);
    }

    pub fn write(self: TrackedSpan, offset: usize, chunk: []const u8) void {
        self.check();
        self.span.write(offset, chunk);
    }

    pub fn sub(self: TrackedSpan, offset: usize, length: usize) TrackedSpan {
        self.check();
        return .{ .owner = self.owner, .generation = self.generation, .span = self.span.sub(offset, length) };
    }
};
