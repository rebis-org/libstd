const std = @import("std");

// The circular window can split one logical run into two spans, so sinks
// must tolerate arbitrary chunking. `write` cannot fail because destinations
// are pre-sized. BufferSink records overflow rather than truncating: a
// partial file that still looks like success is the failure mode an
// integrity layer must not have.

pub const Sink = struct {
    ctx: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, chunk: []const u8) void,

    pub inline fn write(self: Sink, chunk: []const u8) void {
        self.write_fn(self.ctx, chunk);
    }
};

pub const BufferSink = struct {
    storage: []u8,
    len: usize = 0,
    overflowed: bool = false,

    pub fn init(storage: []u8) BufferSink {
        return .{ .storage = storage };
    }

    pub fn sink(self: *BufferSink) Sink {
        return .{ .ctx = self, .write_fn = writeImpl };
    }

    fn writeImpl(ctx: *anyopaque, chunk: []const u8) void {
        const self: *BufferSink = @ptrCast(@alignCast(ctx));
        const room = self.storage.len - self.len;
        if (chunk.len > room) {
            self.overflowed = true;
            if (room == 0) return;
            @memcpy(self.storage[self.len..][0..room], chunk[0..room]);
            self.len += room;
            return;
        }
        @memcpy(self.storage[self.len..][0..chunk.len], chunk);
        self.len += chunk.len;
    }
};

// Warms the shared window of a solid group with predecessor entries nobody
// asked for.
pub const DiscardSink = struct {
    len: u64 = 0,

    pub fn sink(self: *DiscardSink) Sink {
        return .{ .ctx = self, .write_fn = writeImpl };
    }

    fn writeImpl(ctx: *anyopaque, chunk: []const u8) void {
        const self: *DiscardSink = @ptrCast(@alignCast(ctx));
        self.len += chunk.len;
    }
};

test "buffer sink flags overflow instead of truncating silently" {
    var storage: [4]u8 = undefined;
    var overflow = BufferSink.init(&storage);
    const view = overflow.sink();
    view.write("abcdef");
    try std.testing.expect(overflow.overflowed);
    try std.testing.expectEqual(@as(usize, 4), overflow.len);
    try std.testing.expectEqualSlices(u8, "abcd", &storage);
}

test "discard sink counts without storing" {
    var dropped = DiscardSink{};
    const view = dropped.sink();
    view.write("hello ");
    view.write("world");
    try std.testing.expectEqual(@as(u64, 11), dropped.len);
}
