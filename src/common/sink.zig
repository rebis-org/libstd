const std = @import("std");

// Destinations are pre-sized, so `write` cannot fail. BufferSink records
// overflow because silent truncation must not look like success.

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

// Warms a solid group's shared window with predecessor entries the caller
// did not request.
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

test "buffer sink accepts an exact fit without flagging overflow" {
    var storage: [6]u8 = undefined;
    var buffer = BufferSink.init(&storage);
    const view = buffer.sink();
    view.write("abc");
    view.write("def");
    try std.testing.expect(!buffer.overflowed);
    try std.testing.expectEqual(@as(usize, 6), buffer.len);
    try std.testing.expectEqualSlices(u8, "abcdef", &storage);
}

test "buffer sink flags overflow and keeps the room it had" {
    var storage: [4]u8 = undefined;
    var overflow = BufferSink.init(&storage);
    const view = overflow.sink();
    view.write("abcdef");
    try std.testing.expect(overflow.overflowed);
    try std.testing.expectEqual(@as(usize, 4), overflow.len);
    try std.testing.expectEqualSlices(u8, "abcd", &storage);
}

test "buffer sink reports overflow when no room remains" {
    var storage: [2]u8 = undefined;
    var buffer = BufferSink.init(&storage);
    const view = buffer.sink();
    view.write("ab");
    try std.testing.expect(!buffer.overflowed);
    view.write("c");
    try std.testing.expect(buffer.overflowed);
    try std.testing.expectEqual(@as(usize, 2), buffer.len);
    try std.testing.expectEqualSlices(u8, "ab", &storage);
}

test "discard sink counts without storing" {
    var dropped = DiscardSink{};
    const view = dropped.sink();
    view.write("hello ");
    view.write("world");
    try std.testing.expectEqual(@as(u64, 11), dropped.len);
    dropped.sink().write("!");
    try std.testing.expectEqual(@as(u64, 12), dropped.len);
}
