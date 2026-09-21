const std = @import("std");

// The circular window can split one logical run into two spans, so sinks
// must tolerate arbitrary chunking; `write` cannot fail because destinations
// are pre-sized. BufferSink records overflow rather than truncating: a
// partial file that still looks like success is the failure mode an
// integrity layer must not have.

pub const Sink = struct {
    ctx: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, bytes: []const u8) void,

    pub inline fn write(self: Sink, bytes: []const u8) void {
        self.write_fn(self.ctx, bytes);
    }
};

pub const BufferSink = struct {
    buf: []u8,
    len: usize = 0,
    overflowed: bool = false,

    pub fn init(buf: []u8) BufferSink {
        return .{ .buf = buf };
    }

    pub fn sink(self: *BufferSink) Sink {
        return .{ .ctx = self, .write_fn = writeImpl };
    }

    fn writeImpl(ctx: *anyopaque, bytes: []const u8) void {
        const self: *BufferSink = @ptrCast(@alignCast(ctx));
        const room = self.buf.len - self.len;
        if (bytes.len > room) {
            self.overflowed = true;
            if (room == 0) return;
            @memcpy(self.buf[self.len..][0..room], bytes[0..room]);
            self.len += room;
            return;
        }
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};

// Warms the shared window of a solid group with predecessor entries nobody
// asked for.
pub const DiscardSink = struct {
    len: u64 = 0,

    pub fn sink(self: *DiscardSink) Sink {
        return .{ .ctx = self, .write_fn = writeImpl };
    }

    fn writeImpl(ctx: *anyopaque, bytes: []const u8) void {
        const self: *DiscardSink = @ptrCast(@alignCast(ctx));
        self.len += bytes.len;
    }
};

test "buffer sink flags overflow instead of truncating silently" {
    var buf: [4]u8 = undefined;
    var bs = BufferSink.init(&buf);
    const s = bs.sink();
    s.write("abcdef");
    try std.testing.expect(bs.overflowed);
    try std.testing.expectEqual(@as(usize, 4), bs.len);
    try std.testing.expectEqualSlices(u8, "abcd", &buf);
}

test "discard sink counts without storing" {
    var ds = DiscardSink{};
    const s = ds.sink();
    s.write("hello ");
    s.write("world");
    try std.testing.expectEqual(@as(u64, 11), ds.len);
}
