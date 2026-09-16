const std = @import("std");

// Reader machinery only refills buffered readers, so chunks stage through a small buffer; handed bytes are permanently consumed, so accounting uses returned counts.
pub const ChunkInput = struct {
    reader: std.Io.Reader,
    chunk: []const u8 = &.{},
    pos: usize = 0,
    starved: bool = false,

    pub fn init(buffer: []u8) ChunkInput {
        std.debug.assert(buffer.len > 0);
        return .{ .reader = .{ .buffer = buffer, .seek = 0, .end = 0, .vtable = &.{ .stream = stream, .discard = discard, .rebase = rebase } } };
    }

    pub fn stage(self: *ChunkInput, data: []const u8) void {
        self.chunk = data;
        self.pos = 0;
        self.starved = false;
    }

    pub fn remaining(self: *const ChunkInput) []const u8 {
        return self.chunk[self.pos..];
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ChunkInput = @alignCast(@fieldParentPtr("reader", r));
        const available = self.chunk[self.pos..];
        if (available.len == 0) {
            self.starved = true;
            return error.ReadFailed;
        }
        const count = @min(@as(usize, @intFromEnum(limit)), available.len);
        w.writeAll(available[0..count]) catch return error.WriteFailed;
        self.pos += count;
        return count;
    }

    fn discard(r: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        var sink_buffer: [0]u8 = .{};
        var discarding: std.Io.Writer.Discarding = .init(&sink_buffer);
        return stream(r, &discarding.writer, limit) catch |err| switch (err) {
            error.WriteFailed => unreachable,
            else => |e| return e,
        };
    }

    fn rebase(r: *std.Io.Reader, capacity: usize) std.Io.Reader.RebaseError!void {
        const keep = r.end - r.seek;
        @memmove(r.buffer[0..keep], r.buffer[r.seek..r.end]);
        r.end = keep;
        r.seek = 0;
        if (capacity > r.buffer.len - r.end) return error.EndOfStream;
    }
};

pub fn limitFor(remaining: usize) std.Io.Limit {
    return @enumFromInt(remaining);
}
