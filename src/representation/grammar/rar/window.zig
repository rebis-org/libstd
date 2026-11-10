const std = @import("std");

const kernels = @import("../../../common/kernels.zig");
const sink = @import("../../../common/sink.zig");

const Sink = sink.Sink;

// Distances are checked against total_written, so reset need not re-zero
// the window; that memset would dwarf decoding.

pub const Window = struct {
    buffer: []u8,
    mask: usize,
    write_pos: usize,
    total_written: u64,

    pub fn init(buffer: []u8) Window {
        std.debug.assert(buffer.len > 0 and (buffer.len & (buffer.len - 1)) == 0);
        return .{ .buffer = buffer, .mask = buffer.len - 1, .write_pos = 0, .total_written = 0 };
    }

    pub fn reset(self: *Window) void {
        self.write_pos = 0;
        self.total_written = 0;
    }

    pub fn putByte(self: *Window, byte: u8) void {
        self.buffer[self.write_pos & self.mask] = byte;
        self.write_pos += 1;
        self.total_written += 1;
    }

    // An impossible distance zero-fills rather than read stale slots, so
    // corrupt input never yields plausible bytes.
    pub fn copyMatch(self: *Window, distance: usize, length: usize) void {
        if (length == 0) return;

        if (distance == 0 or distance > self.total_written) {
            self.bulkZeroFill(length);
            return;
        }

        const buf_len = self.buffer.len;
        if (distance >= buf_len) {
            // Degenerate for a well-formed stream: distances never exceed
            // the dictionary. Keep the mask semantics of a plain byte loop.
            var src_pos = self.write_pos -% distance;
            for (0..length) |_| {
                const byte = self.buffer[src_pos & self.mask];
                self.putByte(byte);
                src_pos +%= 1;
            }
            return;
        }

        var dst = self.write_pos & self.mask;
        var src = (self.write_pos -% distance) & self.mask;
        var remaining = length;
        while (remaining > 0) {
            const seg = @min(remaining, @min(buf_len - dst, buf_len - src));
            if (src > dst) {
                // The wrapped source would underflow the kernel's flat
                // recomputation; segments here never overlap, so copyForwards is safe.
                std.mem.copyForwards(u8, self.buffer[dst..][0..seg], self.buffer[src..][0..seg]);
            } else {
                kernels.copyMatch(self.buffer, dst, @intCast(distance), @intCast(seg));
            }
            dst = (dst + seg) & self.mask;
            src = (src + seg) & self.mask;
            remaining -= seg;
        }
        self.write_pos += length;
        self.total_written += length;
    }

    fn bulkZeroFill(self: *Window, length: usize) void {
        const dst_phys = self.write_pos & self.mask;
        if (dst_phys + length <= self.buffer.len) {
            @memset(self.buffer[dst_phys..][0..length], 0);
            self.write_pos += length;
            self.total_written += length;
        } else {
            for (0..length) |_| self.putByte(0);
        }
    }

    pub fn getByte(self: *const Window, distance: usize) u8 {
        if (distance == 0 or distance > self.total_written) return 0;
        const pos = self.write_pos -% distance;
        return self.buffer[pos & self.mask];
    }

    // False means the requested bytes were overwritten; the current slots
    // would look valid but be wrong.
    pub fn emitTo(self: *const Window, out: Sink, start_offset: usize, count: usize) bool {
        if (start_offset > self.buffer.len) return false;
        if (count > start_offset) return false;
        if (count == 0) return true;
        const begin = (self.write_pos -% start_offset) & self.mask;
        const first = @min(count, self.buffer.len - begin);
        out.write(self.buffer[begin..][0..first]);
        if (first < count) out.write(self.buffer[0 .. count - first]);
        return true;
    }
};

test "window copy match serves valid distances and zero-fills impossible ones" {
    var buf: [16]u8 = undefined;
    var win = Window.init(&buf);
    for ("AB") |c| win.putByte(c);
    win.copyMatch(2, 4);
    try std.testing.expectEqual(@as(u64, 6), win.total_written);
    try std.testing.expectEqualSlices(u8, "ABABAB", buf[0..6]);

    // Distance zero is impossible: zero-fill, never stale slots.
    win.copyMatch(0, 2);
    try std.testing.expectEqual(@as(u64, 8), win.total_written);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, buf[6..8]);

    // Distance one replicates the zero-filled byte forward; the buffer
    // starts undefined, so only the copy can zero these slots.
    win.copyMatch(1, 3);
    try std.testing.expectEqual(@as(u64, 11), win.total_written);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, buf[8..11]);
}

test "window emit splits across the wrap" {
    var buf: [8]u8 = undefined;
    var win = Window.init(&buf);
    for ("ABCDEFGHIJKL") |c| win.putByte(c);
    var out: [5]u8 = undefined;
    var bs = sink.BufferSink.init(&out);
    try std.testing.expect(win.emitTo(bs.sink(), 5, 5));
    try std.testing.expectEqualSlices(u8, "HIJKL", out[0..bs.len]);
}

test "window emit refuses overwritten history" {
    var buf: [4]u8 = undefined;
    var win = Window.init(&buf);
    for ("ABCDEFGH") |c| win.putByte(c);
    var out: [8]u8 = undefined;
    var bs = sink.BufferSink.init(&out);
    try std.testing.expect(!win.emitTo(bs.sink(), 8, 8));
}

test "window copy match crosses the physical wrap" {
    // The wrapped source takes the forward-copy path, because the kernel's recomputation would underflow; bytes 16..24 overwrite buffer[0..8].
    var buf: [16]u8 = undefined;
    var win = Window.init(&buf);
    for ("ABCDEFGHIJKLMNOPQRSTUVWX") |c| win.putByte(c);
    win.copyMatch(12, 8);
    try std.testing.expectEqualSlices(u8, "QRSTUVWXMNOPQRST", &buf);
    try std.testing.expectEqual(@as(u64, 32), win.total_written);
}
