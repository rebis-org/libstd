const std = @import("std");
const sink = @import("../../common/sink.zig");
const Sink = sink.Sink;
const kernels = @import("../../leaf/kernels.zig");

// Circular LZ window over caller-provided storage. Distances are validated
// against total_written, so bytes from a previous non-solid entry are never
// reachable and reset() deliberately does not re-zero the buffer (the
// reference leaves the same comment in its UnpInitData) — a window-sized
// memset per entry would dwarf decoding on archives of many small files.

pub const Window = struct {
    buffer: []u8,
    mask: usize,
    write_pos: usize,
    total_written: u64,

    // buffer.len must be a power of two.
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

    // An impossible distance (0 or beyond everything written) zero-fills
    // instead of reading stale slots — corrupt streams must not turn into
    // plausible bytes. Wrap-free segments run on the shared match-copy
    // ladder (the hot path for the short matches that dominate LZ output);
    // the circular buffer only segments at the wrap points.
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
            kernels.copyMatch(self.buffer, dst, @intCast(distance), @intCast(seg));
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

    // A logically contiguous run can straddle the wrap point and leave as
    // one or two spans. False means the bytes were overwritten since —
    // returning whatever occupies those slots now would be a wrong answer in
    // a right answer's shape, so callers must refuse.
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

test "window copy match variants" {
    var buf: [16]u8 = undefined;
    var win = Window.init(&buf);
    for ("AB") |c| win.putByte(c);
    win.copyMatch(2, 4); // ABAB
    try std.testing.expectEqual(@as(u64, 6), win.total_written);
    try std.testing.expectEqualSlices(u8, "ABABAB", buf[0..6]);

    win.copyMatch(0, 2); // invalid distance zero-fills
    try std.testing.expectEqual(@as(u8, 0), buf[6]);

    win.copyMatch(1, 3); // RLE
    try std.testing.expectEqual(@as(u8, 0), buf[7]);
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
