const std = @import("std");

pub const ReadCursor = struct {
    buffer: []const u8,
    pos: usize,

    pub fn init(buffer: []const u8) ReadCursor {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn remaining(self: ReadCursor) usize {
        return self.buffer.len - self.pos;
    }

    pub fn remainingSlice(self: ReadCursor) []const u8 {
        return self.buffer[self.pos..];
    }

    fn take(self: *ReadCursor, count: usize) error{DataException}![]const u8 {
        if (count > self.buffer.len - self.pos) return error.DataException;
        const start = self.pos;
        self.pos += count;
        return self.buffer[start..][0..count];
    }

    pub fn readU8(self: *ReadCursor) error{DataException}!u8 {
        return (try self.take(1))[0];
    }

    pub fn readU32Le(self: *ReadCursor) error{DataException}!u32 {
        const raw = try self.readBytes(4);
        return std.mem.readInt(u32, &raw, .little);
    }

    // A tenth byte would push the value past 64 bits: a resource limit,
    // not malformed input.
    pub fn readUleb128(self: *ReadCursor) error{ DataException, ResourceException }!u64 {
        var decoded: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const next = try self.readU8();
            const low_bits: u64 = next & 0x7f;
            if (shift == 63 and low_bits > 1) return error.ResourceException;
            decoded |= low_bits << shift;
            if ((next & 0x80) == 0) return decoded;
            if (shift >= 57) return error.ResourceException;
            shift += 7;
        }
    }

    pub fn readSlice(self: *ReadCursor, length: usize) error{DataException}![]const u8 {
        return self.take(length);
    }

    pub fn advance(self: *ReadCursor, count: u64) error{ DataException, ResourceException }!void {
        const steps = std.math.cast(usize, count) orelse return error.ResourceException;
        _ = try self.take(steps);
    }

    pub fn readBytes(self: *ReadCursor, comptime length: u8) error{DataException}![length]u8 {
        return (try self.take(length))[0..length].*;
    }
};

pub fn utf16LeUnits(code_point: u21) usize {
    return if (code_point < 0x10000) 1 else 2;
}

pub const WriteCursor = struct {
    buffer: []u8,
    pos: usize,

    pub fn init(buffer: []u8) WriteCursor {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn written(self: WriteCursor) usize {
        return self.pos;
    }

    pub fn writeUtf16Le(self: *WriteCursor, code_point: u21) error{CapacityException}!void {
        if (self.pos + 2 * utf16LeUnits(code_point) > self.buffer.len) return error.CapacityException;
        if (code_point < 0x10000) {
            std.mem.writeInt(u16, self.buffer[self.pos..][0..2], @intCast(code_point), .little);
            self.pos += 2;
        } else {
            const high = @as(u32, code_point) - 0x10000;
            std.mem.writeInt(u16, self.buffer[self.pos..][0..2], @intCast(0xD800 + (high >> 10)), .little);
            std.mem.writeInt(u16, self.buffer[self.pos + 2 ..][0..2], @intCast(0xDC00 + (high & 0x3FF)), .little);
            self.pos += 4;
        }
    }

    pub fn writeU8(self: *WriteCursor, next: u8) error{CapacityException}!void {
        if (self.pos >= self.buffer.len) return error.CapacityException;
        self.buffer[self.pos] = next;
        self.pos += 1;
    }

    pub fn writeUleb128(self: *WriteCursor, decoded: u64) error{CapacityException}!void {
        var rest = decoded;
        while (true) {
            var next: u8 = @truncate(rest & 0x7f);
            rest >>= 7;
            if (rest != 0) next |= 0x80;
            try self.writeU8(next);
            if (rest == 0) return;
        }
    }
};
