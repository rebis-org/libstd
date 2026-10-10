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

    fn take(self: *ReadCursor, count: usize) error{InvalidData}![]const u8 {
        if (count > self.buffer.len - self.pos) return error.InvalidData;
        const start = self.pos;
        self.pos += count;
        return self.buffer[start..][0..count];
    }

    pub fn readU8(self: *ReadCursor) error{ InvalidData, ResourceLimit }!u8 {
        return (try self.take(1))[0];
    }

    pub fn readU32Le(self: *ReadCursor) error{ InvalidData, ResourceLimit }!u32 {
        const raw = try self.readBytes(4);
        return std.mem.readInt(u32, &raw, .little);
    }

    pub fn readUleb128(self: *ReadCursor) error{ InvalidData, ResourceLimit }!u64 {
        var decoded: u64 = 0;
        var shift: u6 = 0;
        var seen: usize = 0;
        while (true) : (seen += 1) {
            if (seen >= 10) return error.InvalidData;
            const next = try self.readU8();
            const low_bits: u64 = next & 0x7f;
            if (shift == 63 and low_bits > 1) return error.ResourceLimit;
            decoded |= low_bits << shift;
            if ((next & 0x80) == 0) return decoded;
            if (shift >= 57) return error.ResourceLimit;
            shift += 7;
        }
    }

    pub fn readSlice(self: *ReadCursor, length: usize) error{ InvalidData, ResourceLimit }![]const u8 {
        return self.take(length);
    }

    pub fn advance(self: *ReadCursor, count: u64) error{ InvalidData, ResourceLimit }!void {
        const steps = std.math.cast(usize, count) orelse return error.ResourceLimit;
        _ = try self.take(steps);
    }

    pub fn readBytes(self: *ReadCursor, comptime length: u8) error{ InvalidData, ResourceLimit }![length]u8 {
        return (try self.take(length))[0..length].*;
    }
};

pub const WriteCursor = struct {
    buffer: []u8,
    pos: usize,

    pub fn init(buffer: []u8) WriteCursor {
        return .{ .buffer = buffer, .pos = 0 };
    }

    pub fn written(self: WriteCursor) usize {
        return self.pos;
    }

    pub fn writeU8(self: *WriteCursor, next: u8) error{ InsufficientCapacity, ResourceLimit }!void {
        if (self.pos >= self.buffer.len) return error.InsufficientCapacity;
        self.buffer[self.pos] = next;
        self.pos += 1;
    }

    pub fn writeUleb128(self: *WriteCursor, decoded: u64) error{ InsufficientCapacity, ResourceLimit }!void {
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
