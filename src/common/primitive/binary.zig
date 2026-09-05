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

    pub fn readU8(self: *ReadCursor) error{ InvalidData, ResourceLimit }!u8 {
        if (self.pos >= self.buffer.len) return error.InvalidData;
        const value = self.buffer[self.pos];
        self.pos += 1;
        return value;
    }

    pub fn readU32le(self: *ReadCursor) error{ InvalidData, ResourceLimit }!u32 {
        const bytes = try self.readBytes(4);
        return std.mem.readInt(u32, &bytes, .little);
    }

    pub fn readULEB128(self: *ReadCursor) error{ InvalidData, ResourceLimit }!u64 {
        var value: u64 = 0;
        var shift: u6 = 0;
        var index: usize = 0;
        while (true) : (index += 1) {
            if (index >= 10) return error.InvalidData;
            const byte = try self.readU8();
            const payload: u64 = byte & 0x7f;
            if (shift == 63 and payload > 1) return error.ResourceLimit;
            value |= payload << shift;
            if ((byte & 0x80) == 0) return value;
            if (shift >= 57) return error.ResourceLimit;
            shift += 7;
        }
    }

    pub fn readSlice(self: *ReadCursor, length: usize) error{ InvalidData, ResourceLimit }![]const u8 {
        if (length > self.buffer.len - self.pos) return error.InvalidData;
        const value = self.buffer[self.pos..][0..length];
        self.pos += length;
        return value;
    }

    pub fn advance(self: *ReadCursor, count: u64) error{ InvalidData, ResourceLimit }!void {
        const n = std.math.cast(usize, count) orelse return error.ResourceLimit;
        if (n > self.buffer.len - self.pos) return error.InvalidData;
        self.pos += n;
    }

    pub fn readBytes(self: *ReadCursor, comptime length: u8) error{ InvalidData, ResourceLimit }![length]u8 {
        if (self.buffer.len - self.pos < length) return error.InvalidData;
        const value = self.buffer[self.pos..][0..length].*;
        self.pos += length;
        return value;
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

    pub fn writeU8(self: *WriteCursor, value: u8) error{ InsufficientCapacity, ResourceLimit }!void {
        if (self.pos >= self.buffer.len) return error.InsufficientCapacity;
        self.buffer[self.pos] = value;
        self.pos += 1;
    }

    pub fn writeULEB128(self: *WriteCursor, value: u64) error{ InsufficientCapacity, ResourceLimit }!void {
        var remaining_value = value;
        while (true) {
            var byte: u8 = @truncate(remaining_value & 0x7f);
            remaining_value >>= 7;
            if (remaining_value != 0) byte |= 0x80;
            try self.writeU8(byte);
            if (remaining_value == 0) return;
        }
    }
};
