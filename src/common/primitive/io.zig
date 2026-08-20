const std = @import("std");

const Failure = @import("failure.zig").Failure;

pub fn readByte(reader: *std.Io.Reader) Failure!u8 {
    var buffer: [1]u8 = undefined;
    var iovecs = [_][]u8{buffer[0..]};
    const n = reader.readVec(&iovecs) catch return error.IoFailure;
    if (n == 0) return error.IoFailure;
    return buffer[0];
}

pub fn writeBytes(writer: *std.Io.Writer, bytes: []const u8) Failure!void {
    writer.writeAll(bytes) catch return error.IoFailure;
}

pub fn writeByte(writer: *std.Io.Writer, byte: u8) Failure!void {
    writer.writeAll(&.{byte}) catch return error.IoFailure;
}

pub const Sink = struct {
    bytes: []u8,
    offset: usize = 0,

    pub fn write(self: *Sink, data: []const u8) Failure!void {
        if (self.offset + data.len > self.bytes.len) return error.InsufficientCapacity;
        @memcpy(self.bytes[self.offset..][0..data.len], data);
        self.offset += data.len;
    }

    pub fn writeInt(self: *Sink, comptime T: type, value: T, endian: std.builtin.Endian) Failure!void {
        var buffer: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buffer, value, endian);
        try self.write(&buffer);
    }
};

pub fn checkedConstBytes(pointer: ?[*]const u8, length: u64) Failure![]const u8 {
    const count = std.math.cast(usize, length) orelse return error.ResourceLimit;
    if (count == 0) return &.{};
    const data = pointer orelse return error.InvalidCall;
    return data[0..count];
}

pub fn checkedMutBytes(pointer: ?[*]u8, length: u64) Failure![]u8 {
    const count = std.math.cast(usize, length) orelse return error.ResourceLimit;
    if (count == 0) return &.{};
    const data = pointer orelse return error.InvalidCall;
    return data[0..count];
}

pub const Workspace = struct {
    bytes: []u8,
    cursor: usize = 0,
    required_tracker: ?*usize = null,

    pub fn init(pointer: ?[*]u8, capacity: u64) Failure!Workspace {
        return .{ .bytes = try checkedMutBytes(pointer, capacity) };
    }

    pub fn initTracked(pointer: ?[*]u8, capacity: u64, tracker: *usize) Failure!Workspace {
        return .{ .bytes = try checkedMutBytes(pointer, capacity), .required_tracker = tracker };
    }

    pub fn take(self: *Workspace, comptime T: type, count: usize) Failure![]T {
        const range = try extent(@intFromPtr(self.bytes.ptr), self.cursor, T, count);
        const aligned = range.start;
        const end = range.end;
        if (self.required_tracker) |tracker| {
            if (end > tracker.*) tracker.* = end;
        }
        if (end > self.bytes.len) return error.InsufficientCapacity;
        const output: []T = @alignCast(std.mem.bytesAsSlice(T, self.bytes[aligned..end]));
        self.cursor = end;
        return output;
    }

    pub fn remaining(self: *Workspace) usize {
        return self.bytes.len - self.cursor;
    }
};

pub const WorkspacePlan = struct {
    base: usize,
    cursor: usize = 0,

    pub fn init(pointer: ?[*]u8) WorkspacePlan {
        return .{ .base = if (pointer) |value| @intFromPtr(value) else 0 };
    }

    pub fn take(self: *WorkspacePlan, comptime T: type, count: usize) Failure!void {
        self.cursor = (try extent(self.base, self.cursor, T, count)).end;
    }

    pub fn required(self: WorkspacePlan) usize {
        return self.cursor;
    }
};

const Extent = struct { start: usize, end: usize };

fn extent(base: usize, cursor: usize, comptime T: type, count: usize) Failure!Extent {
    const alignment = @alignOf(T);
    const address = std.math.add(usize, base, cursor) catch return error.ResourceLimit;
    if (address > std.math.maxInt(usize) - (alignment - 1)) return error.ResourceLimit;
    const start = std.mem.alignForward(usize, address, alignment) - base;
    const size = std.math.mul(usize, count, @sizeOf(T)) catch return error.ResourceLimit;
    return .{ .start = start, .end = std.math.add(usize, start, size) catch return error.ResourceLimit };
}
