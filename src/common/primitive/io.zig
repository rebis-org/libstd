const std = @import("std");

const Exception = @import("exception.zig").Exception;

pub fn readByte(reader: *std.Io.Reader) Exception!u8 {
    var buffer: [1]u8 = undefined;
    var iovecs = [_][]u8{buffer[0..]};
    const bytes_read = reader.readVec(&iovecs) catch return error.IoException;
    if (bytes_read == 0) return error.IoException;
    return buffer[0];
}

pub fn writeBytes(writer: *std.Io.Writer, chunk: []const u8) Exception!void {
    writer.writeAll(chunk) catch return error.IoException;
}

pub fn writeByte(writer: *std.Io.Writer, byte: u8) Exception!void {
    writer.writeAll(&.{byte}) catch return error.IoException;
}

pub const Sink = struct {
    bytes: []u8,
    offset: usize = 0,

    pub fn write(self: *Sink, chunk: []const u8) Exception!void {
        if (chunk.len > self.bytes.len - self.offset) return error.CapacityException;
        @memcpy(self.bytes[self.offset..][0..chunk.len], chunk);
        self.offset += chunk.len;
    }

    pub fn writeInt(self: *Sink, comptime T: type, int: T, endian: std.lang.Endian) Exception!void {
        var storage: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &storage, int, endian);
        try self.write(&storage);
    }
};

fn Slice(comptime Ptr: type) type {
    const info = @typeInfo(Ptr).pointer;
    return if (info.attrs.@"const") []const info.child else []info.child;
}

fn checkedSlice(comptime Ptr: type, pointer: ?Ptr, length: u64) Exception!Slice(Ptr) {
    const count = std.math.cast(usize, length) orelse return error.ResourceException;
    if (count == 0) return &.{};
    const base = pointer orelse return error.CallException;
    // Slicing a comptime-known pointer yields a const slice, so the mutable case casts back onto caller-owned memory.
    const slice = base[0..count];
    if (comptime @typeInfo(Ptr).pointer.attrs.@"const") return slice;
    return @constCast(slice);
}

pub fn checkedConstBytes(pointer: ?[*]const u8, length: u64) Exception![]const u8 {
    return checkedSlice([*]const u8, pointer, length);
}

pub fn checkedMutBytes(pointer: ?[*]u8, length: u64) Exception![]u8 {
    return checkedSlice([*]u8, pointer, length);
}

pub const Workspace = struct {
    bytes: []u8,
    cursor: usize = 0,
    required_tracker: ?*usize = null,

    pub fn init(pointer: ?[*]u8, capacity: u64) Exception!Workspace {
        return .{ .bytes = try checkedMutBytes(pointer, capacity) };
    }

    pub fn initTracked(pointer: ?[*]u8, capacity: u64, tracker: *usize) Exception!Workspace {
        var self = try init(pointer, capacity);
        self.required_tracker = tracker;
        return self;
    }

    pub fn take(self: *Workspace, comptime T: type, count: usize) Exception![]T {
        const range = try extent(@intFromPtr(self.bytes.ptr), self.cursor, T, count);
        const aligned = range.start;
        const end = range.end;
        if (self.required_tracker) |tracker| {
            if (end > tracker.*) tracker.* = end;
        }
        if (end > self.bytes.len) return error.CapacityException;
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

    pub fn take(self: *WorkspacePlan, comptime T: type, count: usize) Exception!void {
        self.cursor = (try extent(self.base, self.cursor, T, count)).end;
    }

    pub fn required(self: WorkspacePlan) usize {
        return self.cursor;
    }
};

const Extent = struct { start: usize, end: usize };

fn extent(base: usize, cursor: usize, comptime T: type, count: usize) Exception!Extent {
    const alignment = @alignOf(T);
    const address = std.math.add(usize, base, cursor) catch return error.ResourceException;
    if (address > std.math.maxInt(usize) - (alignment - 1)) return error.ResourceException;
    const start = std.mem.alignForward(usize, address, alignment) - base;
    const size = std.math.mul(usize, count, @sizeOf(T)) catch return error.ResourceException;
    return .{ .start = start, .end = std.math.add(usize, start, size) catch return error.ResourceException };
}
