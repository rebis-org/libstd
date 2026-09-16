const std = @import("std");

pub const Failure = error{ InvalidCall, ResourceLimit, InsufficientCapacity, InvalidData };

pub const Violation = enum { out_of_bounds, use_after_free, lease_violation, overlap };

var empty_storage: [1]u8 = .{0};

// Contract violations trap: out-of-provenance access is a bug, never a
// survivable runtime condition; data-dependent failures stay in Failure.
pub fn trap(violation: Violation, context: []const u8) noreturn {
    var buffer: [128]u8 = undefined;
    const message = std.fmt.bufPrint(&buffer, "Nucleus trap: {s}: {s}.\n", .{ @tagName(violation), context }) catch "Nucleus trap.\n";
    std.debug.print("{s}", .{message});
    std.posix.raise(std.posix.SIG.TRAP) catch {};
    unreachable;
}

pub const Span = struct {
    ptr: [*]u8,
    len: usize,

    pub fn bytes(self: Span) []u8 {
        return self.ptr[0..self.len];
    }

    pub fn sub(self: Span, offset: usize, length: usize) Span {
        if (offset > self.len or length > self.len - offset) trap(.out_of_bounds, "Subspan out of bounds");
        return .{ .ptr = self.ptr + offset, .len = length };
    }

    pub fn read(self: Span, offset: usize, length: usize) []u8 {
        return self.sub(offset, length).bytes();
    }

    pub fn write(self: Span, offset: usize, data: []const u8) void {
        @memcpy(self.sub(offset, data.len).bytes(), data);
    }
};

pub const ConstSpan = struct {
    ptr: [*]const u8,
    len: usize,

    pub fn bytes(self: ConstSpan) []const u8 {
        return self.ptr[0..self.len];
    }

    pub fn sub(self: ConstSpan, offset: usize, length: usize) ConstSpan {
        if (offset > self.len or length > self.len - offset) trap(.out_of_bounds, "Subspan out of bounds");
        return .{ .ptr = self.ptr + offset, .len = length };
    }

    pub fn read(self: ConstSpan, offset: usize, length: usize) []const u8 {
        return self.sub(offset, length).bytes();
    }
};

// Sole conversion from raw envelope pointers, so every boundary crossing is checked once.
fn SpanFor(comptime Pointer: type) type {
    return switch (Pointer) {
        [*]u8 => Span,
        [*]const u8 => ConstSpan,
        else => @compileError("Unsupported span pointer type."),
    };
}

fn spanFrom(comptime Pointer: type, pointer: ?Pointer, length: u64) Failure!SpanFor(Pointer) {
    const count = std.math.cast(usize, length) orelse return error.ResourceLimit;
    if (count == 0) return .{ .ptr = &empty_storage, .len = 0 };
    const data = pointer orelse return error.InvalidCall;
    return .{ .ptr = data, .len = count };
}

pub fn mutSpan(pointer: ?[*]u8, length: u64) Failure!Span {
    return spanFrom([*]u8, pointer, length);
}

pub fn constSpan(pointer: ?[*]const u8, length: u64) Failure!ConstSpan {
    return spanFrom([*]const u8, pointer, length);
}

// Independently handed spans must not alias; overlap is a caller contract violation.
pub fn requireDisjoint(left: ConstSpan, right: ConstSpan, context: []const u8) void {
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    if (left.len == 0 or right.len == 0) return;
    const left_end = left_start + left.len;
    const right_end = right_start + right.len;
    if (left_start < right_end and right_start < left_end) trap(.overlap, context);
}

test "span algebra: read write sub round trip" {
    var backing: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const span: Span = .{ .ptr = &backing, .len = backing.len };
    try std.testing.expectEqual(@as(usize, 16), span.len);
    try std.testing.expectEqual(@as(u8, 5), span.read(5, 1)[0]);
    span.write(5, &.{ 99, 98 });
    try std.testing.expectEqual(@as(u8, 99), backing[5]);
    try std.testing.expectEqual(@as(u8, 98), backing[6]);
    const tail = span.sub(8, 8);
    try std.testing.expectEqual(@as(usize, 8), tail.len);
    try std.testing.expectEqual(@as(u8, 8), tail.bytes()[0]);
}

test "const span mirrors span reads" {
    const backing = [_]u8{ 1, 2, 3 };
    const span: ConstSpan = .{ .ptr = &backing, .len = backing.len };
    try std.testing.expectEqual(@as(u8, 2), span.read(1, 1)[0]);
    const head = span.sub(0, 2);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, head.bytes());
}
