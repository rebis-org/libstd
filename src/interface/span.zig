const std = @import("std");

const diagnostic = @import("diagnostic.zig");

// The interface module cannot import the primitive failure set, and it never
// needs to: a span crossing only answers these two. Naming the exact set keeps
// the substrate vocabulary from becoming a second, divergent one.
pub const Failure = error{ CallFailure, ResourceFailure };

pub const Violation = enum { out_of_bounds, use_after_free, lease_violation, overlap };

const empty_storage: [1]u8 = .{0};

// Contract violations trap: out-of-provenance access is a bug, never a survivable condition.
pub fn trap(violation: Violation, context: []const u8) noreturn {
    var message_storage: [128]u8 = undefined;
    var message_writer: std.Io.Writer = std.Io.Writer.fixed(&message_storage);
    const message = if (message_writer.print("interface trap: {s}: {s}\n", .{ @tagName(violation), context })) |_| message_writer.buffered() else |_| "interface trap.\n";
    diagnostic.writeStderr(message);
    std.posix.raise(std.posix.SIG.TRAP) catch {};
    unreachable;
}

pub fn checkRange(total: usize, offset: usize, length: usize) void {
    if (offset > total or length > total - offset) trap(.out_of_bounds, "subspan is out of bounds.");
}

pub fn hasOverlap(first_start: usize, first_len: usize, second_start: usize, second_len: usize) bool {
    if (first_len == 0 or second_len == 0) return false;
    // Caller-supplied lengths reach here as u64, so an end offset can wrap. The
    // subtraction form stays correct on wrap, where a wrapped end reads as
    // disjoint and the caller traps on the copy instead of reading past it.
    return second_start < first_start +| first_len and first_start < second_start +| second_len;
}

// One span algebra for both mutabilities: the view a span hands out carries the
// span's own mutability, so a const span cannot be written through its type.
fn SpanFor(comptime Pointer: type) type {
    const View = if (Pointer == [*]const u8) []const u8 else []u8;
    return struct {
        ptr: Pointer,
        len: usize,

        pub fn bytes(self: @This()) View {
            return self.ptr[0..self.len];
        }

        pub fn sub(self: @This(), offset: usize, length: usize) @This() {
            checkRange(self.len, offset, length);
            return .{ .ptr = self.ptr + offset, .len = length };
        }

        pub fn read(self: @This(), offset: usize, length: usize) View {
            return self.sub(offset, length).bytes();
        }

        pub fn write(self: @This(), offset: usize, chunk: []const u8) void {
            if (View == []const u8) @compileError("a const span cannot be written.");
            @memcpy(self.sub(offset, chunk.len).bytes(), chunk);
        }
    };
}

pub const Span = SpanFor([*]u8);
pub const ConstSpan = SpanFor([*]const u8);

fn spanFrom(comptime Pointer: type, base: ?Pointer, length: u64) Failure!SpanFor(Pointer) {
    const count = std.math.cast(usize, length) orelse return error.ResourceFailure;
    // A zero length never dereferences the pointer, so the immutable empty
    // storage stands in for the null a caller may legitimately pass.
    if (count == 0) return .{ .ptr = @constCast(&empty_storage), .len = 0 };
    const live = base orelse return error.CallFailure;
    return .{ .ptr = live, .len = count };
}

pub fn mutSpan(pointer: ?[*]u8, length: u64) Failure!Span {
    return spanFrom([*]u8, pointer, length);
}

pub fn constSpan(pointer: ?[*]const u8, length: u64) Failure!ConstSpan {
    return spanFrom([*]const u8, pointer, length);
}

// Independently handed spans must not alias.
pub fn requireDisjoint(first: ConstSpan, second: ConstSpan, context: []const u8) void {
    if (hasOverlap(@intFromPtr(first.ptr), first.len, @intFromPtr(second.ptr), second.len)) trap(.overlap, context);
}

test "span algebra: read, write, and sub round trip" {
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
