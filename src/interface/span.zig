const builtin = @import("builtin");
const std = @import("std");

const diagnostic = @import("diagnostic.zig");

// The interface cannot import the primitive exception set; naming the exact
// two it answers keeps the vocabulary from diverging.
pub const Exception = error{ CallException, ResourceException };

pub const Violation = enum { out_of_bounds, use_after_free, lease_violation, overlap };

const empty_storage: [1]u8 = .{0};

// Contract violations trap: out-of-provenance access is a defect, never a survivable condition.
pub fn trap(violation: Violation, context: []const u8) noreturn {
    var message_storage: [128]u8 = undefined;
    var message_writer: std.Io.Writer = std.Io.Writer.fixed(&message_storage);
    const message = if (message_writer.print("interface trap: {s}: {s}\n", .{ @tagName(violation), context })) |_| message_writer.buffered() else |_| "interface trap.\n";
    diagnostic.writeStderr(message);
    // The raise call needs a C runtime; without one (msvc, android, ohos)
    // the trap instruction carries the violation alone.
    if (comptime diagnostic.has_libc and builtin.target.os.tag != .windows) {
        std.posix.raise(std.posix.SIG.TRAP) catch {};
    }
    @trap();
}

pub fn checkRange(total: usize, offset: usize, length: usize) void {
    if (offset > total or length > total - offset) trap(.out_of_bounds, "subspan is out of bounds.");
}

pub fn hasOverlap(first_start: usize, first_len: usize, second_start: usize, second_len: usize) bool {
    if (first_len == 0 or second_len == 0) return false;
    // A wrapped u64 end reads as disjoint under subtraction, so the copy
    // traps instead of reading past it.
    return second_start < first_start +| first_len and first_start < second_start +| second_len;
}

// One algebra for both mutabilities: the handed-out view carries the span's
// own mutability, so const spans stay unwritable.
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

fn spanFrom(comptime Pointer: type, base: ?Pointer, length: u64) Exception!SpanFor(Pointer) {
    const count = std.math.cast(usize, length) orelse return error.ResourceException;
    // A zero length never dereferences, so immutable empty storage stands
    // in for a legitimately passed null.
    if (count == 0) return .{ .ptr = @constCast(&empty_storage), .len = 0 };
    const live = base orelse return error.CallException;
    return .{ .ptr = live, .len = count };
}

pub fn mutSpan(pointer: ?[*]u8, length: u64) Exception!Span {
    return spanFrom([*]u8, pointer, length);
}

pub fn constSpan(pointer: ?[*]const u8, length: u64) Exception!ConstSpan {
    return spanFrom([*]const u8, pointer, length);
}

// Independently handed spans must not alias.
pub fn requireDisjoint(first: ConstSpan, second: ConstSpan, context: []const u8) void {
    if (hasOverlap(@intFromPtr(first.ptr), first.len, @intFromPtr(second.ptr), second.len)) trap(.overlap, context);
}

test "span algebra reads writes and subs through shared storage" {
    var backing: [16]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const span: Span = .{ .ptr = &backing, .len = backing.len };
    try std.testing.expectEqual(@as(usize, 16), span.len);
    try std.testing.expectEqual(@as(u8, 5), span.read(5, 1)[0]);
    span.write(5, &.{ 99, 98 });
    try std.testing.expectEqual(@as(u8, 99), backing[5]);
    try std.testing.expectEqual(@as(u8, 98), backing[6]);
    // A subspan aliases the backing, so writes through it land there.
    const tail = span.sub(8, 8);
    tail.write(0, &.{42});
    try std.testing.expectEqual(@as(u8, 42), backing[8]);
    try std.testing.expectEqualSlices(u8, backing[8..16], tail.bytes());
    // Zero-length subs stay legal at both edges.
    try std.testing.expectEqual(@as(usize, 0), span.sub(16, 0).len);
    try std.testing.expectEqual(@as(usize, 0), span.sub(0, 0).len);
}

test "const span mirrors span reads without any copy" {
    const backing = [_]u8{ 1, 2, 3 };
    const span: ConstSpan = .{ .ptr = &backing, .len = backing.len };
    try std.testing.expectEqual(@as(u8, 2), span.read(1, 1)[0]);
    const head = span.sub(0, 2);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, head.bytes());
    // The view aliases the backing array, not a copy of it.
    try std.testing.expectEqual(@as(usize, @intFromPtr(&backing[0])), @intFromPtr(head.ptr));
    var mutable: [3]u8 = .{ 7, 8, 9 };
    const viewed: ConstSpan = .{ .ptr = &mutable, .len = mutable.len };
    mutable[1] = 0x5A;
    try std.testing.expectEqual(@as(u8, 0x5A), viewed.read(1, 1)[0]);
}

test "span constructors reject null bases and oversized lengths" {
    var storage: [4]u8 = .{ 9, 8, 7, 6 };
    // Zero length never dereferences, so a null base is still accepted.
    const empty = try mutSpan(null, 0);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    const frozen_empty = try constSpan(null, 0);
    try std.testing.expectEqual(@as(usize, 0), frozen_empty.len);
    // A live base answers with its exact bytes.
    const live = try mutSpan(&storage, storage.len);
    try std.testing.expectEqualSlices(u8, &.{ 9, 8, 7, 6 }, live.bytes());
    // Nonzero length demands a base.
    try std.testing.expectError(error.CallException, mutSpan(null, 4));
    try std.testing.expectError(error.CallException, constSpan(null, 4));
    // A length beyond the address space can only exist on narrow targets.
    if (comptime @sizeOf(usize) < @sizeOf(u64)) {
        try std.testing.expectError(error.ResourceException, mutSpan(&storage, std.math.maxInt(u64)));
        try std.testing.expectError(error.ResourceException, constSpan(&storage, std.math.maxInt(u64)));
    }
}
