const std = @import("std");

const span_module = @import("span.zig");

const ConstSpan = span_module.ConstSpan;
const Exception = span_module.Exception;
const Span = span_module.Span;

// Caller frees are unobservable, so memory is leased per session.
pub const Lease = struct {
    token: u64,
};

pub const Registry = struct {
    pub const Slot = struct {
        base: usize,
        len: usize,
        token: u64,
        live: bool,
    };

    slots: []Slot,
    used: usize = 0,
    next_token: u64 = 1,

    pub fn init(storage: []Slot) Registry {
        return .{ .slots = storage };
    }

    pub fn lease(self: *Registry, memory: ConstSpan) Exception!Lease {
        if (memory.len == 0) return error.CallException;
        for (self.slots[0..self.used]) |slot| {
            if (!slot.live) continue;
            if (span_module.hasOverlap(@intFromPtr(memory.ptr), memory.len, slot.base, slot.len)) return error.CallException;
        }
        // A revoked slot is reusable; appending until the table fills would
        // exhaust it after one round of all-returned leases.
        var index: usize = 0;
        while (index < self.used) : (index += 1) {
            if (!self.slots[index].live) break;
        }
        if (index == self.used) {
            if (self.used == self.slots.len) return error.ResourceException;
            self.used += 1;
        }
        // A wrapped token must not resurrect a live slot's binding.
        var token = self.next_token;
        self.next_token +%= 1;
        while (findSlotIndex(self, .{ .token = token }) != null) {
            token = self.next_token;
            self.next_token +%= 1;
        }
        self.slots[index] = .{
            .base = @intFromPtr(memory.ptr),
            .len = memory.len,
            .token = token,
            .live = true,
        };
        return .{ .token = token };
    }

    pub fn revoke(self: *Registry, leased: Lease) void {
        if (findSlotIndex(self, leased)) |index| self.slots[index].live = false;
    }

    pub fn span(self: *Registry, leased: Lease, offset: usize, length: usize) Span {
        const slot = self.slots[findSlotIndex(self, leased) orelse span_module.trap(.lease_violation, "lease token is unknown.")];
        if (!slot.live) span_module.trap(.lease_violation, "lease was revoked.");
        span_module.checkRange(slot.len, offset, length);
        return .{ .ptr = @ptrFromInt(slot.base + offset), .len = length };
    }

    pub fn constSpan(self: *Registry, leased: Lease, offset: usize, length: usize) ConstSpan {
        const view = self.span(leased, offset, length);
        return .{ .ptr = view.ptr, .len = view.len };
    }
};

fn findSlotIndex(self: *Registry, leased: Lease) ?usize {
    for (self.slots[0..self.used], 0..) |slot, index| {
        if (slot.token == leased.token) return index;
    }
    return null;
}

test "lease reuse reclaims revoked slots while live leases keep their views" {
    var storage: [3]Registry.Slot = undefined;
    var registry = Registry.init(&storage);
    var memory: [2][8]u8 = undefined;
    for (&memory) |*region| region.* = @splat(0x5A);
    const kept = try registry.lease(.{ .ptr = &memory[1], .len = memory[1].len });
    // Repeated lease/revoke rounds must recycle one slot, not grow the table.
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        const held = try registry.lease(.{ .ptr = &memory[0], .len = memory[0].len });
        registry.revoke(held);
    }
    try std.testing.expectEqual(@as(usize, 2), registry.used);
    try std.testing.expectEqualSlices(u8, &memory[1], registry.span(kept, 0, memory[1].len).bytes());
}

test "lease refuses live slots beyond capacity but keeps the held views" {
    var storage: [2]Registry.Slot = undefined;
    var registry = Registry.init(&storage);
    var first: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var second: [8]u8 = undefined;
    var third: [8]u8 = undefined;
    const held_first = try registry.lease(.{ .ptr = &first, .len = first.len });
    const held_second = try registry.lease(.{ .ptr = &second, .len = second.len });
    try std.testing.expectError(error.ResourceException, registry.lease(.{ .ptr = &third, .len = third.len }));
    try std.testing.expectEqual(@as(usize, 2), registry.used);
    // Refusal leaves the earlier leases untouched and readable.
    try std.testing.expectEqualSlices(u8, &.{3}, registry.span(held_first, 3, 1).bytes());
    try std.testing.expectEqual(@as(usize, second.len), registry.span(held_second, 0, second.len).len);
}

test "lease rejects empty memory and live overlaps but accepts adjacent ranges" {
    var storage: [2]Registry.Slot = undefined;
    var registry = Registry.init(&storage);
    var memory: [8]u8 = undefined;
    try std.testing.expectError(error.CallException, registry.lease(.{ .ptr = &memory, .len = 0 }));
    const head = try registry.lease(.{ .ptr = memory[0..4].ptr, .len = 4 });
    try std.testing.expectError(error.CallException, registry.lease(.{ .ptr = memory[2..].ptr, .len = 4 }));
    // Touching ranges do not overlap, so the tail still leases.
    const tail = try registry.lease(.{ .ptr = memory[4..].ptr, .len = 4 });
    try std.testing.expect(tail.token != head.token);
    // Revoking frees the range for a differently tokened lease.
    registry.revoke(head);
    const again = try registry.lease(.{ .ptr = memory[0..4].ptr, .len = 4 });
    try std.testing.expect(again.token != head.token);
}

test "lease tokens stay distinct when the counter wraps past maxint" {
    var storage: [3]Registry.Slot = undefined;
    var registry = Registry.init(&storage);
    registry.next_token = std.math.maxInt(u64);
    var memory: [3][8]u8 = undefined;
    var tokens: [3]u64 = undefined;
    for (0..3) |index| {
        const held = try registry.lease(.{ .ptr = &memory[index], .len = memory[index].len });
        tokens[index] = held.token;
    }
    // The wrap itself must land on maxint without resurrecting a binding.
    try std.testing.expectEqual(std.math.maxInt(u64), tokens[0]);
    for (tokens, 0..) |token, index| {
        for (tokens[0..index]) |earlier| try std.testing.expect(token != earlier);
    }
}

test "lease span and constspan view byte-exact windows of the leased range" {
    var storage: [1]Registry.Slot = undefined;
    var registry = Registry.init(&storage);
    var memory: [8]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const held = try registry.lease(.{ .ptr = &memory, .len = memory.len });
    // The mutable view writes through to the leased memory.
    const view = registry.span(held, 2, 3);
    try std.testing.expectEqual(@as(usize, 3), view.len);
    try std.testing.expectEqual(@as(usize, @intFromPtr(&memory[2])), @intFromPtr(view.ptr));
    view.write(1, &.{0x7E});
    try std.testing.expectEqual(@as(u8, 0x7E), memory[3]);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0x7E, 4 }, view.bytes());
    const frozen = registry.constSpan(held, 6, 2);
    try std.testing.expectEqualSlices(u8, &.{ 6, 7 }, frozen.bytes());
}
