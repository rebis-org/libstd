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
        // A revoked slot is reusable. Appending until the table fills would
        // exhaust it after one round of leases that were all returned.
        var index: usize = 0;
        while (index < self.used) : (index += 1) {
            if (!self.slots[index].live) break;
        }
        if (index == self.used) {
            if (self.used == self.slots.len) return error.ResourceException;
            self.used += 1;
        }
        const token = self.next_token;
        self.next_token +%= 1;
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

test "a revoked slot is reusable" {
    var storage: [2]Registry.Slot = undefined;
    var registry = Registry.init(&storage);
    var memory: [8]u8 = undefined;
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        const held = try registry.lease(.{ .ptr = &memory, .len = memory.len });
        registry.revoke(held);
    }
    // Two live leases still fit, and a third fails on capacity.
    const first = try registry.lease(.{ .ptr = &memory, .len = memory.len });
    var other: [8]u8 = undefined;
    _ = try registry.lease(.{ .ptr = &other, .len = other.len });
    registry.revoke(first);
    _ = try registry.lease(.{ .ptr = &memory, .len = memory.len });
}
