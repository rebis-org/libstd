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
        if (self.used == self.slots.len) return error.ResourceException;
        const token = self.next_token;
        self.next_token += 1;
        self.slots[self.used] = .{
            .base = @intFromPtr(memory.ptr),
            .len = memory.len,
            .token = token,
            .live = true,
        };
        self.used += 1;
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
