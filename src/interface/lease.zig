const span_module = @import("span.zig");

const Span = span_module.Span;
const ConstSpan = span_module.ConstSpan;
const Failure = span_module.Failure;

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

    pub fn lease(self: *Registry, memory: ConstSpan) Failure!Lease {
        if (memory.len == 0) return error.InvalidCall;
        for (self.slots[0..self.used]) |slot| {
            if (!slot.live) continue;
            if (span_module.overlaps(@intFromPtr(memory.ptr), memory.len, slot.base, slot.len)) return error.InvalidCall;
        }
        if (self.used == self.slots.len) return error.ResourceLimit;
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
        for (self.slots[0..self.used]) |*slot| {
            if (slot.token == leased.token) {
                slot.live = false;
                return;
            }
        }
    }

    pub fn span(self: *Registry, leased: Lease, offset: usize, length: usize) Span {
        for (self.slots[0..self.used]) |slot| {
            if (slot.token != leased.token) continue;
            if (!slot.live) span_module.trap(.lease_violation, "lease was revoked.");
            if (offset > slot.len or length > slot.len - offset) span_module.trap(.out_of_bounds, "lease subspan is out of bounds.");
            return .{ .ptr = @ptrFromInt(slot.base + offset), .len = length };
        }
        span_module.trap(.lease_violation, "lease token is unknown.");
    }

    pub fn constSpan(self: *Registry, leased: Lease, offset: usize, length: usize) ConstSpan {
        const view = self.span(leased, offset, length);
        return .{ .ptr = view.ptr, .len = view.len };
    }
};
