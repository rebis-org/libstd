const std = @import("std");

const Failure = @import("../common/primitive/failure.zig").Failure;

// Dynamic dispatch allowed here; leaf inner loops stay comptime-specialized. Caller-owned storage keeps zero library state, so reentrancy holds by construction.
pub const StepStatus = enum { open, done, failed };

pub const StepResult = struct {
    consumed: usize = 0,
    produced: usize = 0,
    status: StepStatus = .open,
    committed: usize = 0,
    downstream: u32 = 0,
    failure: ?Failure = null,
    /// Driver-defined detail for the failure: the required capacity for
    /// insufficient_capacity, 0 where the failure carries no scalar. The C
    /// boundary copies it into the session record on failure.
    failure_value: u64 = 0,
};

pub const Budgets = struct {
    encoded: u64 = 0,
    decoded: u64 = 0,
    work: u64 = 0,
    entries: u64 = 0,
    max_encoded: u64 = std.math.maxInt(u64),
    max_decoded: u64 = std.math.maxInt(u64),
    max_work: u64 = std.math.maxInt(u64),
    max_entries: u64 = std.math.maxInt(u64),

    pub fn addDecoded(self: *Budgets, amount: usize) Failure!void {
        const next = std.math.add(u64, self.decoded, amount) catch return error.ResourceLimit;
        if (next > self.max_decoded) return error.ResourceLimit;
        self.decoded = next;
    }

    pub fn addEncoded(self: *Budgets, amount: usize) Failure!void {
        const next = std.math.add(u64, self.encoded, amount) catch return error.ResourceLimit;
        if (next > self.max_encoded) return error.ResourceLimit;
        self.encoded = next;
    }

    pub fn addWork(self: *Budgets, amount: usize) Failure!void {
        const next = std.math.add(u64, self.work, amount) catch return error.ResourceLimit;
        if (next > self.max_work) return error.ResourceLimit;
        self.work = next;
    }
};

pub const Ops = struct {
    step: *const fn (state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) StepResult,
    destroy: *const fn (state: *anyopaque) void,
};

pub const Session = struct {
    state: *anyopaque,
    ops: *const Ops,
    alive: bool = true,
    /// The last step's failure in envelope status vocabulary, plus the
    /// driver detail. Written by the boundary on failure; hosts read them
    /// through `stdk_session_failure` while the storage is alive.
    failure_status: u32 = 0,
    failure_detail: u64 = 0,

    pub fn step(self: *Session, input: []const u8, output: []u8, end_of_input: bool) StepResult {
        if (!self.alive) return .{ .status = .failed, .failure = error.InvalidCall };
        return self.ops.step(self.state, input, output, end_of_input);
    }

    pub fn destroy(self: *Session) void {
        if (!self.alive) return;
        self.ops.destroy(self.state);
        self.alive = false;
    }
};
