const std = @import("std");

const Failure = @import("../common/primitive/failure.zig").Failure;

// Dynamic dispatch allowed here. Leaf inner loops stay comptime-specialized. Caller-owned storage keeps zero library state, so reentrancy holds by construction.
pub const StepStatus = enum { open, done, failed };

pub const StepResult = struct {
    consumed: usize = 0,
    produced: usize = 0,
    status: StepStatus = .open,
    committed: usize = 0,
    downstream: u32 = 0,
    failure: ?Failure = null,
    // Driver-defined detail: the required capacity for insufficient_capacity,
    // 0 where the failure carries no scalar.
    required_capacity: u64 = 0,
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

    fn charge(current: *u64, ceiling: u64, amount: usize) Failure!void {
        const next = std.math.add(u64, current.*, amount) catch return error.ResourceFailure;
        if (next > ceiling) return error.ResourceFailure;
        current.* = next;
    }

    pub fn addDecoded(self: *Budgets, amount: usize) Failure!void {
        try charge(&self.decoded, self.max_decoded, amount);
    }

    pub fn addEncoded(self: *Budgets, amount: usize) Failure!void {
        try charge(&self.encoded, self.max_encoded, amount);
    }

    pub fn addWork(self: *Budgets, amount: usize) Failure!void {
        try charge(&self.work, self.max_work, amount);
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
    // Sticky failure state machine: once a step fails, later steps fail with
    // CallFailure instead of depending on per-driver recovery conventions.
    failed: bool = false,
    // Handle identity: set by the boundary on create, cleared on destroy, so a
    // failed-create or never-created storage can never dispatch through a
    // garbage ops pointer.
    cookie: u64 = 0,
    // The caller-declared storage extent, for overlap validation at step time.
    storage_len: u64 = 0,
    // The last step's failure in envelope status vocabulary, plus the driver
    // detail. Written by the boundary on failure. Hosts read them through
    // `stdk_session_failure` while the storage is alive.
    failure_status: u32 = 0,
    failure_detail: u64 = 0,

    pub fn step(self: *Session, input: []const u8, output: []u8, end_of_input: bool) StepResult {
        if (!self.alive or self.failed) return .{ .status = .failed, .failure = error.CallFailure };
        return self.ops.step(self.state, input, output, end_of_input);
    }

    pub fn destroy(self: *Session) void {
        if (!self.alive) return;
        self.ops.destroy(self.state);
        self.alive = false;
    }
};
