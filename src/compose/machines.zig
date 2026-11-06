const std = @import("std");

const Exception = @import("../common/primitive/exception.zig").Exception;

// The host shape mirrors sessions: a pure step function over host-delivered events; I/O and timers stay with the host.

pub const StepStatus = enum { running, done, failed };

// One machine transition: events in, actions out, both caller-typed.
pub fn MachineFor(comptime Event: type, comptime Action: type) type {
    return struct {
        state: *anyopaque,
        ops: *const Ops,
        failed: bool = false,

        pub const Ops = struct {
            step: *const fn (state: *anyopaque, event: Event, actions: []Action) Exception!StepStatus,
            destroy: *const fn (state: *anyopaque) void,
        };

        pub const StepResult = struct {
            status: StepStatus,
            actions: []Action,
        };

        pub fn step(self: @This(), event: Event, actions: []Action) Exception!StepResult {
            if (self.failed) return error.CallException;
            const status = try self.ops.step(self.state, event, actions);
            if (status == .failed) return .{ .status = .failed, .actions = actions };
            return .{ .status = status, .actions = actions };
        }

        pub fn markFailed(self: *@This()) void {
            self.failed = true;
        }

        pub fn destroy(self: *@This()) void {
            if (self.failed) return;
            self.ops.destroy(self.state);
            self.failed = true;
        }
    };
}

// A toy machine pins the shape: a counter that terminates after a budget of
// `increment` events.
test "machine stepping consumes events emits actions and honors failure" {
    const Event = enum { increment, reset };
    const Action = enum { notify, halted };
    const Machine = MachineFor(Event, Action);
    const State = struct {
        count: u32,
        budget: u32,
        destroyed: bool = false,

        fn step(state_ptr: *anyopaque, event: Event, actions: []Action) Exception!StepStatus {
            const self: *@This() = @ptrCast(@alignCast(state_ptr));
            switch (event) {
                .increment => {
                    self.count += 1;
                    if (self.count >= self.budget) {
                        actions[0] = .halted;
                        return .done;
                    }
                    actions[0] = .notify;
                },
                .reset => self.count = 0,
            }
            return .running;
        }

        fn destroy(state_ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(state_ptr));
            self.destroyed = true;
        }
    };

    // A reset mid-run sends the counter back to the start of its budget.
    var state: State = .{ .count = 0, .budget = 2 };
    var machine: Machine = .{ .state = &state, .ops = &.{ .step = State.step, .destroy = State.destroy } };
    var action_slots: [1]Action = undefined;
    const first = try machine.step(.increment, &action_slots);
    try std.testing.expectEqual(StepStatus.running, first.status);
    try std.testing.expectEqual(Action.notify, first.actions[0]);
    try std.testing.expectEqual(StepStatus.running, (try machine.step(.reset, &action_slots)).status);
    try std.testing.expectEqual(StepStatus.running, (try machine.step(.increment, &action_slots)).status);
    const done = try machine.step(.increment, &action_slots);
    try std.testing.expectEqual(StepStatus.done, done.status);
    try std.testing.expectEqual(Action.halted, done.actions[0]);
    // Destroy runs the op exactly once, while the state is observable.
    machine.destroy();
    try std.testing.expect(state.destroyed);
    try std.testing.expectEqual(@as(u32, 2), state.count);

    // An op-reported failure passes through with its actions attached.
    const Failing = struct {
        fn step(_: *anyopaque, _: Event, actions: []Action) Exception!StepStatus {
            actions[0] = .halted;
            return .failed;
        }

        fn destroy(state_ptr: *anyopaque) void {
            const flag: *bool = @ptrCast(@alignCast(state_ptr));
            flag.* = true;
        }
    };
    var destroyed = false;
    var failing: Machine = .{ .state = &destroyed, .ops = &.{ .step = Failing.step, .destroy = Failing.destroy } };
    const failed = try failing.step(.increment, &action_slots);
    try std.testing.expectEqual(StepStatus.failed, failed.status);
    try std.testing.expectEqual(Action.halted, failed.actions[0]);
    // The host flag refuses further stepping and guards the destroy op.
    failing.markFailed();
    try std.testing.expectError(error.CallException, failing.step(.increment, &action_slots));
    failing.destroy();
    try std.testing.expect(!destroyed);
}
