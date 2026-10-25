const std = @import("std");

const Exception = @import("../common/primitive/exception.zig").Exception;

// The state machine host shape mirrors sessions: a pure step function over
// host-delivered events; storage and lifetime are the caller's.
// I/O and timers stay with the host: a timeout is an event, never a clock.

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
test "machine shape: stepping consumes events and emits actions" {
    const Event = enum { increment, reset };
    const Action = enum { notify, halted };
    const Machine = MachineFor(Event, Action);
    const State = struct {
        count: u32,
        budget: u32,

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

        fn destroy(_: *anyopaque) void {}
    };

    var state: State = .{ .count = 0, .budget = 3 };
    var machine: Machine = .{ .state = &state, .ops = &.{ .step = State.step, .destroy = State.destroy } };
    var actions: [1]Action = undefined;
    const first = try machine.step(.increment, &actions);
    try std.testing.expectEqual(StepStatus.running, first.status);
    try std.testing.expectEqual(Action.notify, first.actions[0]);
    const second = try machine.step(.increment, &actions);
    try std.testing.expectEqual(StepStatus.running, second.status);
    const third = try machine.step(.increment, &actions);
    try std.testing.expectEqual(StepStatus.done, third.status);
    try std.testing.expectEqual(Action.halted, third.actions[0]);
    machine.markFailed();
    try std.testing.expectError(error.CallException, machine.step(.increment, &actions));
    machine.destroy();
    try std.testing.expect(state.count == 3);
}
