const std = @import("std");

const sessions = @import("../sessions.zig");

const StepResult = sessions.StepResult;

// Both kernel-mediated and bypass paths run identical leaf code, so byte-identity is expected.
fn destroyNoop(state: *anyopaque) void {
    _ = state;
}

fn Ops(comptime Driver: type, comptime step: fn (*Driver, []const u8, []u8, bool) StepResult) sessions.Ops {
    const S = struct {
        fn call(state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) StepResult {
            return step(@ptrCast(@alignCast(state)), input, output, end_of_input);
        }
    };
    return .{ .step = S.call, .destroy = destroyNoop };
}

// One builder binds a driver's init and step into the executor's session;
// the error set derives from the init itself.
fn SessionOf(comptime Driver: type, comptime init_fn: anytype, comptime step: fn (*Driver, []const u8, []u8, bool) StepResult) type {
    const ops = Ops(Driver, step);
    const init_return = @typeInfo(@TypeOf(init_fn)).@"fn".return_type.?;
    return struct {
        fn open(storage: []u8, budgets: sessions.Budgets) @typeInfo(init_return).error_union.error_set!sessions.Session {
            const state = try @call(.auto, init_fn, .{ storage, budgets });
            return .{ .state = state, .ops = &ops };
        }
    };
}

// Binding the triple in one declaration keeps storage, init, and session from drifting apart.
pub fn Pair(comptime args: anytype) type {
    return struct {
        pub const storage = args.storage;
        pub const init = args.init;
        pub const session = SessionOf(args.state, args.init, args.step).open;
    };
}

pub fn stateSize(comptime T: type) usize {
    return std.mem.alignForward(usize, @sizeOf(T), 16);
}

pub fn carveHistory(comptime T: type, storage: []u8, comptime history_len: usize) error{CapacityException}!struct { state: *T, history: []u8 } {
    const size = stateSize(T);
    if (storage.len < size + history_len) return error.CapacityException;
    return .{
        .state = @ptrCast(@alignCast(storage.ptr)),
        .history = storage[size..][0..history_len],
    };
}
