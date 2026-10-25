const std = @import("std");

// An executor schedules a task; the task flips the completion record.
// The default is same-thread: run returns after the task finished.
// Threaded variants are host-owned components injected like an allocator.

pub const Task = extern struct {
    context: *anyopaque,
    invoke: *const fn (context: *anyopaque) callconv(.c) u32,
};

pub const Vtable = extern struct {
    // Schedules task.invoke(task.context) exactly once, on any thread.
    run: *const fn (ptr: *anyopaque, task: Task) callconv(.c) u32,
};

pub const Executor = extern struct {
    ptr: *anyopaque,
    vtable: *const Vtable,

    pub inline fn run(self: Executor, task: Task) u32 {
        return self.vtable.run(self.ptr, task);
    }
};

const inline_state: u8 = 0;

fn inlineRun(_: *anyopaque, task: Task) callconv(.c) u32 {
    return task.invoke(task.context);
}

const inline_vtable: Vtable = .{ .run = inlineRun };

// The default executor: runs the task before returning, so the record is
// done by the time submission returns, the same semantics as stdk_call.
pub const inline_executor: Executor = .{
    .ptr = @constCast(@as(*const u8, &inline_state)),
    .vtable = &inline_vtable,
};

test "executor inline runs the task and returns its status" {
    const Ctx = struct {
        ran: bool = false,
        fn invoke(context: *anyopaque) callconv(.c) u32 {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.ran = true;
            return 7;
        }
    };
    var ctx: Ctx = .{};
    const status = inline_executor.run(.{ .context = &ctx, .invoke = Ctx.invoke });
    try std.testing.expect(ctx.ran);
    try std.testing.expectEqual(@as(u32, 7), status);
}
