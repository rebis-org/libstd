const std = @import("std");

// An executor schedules a task; the task flips the completion record. Threaded variants are host-owned injected components.

// The substrate sits below the kernel, so these constants mirror the Status vocabulary by value; compose pins the pair.
pub const status = struct {
    pub const ok: u32 = 0;
    pub const unsupported: u32 = 2;
    pub const resource_limit: u32 = 7;
};

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

// The default executor runs the task before returning, so the record is done at submission, matching stdk_call.
pub const inline_executor: Executor = .{
    .ptr = @constCast(@as(*const u8, &inline_state)),
    .vtable = &inline_vtable,
};

test "executor inline finishes the task before submission returns" {
    const Ctx = struct {
        ran: bool = false,
        fn invoke(context: *anyopaque) callconv(.c) u32 {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.ran = true;
            return status.resource_limit;
        }
    };
    var ctx: Ctx = .{};
    const code = inline_executor.run(.{ .context = &ctx, .invoke = Ctx.invoke });
    // The task ran to completion inside run, not after it.
    try std.testing.expect(ctx.ran);
    try std.testing.expectEqual(status.resource_limit, code);
    // The mirrored vocabulary keeps its pinned value.
    try std.testing.expectEqual(@as(u32, 7), code);
}
