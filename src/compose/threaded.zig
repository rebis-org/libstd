const builtin = @import("builtin");
const std = @import("std");

const executor_prim = @import("../common/executor.zig");
const lanes_prim = @import("../common/lanes.zig");

const Executor = executor_prim.Executor;
const Task = executor_prim.Task;
const status = executor_prim.status;
const Join = lanes_prim.Join;

// The standard library does not build for the Apple embedded targets, so
// the executor stays out of those slices.
pub const supported = switch (builtin.os.tag) {
    .ios, .tvos, .visionos, .watchos => false,
    else => true,
};

// A wave that did not finish is an internal fault; no unit result is sound.
const unscheduled: u32 = 1;

// The caller owns this executor; one instance serves one lane driver,
// because a Group is not threadsafe.
pub const Threaded = struct {
    const Self = @This();

    // The backing is void off the supported targets, so the failing
    // standard library code there is never analyzed.
    io_instance: if (supported) std.Io.Threaded else void,
    group: std.Io.Group = .init,
    lanes: u8,

    // The allocator must be threadsafe. The pool stays unlimited because
    // std releases a concurrent slot after the join returns.
    pub fn init(allocator: std.mem.Allocator, lanes: u8) error{CallException}!Self {
        if (!supported) @compileError("the threaded executor does not build for this target.");
        // A single-threaded build cannot schedule concurrent tasks; the
        // standard library would refuse every submission at run time.
        if (builtin.single_threaded) return error.CallException;
        if (lanes == 0 or lanes > lanes_prim.max_lanes) return error.CallException;
        return .{
            .io_instance = std.Io.Threaded.init(allocator, .{
                .async_limit = .nothing,
                .concurrent_limit = .unlimited,
            }),
            .lanes = lanes,
        };
    }

    // Joins the workers and restores the process signal handlers.
    pub fn deinit(self: *Self) void {
        self.io_instance.deinit();
    }

    pub fn handle(self: *Self) Executor {
        return .{ .ptr = self, .vtable = &executor_vtable };
    }

    pub fn join(self: *Self) Join {
        return .{ .context = self, .wait = waitAll };
    }

    const executor_vtable: executor_prim.Vtable = .{ .run = submit };

    fn submit(ptr: *anyopaque, task: Task) callconv(.c) u32 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        // A refusal is reported, never degraded to an inline run.
        self.group.concurrent(self.io_instance.io(), runTask, .{task}) catch return status.resource_limit;
        return status.ok;
    }

    fn runTask(task: Task) std.Io.Cancelable!void {
        _ = task.invoke(task.context);
    }

    fn waitAll(ptr: *anyopaque) callconv(.c) u32 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.group.await(self.io_instance.io()) catch return unscheduled;
        return status.ok;
    }
};

test "threaded executor runs every submitted task before the join returns" {
    if (!supported) return error.SkipZigTest;
    if (builtin.single_threaded) return error.SkipZigTest;
    var executor = try Threaded.init(std.testing.allocator, 2);
    defer executor.deinit();

    const Counter = struct {
        ran: std.atomic.Value(u32) = .init(0),

        fn invoke(context: *anyopaque) callconv(.c) u32 {
            const self: *@This() = @ptrCast(@alignCast(context));
            _ = self.ran.fetchAdd(1, .monotonic);
            return status.ok;
        }
    };
    var counter: Counter = .{};
    const handle = executor.handle();
    // More submissions than lanes forces the queue to hold work back.
    var submitted: u32 = 0;
    while (submitted < 8) : (submitted += 1) {
        try std.testing.expectEqual(status.ok, handle.run(.{ .context = &counter, .invoke = Counter.invoke }));
    }
    // A refusing task still runs: the executor ignores task verdicts.
    const Refuser = struct {
        ran: bool = false,

        fn invoke(context: *anyopaque) callconv(.c) u32 {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.ran = true;
            return status.resource_limit;
        }
    };
    var refuser: Refuser = .{};
    try std.testing.expectEqual(status.ok, handle.run(.{ .context = &refuser, .invoke = Refuser.invoke }));

    // The join blocks until every submission landed; repeating it is safe.
    const join = executor.join();
    try std.testing.expectEqual(status.ok, join.wait(join.context));
    try std.testing.expectEqual(status.ok, join.wait(join.context));
    try std.testing.expectEqual(@as(u32, 8), counter.ran.load(.monotonic));
    try std.testing.expect(refuser.ran);
}

test "threaded executor rejects lane counts outside the window" {
    if (!supported) return error.SkipZigTest;
    try std.testing.expectError(error.CallException, Threaded.init(std.testing.allocator, 0));
    try std.testing.expectError(error.CallException, Threaded.init(std.testing.allocator, lanes_prim.max_lanes + 1));
    // Both window edges are accepted wherever threads exist.
    if (builtin.single_threaded) return error.SkipZigTest;
    var minimal = try Threaded.init(std.testing.allocator, 1);
    minimal.deinit();
    var widest = try Threaded.init(std.testing.allocator, lanes_prim.max_lanes);
    widest.deinit();
}
