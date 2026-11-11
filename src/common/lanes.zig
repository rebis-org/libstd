const std = @import("std");

const executor_prim = @import("executor.zig");

const Executor = executor_prim.Executor;
const Task = executor_prim.Task;
const status = executor_prim.status;

// A wave holds at most this many units in flight.
pub const max_lanes: u8 = 8;

// One unit the format proves independent: input, output, and declared size.
pub const Unit = struct {
    ordinal: u32,
    input: []const u8,
    output: []u8,
    decoded_size: u64,
};

// A full join: wait returns after every submitted task has run.
pub const Join = struct {
    context: *anyopaque,
    wait: *const fn (context: *anyopaque) callconv(.c) u32,
};

pub const Options = struct {
    lanes: u8 = 1,
    executor: ?Executor = null,
    join: ?Join = null,
};

// The caller's per-lane resources: decode scratch, and staging for an
// output that is not a slice of the destination.
pub const Lane = struct {
    scratch: []u8 = &.{},
    staging: []u8 = &.{},
};

// One lane's record; the driver reads it only after the wave joined.
pub fn Slot(comptime Source: type) type {
    return struct {
        const Self = @This();

        pub const State = enum { idle, running, done, failed };

        decoder: *Decoder(Source) = undefined,
        index: u8 = 0,
        unit: Unit = .{ .ordinal = 0, .input = &.{}, .output = &.{}, .decoded_size = 0 },
        produced: usize = 0,
        // The status word cannot carry an error, so the record keeps it.
        failure: ?Source.Exception = null,
        state: State = .idle,

        fn task(self: *Self) Task {
            return .{ .context = self, .invoke = invoke };
        }

        fn invoke(context: *anyopaque) callconv(.c) u32 {
            const self: *Self = @ptrCast(@alignCast(context));
            self.decoder.runLane(self);
            return status.ok;
        }
    };
}

// Wave driver over a Source: `Exception`, `nextUnit`, `decode`, `skipUnits`.
pub fn Decoder(comptime Source: type) type {
    return struct {
        const Self = @This();
        const Exception = Source.Exception;

        source: Source,
        options: Options,
        lanes: [max_lanes]Lane,
        slots: [max_lanes]Slot(Source),
        submitted: u32 = 0,
        drain: u32 = 0,
        exhausted: bool = false,
        failure: ?Exception = null,

        comptime {
            if (!@hasDecl(Source, "Exception")) @compileError("a lane source declares its exception set.");
        }

        pub fn init(source: Source, options: Options, lanes: [max_lanes]Lane) Exception!Self {
            if (options.lanes == 0 or options.lanes > max_lanes) return error.CallException;
            // Concurrent submission without a join leaves tasks unobserved
            // and their slots unsynchronized, whatever the lane count.
            if ((options.lanes > 1 or options.executor != null) and options.join == null) return error.UnsupportedException;
            var self: Self = .{ .source = source, .options = options, .lanes = lanes, .slots = undefined };
            for (&self.slots, 0..) |*slot, index| slot.* = .{ .index = @intCast(index) };
            return self;
        }

        // A failure is sticky: every later call returns the first one.
        pub fn next(self: *Self) Exception!?Unit {
            if (self.failure) |failure| return failure;
            if (self.drain == self.submitted) {
                try self.fill();
                if (self.drain == self.submitted) return null;
            }
            const lane: u32 = self.drain % @as(u32, self.options.lanes);
            const slot = &self.slots[lane];
            if (slot.failure) |failure| {
                self.failure = failure;
                return failure;
            }
            // A task that neither produced nor failed never ran.
            if (slot.state != .done) {
                self.failure = error.InternalException;
                return error.InternalException;
            }
            const unit = slot.unit;
            self.drain += 1;
            slot.state = .idle;
            return .{
                .ordinal = unit.ordinal,
                .input = unit.input,
                .output = unit.output[0..slot.produced],
                .decoded_size = unit.decoded_size,
            };
        }

        // Only between waves, so no submitted task outlives a skip.
        pub fn skip(self: *Self, bytes: u64) Exception!void {
            if (self.failure) |failure| return failure;
            if (self.drain != self.submitted) return error.CallException;
            if (!@hasDecl(Source, "skipUnits")) return error.UnsupportedException;
            const units = try self.source.skipUnits(bytes);
            self.submitted = std.math.add(u32, self.submitted, units) catch return error.ResourceException;
            self.drain = self.submitted;
        }

        // One wave; the window is the backpressure, so no semaphore is needed.
        fn fill(self: *Self) Exception!void {
            self.fillWave() catch |err| {
                // A mid-wave failure must not strand submitted tasks over
                // this frame; join what is in flight, then stay sticky.
                if (self.options.join) |join| _ = join.wait(join.context);
                self.failure = err;
                return err;
            };
            if (self.options.join) |join| {
                // A canceled join leaves the wave unfinished; report a fault.
                if (join.wait(join.context) != status.ok) return error.InternalException;
            }
        }

        fn fillWave(self: *Self) Exception!void {
            while (self.submitted - self.drain < self.options.lanes and !self.exhausted) {
                const ordinal = self.submitted;
                const lane: u8 = @intCast(ordinal % @as(u32, self.options.lanes));
                const unit = (try self.source.nextUnit(ordinal, self.lanes[lane].staging)) orelse {
                    self.exhausted = true;
                    break;
                };
                const slot = &self.slots[lane];
                slot.* = .{
                    .decoder = self,
                    .index = lane,
                    .unit = .{
                        .ordinal = ordinal,
                        .input = unit.input,
                        .output = unit.output,
                        .decoded_size = unit.decoded_size,
                    },
                };
                slot.state = .running;
                if (self.options.executor) |executor| {
                    const code = executor.run(slot.task());
                    if (code != status.ok) {
                        slot.failure = statusException(Exception, code);
                        slot.state = .failed;
                    }
                } else {
                    self.runLane(slot);
                }
                self.submitted += 1;
            }
            if (self.options.join) |join| {
                // A canceled join leaves the wave unfinished; report a fault.
                if (join.wait(join.context) != status.ok) return error.InternalException;
            }
        }

        fn runLane(self: *Self, slot: *Slot(Source)) void {
            // A lane decode runs on any thread and reads only its own lane.
            const produced = self.source.decode(slot.unit, self.lanes[slot.index].scratch) catch |err| {
                slot.failure = err;
                slot.state = .failed;
                return;
            };
            // A source that reports more than its slice is faulty.
            if (produced > slot.unit.output.len) {
                slot.failure = error.InternalException;
                slot.state = .failed;
                return;
            }
            slot.produced = produced;
            slot.state = .done;
        }
    };
}

fn statusException(comptime Exception: type, code: u32) Exception {
    return switch (code) {
        status.unsupported => error.UnsupportedException,
        status.resource_limit => error.ResourceException,
        else => error.InternalException,
    };
}

// Everything below is assertion-side machinery, never referenced by the driver.

const unit_bytes = 4;

// A source that reads no bytes; each unit writes its own ordinal.
const TestSource = struct {
    pub const Exception = error{
        CallException,
        UnsupportedException,
        CapacityException,
        DataException,
        ResourceException,
        InternalException,
    };

    total: u32,
    fail_at: ?u32 = null,
    refuse_at: ?u32 = null,
    overreport: bool = false,
    skip_grant: ?u32 = null,
    decoded: u32 = 0,
    skip_calls: u32 = 0,

    pub fn nextUnit(self: *TestSource, ordinal: u32, staging: []u8) Exception!?Unit {
        if (ordinal >= self.total) return null;
        if (self.refuse_at) |bad| {
            if (ordinal == bad) return error.CapacityException;
        }
        if (staging.len < unit_bytes) return error.CapacityException;
        return .{
            .ordinal = ordinal,
            .input = &.{},
            .output = staging[0..unit_bytes],
            .decoded_size = unit_bytes,
        };
    }

    pub fn decode(self: *TestSource, unit: Unit, scratch: []u8) Exception!usize {
        _ = scratch;
        self.decoded += 1;
        if (self.fail_at) |bad| {
            if (unit.ordinal == bad) return error.DataException;
        }
        @memset(unit.output, @truncate(unit.ordinal));
        if (self.overreport) return unit.output.len + 1;
        return unit.output.len;
    }

    pub fn skipUnits(self: *TestSource, bytes: u64) Exception!u32 {
        self.skip_calls += 1;
        if (self.skip_grant) |grant| return grant;
        return @intCast(bytes / unit_bytes);
    }
};

// A source without skipUnits, so the skip entry must refuse it.
const NoSkipSource = struct {
    pub const Exception = TestSource.Exception;

    pub fn nextUnit(_: *NoSkipSource, ordinal: u32, staging: []u8) Exception!?Unit {
        _ = ordinal;
        _ = staging;
        return null;
    }

    pub fn decode(_: *NoSkipSource, unit: Unit, scratch: []u8) Exception!usize {
        _ = unit;
        _ = scratch;
        return 0;
    }
};

// Runs the wave in reverse on the join, so only ordinal delivery passes.
const ReverseExecutor = struct {
    tasks: [max_lanes]Task = undefined,
    count: usize = 0,
    peak: usize = 0,

    const vtable: executor_prim.Vtable = .{ .run = run };

    pub fn executor(self: *ReverseExecutor) Executor {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn join(self: *ReverseExecutor) Join {
        return .{ .context = self, .wait = wait };
    }

    fn run(ptr: *anyopaque, task: Task) callconv(.c) u32 {
        const self: *ReverseExecutor = @ptrCast(@alignCast(ptr));
        self.tasks[self.count] = task;
        self.count += 1;
        self.peak = @max(self.peak, self.count);
        return status.ok;
    }

    fn wait(ptr: *anyopaque) callconv(.c) u32 {
        const self: *ReverseExecutor = @ptrCast(@alignCast(ptr));
        var index = self.count;
        while (index > 0) {
            index -= 1;
            _ = self.tasks[index].invoke(self.tasks[index].context);
        }
        self.count = 0;
        return status.ok;
    }
};

// An executor that accepts every task and never runs it.
const NoopExecutor = struct {
    const vtable: executor_prim.Vtable = .{ .run = run };

    fn run(_: *anyopaque, _: Task) callconv(.c) u32 {
        return status.ok;
    }
};

// An executor that answers every task with one fixed status word.
fn RefusingExecutor(comptime code: u32) type {
    return struct {
        const vtable: executor_prim.Vtable = .{ .run = run };

        fn run(_: *anyopaque, _: Task) callconv(.c) u32 {
            return code;
        }
    };
}

var serial_context: u8 = 0;

fn serialJoin() Join {
    return .{ .context = &serial_context, .wait = waitNoop };
}

fn waitNoop(_: *anyopaque) callconv(.c) u32 {
    return status.ok;
}

// A join that never confirms a wave.
fn failingJoin() Join {
    return .{ .context = &serial_context, .wait = waitFails };
}

fn waitFails(_: *anyopaque) callconv(.c) u32 {
    return status.resource_limit;
}

fn testLanes(staging: *[max_lanes][64]u8) [max_lanes]Lane {
    var lanes: [max_lanes]Lane = @splat(.{});
    for (&lanes, 0..) |*lane, index| lane.staging = &staging[index];
    return lanes;
}

test "lanes deliver each wave in ordinal order" {
    var staging: [max_lanes][64]u8 = undefined;
    var executor: ReverseExecutor = .{};
    const options: Options = .{ .lanes = 4, .executor = executor.executor(), .join = executor.join() };
    var decoder = try Decoder(TestSource).init(.{ .total = 10 }, options, testLanes(&staging));

    var expected: u32 = 0;
    while (try decoder.next()) |unit| : (expected += 1) {
        try std.testing.expectEqual(expected, unit.ordinal);
        try std.testing.expectEqual(@as(u64, unit_bytes), unit.decoded_size);
        try std.testing.expectEqual(@as(usize, unit_bytes), unit.output.len);
        for (unit.output) |byte| try std.testing.expectEqual(@as(u8, @truncate(expected)), byte);
    }
    try std.testing.expectEqual(@as(u32, 10), expected);
    try std.testing.expectEqual(@as(u32, 10), decoder.source.decoded);
}

test "lanes hold no more than one wave in flight" {
    var staging: [max_lanes][64]u8 = undefined;
    var executor: ReverseExecutor = .{};
    const options: Options = .{ .lanes = 4, .executor = executor.executor(), .join = executor.join() };
    var decoder = try Decoder(TestSource).init(.{ .total = 10 }, options, testLanes(&staging));
    while (try decoder.next()) |_| {}
    try std.testing.expectEqual(@as(usize, 4), executor.peak);
}

test "lanes decode serially on the default options" {
    var staging: [max_lanes][64]u8 = undefined;
    var decoder = try Decoder(TestSource).init(.{ .total = 3 }, .{}, testLanes(&staging));
    var expected: u32 = 0;
    while (try decoder.next()) |unit| : (expected += 1) {
        try std.testing.expectEqual(expected, unit.ordinal);
        for (unit.output) |byte| try std.testing.expectEqual(@as(u8, @truncate(expected)), byte);
    }
    try std.testing.expectEqual(@as(u32, 3), expected);
    try std.testing.expectEqual(@as(u32, 3), decoder.source.decoded);
}

test "lanes stay on the first failure once it lands" {
    var staging: [max_lanes][64]u8 = undefined;
    var decoder = try Decoder(TestSource).init(
        .{ .total = 8, .fail_at = 2 },
        .{ .lanes = 2, .join = serialJoin() },
        testLanes(&staging),
    );

    try std.testing.expectEqual(@as(u32, 0), (try decoder.next()).?.ordinal);
    try std.testing.expectEqual(@as(u32, 1), (try decoder.next()).?.ordinal);
    try std.testing.expectError(error.DataException, decoder.next());
    // A retry repeats the failure instead of advancing.
    try std.testing.expectError(error.DataException, decoder.next());
    // The wave decoded unit 3 before the failed unit 2 was delivered, and
    // no retry decoded another byte.
    try std.testing.expectEqual(@as(u32, 4), decoder.source.decoded);
}

test "lanes skip whole units without decoding a byte" {
    var staging: [max_lanes][64]u8 = undefined;
    var decoder = try Decoder(TestSource).init(
        .{ .total = 10 },
        .{ .lanes = 2, .join = serialJoin() },
        testLanes(&staging),
    );
    try decoder.skip(3 * unit_bytes);
    try std.testing.expectEqual(@as(u32, 1), decoder.source.skip_calls);
    try std.testing.expectEqual(@as(u32, 0), decoder.source.decoded);

    const first = (try decoder.next()).?;
    try std.testing.expectEqual(@as(u32, 3), first.ordinal);
    for (first.output) |byte| try std.testing.expectEqual(@as(u8, 3), byte);
    // The wave after the skip holds two units.
    try std.testing.expectEqual(@as(u32, 2), decoder.source.decoded);
}

test "lanes refuse every skip outside its contract" {
    // Mid-wave: a skip must wait for the drain.
    {
        var staging: [max_lanes][64]u8 = undefined;
        var decoder = try Decoder(TestSource).init(
            .{ .total = 4 },
            .{ .lanes = 2, .join = serialJoin() },
            testLanes(&staging),
        );
        _ = (try decoder.next()).?;
        try std.testing.expectError(error.CallException, decoder.skip(unit_bytes));
    }
    // A source without skipUnits is refused at the entry.
    {
        var staging: [max_lanes][64]u8 = undefined;
        var decoder = try Decoder(NoSkipSource).init(.{}, .{}, testLanes(&staging));
        try std.testing.expectError(error.UnsupportedException, decoder.skip(unit_bytes));
    }
    // A grant that overflows the submission counter is a resource fault.
    {
        var staging: [max_lanes][64]u8 = undefined;
        var decoder = try Decoder(TestSource).init(
            .{ .total = 2, .skip_grant = std.math.maxInt(u32) },
            .{},
            testLanes(&staging),
        );
        try decoder.skip(unit_bytes);
        try std.testing.expectEqual(@as(u32, 1), decoder.source.skip_calls);
        try std.testing.expectError(error.ResourceException, decoder.skip(unit_bytes));
    }
}

test "lanes refuse concurrent submission without a join" {
    var staging: [max_lanes][64]u8 = undefined;
    // Several lanes without a join leave tasks unobserved.
    try std.testing.expectError(
        error.UnsupportedException,
        Decoder(TestSource).init(.{ .total = 4 }, .{ .lanes = 2 }, testLanes(&staging)),
    );
    // An executor without a join strands its slots, even on one lane.
    var executor: ReverseExecutor = .{};
    try std.testing.expectError(
        error.UnsupportedException,
        Decoder(TestSource).init(
            .{ .total = 1 },
            .{ .lanes = 1, .executor = executor.executor() },
            testLanes(&staging),
        ),
    );
}

test "lanes bound the lane count at the wave size" {
    var staging: [max_lanes][64]u8 = undefined;
    try std.testing.expectError(
        error.CallException,
        Decoder(TestSource).init(.{ .total = 4 }, .{ .lanes = 0 }, testLanes(&staging)),
    );
    try std.testing.expectError(
        error.CallException,
        Decoder(TestSource).init(.{ .total = 4 }, .{ .lanes = max_lanes + 1 }, testLanes(&staging)),
    );
    // The bound itself is a legal wave.
    var decoder = try Decoder(TestSource).init(
        .{ .total = 8 },
        .{ .lanes = max_lanes, .join = serialJoin() },
        testLanes(&staging),
    );
    try std.testing.expectEqual(@as(u32, 0), (try decoder.next()).?.ordinal);
}

test "lanes join the running wave before a refusal escapes" {
    var staging: [max_lanes][64]u8 = undefined;
    var executor: ReverseExecutor = .{};
    const options: Options = .{ .lanes = 2, .executor = executor.executor(), .join = executor.join() };
    var decoder = try Decoder(TestSource).init(
        .{ .total = 4, .refuse_at = 1 },
        options,
        testLanes(&staging),
    );

    // Unit 0 is already submitted when unit 1 refuses, so the join must
    // run it before the error escapes.
    try std.testing.expectError(error.CapacityException, decoder.next());
    try std.testing.expectEqual(@as(u32, 1), decoder.source.decoded);
    // The refusal is sticky: a retry repeats it instead of re-entering.
    try std.testing.expectError(error.CapacityException, decoder.next());
    try std.testing.expectEqual(@as(u32, 1), decoder.source.decoded);
}

test "lanes translate executor status codes into exceptions" {
    var staging: [max_lanes][64]u8 = undefined;
    var context: u8 = 0;
    // A resource refusal maps to the resource exception.
    {
        const options: Options = .{
            .lanes = 1,
            .executor = .{ .ptr = &context, .vtable = &RefusingExecutor(status.resource_limit).vtable },
            .join = serialJoin(),
        };
        var decoder = try Decoder(TestSource).init(.{ .total = 1 }, options, testLanes(&staging));
        try std.testing.expectError(error.ResourceException, decoder.next());
    }
    // An unsupported refusal maps to the unsupported exception.
    {
        const options: Options = .{
            .lanes = 1,
            .executor = .{ .ptr = &context, .vtable = &RefusingExecutor(status.unsupported).vtable },
            .join = serialJoin(),
        };
        var decoder = try Decoder(TestSource).init(.{ .total = 1 }, options, testLanes(&staging));
        try std.testing.expectError(error.UnsupportedException, decoder.next());
    }
    // Any other status word can carry no error, so it is an internal fault.
    {
        const options: Options = .{
            .lanes = 1,
            .executor = .{ .ptr = &context, .vtable = &RefusingExecutor(0xbad1dea).vtable },
            .join = serialJoin(),
        };
        var decoder = try Decoder(TestSource).init(.{ .total = 1 }, options, testLanes(&staging));
        try std.testing.expectError(error.InternalException, decoder.next());
    }
}

test "lanes answer contract faults with the internal exception" {
    // A source that reports more than it wrote is faulty.
    {
        var staging: [max_lanes][64]u8 = undefined;
        var decoder = try Decoder(TestSource).init(
            .{ .total = 1, .overreport = true },
            .{},
            testLanes(&staging),
        );
        try std.testing.expectError(error.InternalException, decoder.next());
        try std.testing.expectError(error.InternalException, decoder.next());
    }
    // A task that neither produced nor failed never ran.
    {
        var staging: [max_lanes][64]u8 = undefined;
        var context: u8 = 0;
        const options: Options = .{
            .lanes = 1,
            .executor = .{ .ptr = &context, .vtable = &NoopExecutor.vtable },
            .join = serialJoin(),
        };
        var decoder = try Decoder(TestSource).init(.{ .total = 1 }, options, testLanes(&staging));
        try std.testing.expectError(error.InternalException, decoder.next());
    }
    // A canceled join leaves the wave unconfirmed.
    {
        var staging: [max_lanes][64]u8 = undefined;
        var decoder = try Decoder(TestSource).init(
            .{ .total = 1 },
            .{ .lanes = 1, .join = failingJoin() },
            testLanes(&staging),
        );
        try std.testing.expectError(error.InternalException, decoder.next());
        // The unit decoded; only the confirmation was refused.
        try std.testing.expectEqual(@as(u32, 1), decoder.source.decoded);
    }
}
