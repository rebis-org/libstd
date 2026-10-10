const span = @import("span.zig");

const Failure = span.Failure;

// Plain extern structs: no vtable crosses the ABI. Not exported: the ABI gate
// pins stdk_call as the sole export.
pub const Surface = extern struct {
    ptr: ?[*]u8,
    len: u64,
};

pub const ConstSurface = extern struct {
    ptr: ?[*]const u8,
    len: u64,
};

pub const Status = enum(u32) {
    ok = 0,
    invalid_call = 1,
    resource_limit = 2,
    _,
};

fn statusFor(failure: Failure) u32 {
    return switch (failure) {
        error.InvalidCall => @backingInt(Status.invalid_call),
        error.ResourceLimit => @backingInt(Status.resource_limit),
        error.InsufficientCapacity, error.InvalidData => @backingInt(Status.invalid_call),
    };
}

// Source/destination aliasing traps as overlap.
pub fn copy(destination: Surface, source: ConstSurface) callconv(.c) u32 {
    const sink = span.mutSpan(destination.ptr, destination.len) catch |failure| return statusFor(failure);
    const origin = span.constSpan(source.ptr, source.len) catch |failure| return statusFor(failure);
    span.requireDisjoint(.{ .ptr = sink.ptr, .len = sink.len }, origin, "surface copy regions overlap.");
    const limit = @min(sink.len, origin.len);
    sink.write(0, origin.read(0, limit));
    return @backingInt(Status.ok);
}
