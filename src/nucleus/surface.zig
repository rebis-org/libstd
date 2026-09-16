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
        error.InvalidCall => @intFromEnum(Status.invalid_call),
        error.ResourceLimit => @intFromEnum(Status.resource_limit),
        error.InsufficientCapacity, error.InvalidData => @intFromEnum(Status.invalid_call),
    };
}

// Source/destination aliasing traps as overlap (in-place is a different verb);
// null with nonzero length returns a status, provenance violations trap.
pub fn nucleusCopy(output: Surface, input: ConstSurface) callconv(.c) u32 {
    const destination = span.mutSpan(output.ptr, output.len) catch |failure| return statusFor(failure);
    const source = span.constSpan(input.ptr, input.len) catch |failure| return statusFor(failure);
    span.requireDisjoint(.{ .ptr = destination.ptr, .len = destination.len }, source, "Surface copy regions overlap.");
    const limit = @min(destination.len, source.len);
    destination.write(0, source.read(0, limit));
    return @intFromEnum(Status.ok);
}
