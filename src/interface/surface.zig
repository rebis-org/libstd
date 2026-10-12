const span = @import("span.zig");

const Failure = span.Failure;

// Plain extern structs: no vtable crosses the ABI.
pub const Surface = extern struct {
    ptr: ?[*]u8,
    len: u64,
};

pub const ConstSurface = extern struct {
    ptr: ?[*]const u8,
    len: u64,
};

// A crossing that fails reports the boundary's own vocabulary.
// The interface sits below the kernel owning those values; restating them
// would drift from the frozen wire numbers.
pub const status_ok: u32 = 0;
pub const status_invalid_call: u32 = 1;
pub const status_resource_limit: u32 = 7;

fn statusFor(failure: Failure) u32 {
    return switch (failure) {
        error.CallFailure => status_invalid_call,
        error.ResourceFailure => status_resource_limit,
    };
}

pub fn copy(sink_surface: Surface, origin_surface: ConstSurface) callconv(.c) u32 {
    const sink = span.mutSpan(sink_surface.ptr, sink_surface.len) catch |failure| return statusFor(failure);
    const origin = span.constSpan(origin_surface.ptr, origin_surface.len) catch |failure| return statusFor(failure);
    span.requireDisjoint(.{ .ptr = sink.ptr, .len = sink.len }, origin, "surface copy regions overlap.");
    const limit = @min(sink.len, origin.len);
    sink.write(0, origin.read(0, limit));
    return status_ok;
}
