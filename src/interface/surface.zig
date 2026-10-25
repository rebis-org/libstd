const span = @import("span.zig");

const Exception = span.Exception;

// Plain extern structs: no vtable crosses the ABI.
pub const Surface = extern struct {
    ptr: ?[*]u8,
    len: u64,
};

pub const ConstSurface = extern struct {
    ptr: ?[*]const u8,
    len: u64,
};

// A failed crossing reports the boundary's own vocabulary; the kernel above
// owns those frozen values, so restating them here drifts.
pub const status_ok: u32 = 0;
pub const status_invalid_call: u32 = 1;
pub const status_resource_limit: u32 = 7;

fn statusFor(exception: Exception) u32 {
    return switch (exception) {
        error.CallException => status_invalid_call,
        error.ResourceException => status_resource_limit,
    };
}

pub fn copy(sink_surface: Surface, origin_surface: ConstSurface) callconv(.c) u32 {
    const sink = span.mutSpan(sink_surface.ptr, sink_surface.len) catch |exception| return statusFor(exception);
    const origin = span.constSpan(origin_surface.ptr, origin_surface.len) catch |exception| return statusFor(exception);
    span.requireDisjoint(.{ .ptr = sink.ptr, .len = sink.len }, origin, "surface copy regions overlap.");
    const limit = @min(sink.len, origin.len);
    sink.write(0, origin.read(0, limit));
    return status_ok;
}
