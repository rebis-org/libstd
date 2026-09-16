const invoke = @import("compose/call.zig").invoke;
const Call = @import("kernel/envelope.zig").Call;

// Default wiring only; callers may assemble or bypass these pieces.
comptime {
    _ = @import("compose/api.zig");
}

pub export fn stdk_call(call: ?*Call) callconv(.c) u32 {
    return invoke(call);
}
