const builtin = @import("builtin");
const std = @import("std");

const invoke = @import("compose/call.zig").invoke;
const Call = @import("kernel/envelope.zig").Call;

// Zig provides no libc for the android and ohos ABIs, so naming std.c fails there.
const has_libc: bool = switch (builtin.target.abi) {
    .android, .androideabi, .ohos, .ohoseabi => false,
    else => true,
};

// Keep panics off std.debug's default handler: its debug_io instantiates
// std.Io.Threaded, which does not compile for iOS targets on 0.17.0. The
// library traps like every other contract violation.
pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        _ = first_trace_addr;
        if (comptime has_libc) {
            // Raw write keeps std.debug's debug_io, and its std.Io.Threaded, out.
            _ = std.c.write(2, msg.ptr, msg.len);
            _ = std.c.write(2, "\n", 1);
            std.c.abort();
        }
        // No libc to name: the contract violation still traps, without a message.
        @trap();
    }
}.panicFn);

// Default wiring only. Callers may assemble or bypass these pieces.
comptime {
    _ = @import("compose/api.zig");
}

pub export fn stdk_call(call: ?*Call) callconv(.c) u32 {
    return invoke(call);
}
