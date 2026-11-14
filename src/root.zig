const std = @import("std");

const diagnostic = @import("interface").diagnostic;

const invoke = @import("compose/call.zig").invoke;
const Call = @import("kernel/envelope.zig").Call;

// The default handler needs libc-backed Io; panics use the diagnostic
// channel and trap so libc-less ABIs keep a deterministic failure.
pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        _ = first_trace_addr;
        // The write is per-OS (kernel32 on Windows, syscalls on libc-less
        // linux ABIs); only the abort needs a C runtime.
        diagnostic.writeStderr(msg);
        diagnostic.writeStderr("\n");
        if (comptime diagnostic.has_libc) {
            std.c.abort();
            unreachable;
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
