const std = @import("std");

const diagnostic = @import("interface").diagnostic;

const invoke = @import("compose/call.zig").invoke;
const Call = @import("kernel/envelope.zig").Call;

// Keep panics off std.debug's default handler: its debug_io instantiates
// std.Io.Threaded, which fails to compile for the Apple embedded targets.
// Upstream tracked as ziglang/zig#37061, fixed on master but unreleased.
// The library traps like every other contract violation.
pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        _ = first_trace_addr;
        // The write is per-OS (kernel32 on Windows, the syscall on linux
        // ABIs without libc); only the abort needs a C runtime.
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
