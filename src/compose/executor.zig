// The executor contract is defined one layer down in common/executor.zig, so the grammar layer adopts it without importing compose.

const shared = @import("../common/executor.zig");
const envelope = @import("../kernel/envelope.zig");

pub const Executor = shared.Executor;
pub const Task = shared.Task;
pub const Vtable = shared.Vtable;
pub const inline_executor = shared.inline_executor;
pub const status = shared.status;

// The substrate cannot import the kernel, so it copies the status values; drift would break the C boundary.

comptime {
    if (shared.status.ok != envelope.Status.ok) @compileError("common executor status.ok drifted from the kernel vocabulary.");
    if (shared.status.unsupported != envelope.Status.unsupported) @compileError("common executor status.unsupported drifted from the kernel vocabulary.");
    if (shared.status.resource_limit != envelope.Status.resource_limit) @compileError("common executor status.resource_limit drifted from the kernel vocabulary.");
}
