const threaded = @import("compose/threaded.zig");

// These targets cannot build the standard thread support, so the gate keeps
// the executor out.
comptime {
    if (threaded.supported) @compileError("the threaded executor must stay gated off on this target.");
}

pub export fn stdk_threaded_gate() void {}
