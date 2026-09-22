// Unit-test entry for the grammar layer, wired into `zig build unit`. The
// module root has to sit at src/ so the grammar's `../common` imports stay
// inside the module path.
test {
    _ = @import("grammar/rar.zig");
    // The writer's test block covers create→inspect→decode round trips,
    // including zero-length entries; without this reference the aggregate
    // root compiles the facade only and the block never runs.
    _ = @import("grammar/rar/writer.zig");
}
