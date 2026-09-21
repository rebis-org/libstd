// Unit-test entry for the grammar layer, wired into `zig build unit`. The
// module root has to sit at src/ so the grammar's `../common` imports stay
// inside the module path.
test {
    _ = @import("grammar/rar.zig");
}
