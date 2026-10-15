// Unit-test entry for the volume layer, wired into `zig build unit`. The
// module root has to sit at src/ so the volume's `../common` imports stay
// inside the module path.
test {
    _ = @import("./volume/iso/offprem.zig");
    _ = @import("./volume/iso/onprem.zig");
    _ = @import("./volume/squashfs/offprem.zig");
    _ = @import("./volume/squashfs/onprem.zig");
}
