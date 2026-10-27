// The module roots here so the harness's cross-directory imports stay
// inside the module path. The eager reference is required: without it the
// lazy pub const leaves decode.zig unanalyzed and the runner discovers none
// of its tests.
pub const decode = @import("testing/fuzz/decode.zig");

comptime {
    _ = decode;
}
