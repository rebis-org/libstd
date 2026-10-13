const builtin = @import("builtin");
const std = @import("std");

// Zig ships no libc for the android and ohos ABIs, so naming std.c fails there.
pub const has_libc: bool = switch (builtin.target.abi) {
    .android, .androideabi, .ohos, .ohoseabi => false,
    else => true,
};

// std.debug's default handler instantiates std.Io.Threaded, which fails to
// compile for the Apple embedded targets (ziglang/zig#37061, unreleased).
// A raw fd write keeps every diagnostic path off that handler.
pub fn writeStderr(bytes: []const u8) void {
    if (comptime has_libc) {
        _ = std.c.write(2, bytes.ptr, bytes.len);
        return;
    }
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.write(2, bytes.ptr, bytes.len);
    }
}
