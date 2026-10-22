const builtin = @import("builtin");
const std = @import("std");

// Zig ships no libc for these ABIs: android and ohos lack any port, and the
// msvc ABI keeps Microsoft CRT out of the library, so archives stay
// toolchain-independent and consumers bring their own runtime.
pub const has_libc: bool = switch (builtin.target.abi) {
    .android, .androideabi, .ohos, .ohoseabi, .msvc, .itanium => false,
    else => true,
};

// std.debug's default handler instantiates std.Io.Threaded, which fails to
// compile for the Apple embedded targets (ziglang/zig#37061, unreleased).
// A raw stderr write keeps every diagnostic path off that handler.
extern "kernel32" fn GetStdHandle(n_std_handle: c_ulong) callconv(.winapi) std.os.windows.HANDLE;
extern "kernel32" fn WriteFile(
    file: std.os.windows.HANDLE,
    buffer: [*]const u8,
    bytes_to_write: u32,
    bytes_written: ?*u32,
    overlapped: ?*anyopaque,
) callconv(.winapi) std.os.windows.BOOL;

// The standard-error pseudo handle; kernel32 resolves it per call, so no
// handle opens, tracks, or closes here.
const std_error_handle: c_ulong = @bitCast(@as(i32, -12));

pub fn writeStderr(bytes: []const u8) void {
    // Windows stderr is a handle, not an fd: WriteFile takes the pseudo
    // handle, where std.c.write would need a real one.
    if (comptime builtin.target.os.tag == .windows) {
        const handle = GetStdHandle(std_error_handle);
        if (handle == std.os.windows.INVALID_HANDLE_VALUE) return;
        _ = WriteFile(handle, bytes.ptr, @intCast(bytes.len), null, null);
        return;
    }
    if (comptime has_libc) {
        _ = std.c.write(2, bytes.ptr, bytes.len);
        return;
    }
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.write(2, bytes.ptr, bytes.len);
    }
}
