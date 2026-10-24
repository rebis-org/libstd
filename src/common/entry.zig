const std = @import("std");

const bounds = @import("primitive/bounds.zig");
const exception_prim = @import("primitive/exception.zig");

const Exception = exception_prim.Exception;

// The entry vocabulary every container shares: what a write request carries and
// what a read projection reports when it has nothing of its own to add. A
// format declares its own struct only where its wire carries more.
pub const Entry = struct {
    name: []const u8,
    data: []const u8 = &.{},
    link_name: []const u8 = &.{},
    mode: u32 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    modification_time: u64 = 0,
    typeflag: u8 = '0',
    devmajor: u32 = 0,
    devminor: u32 = 0,
    rdevmajor: u32 = 0,
    rdevminor: u32 = 0,
    ino: u32 = 0,
    nlink: u32 = 1,
};

// A reader that addresses entries by ordinal and reports only their length.
pub const Sized = struct {
    size: u64,
    ordinal: u64,
};

// The rule every container enforces before it writes a name: nothing escapes
// the destination, and the name is a C string on the wire.
// A path component that names something: empty and dot segments name nothing.
pub fn isComponent(name: []const u8) bool {
    return name.len != 0 and !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..");
}

// The trailing component of a path, or null when the path ends in a separator.
pub fn leafName(name: []const u8) ?[]const u8 {
    var index: usize = name.len;
    while (index > 0) {
        index -= 1;
        if (name[index] == '/') return if (index + 1 < name.len) name[index + 1 ..] else null;
    }
    return name;
}

pub fn validateName(name: []const u8) Exception!void {
    if (std.mem.findScalar(u8, name, 0) != null) return error.CallException;
    if (bounds.isAbsoluteOrTraversal(name)) return error.CallException;
}

test "entry name rule rejects escaping and embedded terminators" {
    try validateName("dir/file.txt");
    try std.testing.expectError(error.CallException, validateName(""));
    try std.testing.expectError(error.CallException, validateName("/etc/passwd"));
    try std.testing.expectError(error.CallException, validateName("a/../../b"));
    try std.testing.expectError(error.CallException, validateName("a\\b"));
    try std.testing.expectError(error.CallException, validateName("a\x00b"));
}
