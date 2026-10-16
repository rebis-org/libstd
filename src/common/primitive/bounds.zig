const std = @import("std");

const exception = @import("exception.zig");

const Exception = exception.Exception;

fn add(comptime T: type, augend: T, addend: T) Exception!T {
    return std.math.add(T, augend, addend) catch error.ResourceException;
}

pub fn addUsize(left: usize, right: usize) Exception!usize {
    return add(usize, left, right);
}

pub fn addU64(left: u64, right: u64) Exception!u64 {
    return add(u64, left, right);
}

pub fn slice(bytes: []const u8, offset: u64, length: u64) Exception![]const u8 {
    const start = std.math.cast(usize, offset) orelse return error.ResourceException;
    const count = std.math.cast(usize, length) orelse return error.ResourceException;
    if (start > bytes.len or count > bytes.len - start) return error.DataException;
    return bytes[start..][0..count];
}

// Archive members must stay inside the destination directory: no empty
// name, no absolute path, no backslash separator, no parent traversal.
pub fn isAbsoluteOrTraversal(name: []const u8) bool {
    if (name.len == 0) return true;
    if (name[0] == '/') return true;
    if (std.mem.findScalar(u8, name, '\\') != null) return true;
    var segments = std.mem.splitScalar(u8, name, '/');
    while (segments.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) return true;
    }
    return false;
}
