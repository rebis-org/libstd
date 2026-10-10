const std = @import("std");

const failure = @import("failure.zig");
const Failure = failure.Failure;

fn add(comptime T: type, augend: T, addend: T) Failure!T {
    return std.math.add(T, augend, addend) catch error.ResourceLimit;
}

pub fn addUsize(left: usize, right: usize) Failure!usize {
    return add(usize, left, right);
}

pub fn addU64(left: u64, right: u64) Failure!u64 {
    return add(u64, left, right);
}

pub fn slice(bytes: []const u8, offset: u64, length: u64) Failure![]const u8 {
    const start = std.math.cast(usize, offset) orelse return error.ResourceLimit;
    const count = std.math.cast(usize, length) orelse return error.ResourceLimit;
    if (start > bytes.len or count > bytes.len - start) return error.InvalidData;
    return bytes[start..][0..count];
}
