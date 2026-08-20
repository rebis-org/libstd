const std = @import("std");

const failure_prim = @import("failure.zig");
const Failure = failure_prim.Failure;

pub fn add(left: usize, right: usize) Failure!usize {
    return std.math.add(usize, left, right) catch error.ResourceLimit;
}

pub fn add64(left: u64, right: u64) Failure!u64 {
    return std.math.add(u64, left, right) catch error.ResourceLimit;
}

pub fn slice(data: []const u8, offset: u64, length: u64) Failure![]const u8 {
    const start = std.math.cast(usize, offset) orelse return error.ResourceLimit;
    const count = std.math.cast(usize, length) orelse return error.ResourceLimit;
    if (start > data.len or count > data.len - start) return error.InvalidData;
    return data[start..][0..count];
}
