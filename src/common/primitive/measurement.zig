const std = @import("std");

const exception = @import("exception.zig");
const tee = @import("tee.zig");

const Exception = exception.Exception;

pub const Counter = tee.CountingTee(.{});

// A measured byte count as an addressable length, so no decoder repeats the
// narrowing and its resource-limit policy.
pub fn measuredLength(counter: *const Counter) Exception!usize {
    return std.math.cast(usize, counter.written()) orelse error.ResourceException;
}
