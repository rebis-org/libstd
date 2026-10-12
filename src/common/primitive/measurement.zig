const std = @import("std");

const failure = @import("failure.zig");
const tee = @import("tee.zig");

const Failure = failure.Failure;

pub const Counter = tee.CountingTee(.{});

// A measured byte count as an addressable length, so no decoder repeats the
// narrowing and its resource-limit policy.
pub fn measuredLength(counter: *const Counter) Failure!usize {
    return std.math.cast(usize, counter.written()) orelse error.ResourceFailure;
}
