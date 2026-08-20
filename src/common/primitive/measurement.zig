const std = @import("std");

const tee = @import("tee.zig");

pub const Counter = tee.CountingTee(false, false);
