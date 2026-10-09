const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

pub const Implementation = enum { onprem, offprem };

pub const XxHash32 = switch (options.xxh32_impl) {
    .onprem => onprem.XxHash32,
    .offprem => std.hash.XxHash32,
};
