const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

pub const Implementation = enum { onprem, offprem };

pub const XxHash64 = switch (options.xxh64_impl) {
    .onprem => onprem.XxHash64,
    .offprem => std.hash.XxHash64,
};
