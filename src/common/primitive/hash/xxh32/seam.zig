const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

pub const Onprem = onprem.XxHash32;
pub const Offprem = std.hash.XxHash32;

pub const XxHash32 = seam.ValueHash(options.xxh32_impl, Onprem, Offprem);
