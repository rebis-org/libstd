const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const onprem = @import("onprem.zig");

pub const Offprem = std.hash.XxHash32;
pub const Onprem = onprem.XxHash32;

pub const XxHash32 = seam.Hash(options.xxh32_impl, Onprem, Offprem);
