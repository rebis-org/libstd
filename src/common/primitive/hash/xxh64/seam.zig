const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

pub const Onprem = onprem.XxHash64;
pub const Offprem = std.hash.XxHash64;

pub const XxHash64 = seam.ValueHash(options.xxh64_impl, Onprem, Offprem);
