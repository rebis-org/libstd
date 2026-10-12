const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const onprem = @import("onprem.zig");

pub const Offprem = std.hash.XxHash64;
pub const Onprem = onprem.XxHash64;

pub const XxHash64 = seam.Hash(options.xxh64_impl, Onprem, Offprem);
