const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

pub const Onprem = onprem.Sha1;
pub const Offprem = std.crypto.hash.Sha1;

pub const Sha1 = seam.Digest(options.sha1_impl, Onprem, Offprem);
