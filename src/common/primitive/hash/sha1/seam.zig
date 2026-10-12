const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const onprem = @import("onprem.zig");

pub const Offprem = std.crypto.hash.Sha1;
pub const Onprem = onprem.Sha1;

pub const Sha1 = seam.Digest(options.sha1_impl, Onprem, Offprem);
