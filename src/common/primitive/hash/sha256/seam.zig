const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

pub const Onprem = onprem.Sha256;
pub const Offprem = std.crypto.hash.sha2.Sha256;

pub const Sha256 = seam.Digest(options.sha256_impl, Onprem, Offprem);
