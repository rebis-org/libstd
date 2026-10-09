const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

pub const Implementation = enum { onprem, offprem };
pub const Sha256 = switch (options.sha256_impl) {
    .onprem => onprem.Sha256,
    .offprem => std.crypto.hash.sha2.Sha256,
};
