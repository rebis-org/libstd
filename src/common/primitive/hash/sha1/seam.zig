const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

pub const Implementation = enum { onprem, offprem };
pub const Sha1 = switch (options.sha1_impl) {
    .onprem => onprem.Sha1,
    .offprem => std.crypto.hash.Sha1,
};
