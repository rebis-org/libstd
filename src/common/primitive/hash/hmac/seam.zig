const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const sha1 = @import("../sha1/seam.zig");
const sha256 = @import("../sha256/seam.zig");

pub const Implementation = enum { onprem, offprem };

pub fn Hmac(comptime H: type) type {
    return switch (options.hmac_impl) {
        .onprem => onprem.Hmac(H),
        .offprem => std.crypto.auth.hmac.Hmac(H),
    };
}

pub const HmacSha1 = Hmac(sha1.Sha1);
pub const HmacSha256 = Hmac(sha256.Sha256);
