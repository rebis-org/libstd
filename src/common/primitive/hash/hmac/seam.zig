const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");
const sha1_onprem = @import("../sha1/onprem.zig");
const sha256_onprem = @import("../sha256/onprem.zig");

fn HmacPair(comptime ShaOnprem: type, comptime ShaOffprem: type) type {
    return struct {
        pub const Onprem = onprem.Hmac(ShaOnprem);
        pub const Offprem = std.crypto.auth.hmac.Hmac(ShaOffprem);
        pub const Mac = seam.Mac(options.hmac_impl, Onprem, Offprem);
    };
}

const sha1_pair = HmacPair(sha1_onprem.Sha1, std.crypto.hash.Sha1);
const sha256_pair = HmacPair(sha256_onprem.Sha256, std.crypto.hash.sha2.Sha256);

pub const HmacSha1Onprem = sha1_pair.Onprem;
pub const HmacSha1Offprem = sha1_pair.Offprem;
pub const HmacSha256Onprem = sha256_pair.Onprem;
pub const HmacSha256Offprem = sha256_pair.Offprem;

pub const HmacSha1 = sha1_pair.Mac;
pub const HmacSha256 = sha256_pair.Mac;
