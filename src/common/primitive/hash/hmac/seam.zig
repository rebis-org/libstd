const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");
const sha1_onprem = @import("../sha1/onprem.zig");
const sha256_onprem = @import("../sha256/onprem.zig");

pub const HmacSha1Onprem = onprem.Hmac(sha1_onprem.Sha1);
pub const HmacSha1Offprem = std.crypto.auth.hmac.Hmac(std.crypto.hash.Sha1);
pub const HmacSha256Onprem = onprem.Hmac(sha256_onprem.Sha256);
pub const HmacSha256Offprem = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256);

pub const HmacSha1 = seam.Mac(options.hmac_impl, HmacSha1Onprem, HmacSha1Offprem);
pub const HmacSha256 = seam.Mac(options.hmac_impl, HmacSha256Onprem, HmacSha256Offprem);
