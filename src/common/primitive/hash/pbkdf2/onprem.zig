const std = @import("std");

// RFC 2898.

pub const WeakParametersError = error{WeakParameters};
pub const OutputTooLongError = error{OutputTooLong};

pub fn pbkdf2(dk: []u8, password: []const u8, salt: []const u8, rounds: u32, comptime Prf: type) (WeakParametersError || OutputTooLongError)!void {
    if (rounds < 1) return error.WeakParameters;
    if (dk.len / Prf.mac_length >= std.math.maxInt(u32)) return error.OutputTooLong;

    var block_counter: u32 = 1;
    var offset: usize = 0;
    while (offset < dk.len) : (block_counter +%= 1) {
        // The password pads never change across rounds, so bind once per block.
        const base = Prf.init(password);
        var first = base;
        first.update(salt);
        var counter_be: [4]u8 = undefined;
        std.mem.writeInt(u32, &counter_be, block_counter, .big);
        first.update(&counter_be);
        var block_mac: [Prf.mac_length]u8 = first.finalResult();
        var xor_acc = block_mac;
        var round: u32 = 1;
        while (round < rounds) : (round += 1) {
            var iter = base;
            iter.update(&block_mac);
            block_mac = iter.finalResult();
            for (&xor_acc, block_mac) |*byte, other| byte.* ^= other;
        }
        const copy_len = @min(Prf.mac_length, dk.len - offset);
        @memcpy(dk[offset..][0..copy_len], xor_acc[0..copy_len]);
        offset += copy_len;
    }
}

test "pbkdf2 onprem splits its output blocks and rejects zero rounds" {
    const hmac_onprem = @import("../hmac/onprem.zig");
    const sha256_onprem = @import("../sha256/onprem.zig");
    const sha1_onprem = @import("../sha1/onprem.zig");
    const testing = std.testing;

    const Prf = hmac_onprem.Hmac(sha256_onprem.Sha256);
    const PrfSha1 = hmac_onprem.Hmac(sha1_onprem.Sha1);

    // RFC 6070 pins the sha1 ladder at one and two rounds.
    var dk20: [20]u8 = undefined;
    try pbkdf2(&dk20, "password", "salt", 1, PrfSha1);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6 }, &dk20);
    try pbkdf2(&dk20, "password", "salt", 2, PrfSha1);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57 }, &dk20);

    // A 25-byte output spills five bytes into the second block.
    var dk25: [25]u8 = undefined;
    try pbkdf2(&dk25, "password", "salt", 4096, PrfSha1);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1, 0x2e, 0x46, 0x3f, 0x6c, 0x4c }, &dk25);

    // RFC 7914 pins two full sha256 blocks from one password.
    var dk64: [64]u8 = undefined;
    try pbkdf2(&dk64, "passwd", "salt", 1, Prf);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
        0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
        0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
        0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5, 0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
    }, &dk64);

    // The stdlib sweep keeps round-count agreement over a ragged
    // 70-byte output: two full blocks plus a six-byte tail.
    var dk_ours: [70]u8 = undefined;
    var dk_theirs: [70]u8 = undefined;
    for ([_]u32{ 1, 2, 7, 1000 }) |rounds| {
        try pbkdf2(&dk_ours, "password", "salt", rounds, Prf);
        try std.crypto.pwhash.pbkdf2(&dk_theirs, "password", "salt", rounds, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256));
        try testing.expectEqualSlices(u8, &dk_theirs, &dk_ours);
    }

    // Zero rounds never derive anything.
    try testing.expectError(error.WeakParameters, pbkdf2(&dk_ours, "password", "salt", 0, Prf));
}
