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
        var prf = Prf.init(password);
        prf.update(salt);
        var counter_be: [4]u8 = undefined;
        std.mem.writeInt(u32, &counter_be, block_counter, .big);
        prf.update(&counter_be);
        var block_mac: [Prf.mac_length]u8 = prf.finalResult();
        var xor_acc = block_mac;
        var round: u32 = 1;
        while (round < rounds) : (round += 1) {
            var iter = Prf.init(password);
            iter.update(&block_mac);
            block_mac = iter.finalResult();
            for (&xor_acc, block_mac) |*byte, other| byte.* ^= other;
        }
        const copy_len = @min(Prf.mac_length, dk.len - offset);
        @memcpy(dk[offset..][0..copy_len], xor_acc[0..copy_len]);
        offset += copy_len;
    }
}

test "pbkdf2 onprem matches the std oracle" {
    const hmac_onprem = @import("../hmac/onprem.zig");
    const sha256_onprem = @import("../sha256/onprem.zig");
    const Prf = hmac_onprem.Hmac(sha256_onprem.Sha256);
    var dk_ours: [70]u8 = undefined;
    var dk_theirs: [70]u8 = undefined;
    for ([_]u32{ 1, 2, 7, 1000 }) |rounds| {
        try pbkdf2(&dk_ours, "password", "salt", rounds, Prf);
        try std.crypto.pwhash.pbkdf2(&dk_theirs, "password", "salt", rounds, std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256));
        try std.testing.expectEqualSlices(u8, &dk_theirs, &dk_ours);
    }
    try std.testing.expectError(error.WeakParameters, pbkdf2(&dk_ours, "password", "salt", 0, Prf));
}
