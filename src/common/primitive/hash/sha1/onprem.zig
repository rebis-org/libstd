const std = @import("std");

const seam = @import("seam");

const merkle = @import("../merkle.zig");

// FIPS 180-1.
// RAR4's KDF and WinZIP AE-2 authentication require SHA-1, and no faster hardware path has been verified.

pub const Sha1 = merkle.Digest(5, 20, .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }, compressSha1);

fn compressSha1(state: *align(16) [5]u32, block: *const [64]u8) void {
    // Circular schedule with comptime-dispatched round groups removes both
    // per-round switches and the 80-word stack frame.
    var w: [16]u32 = undefined;
    for (0..16) |index| {
        w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    inline for ([4]u32{ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 }, 0..) |k, group| {
        inline for (0..20) |round| {
            const index: usize = group * 20 + round;
            if (index >= 16) {
                const value = w[(index - 3) & 15] ^ w[(index - 8) & 15] ^ w[(index - 14) & 15] ^ w[index & 15];
                w[index & 15] = std.math.rotl(u32, value, @as(u32, 1));
            }
            const f: u32 = switch (group) {
                0 => (b & c) | (~b & d),
                1 => b ^ c ^ d,
                2 => (b & c) | (b & d) | (c & d),
                else => b ^ c ^ d,
            };
            const t = std.math.rotl(u32, a, @as(u32, 5)) +% f +% e +% k +% w[index & 15];
            e = d;
            d = c;
            c = std.math.rotl(u32, b, @as(u32, 30));
            b = a;
            a = t;
        }
    }
    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
    state[4] +%= e;
}

test "sha1 onprem matches the stdlib oracle" {
    try seam.expectAgreement(Sha1.init(.{}), std.crypto.hash.Sha1.init(.{}), 0x5A1, true, null);
}
