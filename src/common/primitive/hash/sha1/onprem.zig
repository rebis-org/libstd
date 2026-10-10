const std = @import("std");
const builtin = @import("builtin");

const merkle = @import("../merkle.zig");

// FIPS 180-1.
// RAR4's KDF and WinZIP AE-2 authentication require SHA-1, and no faster hardware path has been verified.

pub const Sha1 = merkle.Digest(5, 20, .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }, compressSha1);

fn compressSha1(state: *align(16) [5]u32, block: *const [64]u8) void {
    var w: [80]u32 = undefined;
    for (0..16) |index| {
        w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
    }
    for (16..80) |index| {
        w[index] = std.math.rotl(u32, w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], @as(u32, 1));
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    for (0..80) |index| {
        const f: u32 = switch (index / 20) {
            0 => (b & c) | (~b & d),
            1 => b ^ c ^ d,
            2 => (b & c) | (b & d) | (c & d),
            else => b ^ c ^ d,
        };
        const k: u32 = switch (index / 20) {
            0 => 0x5A827999,
            1 => 0x6ED9EBA1,
            2 => 0x8F1BBCDC,
            else => 0xCA62C1D6,
        };
        const t = std.math.rotl(u32, a, @as(u32, 5)) +% f +% e +% k +% w[index];
        e = d;
        d = c;
        c = std.math.rotl(u32, b, @as(u32, 30));
        b = a;
        a = t;
    }
    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
    state[4] +%= e;
}

test "sha1 onprem matches the std oracle" {
    var rng = std.Random.DefaultPrng.init(0x5A1);
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        var ours = Sha1.init(.{});
        ours.update(buf[0 .. size / 2]);
        ours.update(buf[size / 2 ..]);
        var theirs = std.crypto.hash.Sha1.init(.{});
        theirs.update(buf);
        try std.testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
    }
    const long = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(long);
    rng.random().bytes(long);
    var ours = Sha1.init(.{});
    ours.update(long);
    var theirs = std.crypto.hash.Sha1.init(.{});
    theirs.update(long);
    try std.testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
}
