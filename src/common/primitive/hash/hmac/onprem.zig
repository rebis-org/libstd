const std = @import("std");

// RFC 2104.

pub fn Hmac(comptime H: type) type {
    return struct {
        const Self = @This();

        pub const mac_length = H.digest_length;

        inner: H,
        outer: H,

        pub fn init(key: []const u8) Self {
            var key_block: [H.block_length]u8 = @splat(0);
            if (key.len > H.block_length) {
                var hashed = H.init(.{});
                hashed.update(key);
                const digest = hashed.finalResult();
                @memcpy(key_block[0..digest.len], &digest);
            } else {
                @memcpy(key_block[0..key.len], key);
            }
            var inner_pad: [H.block_length]u8 = undefined;
            var outer_pad: [H.block_length]u8 = undefined;
            for (key_block, 0..) |byte, index| {
                inner_pad[index] = byte ^ 0x36;
                outer_pad[index] = byte ^ 0x5c;
            }
            var inner = H.init(.{});
            inner.update(&inner_pad);
            var outer = H.init(.{});
            outer.update(&outer_pad);
            return .{ .inner = inner, .outer = outer };
        }

        pub fn update(self: *Self, input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *Self, out: *[mac_length]u8) void {
            var digest: [H.digest_length]u8 = undefined;
            self.inner.final(&digest);
            self.outer.update(&digest);
            self.outer.final(out);
        }

        pub fn finalResult(self: *Self) [mac_length]u8 {
            var out: [mac_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

test "hmac onprem matches independent oracles for every key length class" {
    const sha256 = @import("../sha256/seam.zig");
    const sha1 = @import("../sha1/seam.zig");
    const testing = std.testing;

    // RFC 2202 pins the short-key pad path against absolute answers.
    const key20: [20]u8 = @splat(0x0b);
    var tc1 = Hmac(sha1.Sha1).init(&key20);
    tc1.update("Hi There");
    try testing.expectEqualSlices(u8, &[_]u8{ 0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00 }, &tc1.finalResult());

    var tc2 = Hmac(sha1.Sha1).init("Jefe");
    tc2.update("what do ya want for nothing?");
    try testing.expectEqualSlices(u8, &[_]u8{ 0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79 }, &tc2.finalResult());

    const key_aa: [20]u8 = @splat(0xaa);
    const tc3_data: [50]u8 = @splat(0xdd);
    var tc3 = Hmac(sha1.Sha1).init(&key_aa);
    tc3.update(&tc3_data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3 }, &tc3.finalResult());

    const key32: [32]u8 = @splat(0x0b);
    var tc1_256 = Hmac(sha256.Sha256).init(&key32);
    tc1_256.update("Hi There");
    try testing.expectEqualSlices(u8, &[_]u8{ 0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd, 0xc5, 0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6, 0x8c, 0xf7 }, &tc1_256.finalResult());

    // Keys past the block length hash first; the pad branch has no
    // shorter cousin, so only long-key pins reach it.
    const long_key: [131]u8 = @splat(0xaa);
    const long_msg = "Test Using Larger Than Block-Size Key - Hash Key First";
    var long1 = Hmac(sha1.Sha1).init(&long_key);
    long1.update(long_msg);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x90, 0xd0, 0xda, 0xce, 0x1c, 0x1b, 0xdc, 0x95, 0x73, 0x39, 0x30, 0x78, 0x03, 0x16, 0x03, 0x35, 0xbd, 0xe6, 0xdf, 0x2b }, &long1.finalResult());
    var long256 = Hmac(sha256.Sha256).init(&long_key);
    long256.update(long_msg);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54 }, &long256.finalResult());

    // The stdlib sweep keeps split-size agreement for short keys.
    var rng = std.Random.DefaultPrng.init(0x484D4143);
    var size: usize = 0;
    while (size <= 512) : (size += 7) {
        const buf = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(buf);
        rng.random().bytes(buf);
        const key = buf[0..@min(size, 40)];
        var ours = Hmac(sha256.Sha256).init(key);
        ours.update(buf);
        var theirs = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).init(key);
        theirs.update(buf);
        try testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
        var ours1 = Hmac(sha1.Sha1).init(key);
        ours1.update(buf);
        var theirs1 = std.crypto.auth.hmac.Hmac(std.crypto.hash.Sha1).init(key);
        theirs1.update(buf);
        try testing.expectEqualSlices(u8, &theirs1.finalResult(), &ours1.finalResult());
    }

    // Boundary keys around the block length stay on the oracle too.
    var message: [300]u8 = undefined;
    rng.random().bytes(&message);
    for ([_]usize{ 63, 64, 65, 128, 131 }) |key_len| {
        const key = message[0..key_len];
        var ours = Hmac(sha256.Sha256).init(key);
        ours.update(&message);
        var theirs = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).init(key);
        theirs.update(&message);
        try testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
        var ours1 = Hmac(sha1.Sha1).init(key);
        ours1.update(&message);
        var theirs1 = std.crypto.auth.hmac.Hmac(std.crypto.hash.Sha1).init(key);
        theirs1.update(&message);
        try testing.expectEqualSlices(u8, &theirs1.finalResult(), &ours1.finalResult());
    }
}
