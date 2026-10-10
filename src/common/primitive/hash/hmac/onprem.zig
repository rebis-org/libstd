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

test "hmac onprem matches the std oracle" {
    const sha256 = @import("../sha256/seam.zig");
    const sha1 = @import("../sha1/seam.zig");
    var rng = std.Random.DefaultPrng.init(0x484D4143);
    var size: usize = 0;
    while (size <= 512) : (size += 7) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        const key = buf[0..@min(size, 40)];
        var ours = Hmac(sha256.Sha256).init(key);
        ours.update(buf);
        var theirs = std.crypto.auth.hmac.Hmac(std.crypto.hash.sha2.Sha256).init(key);
        theirs.update(buf);
        try std.testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
        var ours1 = Hmac(sha1.Sha1).init(key);
        ours1.update(buf);
        var theirs1 = std.crypto.auth.hmac.Hmac(std.crypto.hash.Sha1).init(key);
        theirs1.update(buf);
        try std.testing.expectEqualSlices(u8, &theirs1.finalResult(), &ours1.finalResult());
    }
}
