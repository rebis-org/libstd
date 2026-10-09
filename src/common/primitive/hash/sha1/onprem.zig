const std = @import("std");
const builtin = @import("builtin");

// FIPS 180-1.
// RAR4's KDF and WinZIP AE-2 authentication require SHA-1, and no faster hardware path has been verified.

pub const Sha1 = struct {
    const Self = @This();

    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};

    state: [5]u32,
    buffer: [64]u8 = undefined,
    buffered: u8 = 0,
    total: u64 = 0,

    pub fn init(_: Options) Self {
        return .{ .state = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 } };
    }

    pub fn hash(input: []const u8, out: *[digest_length]u8, options: Options) void {
        var hasher = Self.init(options);
        hasher.update(input);
        hasher.final(out);
    }

    pub fn update(self: *Self, input: []const u8) void {
        var remaining = input;
        if (self.buffered != 0 and self.buffered + remaining.len >= 64) {
            const take = 64 - self.buffered;
            @memcpy(self.buffer[self.buffered..][0..take], remaining[0..take]);
            self.round(&self.buffer);
            self.buffered = 0;
            remaining = remaining[take..];
        }
        while (remaining.len >= 64) {
            self.round(remaining[0..64]);
            remaining = remaining[64..];
        }
        if (remaining.len != 0) {
            @memcpy(self.buffer[self.buffered..][0..remaining.len], remaining);
            self.buffered += @intCast(remaining.len);
        }
        self.total +%= input.len;
    }

    pub fn final(self: *Self, out: *[digest_length]u8) void {
        const bit_length = self.total *% 8;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if (64 - self.buffered < 8) {
            @memset(self.buffer[self.buffered..], 0);
            self.round(&self.buffer);
            self.buffered = 0;
        }
        @memset(self.buffer[self.buffered..56], 0);
        std.mem.writeInt(u64, self.buffer[56..64], bit_length, .big);
        self.round(&self.buffer);
        for (self.state, 0..) |word, index| {
            std.mem.writeInt(u32, out[4 * index ..][0..4], word, .big);
        }
    }

    pub fn finalResult(self: *Self) [digest_length]u8 {
        var out: [digest_length]u8 = undefined;
        self.final(&out);
        return out;
    }

    fn round(self: *Self, block: *const [64]u8) void {
        var w: [80]u32 = undefined;
        for (0..16) |index| {
            w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
        }
        for (16..80) |index| {
            w[index] = std.math.rotl(u32, w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], @as(u32, 1));
        }
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
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
        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
    }
};

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
