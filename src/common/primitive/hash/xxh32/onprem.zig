const std = @import("std");

const seam = @import("seam");

const rotate = @import("../rotate.zig");

// Cyan4973/xxHash.

pub const XxHash32 = struct {
    const Self = @This();

    seed: u32,
    total: u64,
    acc1: u32,
    acc2: u32,
    acc3: u32,
    acc4: u32,
    buffer: [16]u8,
    buffered: usize,

    const prime_1: u32 = 0x9E3779B1;
    const prime_2: u32 = 0x85EBCA77;
    const prime_3: u32 = 0xC2B2AE3D;
    const prime_4: u32 = 0x27D4EB2F;
    const prime_5: u32 = 0x165667B1;

    pub fn init(seed: u32) Self {
        return .{
            .seed = seed,
            .total = 0,
            .acc1 = seed +% prime_1 +% prime_2,
            .acc2 = seed +% prime_2,
            .acc3 = seed,
            .acc4 = seed -% prime_1,
            .buffer = undefined,
            .buffered = 0,
        };
    }

    pub fn update(self: *Self, input: []const u8) void {
        self.total += input.len;
        var rest_input = input;
        if (self.buffered != 0) {
            const want = 16 - self.buffered;
            const take = @min(want, rest_input.len);
            @memcpy(self.buffer[self.buffered..][0..take], rest_input[0..take]);
            self.buffered += take;
            rest_input = rest_input[take..];
            if (self.buffered == 16) {
                self.consume(&self.buffer);
                self.buffered = 0;
            }
        }
        while (rest_input.len >= 16) {
            self.consume(rest_input[0..16]);
            rest_input = rest_input[16..];
        }
        if (rest_input.len != 0) {
            @memcpy(self.buffer[0..rest_input.len], rest_input);
            self.buffered = rest_input.len;
        }
    }

    fn consume(self: *Self, lanes: *const [16]u8) void {
        self.acc1 = round(self.acc1, std.mem.readInt(u32, lanes[0..4], .little));
        self.acc2 = round(self.acc2, std.mem.readInt(u32, lanes[4..8], .little));
        self.acc3 = round(self.acc3, std.mem.readInt(u32, lanes[8..12], .little));
        self.acc4 = round(self.acc4, std.mem.readInt(u32, lanes[12..16], .little));
    }

    fn round(acc: u32, lane: u32) u32 {
        return rotate.rotl(acc +% lane *% prime_2, 13) *% prime_1;
    }

    pub fn final(self: *Self) u32 {
        var hash: u32 = undefined;
        if (self.total >= 16) {
            hash = rotate.rotl(self.acc1, 1) +% rotate.rotl(self.acc2, 7) +%
                rotate.rotl(self.acc3, 12) +% rotate.rotl(self.acc4, 18);
        } else {
            hash = self.seed +% prime_5;
        }
        hash +%= @truncate(self.total);
        var rest: []const u8 = self.buffer[0..self.buffered];
        while (rest.len >= 4) {
            hash +%= std.mem.readInt(u32, rest[0..4], .little) *% prime_3;
            hash = rotate.rotl(hash, 17) *% prime_4;
            rest = rest[4..];
        }
        while (rest.len != 0) {
            hash +%= @as(u32, rest[0]) *% prime_5;
            hash = rotate.rotl(hash, 11) *% prime_1;
            rest = rest[1..];
        }
        hash ^= hash >> 15;
        hash *%= prime_2;
        hash ^= hash >> 13;
        hash *%= prime_3;
        hash ^= hash >> 16;
        return hash;
    }
};

test "xxh32 onprem pins the reference catalog and tracks the stdlib oracle" {
    const testing = std.testing;

    // The reference catalog pins the short-input tail paths at seed zero.
    var empty = XxHash32.init(0);
    try testing.expectEqual(@as(u32, 0x02CC5D05), empty.final());

    var a = XxHash32.init(0);
    a.update("a");
    try testing.expectEqual(@as(u32, 0x550D7456), a.final());

    var abc = XxHash32.init(0);
    abc.update("abc");
    try testing.expectEqual(@as(u32, 0x32D153FF), abc.final());

    // A split feed proves buffered bytes join later stripes.
    var split = XxHash32.init(0);
    split.update("ab");
    split.update("c");
    try testing.expectEqual(@as(u32, 0x32D153FF), split.final());

    try seam.expectAgreement(XxHash32.init(0), std.hash.XxHash32.init(0), 0x3232, false, null);

    // A seeded sweep guards the seed arithmetic the zero-seed pins miss.
    var buf: [271]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xC0FFEE);
    rng.random().bytes(&buf);
    for ([_]usize{ 0, 1, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 255, 256, 271 }) |len| {
        var ours = XxHash32.init(0xC0FFEE);
        ours.update(buf[0..len]);
        var theirs = std.hash.XxHash32.init(0xC0FFEE);
        theirs.update(buf[0..len]);
        try testing.expectEqual(theirs.final(), ours.final());
    }
}
