const std = @import("std");

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
        return std.math.rotl(u32, acc +% lane *% prime_2, @as(u32, 13)) *% prime_1;
    }

    pub fn final(self: *Self) u32 {
        var hash: u32 = undefined;
        if (self.total >= 16) {
            hash = std.math.rotl(u32, self.acc1, 1) +% std.math.rotl(u32, self.acc2, 7) +%
                std.math.rotl(u32, self.acc3, 12) +% std.math.rotl(u32, self.acc4, 18);
        } else {
            hash = self.seed +% prime_5;
        }
        hash +%= @truncate(self.total);
        var rest: []const u8 = self.buffer[0..self.buffered];
        while (rest.len >= 4) {
            hash +%= std.mem.readInt(u32, rest[0..4], .little) *% prime_3;
            hash = std.math.rotl(u32, hash, 17) *% prime_4;
            rest = rest[4..];
        }
        while (rest.len != 0) {
            hash +%= @as(u32, rest[0]) *% prime_5;
            hash = std.math.rotl(u32, hash, 11) *% prime_1;
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

test "xxh32 onprem matches the std oracle" {
    var rng = std.Random.DefaultPrng.init(0x3232);
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        var actual = XxHash32.init(0);
        actual.update(buf[0 .. size / 2]);
        actual.update(buf[size / 2 ..]);
        var expected = std.hash.XxHash32.init(0);
        expected.update(buf);
        try std.testing.expectEqual(expected.final(), actual.final());
    }
}
