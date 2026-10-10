const std = @import("std");

// Cyan4973/xxHash.

pub const XxHash64 = struct {
    const Self = @This();

    seed: u64,
    total: u64,
    acc1: u64,
    acc2: u64,
    acc3: u64,
    acc4: u64,
    buffer: [32]u8,
    buffered: usize,

    const prime_1: u64 = 0x9E3779B185EBCA87;
    const prime_2: u64 = 0xC2B2AE3D27D4EB4F;
    const prime_3: u64 = 0x165667B19E3779F9;
    const prime_4: u64 = 0x85EBCA77C2B2AE63;
    const prime_5: u64 = 0x27D4EB2F165667C5;

    pub fn init(seed: u64) Self {
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
            const want = 32 - self.buffered;
            const take = @min(want, rest_input.len);
            @memcpy(self.buffer[self.buffered..][0..take], rest_input[0..take]);
            self.buffered += take;
            rest_input = rest_input[take..];
            if (self.buffered == 32) {
                self.consumeStripe(&self.buffer);
                self.buffered = 0;
            }
        }
        while (rest_input.len >= 32) {
            self.consumeStripe(rest_input[0..32]);
            rest_input = rest_input[32..];
        }
        if (rest_input.len != 0) {
            @memcpy(self.buffer[0..rest_input.len], rest_input);
            self.buffered = rest_input.len;
        }
    }

    fn consumeStripe(self: *Self, stripe: *const [32]u8) void {
        self.acc1 = round(self.acc1, std.mem.readInt(u64, stripe[0..8], .little));
        self.acc2 = round(self.acc2, std.mem.readInt(u64, stripe[8..16], .little));
        self.acc3 = round(self.acc3, std.mem.readInt(u64, stripe[16..24], .little));
        self.acc4 = round(self.acc4, std.mem.readInt(u64, stripe[24..32], .little));
    }

    fn round(acc: u64, lane: u64) u64 {
        return std.math.rotl(u64, acc +% lane *% prime_2, @as(u64, 31)) *% prime_1;
    }

    fn mergeAccumulator(acc: u64, other: u64) u64 {
        return (acc ^ round(0, other)) *% prime_1 +% prime_4;
    }

    pub fn final(self: *Self) u64 {
        var hash: u64 = if (self.total >= 32)
            std.math.rotl(u64, self.acc1, 1) +% std.math.rotl(u64, self.acc2, 7) +%
                std.math.rotl(u64, self.acc3, 12) +% std.math.rotl(u64, self.acc4, 18)
        else
            self.seed +% prime_5;
        if (self.total >= 32) {
            hash = mergeAccumulator(hash, self.acc1);
            hash = mergeAccumulator(hash, self.acc2);
            hash = mergeAccumulator(hash, self.acc3);
            hash = mergeAccumulator(hash, self.acc4);
        }
        hash +%= self.total;
        var rest: []const u8 = self.buffer[0..self.buffered];
        while (rest.len >= 8) {
            hash ^= round(0, std.mem.readInt(u64, rest[0..8], .little));
            hash = std.math.rotl(u64, hash, 27) *% prime_1 +% prime_4;
            rest = rest[8..];
        }
        if (rest.len >= 4) {
            hash ^= @as(u64, std.mem.readInt(u32, rest[0..4], .little)) *% prime_1;
            hash = std.math.rotl(u64, hash, 23) *% prime_2 +% prime_3;
            rest = rest[4..];
        }
        while (rest.len != 0) {
            hash ^= @as(u64, rest[0]) *% prime_5;
            hash = std.math.rotl(u64, hash, 11) *% prime_1;
            rest = rest[1..];
        }
        hash ^= hash >> 33;
        hash *%= prime_2;
        hash ^= hash >> 29;
        hash *%= prime_3;
        hash ^= hash >> 32;
        return hash;
    }
};

test "xxh64 onprem matches the std oracle" {
    var rng = std.Random.DefaultPrng.init(0x6464);
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        var actual = XxHash64.init(0);
        actual.update(buf[0 .. size / 2]);
        actual.update(buf[size / 2 ..]);
        var expected = std.hash.XxHash64.init(0);
        expected.update(buf);
        try std.testing.expectEqual(expected.final(), actual.final());
    }
    const long = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(long);
    rng.random().bytes(long);
    var actual = XxHash64.init(0);
    actual.update(long);
    var expected = std.hash.XxHash64.init(0);
    expected.update(long);
    try std.testing.expectEqual(expected.final(), actual.final());
}
