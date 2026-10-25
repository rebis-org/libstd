const std = @import("std");

// The Merkle-Damgård skeleton every short FIPS 180 digest shares.
pub fn Digest(
    comptime state_len: usize,
    comptime digest_len: usize,
    comptime initial: [state_len]u32,
    comptime compress: *const fn (state: *align(16) [state_len]u32, block: *const [64]u8) void,
) type {
    return struct {
        const Self = @This();

        pub const block_length = 64;
        pub const digest_length = digest_len;
        pub const Options = struct {};

        state: [state_len]u32 align(16),
        buffer: [64]u8 = undefined,
        buffered: u8 = 0,
        total: u64 = 0,

        pub fn init(_: Options) Self {
            return .{ .state = initial };
        }

        pub fn update(self: *Self, input: []const u8) void {
            var remaining = input;
            if (self.buffered != 0 and self.buffered + remaining.len >= 64) {
                const take = 64 - self.buffered;
                @memcpy(self.buffer[self.buffered..][0..take], remaining[0..take]);
                compress(&self.state, &self.buffer);
                self.buffered = 0;
                remaining = remaining[take..];
            }
            while (remaining.len >= 64) {
                compress(&self.state, remaining[0..64]);
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
                compress(&self.state, &self.buffer);
                self.buffered = 0;
            }
            @memset(self.buffer[self.buffered..56], 0);
            std.mem.writeInt(u64, self.buffer[56..64], bit_length, .big);
            compress(&self.state, &self.buffer);
            for (self.state, 0..) |word, index| {
                std.mem.writeInt(u32, out[4 * index ..][0..4], word, .big);
            }
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}

// Tail residues must match across pipeline crossings, hence the misaligned and
// split sweeps. Callers' comptime SkipZigTest keeps foreign-arch asm unreferenced.
fn checkHwScalar(rng: *std.Random.DefaultPrng, comptime Hw: type, comptime Sw: type, size: usize) !void {
    const buf = try std.testing.allocator.alloc(u8, size + 8);
    defer std.testing.allocator.free(buf);
    rng.random().bytes(buf);
    for ([_]usize{ 0, 1, 7 }) |align_off| {
        const input = buf[align_off..][0..size];
        for ([_]usize{ 0, 1, 63, 64, 65, size / 2, size }) |split_at| {
            const cut = @min(split_at, size);
            var hw = Hw.init(.{});
            hw.update(input[0..cut]);
            hw.update(input[cut..]);
            var sw = Sw.init(.{});
            sw.update(input[0..cut]);
            sw.update(input[cut..]);
            try std.testing.expectEqualSlices(u8, &sw.finalResult(), &hw.finalResult());
        }
    }
}

pub fn expectHwMatchesScalar(
    comptime state_len: usize,
    comptime digest_len: usize,
    comptime initial: [state_len]u32,
    comptime hw: *const fn (state: *align(16) [state_len]u32, block: *const [64]u8) void,
    comptime sw: *const fn (state: *align(16) [state_len]u32, block: *const [64]u8) void,
    seed: u64,
) !void {
    const Hw = Digest(state_len, digest_len, initial, hw);
    const Sw = Digest(state_len, digest_len, initial, sw);
    var rng = std.Random.DefaultPrng.init(seed);
    // Linear sweep covers every tail residue twice; spots cover multi-block and megabyte scales.
    var size: usize = 0;
    while (size <= 256) : (size += 1) {
        try checkHwScalar(&rng, Hw, Sw, size);
    }
    for ([_]usize{ 512, 1000, 4096, 5552, 65536, 1 << 20 }) |big| {
        try checkHwScalar(&rng, Hw, Sw, big);
    }
}
