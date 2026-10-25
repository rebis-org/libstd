const std = @import("std");

const scalar = @import("../sha256/onprem.zig");

// Multi-buffer SHA-256 in the ISA-L shape: N independent lanes advanced
// together, one compress pass per call.
// The portable arm streams each lane through the scalar core; hardware arms
// interleave rounds at the compress site.

pub const lanes_max: usize = 8;

pub fn checkLanes(comptime lanes: usize) void {
    if (lanes == 0 or lanes > lanes_max) @compileError("sha256_mb lanes must be 1..8, the ISA-L shape.");
}

pub fn Sha256Mb(comptime lanes: usize) type {
    checkLanes(lanes);
    return struct {
        const Self = @This();

        lanes: [lanes]scalar.Sha256,

        pub const lane_count = lanes;
        pub const digest_length = 32;
        pub const block_length = 64;

        pub fn init() Self {
            var self: Self = undefined;
            for (&self.lanes) |*lane| lane.* = scalar.Sha256.init(.{});
            return self;
        }

        pub fn update(self: *Self, lane: usize, input: []const u8) void {
            std.debug.assert(lane < lanes);
            self.lanes[lane].update(input);
        }

        pub fn final(self: *const Self, lane: usize, out: *[digest_length]u8) void {
            std.debug.assert(lane < lanes);
            var copy = self.lanes[lane];
            copy.final(out);
        }

        pub fn finalResult(self: *const Self, lane: usize) [digest_length]u8 {
            std.debug.assert(lane < lanes);
            var copy = self.lanes[lane];
            return copy.finalResult();
        }
    };
}

test "sha256_mb portable matches per-lane scalar digests" {
    const testing = std.testing;
    var rng = std.Random.DefaultPrng.init(0x51a256);
    const random = rng.random();
    inline for ([_]usize{ 1, 2, 4, 8 }) |lanes| {
        const Mb = Sha256Mb(lanes);
        var mb = Mb.init();
        var expected: [lanes][32]u8 = undefined;
        var messages: [lanes][1024]u8 = undefined;
        var lengths: [lanes]usize = undefined;
        for (0..lanes) |lane| {
            lengths[lane] = random.uintLessThan(usize, messages[lane].len + 1);
            random.bytes(messages[lane][0..lengths[lane]]);
            std.crypto.hash.sha2.Sha256.hash(messages[lane][0..lengths[lane]], &expected[lane], .{});
        }
        // Split updates exercise the per-lane staging, not just whole messages.
        for (0..lanes) |lane| {
            const whole = messages[lane][0..lengths[lane]];
            const cut = @min(whole.len, random.uintLessThan(usize, whole.len + 1));
            mb.update(lane, whole[0..cut]);
            mb.update(lane, whole[cut..]);
        }
        for (0..lanes) |lane| {
            try testing.expectEqualSlices(u8, &expected[lane], &mb.finalResult(lane));
        }
    }
}
