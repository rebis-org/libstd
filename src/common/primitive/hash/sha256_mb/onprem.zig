const std = @import("std");

const scalar = @import("../sha256/onprem.zig");

// Multi-buffer SHA-256 in the ISA-L shape: N independent lanes advanced together, one compress pass per call.

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

test "sha256_mb keeps every lane independent across split feeds" {
    const testing = std.testing;
    var rng = std.Random.DefaultPrng.init(0x51A256);
    const random = rng.random();
    inline for (1..9) |lanes| {
        const Mb = Sha256Mb(lanes);
        var mb = Mb.init();
        var expected: [lanes][32]u8 = undefined;
        var messages: [lanes][1024]u8 = undefined;
        var lengths: [lanes]usize = undefined;
        var cuts: [lanes]usize = undefined;
        for (0..lanes) |lane| {
            lengths[lane] = random.uintLessThan(usize, messages[lane].len + 1);
            random.bytes(messages[lane][0..lengths[lane]]);
            std.crypto.hash.sha2.Sha256.hash(messages[lane][0..lengths[lane]], &expected[lane], .{});
        }
        // All first halves land before any second half, so shared staging
        // between lanes would corrupt at least one digest.
        for (0..lanes) |lane| {
            const whole = messages[lane][0..lengths[lane]];
            cuts[lane] = @min(whole.len, random.uintLessThan(usize, whole.len + 1));
            mb.update(lane, whole[0..cuts[lane]]);
        }
        for (0..lanes) |lane| {
            const whole = messages[lane][0..lengths[lane]];
            mb.update(lane, whole[cuts[lane]..]);
        }
        // Both finalizers answer; odd lanes exercise the copying final.
        for (0..lanes) |lane| {
            if (lane % 2 == 0) {
                try testing.expectEqualSlices(u8, &expected[lane], &mb.finalResult(lane));
            } else {
                var out: [32]u8 = undefined;
                mb.final(lane, &out);
                try testing.expectEqualSlices(u8, &expected[lane], &out);
            }
        }
    }

    // The wrapper still answers the published fips vector on any lane.
    var pin = Sha256Mb(2).init();
    pin.update(0, "abc");
    try testing.expectEqualSlices(u8, &[_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    }, &pin.finalResult(0));
}
