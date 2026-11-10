const std = @import("std");

const seam = @import("seam");

const onprem = @import("onprem.zig");

// Multi-buffer rides the sha256 provider axis: an alternate interface over the same capability, not a new primitive.

fn StdMb(comptime lanes: usize) type {
    return struct {
        const Self = @This();
        const Std = std.crypto.hash.sha2.Sha256;

        lanes: [lanes]Std,

        pub const lane_count = lanes;
        pub const digest_length = 32;
        pub const block_length = 64;

        pub fn init() Self {
            var self: Self = undefined;
            for (&self.lanes) |*lane| lane.* = Std.init(.{});
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

pub fn Sha256Mb(comptime lanes: usize) type {
    onprem.checkLanes(lanes);
    const PairT = seam.Pair(onprem.Sha256Mb(lanes), StdMb(lanes));
    return struct {
        const Self = @This();

        inner: PairT,

        pub const lane_count = lanes;
        pub const digest_length = 32;
        pub const block_length = 64;

        pub fn init() Self {
            return bind(seam.default_provider);
        }

        pub fn bind(provider: seam.Provider) Self {
            return switch (provider) {
                .onprem => .{ .inner = .{ .onprem = onprem.Sha256Mb(lanes).init() } },
                .offprem => .{ .inner = .{ .offprem = StdMb(lanes).init() } },
            };
        }

        pub fn update(self: *Self, lane: usize, input: []const u8) void {
            switch (self.inner) {
                inline else => |*impl| impl.update(lane, input),
            }
        }

        pub fn final(self: *const Self, lane: usize, out: *[digest_length]u8) void {
            switch (self.inner) {
                inline else => |*impl| impl.final(lane, out),
            }
        }

        pub fn finalResult(self: *const Self, lane: usize) [digest_length]u8 {
            return switch (self.inner) {
                inline else => |*impl| impl.finalResult(lane),
            };
        }
    };
}

test "sha256_mb seam arms answer identically for every lane count" {
    const testing = std.testing;
    var rng = std.Random.DefaultPrng.init(0x6B);
    const random = rng.random();
    // Lengths straddle the 64-byte block boundary lane by lane.
    const lengths = [_]usize{ 0, 1, 63, 64, 65, 127, 128, 199 };
    inline for (1..9) |lanes| {
        const Mb = Sha256Mb(lanes);
        var ours = Mb.bind(.onprem);
        var theirs = Mb.bind(.offprem);
        var expected: [lanes][32]u8 = undefined;
        var message: [199]u8 = undefined;
        random.bytes(&message);
        for (0..lanes) |lane| {
            const input = message[0..lengths[lane]];
            std.crypto.hash.sha2.Sha256.hash(input, &expected[lane], .{});
            ours.update(lane, input);
            theirs.update(lane, input);
        }
        for (0..lanes) |lane| {
            try testing.expectEqualSlices(u8, &expected[lane], &ours.finalResult(lane));
            try testing.expectEqualSlices(u8, &expected[lane], &theirs.finalResult(lane));
        }
    }

    // The default constructor lands on the published fips answer too.
    var default_mb = Sha256Mb(3).init();
    default_mb.update(0, "abc");
    default_mb.update(1, "abc");
    default_mb.update(2, "abc");
    const want = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try testing.expectEqualSlices(u8, &want, &default_mb.finalResult(0));
    try testing.expectEqualSlices(u8, &want, &default_mb.finalResult(1));
    try testing.expectEqualSlices(u8, &want, &default_mb.finalResult(2));
}
