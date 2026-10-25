const std = @import("std");

const seam = @import("seam");

const onprem = @import("onprem.zig");

// Multi-buffer rides the sha256 provider axis: an alternate interface over
// the same capability, not a new primitive. Mergeable builds keep both arms
// and dispatch once per bound instance, the seam's standing rule.

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

test "sha256_mb seam arms agree across sizes and lanes" {
    const testing = std.testing;
    var rng = std.Random.DefaultPrng.init(0x6b);
    const random = rng.random();
    inline for ([_]seam.Provider{ .onprem, .offprem }) |provider| {
        inline for ([_]usize{ 1, 4, 8 }) |lanes| {
            var mb = Sha256Mb(lanes).bind(provider);
            var expected: [lanes][32]u8 = undefined;
            for (0..lanes) |lane| {
                var message: [512]u8 = undefined;
                const len = random.uintLessThan(usize, message.len + 1);
                random.bytes(message[0..len]);
                std.crypto.hash.sha2.Sha256.hash(message[0..len], &expected[lane], .{});
                mb.update(lane, message[0..len]);
            }
            for (0..lanes) |lane| {
                try testing.expectEqualSlices(u8, &expected[lane], &mb.finalResult(lane));
            }
        }
    }
}
