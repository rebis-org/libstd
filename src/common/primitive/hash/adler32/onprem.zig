const builtin = @import("builtin");
const std = @import("std");

const options = @import("options");

// RFC 1950.
// The 16-way unrolled inner loop defers the modulo to one reduction per NMAX bytes.
// NEON is baseline on aarch64, so the wide path needs no extra target feature;
// the portable flag turns it off.

const has_neon = builtin.target.cpu.arch == .aarch64 and !options.adler32_portable;

// Lane k covers bytes 4k..4k+3, so its weights count down from 16-4k.
const lane_weights = [4]@Vector(4, u32){
    .{ 16, 15, 14, 13 },
    .{ 12, 11, 10, 9 },
    .{ 8, 7, 6, 5 },
    .{ 4, 3, 2, 1 },
};

inline fn adlerGroup16(s1: *u32, s2: *u32, bytes: *const [16]u8) void {
    var t1: @Vector(4, u32) = @splat(0);
    var t2: @Vector(4, u32) = @splat(0);
    inline for (0..4) |k| {
        const w: @Vector(4, u32) = @intCast(@as(@Vector(4, u8), bytes[4 * k ..][0..4].*));
        t1 += w;
        t2 += lane_weights[k] *% w;
    }
    s2.* +%= 16 *% s1.* +% @reduce(.Add, t2);
    s1.* +%= @reduce(.Add, t1);
}

pub const Adler32 = struct {
    const Self = @This();
    const base: u32 = 65521;
    const nmax: usize = 5552;

    adler: u32 = 1,

    pub fn init() Self {
        return .{};
    }

    pub fn update(self: *Self, input: []const u8) void {
        self.adler = permute(self.adler, input);
    }

    pub fn final(self: *const Self) u32 {
        return self.adler;
    }

    fn step16(s1: *u32, s2: *u32, block: *const [16]u8) void {
        comptime var j: usize = 0;
        inline while (j < 16) : (j += 1) {
            s1.* +%= block[j];
            s2.* +%= s1.*;
        }
    }

    fn permute(state: u32, input: []const u8) u32 {
        var s1 = state & 0xffff;
        var s2 = (state >> 16) & 0xffff;

        if (comptime has_neon) {
            // Whole 16-byte groups run four lanes wide; the modulo fires once per
            // NMAX bytes exactly like the scalar loop, so both sums stay inside u32.
            var data = input;
            while (data.len >= nmax) {
                var index: usize = 0;
                while (index < nmax) : (index += 16) {
                    adlerGroup16(&s1, &s2, data[index..][0..16]);
                }
                s1 %= base;
                s2 %= base;
                data = data[nmax..];
            }
            var index: usize = 0;
            while (index + 16 <= data.len) : (index += 16) {
                adlerGroup16(&s1, &s2, data[index..][0..16]);
            }
            while (index < data.len) : (index += 1) {
                s1 +%= data[index];
                s2 +%= s1;
            }
            s1 %= base;
            s2 %= base;
            return s1 | (s2 << 16);
        }

        if (input.len == 1) {
            s1 +%= input[0];
            if (s1 >= base) s1 -= base;
            s2 +%= s1;
            if (s2 >= base) s2 -= base;
        } else if (input.len < 16) {
            for (input) |b| {
                s1 +%= b;
                s2 +%= s1;
            }
            s1 %= base;
            s2 %= base;
        } else {
            const rounds = nmax / 16;
            var index: usize = 0;
            while (index + nmax <= input.len) {
                var done: usize = 0;
                while (done < rounds) : (done += 1) {
                    step16(&s1, &s2, input[index..][0..16]);
                    index += 16;
                }
                s1 %= base;
                s2 %= base;
            }
            while (index + 16 <= input.len) : (index += 16) {
                step16(&s1, &s2, input[index..][0..16]);
            }
            while (index < input.len) : (index += 1) {
                s1 +%= input[index];
                s2 +%= s1;
            }
            s1 %= base;
            s2 %= base;
        }

        return s1 | (s2 << 16);
    }
};

test "adler32 onprem matches the std oracle" {
    var rng = std.Random.DefaultPrng.init(0xA012);
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        var ours = Adler32.init();
        ours.update(buf[0 .. size / 2]);
        ours.update(buf[size / 2 ..]);
        var theirs: std.hash.Adler32 = .{};
        theirs.update(buf);
        try std.testing.expectEqual(theirs.adler, ours.final());
    }
    const long = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(long);
    rng.random().bytes(long);
    var ours = Adler32.init();
    ours.update(long);
    var theirs: std.hash.Adler32 = .{};
    theirs.update(long);
    try std.testing.expectEqual(theirs.adler, ours.final());
}
