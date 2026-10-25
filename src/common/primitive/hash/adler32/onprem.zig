const builtin = @import("builtin");
const std = @import("std");

const options = @import("options");
const seam = @import("seam");

// RFC 1950. The wide path follows Chromium zlib's adler32_simd.c, shared
// with zlib-ng's NEON and AVX2 arms.

const lane_len: usize = blk: {
    if (options.adler32_portable) break :blk 0;
    break :blk switch (builtin.target.cpu.arch) {
        .aarch64 => 16,
        .x86_64 => if (builtin.target.cpu.has(.x86, .avx2)) 32 else 0,
        else => 0,
    };
};
const has_wide = lane_len != 0;
const block_size: usize = 2 * lane_len;
const chunk_size: usize = if (has_wide) nmax / block_size * block_size else 0;
const nmax: usize = 5552;

pub const Adler32 = struct {
    const Self = @This();
    const base: u32 = 65521;

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

    fn evenMask(comptime l: usize) @Vector(l / 2, i32) {
        var m: [l / 2]i32 = undefined;
        for (0..l / 2) |i| m[i] = @intCast(2 * i);
        return m;
    }

    fn oddMask(comptime l: usize) @Vector(l / 2, i32) {
        var m: [l / 2]i32 = undefined;
        for (0..l / 2) |i| m[i] = @intCast(2 * i + 1);
        return m;
    }

    fn iota(comptime count: usize, comptime start: usize) @Vector(count, i32) {
        var m: [count]i32 = undefined;
        for (0..count) |i| m[i] = @intCast(start + i);
        return m;
    }

    // The NMAX window caps the block count at every L, so no u16 column
    // or u32 lane overflows.
    fn foldBlocks(comptime l: usize, s1: *u32, s2: *u32, data: []const u8) void {
        const Lane = @Vector(l, u8);
        const Half = @Vector(l / 2, u16);
        const Words = @Vector(l / 4, u32);

        var index: usize = 0;
        if (data.len >= 2 * l) {
            const a_init = s1.*;
            var a_v: Words = @splat(0);
            var b_v: Words = @splat(0);
            var col1: Half = @splat(0);
            var col2: Half = @splat(0);
            var col3: Half = @splat(0);
            var col4: Half = @splat(0);
            while (index + 2 * l <= data.len) : (index += 2 * l) {
                const bytes1: Lane = @as(Lane, data[index..][0..l].*);
                const bytes2: Lane = @as(Lane, data[index + l ..][0..l].*);
                b_v +%= a_v;
                a_v +%= pairSumWiden(l, pairSumAcc(l, pairSum(l, bytes1), bytes2));
                col1 = col1 +% @as(Half, @intCast(@shuffle(u8, bytes1, undefined, iota(l / 2, 0))));
                col2 = col2 +% @as(Half, @intCast(@shuffle(u8, bytes1, undefined, iota(l / 2, l / 2))));
                col3 = col3 +% @as(Half, @intCast(@shuffle(u8, bytes2, undefined, iota(l / 2, 0))));
                col4 = col4 +% @as(Half, @intCast(@shuffle(u8, bytes2, undefined, iota(l / 2, l / 2))));
            }
            // b_v lanes count whole blocks behind the current one; one shift
            // restores block weights, weightPass adds byte weights.
            b_v *%= @as(Words, @splat(@intCast(2 * l)));
            inline for (0..4) |c| {
                const col = switch (c) {
                    0 => col1,
                    1 => col2,
                    2 => col3,
                    else => col4,
                };
                b_v = weightPass(l, b_v, col, c, 0);
                b_v = weightPass(l, b_v, col, c, 1);
            }
            s1.* +%= @reduce(.Add, a_v);
            s2.* +%= a_init *% @as(u32, @intCast(index)) +% @reduce(.Add, b_v);
            s1.* %= base;
            s2.* %= base;
        }
        while (index < data.len) : (index += 1) {
            s1.* +%= data[index];
            s2.* +%= s1.*;
        }
        s1.* %= base;
        s2.* %= base;
    }

    fn pairSum(comptime l: usize, bytes: @Vector(l, u8)) @Vector(l / 2, u16) {
        const even: @Vector(l / 2, u8) = @shuffle(u8, bytes, undefined, evenMask(l));
        const odd: @Vector(l / 2, u8) = @shuffle(u8, bytes, undefined, oddMask(l));
        return @as(@Vector(l / 2, u16), @intCast(even)) +% @as(@Vector(l / 2, u16), @intCast(odd));
    }

    fn pairSumWiden(comptime l: usize, halves: @Vector(l / 2, u16)) @Vector(l / 4, u32) {
        const even: @Vector(l / 4, u16) = @shuffle(u16, halves, undefined, evenMask(l / 2));
        const odd: @Vector(l / 4, u16) = @shuffle(u16, halves, undefined, oddMask(l / 2));
        return @as(@Vector(l / 4, u32), @intCast(even)) +% @as(@Vector(l / 4, u32), @intCast(odd));
    }

    fn pairSumAcc(comptime l: usize, acc: @Vector(l / 2, u16), bytes: @Vector(l, u8)) @Vector(l / 2, u16) {
        const even: @Vector(l / 2, u8) = @shuffle(u8, bytes, undefined, evenMask(l));
        const odd: @Vector(l / 2, u8) = @shuffle(u8, bytes, undefined, oddMask(l));
        return acc +% @as(@Vector(l / 2, u16), @intCast(even)) +% @as(@Vector(l / 2, u16), @intCast(odd));
    }

    fn weightPass(comptime l: usize, acc: @Vector(l / 4, u32), col: @Vector(l / 2, u16), comptime c: usize, comptime part: usize) @Vector(l / 4, u32) {
        const quarter: @Vector(l / 4, u16) = @shuffle(u16, col, undefined, iota(l / 4, part * (l / 4)));
        const weights: @Vector(l / 4, u32) = comptime blk: {
            var arr: [l / 4]u32 = undefined;
            for (0..l / 4) |i| {
                const j = part * (l / 4) + i;
                arr[i] = @intCast(2 * l - c * (l / 2) - j);
            }
            break :blk arr;
        };
        return acc +% @as(@Vector(l / 4, u32), @intCast(quarter)) *% weights;
    }

    fn permute(state: u32, input: []const u8) u32 {
        var s1 = state & 0xffff;
        var s2 = (state >> 16) & 0xffff;

        if (comptime has_wide) {
            var data = input;
            while (data.len >= chunk_size) {
                foldBlocks(lane_len, &s1, &s2, data[0..chunk_size]);
                data = data[chunk_size..];
            }
            foldBlocks(lane_len, &s1, &s2, data);
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

test "adler32 onprem matches the stdlib oracle" {
    try seam.expectAgreement(Adler32.init(), std.hash.Adler32{}, 0xA012, false, "adler");
}
