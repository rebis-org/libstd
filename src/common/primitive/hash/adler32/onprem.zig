const builtin = @import("builtin");
const std = @import("std");

const options = @import("options");
const seam = @import("seam");

// RFC 1950.
// The wide path follows the Chromium zlib scheme (adler32_simd.c): 32-byte
// blocks accumulate plain byte sums in u16 columns and u32 lanes, all position
// weighting is deferred to one multiply-accumulate pass after the block run,
// and the modulo fires once per NMAX window. NEON is baseline on aarch64, so
// the wide path needs no extra target feature; the portable flag turns it off.

const has_neon = builtin.target.cpu.arch == .aarch64 and !options.adler32_portable;

const Bytes16 = @Vector(16, u8);
const Bytes8 = @Vector(8, u8);
const Half16 = @Vector(8, u16);
const Half8 = @Vector(4, u16);
const Words = @Vector(4, u32);

const even_bytes: @Vector(8, i32) = .{ 0, 2, 4, 6, 8, 10, 12, 14 };
const odd_bytes: @Vector(8, i32) = .{ 1, 3, 5, 7, 9, 11, 13, 15 };
const even_halves: @Vector(4, i32) = .{ 0, 2, 4, 6 };
const odd_halves: @Vector(4, i32) = .{ 1, 3, 5, 7 };
const low_bytes: @Vector(8, i32) = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
const high_bytes: @Vector(8, i32) = .{ 8, 9, 10, 11, 12, 13, 14, 15 };
const low_halves: @Vector(4, i32) = .{ 0, 1, 2, 3 };
const high_halves: @Vector(4, i32) = .{ 4, 5, 6, 7 };

inline fn pairSum(bytes: Bytes16) Half16 {
    const even: Bytes8 = @shuffle(u8, bytes, undefined, even_bytes);
    const odd: Bytes8 = @shuffle(u8, bytes, undefined, odd_bytes);
    return @as(Half16, @intCast(even)) +% @as(Half16, @intCast(odd));
}

inline fn pairSumAcc(acc: Half16, bytes: Bytes16) Half16 {
    const even: Bytes8 = @shuffle(u8, bytes, undefined, even_bytes);
    const odd: Bytes8 = @shuffle(u8, bytes, undefined, odd_bytes);
    return acc +% @as(Half16, @intCast(even)) +% @as(Half16, @intCast(odd));
}

inline fn pairSumWiden(halves: Half16) Words {
    const even: Half8 = @shuffle(u16, halves, undefined, even_halves);
    const odd: Half8 = @shuffle(u16, halves, undefined, odd_halves);
    return @as(Words, @intCast(even)) +% @as(Words, @intCast(odd));
}

inline fn byteAcc(acc: Half16, bytes: Bytes8) Half16 {
    return acc +% @as(Half16, @intCast(bytes));
}

inline fn weightAcc(acc: Words, sums: Half8, weights: Half8) Words {
    return acc +% @as(Words, @intCast(sums)) *% @as(Words, @intCast(weights));
}

pub const Adler32 = struct {
    const Self = @This();
    const base: u32 = 65521;
    const nmax: usize = 5552;
    const block_size: usize = 32;
    const chunk_size: usize = nmax / block_size * block_size;

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

    // Full 32-byte blocks fold through the vectors; the tail runs scalar.
    // Entering sums must be reduced; leaving sums are reduced. The u16 column
    // and u32 lane bounds hold because one call covers at most nmax bytes.
    fn foldBlocks(s1: *u32, s2: *u32, data: []const u8) void {
        var index: usize = 0;
        if (data.len >= block_size) {
            const a_init = s1.*;
            var a_v: Words = @splat(0);
            var b_v: Words = @splat(0);
            var col1: Half16 = @splat(0);
            var col2: Half16 = @splat(0);
            var col3: Half16 = @splat(0);
            var col4: Half16 = @splat(0);
            while (index + block_size <= data.len) : (index += block_size) {
                const bytes1: Bytes16 = @as(Bytes16, data[index..][0..16].*);
                const bytes2: Bytes16 = @as(Bytes16, data[index + 16 ..][0..16].*);
                b_v +%= a_v;
                a_v +%= pairSumWiden(pairSumAcc(pairSum(bytes1), bytes2));
                col1 = byteAcc(col1, @shuffle(u8, bytes1, undefined, low_bytes));
                col2 = byteAcc(col2, @shuffle(u8, bytes1, undefined, high_bytes));
                col3 = byteAcc(col3, @shuffle(u8, bytes2, undefined, low_bytes));
                col4 = byteAcc(col4, @shuffle(u8, bytes2, undefined, high_bytes));
            }
            // Every lane of b_v counts whole 32-byte blocks behind the current
            // one, so one shift restores the block weights; the multiply pass
            // then adds the byte weights inside one block.
            b_v *%= @as(Words, @splat(32));
            b_v = weightAcc(b_v, @shuffle(u16, col1, undefined, low_halves), .{ 32, 31, 30, 29 });
            b_v = weightAcc(b_v, @shuffle(u16, col1, undefined, high_halves), .{ 28, 27, 26, 25 });
            b_v = weightAcc(b_v, @shuffle(u16, col2, undefined, low_halves), .{ 24, 23, 22, 21 });
            b_v = weightAcc(b_v, @shuffle(u16, col2, undefined, high_halves), .{ 20, 19, 18, 17 });
            b_v = weightAcc(b_v, @shuffle(u16, col3, undefined, low_halves), .{ 16, 15, 14, 13 });
            b_v = weightAcc(b_v, @shuffle(u16, col3, undefined, high_halves), .{ 12, 11, 10, 9 });
            b_v = weightAcc(b_v, @shuffle(u16, col4, undefined, low_halves), .{ 8, 7, 6, 5 });
            b_v = weightAcc(b_v, @shuffle(u16, col4, undefined, high_halves), .{ 4, 3, 2, 1 });
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

    fn permute(state: u32, input: []const u8) u32 {
        var s1 = state & 0xffff;
        var s2 = (state >> 16) & 0xffff;

        if (comptime has_neon) {
            var data = input;
            while (data.len >= chunk_size) {
                foldBlocks(&s1, &s2, data[0..chunk_size]);
                data = data[chunk_size..];
            }
            foldBlocks(&s1, &s2, data);
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
