const builtin = @import("builtin");
const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const merkle = @import("../merkle.zig");

// FIPS 180-1; RAR4's KDF and WinZIP AE-2 need SHA-1. OpenSSL crypto/sha/asm: each sha1c/p/m runs four rounds per lane.

const initial_state: [5]u32 = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

const has_arm8sha1 = !options.sha1_portable and builtin.target.cpu.arch == .aarch64 and
    builtin.zig_backend != .stage2_c and builtin.target.cpu.has(.aarch64, .sha2);

pub const Sha1 = merkle.Digest(5, 20, initial_state, compressSha1);

fn compressSha1(state: *align(16) [5]u32, block: *const [64]u8) void {
    if (comptime has_arm8sha1) {
        compressAarch64(state, block);
        return;
    }
    compressScalar(state, block);
}

// Twenty groups cover four rounds each with K pre-added; Zig cannot name S-register views, so registers stay pinned.
fn compressAarch64(state: *align(16) [5]u32, block: *const [64]u8) void {
    const V4u32 = @Vector(4, u32);
    const k4 = [4]V4u32{
        @splat(0x5A827999),
        @splat(0x6ED9EBA1),
        @splat(0x8F1BBCDC),
        @splat(0xCA62C1D6),
    };

    const words: [16]u32 = std.mem.bytesToValue([16]u32, block);
    var schedule: [4]V4u32 = undefined;
    inline for (0..4) |group| {
        schedule[group] = @byteSwap(@as(V4u32, words[4 * group ..][0..4].*));
    }

    var abcd: V4u32 = state[0..4].*;
    // The e operand is the v1 scalar view; sha1h zeroes lanes 1-3,
    // so e lanes 1-3 are never read.
    const e1: V4u32 = .{ state[4], 0, 0, 0 };
    var e2: V4u32 = undefined;
    var e3: V4u32 = undefined;

    inline for (0..20) |group| {
        if (group >= 4) {
            // W[i] = rol1(W[i-3]^W[i-8]^W[i-14]^W[i-16]).
            // The sha1su0/sha1su1 pair rotates the schedule across the oldest and newest groups.
            schedule[group % 4] = asm ("sha1su0.4s %[d], %[n], %[m]"
                : [d] "=w" (-> V4u32),
                : [_] "0" (schedule[group % 4]),
                  [n] "w" (schedule[(group + 1) % 4]),
                  [m] "w" (schedule[(group + 2) % 4]),
            );
            schedule[group % 4] = asm ("sha1su1.4s %[d], %[fourth]"
                : [d] "=w" (-> V4u32),
                : [_] "0" (schedule[group % 4]),
                  [fourth] "w" (schedule[(group + 3) % 4]),
            );
        }
        const wk: V4u32 = schedule[group % 4] +% k4[group / 5];
        const round = switch (group / 5) {
            0 => "c",
            1 => "p",
            2 => "m",
            else => "p",
        };
        // The next group's e is rol30 of the a entering this group.
        if (group % 2 == 1) {
            e3 = asm ("sha1h s3, s0"
                : [eout] "={v3}" (-> V4u32),
                : [abcd_ro] "{v0}" (abcd),
            );
        } else {
            e2 = asm ("sha1h s2, s0"
                : [eout] "={v2}" (-> V4u32),
                : [abcd_ro] "{v0}" (abcd),
            );
        }
        if (group == 0) {
            abcd = asm ("sha1" ++ round ++ ".4s q0, s1, %[wk]"
                : [abcd] "={v0}" (-> V4u32),
                : [_] "0" (abcd),
                  [wk] "w" (wk),
                  [ein] "{v1}" (e1),
            );
        } else if (group % 2 == 1) {
            abcd = asm ("sha1" ++ round ++ ".4s q0, s2, %[wk]"
                : [abcd] "={v0}" (-> V4u32),
                : [_] "0" (abcd),
                  [wk] "w" (wk),
                  [ein] "{v2}" (e2),
            );
        } else {
            abcd = asm ("sha1" ++ round ++ ".4s q0, s3, %[wk]"
                : [abcd] "={v0}" (-> V4u32),
                : [_] "0" (abcd),
                  [wk] "w" (wk),
                  [ein] "{v3}" (e3),
            );
        }
    }

    state[0..4].* = abcd +% @as(V4u32, state[0..4].*);
    // The last pre-group sha1h (group 19, odd) holds the terminal e in v3.
    state[4] = e1[0] +% e3[0];
}

// The circular schedule and comptime round groups remove per-round switches and the 80-word stack frame.
fn compressScalar(state: *align(16) [5]u32, block: *const [64]u8) void {
    var w: [16]u32 = undefined;
    for (0..16) |index| {
        w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    inline for ([4]u32{ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 }, 0..) |k, group| {
        inline for (0..20) |round| {
            const index: usize = group * 20 + round;
            if (index >= 16) {
                const value = w[(index - 3) & 15] ^ w[(index - 8) & 15] ^ w[(index - 14) & 15] ^ w[index & 15];
                w[index & 15] = std.math.rotl(u32, value, @as(u32, 1));
            }
            const f: u32 = switch (group) {
                0 => (b & c) | (~b & d),
                1 => b ^ c ^ d,
                2 => (b & c) | (b & d) | (c & d),
                else => b ^ c ^ d,
            };
            const t = std.math.rotl(u32, a, @as(u32, 5)) +% f +% e +% k +% w[index & 15];
            e = d;
            d = c;
            c = std.math.rotl(u32, b, @as(u32, 30));
            b = a;
            a = t;
        }
    }
    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
    state[4] +%= e;
}

test "sha1 hardware compression matches the scalar path" {
    if (comptime !has_arm8sha1) return error.SkipZigTest;
    try merkle.expectHwMatchesScalar(5, 20, initial_state, compressAarch64, compressScalar, 0x5A1D1);
}

test "sha1 onprem pins the fips 180-1 answers and tracks the stdlib oracle" {
    const testing = std.testing;

    // FIPS 180-1 pins the empty, short, and two-block answers.
    var empty = Sha1.init(.{});
    var digest: [20]u8 = undefined;
    empty.final(&digest);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 }, &digest);

    var abc = Sha1.init(.{});
    abc.update("abc");
    try testing.expectEqualSlices(u8, &[_]u8{ 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d }, &abc.finalResult());

    // Split feeds prove the second block consumes buffered state.
    var two_block = Sha1.init(.{});
    two_block.update("abcdbcdecdefdefgefghfghighij");
    two_block.update("hijkijkljklmklmnlmnomnopnopq");
    try testing.expectEqualSlices(u8, &[_]u8{ 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 }, &two_block.finalResult());

    try seam.expectAgreement(Sha1.init(.{}), std.crypto.hash.Sha1.init(.{}), 0x5A1, true, null);
}
