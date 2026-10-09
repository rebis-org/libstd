const std = @import("std");
const builtin = @import("builtin");

// FIPS 180-4.
// The scalar loop is needed as a portable fallback for targets without the aarch64 sha2 extension.

pub const Sha256 = struct {
    const Self = @This();

    pub const block_length = 64;
    pub const digest_length = 32;
    pub const Options = struct {};

    state: [8]u32 align(16),
    buffer: [64]u8 = undefined,
    buffered: u8 = 0,
    total: u64 = 0,

    pub fn init(_: Options) Self {
        return .{ .state = .{
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        } };
    }

    pub fn hash(input: []const u8, out: *[digest_length]u8, options: Options) void {
        var hasher = Self.init(options);
        hasher.update(input);
        hasher.final(out);
    }

    pub fn update(self: *Self, input: []const u8) void {
        var remaining = input;
        if (self.buffered != 0 and self.buffered + remaining.len >= 64) {
            const take = 64 - self.buffered;
            @memcpy(self.buffer[self.buffered..][0..take], remaining[0..take]);
            self.round(&self.buffer);
            self.buffered = 0;
            remaining = remaining[take..];
        }
        while (remaining.len >= 64) {
            self.round(remaining[0..64]);
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
            self.round(&self.buffer);
            self.buffered = 0;
        }
        @memset(self.buffer[self.buffered..56], 0);
        std.mem.writeInt(u64, self.buffer[56..64], bit_length, .big);
        self.round(&self.buffer);
        for (self.state, 0..) |word, index| {
            std.mem.writeInt(u32, out[4 * index ..][0..4], word, .big);
        }
    }

    pub fn finalResult(self: *Self) [digest_length]u8 {
        var out: [digest_length]u8 = undefined;
        self.final(&out);
        return out;
    }

    fn round(self: *Self, block: *const [64]u8) void {
        var w: [64]u32 align(16) = undefined;
        for (0..16) |index| {
            w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
        }
        if (comptime builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and builtin.cpu.has(.aarch64, .sha2)) {
            compressAarch64(&self.state, &w);
            return;
        }
        for (16..64) |index| {
            const lower = w[index - 15];
            const upper = w[index - 2];
            w[index] = w[index - 16] +% w[index - 7] +%
                (std.math.rotr(u32, lower, 7) ^ std.math.rotr(u32, lower, 18) ^ (lower >> 3)) +%
                (std.math.rotr(u32, upper, 17) ^ std.math.rotr(u32, upper, 19) ^ (upper >> 10));
        }
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        var f = self.state[5];
        var g = self.state[6];
        var h = self.state[7];
        for (0..64) |index| {
            const sum1 = std.math.rotr(u32, e, 6) ^ std.math.rotr(u32, e, 11) ^ std.math.rotr(u32, e, 25);
            const choice = (e & f) ^ (~e & g);
            const sum0 = std.math.rotr(u32, a, 2) ^ std.math.rotr(u32, a, 13) ^ std.math.rotr(u32, a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const t1 = h +% sum1 +% choice +% k[index] +% w[index];
            const t2 = sum0 +% majority;
            h = g;
            g = f;
            f = e;
            e = d +% t1;
            d = c;
            c = b;
            b = a;
            a = t1 +% t2;
        }
        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
        self.state[5] +%= f;
        self.state[6] +%= g;
        self.state[7] +%= h;
    }

    // sha256h/h2 carry a full round each; su0/su1 build the message schedule.
    fn compressAarch64(state: *align(16) [8]u32, w: *align(16) [64]u32) void {
        const V4u32 = @Vector(4, u32);
        var x: V4u32 = state[0..4].*;
        var y: V4u32 = state[4..8].*;
        const w_v = @as(*[16]V4u32, @ptrCast(w));

        comptime var round_group: u8 = 0;
        inline while (round_group < 16) : (round_group += 1) {
            if (round_group > 3) {
                w_v[round_group] = asm (
                    \\sha256su0.4s %[w0_3], %[w4_7]
                    \\sha256su1.4s %[w0_3], %[w8_11], %[w12_15]
                    : [w0_3] "=&w" (-> V4u32),
                    : [_] "0" (w_v[round_group - 4]),
                      [w4_7] "w" (w_v[round_group - 3]),
                      [w8_11] "w" (w_v[round_group - 2]),
                      [w12_15] "w" (w_v[round_group - 1]),
                );
            }

            const wk: V4u32 = w_v[round_group] +% @as(V4u32, k[4 * round_group ..][0..4].*);
            asm volatile (
                \\mov.4s v0, %[x]
                \\sha256h.4s %[x], %[y], %[wk]
                \\sha256h2.4s %[y], v0, %[wk]
                : [x] "=w" (x),
                  [y] "=w" (y),
                : [_] "0" (x),
                  [_] "1" (y),
                  [wk] "w" (wk),
                : .{ .v0 = true });
        }

        state[0..4].* = x +% @as(V4u32, state[0..4].*);
        state[4..8].* = y +% @as(V4u32, state[4..8].*);
    }

    const k = [64]u32{
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    };
};

test "sha256 onprem matches the std oracle" {
    var rng = std.Random.DefaultPrng.init(0x5A256);
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        var ours = Sha256.init(.{});
        ours.update(buf[0 .. size / 2]);
        ours.update(buf[size / 2 ..]);
        var theirs = std.crypto.hash.sha2.Sha256.init(.{});
        theirs.update(buf);
        try std.testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
    }
    const long = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(long);
    rng.random().bytes(long);
    var ours = Sha256.init(.{});
    ours.update(long);
    var theirs = std.crypto.hash.sha2.Sha256.init(.{});
    theirs.update(long);
    try std.testing.expectEqualSlices(u8, &theirs.finalResult(), &ours.finalResult());
}
