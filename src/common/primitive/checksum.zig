const builtin = @import("builtin");
const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const adler32_seam = @import("hash/adler32/seam.zig");
const xxh32_seam = @import("hash/xxh32/seam.zig");
const xxh64_seam = @import("hash/xxh64/seam.zig");

pub const Provider = seam.Provider;
pub const default_provider = seam.default_provider;
pub const Adler32 = adler32_seam.Inner;
pub const XxHash32 = xxh32_seam.XxHash32;
pub const XxHash64 = xxh64_seam.XxHash64;

// Zig inline asm cannot name the 32-bit register views, so the crc32 instructions bind fixed X registers.

const crc32_hw = builtin.target.cpu.arch == .aarch64 and !options.crc32_portable;
const has_crc32_kernel = crc32_hw and builtin.target.cpu.has(.aarch64, .crc);
// LLVM's aes feature implies pmull, which the fold kernel multiplies with.
const has_crc32_pmull = has_crc32_kernel and builtin.target.cpu.has(.aarch64, .aes);
const crc64_hw = builtin.target.cpu.arch == .aarch64 and !options.crc64xz_portable;
const has_crc64_pmull = crc64_hw and builtin.target.cpu.has(.aarch64, .aes);
// PCLMULQDQ multiplies carry-less like PMULL, so the fold kernels below stay shared.
const x86_clmul = builtin.target.cpu.arch == .x86_64 and
    builtin.zig_backend != .stage2_c and
    builtin.target.cpu.has(.x86, .pclmul);
const has_crc32_clmul = x86_clmul and !options.crc32_portable;
const has_crc64_clmul = x86_clmul and !options.crc64xz_portable;

const crc_lane = @Vector(2, u64);

// Fold constants for the reflected CRC32 polynomial 0xEDB88320 (vendor 7zCrc arm64 literal pool).
const crc32_fold_k = FoldK{
    .k0 = .{ 0x000000008f352d95, 0x000000001d9513d7 },
    .k1 = .{ 0x00000000ae689191, 0x00000000ccaa009e },
    .k2 = .{ 0x00000000f1da05aa, 0x0000000081256527 },
    .k3 = .{ 0x0000000033fff533, 0x00000000910eeec1 },
};

inline fn crc32x(crc: u32, word: u64) u32 {
    return asm ("crc32x w8, w8, x9"
        : [ret] "={x8}" (-> u32),
        : [crc] "{x8}" (crc),
          [word] "{x9}" (word),
    );
}

inline fn crc32w(crc: u32, data: u32) u32 {
    return asm ("crc32w w8, w8, w9"
        : [ret] "={x8}" (-> u32),
        : [crc] "{x8}" (crc),
          [data] "{x9}" (data),
    );
}

inline fn crc32b(crc: u32, data: u8) u32 {
    return asm ("crc32b w8, w8, w9"
        : [ret] "={x8}" (-> u32),
        : [crc] "{x8}" (crc),
          [data] "{x9}" (data),
    );
}

inline fn pmull1(a: crc_lane, b: crc_lane) crc_lane {
    return asm ("pmull %[ret].1q, %[a].1d, %[b].1d"
        : [ret] "=x" (-> crc_lane),
        : [a] "x" (a),
          [b] "x" (b),
    );
}

inline fn pmull2(a: crc_lane, b: crc_lane) crc_lane {
    return asm ("pmull2 %[ret].1q, %[a].2d, %[b].2d"
        : [ret] "=x" (-> crc_lane),
        : [a] "x" (a),
          [b] "x" (b),
    );
}

// PCLMULQDQ counterpart of the PMULL pair; the early-clobber output copies first because
// the instruction cannot write a tied operand. Encoding per Chromium zlib crc32_simd.c.
inline fn clmul1(a: crc_lane, b: crc_lane) crc_lane {
    return asm (
        \\ movdqa     %[a], %[ret]
        \\ pclmulqdq  $0, %[b], %[ret]
        : [ret] "=&x" (-> crc_lane),
        : [a] "x" (a),
          [b] "x" (b),
    );
}

inline fn clmul2(a: crc_lane, b: crc_lane) crc_lane {
    return asm (
        \\ movdqa     %[a], %[ret]
        \\ pclmulqdq  $0x11, %[b], %[ret]
        : [ret] "=&x" (-> crc_lane),
        : [a] "x" (a),
          [b] "x" (b),
    );
}

inline fn foldLane(lane: crc_lane, input: crc_lane, k: crc_lane) crc_lane {
    if (comptime builtin.target.cpu.arch == .aarch64) {
        return pmull1(lane, k) ^ input ^ pmull2(lane, k);
    } else {
        return clmul1(lane, k) ^ input ^ clmul2(lane, k);
    }
}

// One 16-byte load per lane. The helper must inline: a call in the fold loop
// costs more than the load itself, because no q register survives a call.
inline fn loadLane(bytes: *const [16]u8) crc_lane {
    const lane: *align(1) const crc_lane = @ptrCast(bytes);
    return lane.*;
}

fn crc32Aarch64Scalar(crc_in: u32, input: []const u8) u32 {
    var crc = crc_in;
    var data = input;
    while (data.len >= 8) {
        crc = crc32x(crc, std.mem.readInt(u64, data[0..8], .little));
        data = data[8..];
    }
    if (data.len >= 4) {
        crc = crc32w(crc, std.mem.readInt(u32, data[0..4], .little));
        data = data[4..];
    }
    for (data) |byte| crc = crc32b(crc, byte);
    return crc;
}

const Crc32Aarch64Tail = struct {
    const folds_16_byte_lanes = true;

    inline fn byte(crc: u32, data: u8) u32 {
        return crc32b(crc, data);
    }

    inline fn word(crc: u32, data: u64) u32 {
        return crc32x(crc, data);
    }
};

const FoldK = struct { k0: crc_lane, k1: crc_lane, k2: crc_lane, k3: crc_lane };

// Carry-less fold state (PMULL or PCLMULQDQ) shared by every width; the
// caller routes only inputs at or above crc_pmull_threshold, because folding
// costs a fixed setup that short inputs never repay. The tail re-enters the
// folded state and drains the remainder: hardware CRC steps on aarch64,
// table steps where no such instruction exists.
fn crcFold(comptime T: type, comptime K: FoldK, crc_in: T, input: []const u8, comptime Tail: type) T {
    var crc = crc_in;
    var data = input;
    while (data.len != 0 and @intFromPtr(data.ptr) & 15 != 0) {
        crc = Tail.byte(crc, data[0]);
        data = data[1..];
    }
    if (data.len >= 128) {
        var lanes: [8]crc_lane = undefined;
        for (0..8) |i| {
            lanes[i] = loadLane(data[i * 16 ..][0..16]);
        }
        lanes[0][0] ^= crc;
        data = data[128..];
        while (data.len >= 128) {
            for (0..8) |i| {
                lanes[i] = foldLane(lanes[i], loadLane(data[i * 16 ..][0..16]), K.k3);
            }
            data = data[128..];
        }
        lanes[0] = foldLane(lanes[0], lanes[1], K.k1);
        lanes[2] = foldLane(lanes[2], lanes[3], K.k1);
        lanes[4] = foldLane(lanes[4], lanes[5], K.k1);
        lanes[6] = foldLane(lanes[6], lanes[7], K.k1);
        lanes[0] = foldLane(lanes[0], lanes[2], K.k2);
        lanes[4] = foldLane(lanes[4], lanes[6], K.k2);
        lanes[0] = foldLane(lanes[0], lanes[4], K.k0);
        crc = Tail.word(0, lanes[0][0]);
        crc = Tail.word(crc, lanes[0][1]);
    }
    if (data.len >= 64) {
        var lanes: [4]crc_lane = undefined;
        for (0..4) |i| {
            lanes[i] = loadLane(data[i * 16 ..][0..16]);
        }
        lanes[0][0] ^= crc;
        data = data[64..];
        while (data.len >= 64) {
            for (0..4) |i| {
                lanes[i] = foldLane(lanes[i], loadLane(data[i * 16 ..][0..16]), K.k0);
            }
            data = data[64..];
        }
        lanes[0] = foldLane(lanes[0], lanes[1], K.k1);
        lanes[2] = foldLane(lanes[2], lanes[3], K.k1);
        lanes[0] = foldLane(lanes[0], lanes[2], K.k2);
        crc = Tail.word(0, lanes[0][0]);
        crc = Tail.word(crc, lanes[0][1]);
    }
    if (comptime Tail.folds_16_byte_lanes) {
        if (data.len >= 16) {
            var lane = loadLane(data[0..16]);
            lane[0] ^= crc;
            data = data[16..];
            while (data.len >= 16) {
                lane = foldLane(lane, loadLane(data[0..16]), K.k1);
                data = data[16..];
            }
            crc = Tail.word(0, lane[0]);
            crc = Tail.word(crc, lane[1]);
        }
    }
    while (data.len >= 8) {
        crc = Tail.word(crc, std.mem.readInt(u64, data[0..8], .little));
        data = data[8..];
    }
    for (data) |byte| crc = Tail.byte(crc, byte);
    return crc;
}

// A chain of 16-byte lanes ending in table steps loses to slicing-by-8, so
// the table tail never folds here; it drains whole words instead.
fn Crc32TableTail(comptime tables: *const [8][256]u32) type {
    return struct {
        const folds_16_byte_lanes = false;

        inline fn byte(crc: u32, data: u8) u32 {
            return (crc >> 8) ^ tables[0][@as(usize, @intCast((crc ^ data) & 0xff))];
        }

        inline fn word(crc: u32, data: u64) u32 {
            return fold8(u32, tables, true, crc, &std.mem.toBytes(data));
        }
    };
}

fn Crc64Tail(comptime tables: *const [8][256]u64) type {
    return struct {
        const folds_16_byte_lanes = true;

        inline fn byte(crc: u64, data: u8) u64 {
            return (crc >> 8) ^ tables[0][(crc ^ data) & 0xff];
        }

        inline fn word(crc: u64, data: u64) u64 {
            return fold8(u64, tables, true, crc, &std.mem.toBytes(data));
        }
    };
}

// CRC-64/XZ (reflected ECMA polynomial) fold constants. A fold by shift s pairs x^s with
// x^(s-64), and deriving them at comptime from the recurrence keeps them in step with the table.
const crc64_poly: u64 = 0xC96C5795D7870F42;

fn crc64Xpow(comptime n: u16) u64 {
    // The same register recurrence as the byte table, from x^0 = 1.
    @setEvalBranchQuota(4 * n + 64);
    var v: u64 = 1;
    for (0..n) |_| {
        v = (v >> 1) ^ (if (v & 1 != 0) crc64_poly else 0);
    }
    return v;
}

const crc64_fold_k = FoldK{
    .k0 = .{ crc64Xpow(512), crc64Xpow(448) },
    .k1 = .{ crc64Xpow(128), crc64Xpow(64) },
    .k2 = .{ crc64Xpow(256), crc64Xpow(192) },
    .k3 = .{ crc64Xpow(1024), crc64Xpow(960) },
};

// Folding pays off above this length; the threshold comes from a synthetic sweep.
const crc_pmull_threshold = 256;

const OnpremCrc32 = TableCrc(u32, 0xedb8_8320, true);
const OnpremXzCrc64 = TableCrc(u64, 0xc96c5795d7870f42, true);
const OnpremBzip2Crc32 = TableCrc(u32, 0x04c11db7, false);

pub const Crc32 = seam.Checksum(options.crc32_impl, OnpremCrc32, std.hash.Crc32);
pub const XzCrc64 = seam.Checksum(options.crc64xz_impl, OnpremXzCrc64, std.hash.crc.@"CRC-64/XZ");
pub const Bzip2Crc32 = seam.Checksum(options.bzip2crc32_impl, OnpremBzip2Crc32, std.hash.crc.@"CRC-32/BZIP2");

// A one-shot over any bound checksum: bind, feed the whole input, finish.
fn seal(comptime H: type, bound: H, input: []const u8) @typeInfo(@TypeOf(H.final)).@"fn".return_type.? {
    var hash = bound;
    hash.update(input);
    return hash.final();
}

pub fn crc32(input: []const u8) u32 {
    return crc32With(default_provider, input);
}

pub fn crc32With(provider: seam.Provider, input: []const u8) u32 {
    return seal(Crc32, Crc32.bind(provider), input);
}

pub fn xxh64(input: []const u8) u64 {
    return xxh64With(default_provider, input);
}

pub fn xxh64With(provider: seam.Provider, input: []const u8) u64 {
    return seal(XxHash64, XxHash64.bind(provider, 0), input);
}

pub fn adler32(input: []const u8) u32 {
    return adler32With(default_provider, input);
}

pub fn adler32With(provider: seam.Provider, input: []const u8) u32 {
    return seal(Adler32, Adler32.bind(provider), input);
}

pub fn xxh32(input: []const u8) u32 {
    return xxh32With(default_provider, input);
}

pub fn xxh32With(provider: seam.Provider, input: []const u8) u32 {
    return seal(XxHash32, XxHash32.bind(provider, 0), input);
}

// One slicing-by-8 step over eight input bytes; the table index order is
// the reflected xz layout (crc32_fast.c / crc64_fast.c) and the big-endian
// braid (crc32_table_be.h), selected by comptime direction.
inline fn fold8(comptime T: type, comptime tables: *const [8][256]T, comptime reflected: bool, crc: T, chunk: *const [8]u8) T {
    if (comptime reflected) {
        const bytes_per_word = @bitSizeOf(T) / 8;
        const words = 8 / bytes_per_word;
        var out: T = 0;
        var x = crc;
        inline for (0..words) |wi| {
            const w = x ^ std.mem.readInt(T, chunk[wi * bytes_per_word ..][0..bytes_per_word], .little);
            x = 0;
            inline for (0..bytes_per_word) |bi| {
                out ^= tables[7 - wi * bytes_per_word - bi][@as(usize, @intCast((w >> (bi * 8)) & 0xff))];
            }
        }
        return out;
    } else {
        var c = crc ^ std.mem.readInt(u32, chunk[0..4], .big);
        c = tables[7][@as(usize, @intCast((c >> 24) & 0xff))] ^
            tables[6][@as(usize, @intCast((c >> 16) & 0xff))] ^
            tables[5][@as(usize, @intCast((c >> 8) & 0xff))] ^
            tables[4][@as(usize, @intCast(c & 0xff))];
        const v = std.mem.readInt(u32, chunk[4..8], .big);
        return c ^ tables[3][@as(usize, @intCast((v >> 24) & 0xff))] ^
            tables[2][@as(usize, @intCast((v >> 16) & 0xff))] ^
            tables[1][@as(usize, @intCast((v >> 8) & 0xff))] ^
            tables[0][@as(usize, @intCast(v & 0xff))];
    }
}

inline fn fold4(comptime T: type, comptime tables: *const [8][256]T, crc: T, chunk: *const [4]u8) T {
    const w: T = (crc & 0xffff_ffff) ^ std.mem.readInt(u32, chunk[0..4], .little);
    var out: T = tables[3][@as(usize, @intCast(w & 0xff))] ^
        tables[2][@as(usize, @intCast((w >> 8) & 0xff))] ^
        tables[1][@as(usize, @intCast((w >> 16) & 0xff))] ^
        tables[0][@as(usize, @intCast((w >> 24) & 0xff))];
    if (comptime T == u64) out ^= crc >> 32;
    return out;
}

fn TableCrc(comptime T: type, comptime poly: T, comptime reflected: bool) type {
    const bits = @bitSizeOf(T);
    return struct {
        state: T,

        pub fn init() @This() {
            return .{ .state = ~@as(T, 0) };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            if (comptime T == u32 and reflected) {
                if (comptime has_crc32_kernel) {
                    if (input.len >= crc_pmull_threshold and comptime has_crc32_pmull) {
                        self.state = crcFold(u32, crc32_fold_k, self.state, input, Crc32Aarch64Tail);
                    } else {
                        self.state = crc32Aarch64Scalar(self.state, input);
                    }
                    return;
                }
                if (comptime has_crc32_clmul) {
                    if (input.len >= crc_pmull_threshold) {
                        self.state = crcFold(u32, crc32_fold_k, self.state, input, Crc32TableTail(&tables));
                        return;
                    }
                }
                var crc = self.state;
                var i: usize = 0;
                while (i + 8 <= input.len) : (i += 8) {
                    crc = fold8(u32, &tables, true, crc, input[i..][0..8]);
                }
                if (i + 4 <= input.len) {
                    crc = fold4(u32, &tables, crc, input[i..][0..4]);
                    i += 4;
                }
                while (i < input.len) : (i += 1) {
                    crc = (crc >> 8) ^ table[@as(usize, @intCast((crc ^ input[i]) & 0xff))];
                }
                self.state = crc;
                return;
            }
            if (comptime reflected) {
                if (comptime T == u64 and (has_crc64_pmull or has_crc64_clmul)) {
                    if (input.len >= crc_pmull_threshold) {
                        self.state = crcFold(u64, crc64_fold_k, self.state, input, Crc64Tail(&tables));
                        return;
                    }
                }
                var crc = self.state;
                var i: usize = 0;
                while (i + 8 <= input.len) : (i += 8) {
                    crc = fold8(u64, &tables, true, crc, input[i..][0..8]);
                }
                if (i + 4 <= input.len) {
                    crc = fold4(u64, &tables, crc, input[i..][0..4]);
                    i += 4;
                }
                while (i < input.len) : (i += 1) {
                    crc = (crc >> 8) ^ table[@as(usize, @intCast((crc ^ input[i]) & 0xff))];
                }
                self.state = crc;
            } else {
                var crc = self.state;
                var i: usize = 0;
                while (i + 8 <= input.len) : (i += 8) {
                    crc = fold8(u32, &tables, false, crc, input[i..][0..8]);
                }
                if (i + 4 <= input.len) {
                    crc ^= std.mem.readInt(u32, input[i..][0..4], .big);
                    crc = tables[3][(crc >> 24) & 0xff] ^
                        tables[2][((crc >> 16) & 0xff)] ^
                        tables[1][((crc >> 8) & 0xff)] ^
                        tables[0][crc & 0xff];
                    i += 4;
                }
                while (i < input.len) : (i += 1) {
                    crc = (crc << 8) ^ table[((crc >> (bits - 8)) ^ input[i]) & 0xff];
                }
                self.state = crc;
            }
        }

        pub fn final(self: *const @This()) T {
            return ~self.state;
        }

        const table: [256]T = blk: {
            @setEvalBranchQuota(10000);
            var t: [256]T = undefined;
            for (0..256) |i| {
                var crc: T = if (reflected) @intCast(i) else @as(T, @intCast(i)) << @intCast(bits - 8);
                var j: u32 = 0;
                while (j < 8) : (j += 1) {
                    if (reflected) {
                        crc = if (crc & 1 != 0) (crc >> 1) ^ poly else crc >> 1;
                    } else {
                        const high: T = @as(T, 1) << @intCast(bits - 1);
                        crc = if (crc & high != 0) (crc << 1) ^ poly else crc << 1;
                    }
                }
                t[i] = crc;
            }
            break :blk t;
        };

        const tables: [8][256]T = blk: {
            @setEvalBranchQuota(20000);
            var t: [8][256]T = undefined;
            if (reflected) {
                for (0..256) |i| {
                    var crc: T = table[i];
                    t[0][i] = crc;
                    for (1..8) |k| {
                        crc = table[@intCast(crc & 0xff)] ^ (crc >> 8);
                        t[k][i] = crc;
                    }
                }
            } else {
                for (0..256) |i| t[0][i] = table[i];
                for (1..8) |k| {
                    for (0..256) |i| {
                        const prev = t[k - 1][i];
                        t[k][i] = (prev << 8) ^ table[(prev >> (bits - 8)) & 0xff];
                    }
                }
            }
            break :blk t;
        };
    };
}

test "xxh32 matches the published vectors" {
    try std.testing.expectEqual(@as(u32, 0x02CC5D05), xxh32(""));
    try std.testing.expectEqual(@as(u32, 0x550D7456), xxh32("a"));
    try std.testing.expectEqual(@as(u32, 0x32D153FF), xxh32("abc"));
    try std.testing.expectEqual(@as(u32, 0xE2293B2F), xxh32("Nobody inspects the spammish repetition"));
}

test "adler32 matches the published vectors" {
    try std.testing.expectEqual(@as(u32, 0x00000001), adler32(""));
    try std.testing.expectEqual(@as(u32, 0x091E01DE), adler32("123456789"));
    try std.testing.expectEqual(@as(u32, 0x11E60398), adler32("Wikipedia"));
    var hasher = Adler32.init();
    hasher.update("1234");
    hasher.update("56789");
    try std.testing.expectEqual(@as(u32, 0x091E01DE), hasher.final());
}

test "crc32 matches the published vectors" {
    try std.testing.expectEqual(@as(u32, 0x00000000), crc32(""));
    try std.testing.expectEqual(@as(u32, 0xCBF43926), crc32("123456789"));
    var hash = Crc32.init();
    hash.update("1234");
    hash.update("56789");
    try std.testing.expectEqual(crc32("123456789"), hash.final());
}

test "crc32 matches std.hash.Crc32 across sizes" {
    // Sizes hit every tail bucket, and the split update exercises the streaming state
    // across kernel switches.
    var rng = std.Random.DefaultPrng.init(0xC32C);
    const allocator = std.testing.allocator;
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try allocator.alloc(u8, size);
        rng.random().bytes(buf);
        try std.testing.expectEqual(std.hash.Crc32.hash(buf), crc32(buf));
        allocator.free(buf);
    }
    var big: usize = 4096;
    while (big <= 1 << 20) : (big += 65521) {
        const buf = try allocator.alloc(u8, big);
        rng.random().bytes(buf);
        try std.testing.expectEqual(std.hash.Crc32.hash(buf), crc32(buf));
        var hash = Crc32.init();
        hash.update(buf[0 .. big / 3]);
        hash.update(buf[big / 3 ..]);
        try std.testing.expectEqual(std.hash.Crc32.hash(buf), hash.final());
        allocator.free(buf);
    }
}

test "xxh64 matches the published vectors" {
    try std.testing.expectEqual(@as(u64, 0xEF46DB3751D8E999), xxh64(""));
    try std.testing.expectEqual(@as(u64, 0xD24EC4F1A98C6E5B), xxh64("a"));
    var hasher = XxHash64.init(0);
    hasher.update("hello ");
    hasher.update("world");
    try std.testing.expectEqual(xxh64("hello world"), hasher.final());
}

test "crc64 xz matches the reference vectors" {
    var hash = XzCrc64.init();
    hash.update("123456789");
    try std.testing.expectEqual(@as(u64, 0x995DC9BBDF1939FA), hash.final());
    var hasher = XzCrc64.init();
    hasher.update("1234");
    hasher.update("56789");
    try std.testing.expectEqual(@as(u64, 0x995DC9BBDF1939FA), hasher.final());
}

test "bzip2 crc32 matches the published check value" {
    var hash = Bzip2Crc32.init();
    hash.update("123456789");
    try std.testing.expectEqual(@as(u32, 0xFC891918), hash.final());
    var hasher = Bzip2Crc32.init();
    hasher.update("1234");
    hasher.update("56789");
    try std.testing.expectEqual(@as(u32, 0xFC891918), hasher.final());
}

test "crc64 xz fold matches the byte table across sizes" {
    // The portable byte table is the reference, because that is the only path a non-aarch64 target runs.
    var rng = std.Random.DefaultPrng.init(0xC64C);
    const allocator = std.testing.allocator;
    const table = comptime blk: {
        @setEvalBranchQuota(10000);
        var t: [256]u64 = undefined;
        for (0..256) |i| {
            var crc: u64 = @intCast(i);
            for (0..8) |_| {
                crc = if (crc & 1 != 0) (crc >> 1) ^ 0xC96C5795D7870F42 else crc >> 1;
            }
            t[i] = crc;
        }
        break :blk t;
    };
    var size: usize = 0;
    while (size <= 2048) : (size += 1) {
        const buf = try allocator.alloc(u8, size);
        rng.random().bytes(buf);
        var fast = XzCrc64.init();
        fast.update(buf);
        var raw: u64 = ~@as(u64, 0);
        for (buf) |b| raw = (raw >> 8) ^ table[(raw ^ b) & 0xff];
        try std.testing.expectEqual(~raw, fast.final());
        allocator.free(buf);
    }
    var big: usize = 4096;
    while (big <= 1 << 20) : (big += 65521) {
        const buf = try allocator.alloc(u8, big);
        rng.random().bytes(buf);
        var fast = XzCrc64.init();
        fast.update(buf[0 .. big / 3]);
        fast.update(buf[big / 3 ..]);
        var raw: u64 = ~@as(u64, 0);
        for (buf) |b| raw = (raw >> 8) ^ table[(raw ^ b) & 0xff];
        try std.testing.expectEqual(~raw, fast.final());
        allocator.free(buf);
    }
}

test "checksum capabilities agree across providers when mergeable" {
    const all_mergeable = options.crc32_impl == .mergeable and
        options.crc64xz_impl == .mergeable and
        options.bzip2crc32_impl == .mergeable and
        options.xxh32_impl == .mergeable and
        options.xxh64_impl == .mergeable and
        options.adler32_impl == .mergeable;
    if (!all_mergeable) return error.SkipZigTest;
    var rng = std.Random.DefaultPrng.init(0xCC4C);
    const allocator = std.testing.allocator;
    var size: usize = 0;
    while (size <= 512) : (size += 13) {
        const buf = try allocator.alloc(u8, size);
        defer allocator.free(buf);
        rng.random().bytes(buf);
        var crc_on = Crc32.bind(.onprem);
        crc_on.update(buf);
        var crc_off = Crc32.bind(.offprem);
        crc_off.update(buf);
        try std.testing.expectEqual(crc_on.final(), crc_off.final());
        var xz_on = XzCrc64.bind(.onprem);
        xz_on.update(buf[0 .. buf.len / 2]);
        xz_on.update(buf[buf.len / 2 ..]);
        var xz_off = XzCrc64.bind(.offprem);
        xz_off.update(buf);
        try std.testing.expectEqual(xz_on.final(), xz_off.final());
        var bz_on = Bzip2Crc32.bind(.onprem);
        bz_on.update(buf);
        var bz_off = Bzip2Crc32.bind(.offprem);
        bz_off.update(buf);
        try std.testing.expectEqual(bz_on.final(), bz_off.final());
        var x32_on = XxHash32.bind(.onprem, 0);
        x32_on.update(buf);
        var x32_off = XxHash32.bind(.offprem, 0);
        x32_off.update(buf);
        try std.testing.expectEqual(x32_on.final(), x32_off.final());
        var x64_on = XxHash64.bind(.onprem, 0);
        x64_on.update(buf[0 .. buf.len / 3]);
        x64_on.update(buf[buf.len / 3 ..]);
        var x64_off = XxHash64.bind(.offprem, 0);
        x64_off.update(buf);
        try std.testing.expectEqual(x64_on.final(), x64_off.final());
        var ad_on = Adler32.bind(.onprem);
        ad_on.update(buf);
        var ad_off = Adler32.bind(.offprem);
        ad_off.update(buf);
        try std.testing.expectEqual(ad_on.final(), ad_off.final());
    }
}
