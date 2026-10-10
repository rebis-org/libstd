const std = @import("std");
const builtin = @import("builtin");

const options = @import("options");
const seam = @import("seam");

// Zig inline asm cannot name the 32-bit register views, so the crc32 instructions bind
// fixed X registers. The fold mirrors the vendor ip7z/7zip arm64 loop.
const crc32_hw = builtin.cpu.arch == .aarch64 and !options.crc32_portable;
const has_crc32_kernel = crc32_hw and builtin.cpu.has(.aarch64, .crc);
// LLVM's aes feature implies pmull, which the fold kernel multiplies with.
const has_crc32_pmull = has_crc32_kernel and builtin.cpu.has(.aarch64, .aes);
const crc64_hw = builtin.cpu.arch == .aarch64 and !options.crc64xz_portable;
const has_crc64_pmull = crc64_hw and builtin.cpu.has(.aarch64, .aes);

const crc_lane = @Vector(2, u64);

// Fold constants for the reflected CRC32 polynomial 0xEDB88320 (vendor 7zCrc arm64 literal pool).
const crc_k0: crc_lane = .{ 0x000000008f352d95, 0x000000001d9513d7 };
const crc_k1: crc_lane = .{ 0x00000000ae689191, 0x00000000ccaa009e };
const crc_k2: crc_lane = .{ 0x00000000f1da05aa, 0x0000000081256527 };

fn crc32x(crc: u32, data: u64) u32 {
    return asm ("crc32x w8, w8, x9"
        : [ret] "={x8}" (-> u32),
        : [crc] "{x8}" (crc),
          [data] "{x9}" (data),
    );
}

fn crc32w(crc: u32, data: u32) u32 {
    return asm ("crc32w w8, w8, w9"
        : [ret] "={x8}" (-> u32),
        : [crc] "{x8}" (crc),
          [data] "{x9}" (data),
    );
}

fn crc32b(crc: u32, data: u8) u32 {
    return asm ("crc32b w8, w8, w9"
        : [ret] "={x8}" (-> u32),
        : [crc] "{x8}" (crc),
          [data] "{x9}" (data),
    );
}

fn pmull1(a: crc_lane, b: crc_lane) crc_lane {
    return asm ("pmull %[ret].1q, %[a].1d, %[b].1d"
        : [ret] "=x" (-> crc_lane),
        : [a] "x" (a),
          [b] "x" (b),
    );
}

fn pmull2(a: crc_lane, b: crc_lane) crc_lane {
    return asm ("pmull2 %[ret].1q, %[a].2d, %[b].2d"
        : [ret] "=x" (-> crc_lane),
        : [a] "x" (a),
          [b] "x" (b),
    );
}

fn foldLane(lane: crc_lane, data: crc_lane, k: crc_lane) crc_lane {
    return pmull1(lane, k) ^ data ^ pmull2(lane, k);
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

// CRC32 state via four-lane PMULL folding. The caller routes only inputs at or above
// crc32_pmull_threshold, because folding costs a fixed setup that short inputs never repay.
fn crc32Aarch64Fold(crc_in: u32, input: []const u8) u32 {
    var crc = crc_in;
    var data = input;
    while (data.len != 0 and @intFromPtr(data.ptr) & 15 != 0) {
        crc = crc32b(crc, data[0]);
        data = data[1..];
    }
    if (data.len >= 64) {
        var lanes: [4]crc_lane = undefined;
        for (0..4) |i| {
            lanes[i] = std.mem.bytesToValue(crc_lane, data[i * 16 ..][0..16]);
        }
        lanes[0][0] ^= crc;
        data = data[64..];
        while (data.len >= 64) {
            for (0..4) |i| {
                lanes[i] = foldLane(lanes[i], std.mem.bytesToValue(crc_lane, data[i * 16 ..][0..16]), crc_k0);
            }
            data = data[64..];
        }
        lanes[0] = foldLane(lanes[0], lanes[1], crc_k1);
        lanes[2] = foldLane(lanes[2], lanes[3], crc_k1);
        lanes[0] = foldLane(lanes[0], lanes[2], crc_k2);
        crc = crc32x(0, lanes[0][0]);
        crc = crc32x(crc, lanes[0][1]);
    }
    while (data.len >= 16) {
        var lane = std.mem.bytesToValue(crc_lane, data[0..16]);
        lane[0] ^= crc;
        data = data[16..];
        while (data.len >= 16) {
            lane = foldLane(lane, std.mem.bytesToValue(crc_lane, data[0..16]), crc_k1);
            data = data[16..];
        }
        crc = crc32x(0, lane[0]);
        crc = crc32x(crc, lane[1]);
    }
    if (data.len >= 8) {
        crc = crc32x(crc, std.mem.readInt(u64, data[0..8], .little));
        data = data[8..];
    }
    for (data) |byte| crc = crc32b(crc, byte);
    return crc;
}

// CRC-64/XZ (reflected ECMA polynomial) fold constants. A fold by shift s pairs x^s with
// x^(s-64), and deriving them at comptime from the recurrence keeps them in step with the table.
const crc64_poly: u64 = 0xC96C5795D7870F42;

fn crc64Xpow(comptime n: u16) u64 {
    // The same register recurrence as the byte table, from x^0 = 1.
    var v: u64 = 1;
    for (0..n) |_| {
        v = (v >> 1) ^ (if (v & 1 != 0) crc64_poly else 0);
    }
    return v;
}

const crc64_k0: crc_lane = .{ crc64Xpow(512), crc64Xpow(448) };
const crc64_k1: crc_lane = .{ crc64Xpow(128), crc64Xpow(64) };
const crc64_k2: crc_lane = .{ crc64Xpow(256), crc64Xpow(192) };

// CRC-64/XZ state via PMULL folding. No hardware crc64 instruction exists, so each folded
// lane re-enters the register through 16 byte-table steps, amortized over the region.
fn crc64Aarch64Fold(crc_in: u64, input: []const u8, comptime table: *const [256]u64) u64 {
    var crc = crc_in;
    var data = input;
    while (data.len != 0 and @intFromPtr(data.ptr) & 15 != 0) {
        crc = (crc >> 8) ^ table[(crc ^ data[0]) & 0xff];
        data = data[1..];
    }
    if (data.len >= 64) {
        var lanes: [4]crc_lane = undefined;
        for (0..4) |i| {
            lanes[i] = std.mem.bytesToValue(crc_lane, data[i * 16 ..][0..16]);
        }
        lanes[0][0] ^= crc;
        data = data[64..];
        while (data.len >= 64) {
            for (0..4) |i| {
                lanes[i] = foldLane(lanes[i], std.mem.bytesToValue(crc_lane, data[i * 16 ..][0..16]), crc64_k0);
            }
            data = data[64..];
        }
        lanes[0] = foldLane(lanes[0], lanes[1], crc64_k1);
        lanes[2] = foldLane(lanes[2], lanes[3], crc64_k1);
        lanes[0] = foldLane(lanes[0], lanes[2], crc64_k2);
        crc = 0;
        for (std.mem.toBytes(lanes[0])) |byte| {
            crc = (crc >> 8) ^ table[(crc ^ byte) & 0xff];
        }
    }
    while (data.len >= 16) {
        var lane = std.mem.bytesToValue(crc_lane, data[0..16]);
        lane[0] ^= crc;
        data = data[16..];
        while (data.len >= 16) {
            lane = foldLane(lane, std.mem.bytesToValue(crc_lane, data[0..16]), crc64_k1);
            data = data[16..];
        }
        crc = 0;
        for (std.mem.toBytes(lane)) |byte| {
            crc = (crc >> 8) ^ table[(crc ^ byte) & 0xff];
        }
    }
    if (data.len >= 8) {
        for (data[0..8]) |byte| {
            crc = (crc >> 8) ^ table[(crc ^ byte) & 0xff];
        }
        data = data[8..];
    }
    for (data) |byte| crc = (crc >> 8) ^ table[(crc ^ byte) & 0xff];
    return crc;
}

// Folding pays off above this length; the threshold comes from a synthetic sweep.
const crc_pmull_threshold = 256;

const OnpremCrc32 = TableCrc(u32, 0xedb8_8320, true);
const OnpremXzCrc64 = TableCrc(u64, 0xc96c5795d7870f42, true);
const OnpremBzip2Crc32 = TableCrc(u32, 0x04c11db7, false);

pub const Crc32 = seam.Checksum(options.crc32_impl, OnpremCrc32, std.hash.Crc32);
pub const XzCrc64 = seam.Checksum(options.crc64xz_impl, OnpremXzCrc64, std.hash.crc.@"CRC-64/XZ");
pub const Bzip2Crc32 = seam.Checksum(options.bzip2crc32_impl, OnpremBzip2Crc32, std.hash.crc.@"CRC-32/BZIP2");

pub const Provider = seam.Provider;
pub const default_provider = seam.default_provider;

pub fn crc32(input: []const u8) u32 {
    var hash = Crc32.init();
    hash.update(input);
    return hash.final();
}

pub fn crc32With(provider: seam.Provider, input: []const u8) u32 {
    var hash = Crc32.bind(provider);
    hash.update(input);
    return hash.final();
}

// xxHash and Adler32 route through their capability seams; each seam can
// point at the on-prem port, std, or any compatible implementation.
const xxh32_seam = @import("hash/xxh32/seam.zig");
const xxh64_seam = @import("hash/xxh64/seam.zig");
const adler32_seam = @import("hash/adler32/seam.zig");

pub const XxHash64 = xxh64_seam.XxHash64;
pub const XxHash32 = xxh32_seam.XxHash32;

pub fn xxh64(input: []const u8) u64 {
    var hasher = XxHash64.init(0);
    hasher.update(input);
    return hasher.final();
}

pub fn xxh64With(provider: seam.Provider, input: []const u8) u64 {
    var hasher = XxHash64.bind(provider, 0);
    hasher.update(input);
    return hasher.final();
}

pub const Adler32 = struct {
    inner: adler32_seam.Inner = .{},

    pub fn init() Adler32 {
        return .{};
    }

    pub fn bind(provider: seam.Provider) Adler32 {
        return .{ .inner = adler32_seam.Inner.bind(provider) };
    }

    pub fn update(self: *Adler32, input: []const u8) void {
        self.inner.update(input);
    }

    pub fn final(self: *const Adler32) u32 {
        return self.inner.adler();
    }
};

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
                        self.state = crc32Aarch64Fold(self.state, input);
                    } else {
                        self.state = crc32Aarch64Scalar(self.state, input);
                    }
                    return;
                }
                var crc = self.state;
                var i: usize = 0;
                while (i + 4 <= input.len) : (i += 4) {
                    crc = tables[3][@as(usize, @intCast((crc ^ input[i]) & 0xff))] ^
                        tables[2][@as(usize, @intCast(((crc >> 8) ^ input[i + 1]) & 0xff))] ^
                        tables[1][@as(usize, @intCast(((crc >> 16) ^ input[i + 2]) & 0xff))] ^
                        tables[0][@as(usize, @intCast(((crc >> 24) ^ input[i + 3]) & 0xff))];
                }
                while (i < input.len) : (i += 1) {
                    crc = (crc >> 8) ^ table[@as(usize, @intCast((crc ^ input[i]) & 0xff))];
                }
                self.state = crc;
                return;
            }
            if (comptime reflected) {
                if (comptime T == u64 and has_crc64_pmull) {
                    if (input.len >= crc_pmull_threshold) {
                        self.state = crc64Aarch64Fold(self.state, input, &table);
                        return;
                    }
                }
                for (input) |b| self.state = (self.state >> 8) ^ table[(self.state ^ b) & 0xff];
            } else {
                for (input) |b| self.state = (self.state << 8) ^ table[((self.state >> (bits - 8)) ^ b) & 0xff];
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

        const tables: [4][256]T = blk: {
            @setEvalBranchQuota(10000);
            var t: [4][256]T = undefined;
            for (0..256) |i| {
                var crc: T = table[i];
                t[0][i] = crc;
                for (1..4) |k| {
                    crc = table[@intCast(crc & 0xff)] ^ (crc >> 8);
                    t[k][i] = crc;
                }
            }
            break :blk t;
        };
    };
}

pub fn adler32(input: []const u8) u32 {
    var hasher = Adler32.init();
    hasher.update(input);
    return hasher.final();
}

pub fn adler32With(provider: seam.Provider, input: []const u8) u32 {
    var hasher = Adler32.bind(provider);
    hasher.update(input);
    return hasher.final();
}

pub fn xxh32With(provider: seam.Provider, input: []const u8) u32 {
    var hasher = XxHash32.bind(provider, 0);
    hasher.update(input);
    return hasher.final();
}

pub fn xxh32(input: []const u8) u32 {
    var hasher = XxHash32.init(0);
    hasher.update(input);
    return hasher.final();
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
