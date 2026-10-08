const std = @import("std");
const builtin = @import("builtin");

const options = @import("options");

extern fn stdk_crc32_le(crc: u32, data: [*]const u8, len: usize) u32;
extern fn stdk_crc32_le_pmull(crc: u32, data: [*]const u8, len: usize) u32;

// Folding pays off above this length; the threshold comes from a synthetic sweep.
const crc32_pmull_threshold = 256;

pub const Crc32 = TableCrc(u32, 0xedb8_8320, true);

pub fn crc32(input: []const u8) u32 {
    var hash = Crc32.init();
    hash.update(input);
    return hash.final();
}

pub const XxHash64 = struct {
    accumulator_1: u64,
    accumulator_2: u64,
    accumulator_3: u64,
    accumulator_4: u64,
    buffer: [32]u8,
    buffered: usize = 0,
    total: u64 = 0,

    const prime_1: u64 = 0x9e37_79b1_85eb_ca87;
    const prime_2: u64 = 0xc2b2_ae3d_27d4_eb4f;
    const prime_3: u64 = 0x1656_67b1_9e37_79f9;
    const prime_4: u64 = 0x85eb_ca77_c2b2_ae63;
    const prime_5: u64 = 0x27d4_eb2f_1656_67c5;

    pub fn init(seed: u64) XxHash64 {
        // The stripe buffer stays undefined until update fills it before any read.
        return .{
            .accumulator_1 = seed +% prime_1 +% prime_2,
            .accumulator_2 = seed +% prime_2,
            .accumulator_3 = seed,
            .accumulator_4 = seed -% prime_1,
            .buffer = undefined,
        };
    }

    fn round(accumulator: u64, input: u64) u64 {
        return std.math.rotl(u64, accumulator +% (input *% prime_2), 31) *% prime_1;
    }

    fn mergeAccumulator(accumulator: u64, input: u64) u64 {
        return (accumulator ^ round(0, input)) *% prime_1 +% prime_4;
    }

    fn consumeStripe(self: *XxHash64, bytes: *const [32]u8) void {
        self.accumulator_1 = round(self.accumulator_1, std.mem.readInt(u64, bytes[0..8], .little));
        self.accumulator_2 = round(self.accumulator_2, std.mem.readInt(u64, bytes[8..16], .little));
        self.accumulator_3 = round(self.accumulator_3, std.mem.readInt(u64, bytes[16..24], .little));
        self.accumulator_4 = round(self.accumulator_4, std.mem.readInt(u64, bytes[24..32], .little));
    }

    pub fn update(self: *XxHash64, input: []const u8) void {
        self.total +%= input.len;
        var remaining = input;
        if (self.buffered != 0) {
            const take = @min(remaining.len, 32 - self.buffered);
            @memcpy(self.buffer[self.buffered..][0..take], remaining[0..take]);
            self.buffered += take;
            remaining = remaining[take..];
            if (self.buffered == 32) {
                self.consumeStripe(&self.buffer);
                self.buffered = 0;
            }
        }
        while (remaining.len >= 32) {
            self.consumeStripe(remaining[0..32]);
            remaining = remaining[32..];
        }
        if (remaining.len != 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buffered = remaining.len;
        }
    }

    pub fn final(self: *const XxHash64) u64 {
        var hash: u64 = if (self.total >= 32)
            std.math.rotl(u64, self.accumulator_1, 1) +%
                std.math.rotl(u64, self.accumulator_2, 7) +%
                std.math.rotl(u64, self.accumulator_3, 12) +%
                std.math.rotl(u64, self.accumulator_4, 18)
        else
            self.accumulator_3 +% prime_5;
        if (self.total >= 32) {
            hash = mergeAccumulator(hash, self.accumulator_1);
            hash = mergeAccumulator(hash, self.accumulator_2);
            hash = mergeAccumulator(hash, self.accumulator_3);
            hash = mergeAccumulator(hash, self.accumulator_4);
        }
        hash +%= self.total;
        var tail = self.buffer[0..self.buffered];
        while (tail.len >= 8) {
            hash ^= round(0, std.mem.readInt(u64, tail[0..8], .little));
            hash = std.math.rotl(u64, hash, 27) *% prime_1 +% prime_4;
            tail = tail[8..];
        }
        if (tail.len >= 4) {
            hash ^= @as(u64, std.mem.readInt(u32, tail[0..4], .little)) *% prime_1;
            hash = std.math.rotl(u64, hash, 23) *% prime_2 +% prime_3;
            tail = tail[4..];
        }
        while (tail.len != 0) {
            hash ^= @as(u64, tail[0]) *% prime_5;
            hash = std.math.rotl(u64, hash, 11) *% prime_1;
            tail = tail[1..];
        }
        hash ^= hash >> 33;
        hash *%= prime_2;
        hash ^= hash >> 29;
        hash *%= prime_3;
        hash ^= hash >> 32;
        return hash;
    }
};

pub fn xxh64(input: []const u8) u64 {
    var hasher = XxHash64.init(0);
    hasher.update(input);
    return hasher.final();
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
                if (comptime !options.portable and builtin.target.cpu.arch == .aarch64) {
                    if (input.len >= crc32_pmull_threshold) {
                        self.state = stdk_crc32_le_pmull(self.state, input.ptr, input.len);
                    } else {
                        self.state = stdk_crc32_le(self.state, input.ptr, input.len);
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
                        if (crc & 1 != 0) crc = (crc >> 1) ^ poly else crc >>= 1;
                    } else {
                        const high: T = @as(T, 1) << @intCast(bits - 1);
                        if (crc & high != 0) crc = (crc << 1) ^ poly else crc <<= 1;
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
                    crc = table[@as(usize, @intCast(crc & 0xff))] ^ (crc >> 8);
                    t[k][i] = crc;
                }
            }
            break :blk t;
        };
    };
}

pub const Bzip2Crc32 = TableCrc(u32, 0x04c11db7, false);
pub const XzCrc64 = TableCrc(u64, 0xc96c5795d7870f42, true);

pub const Adler32 = struct {
    state: u32,

    pub fn init() Adler32 {
        return .{ .state = 1 };
    }

    pub fn update(self: *Adler32, input: []const u8) void {
        var low: u32 = self.state & 0xffff;
        var high: u32 = self.state >> 16;
        var index: usize = 0;
        while (index < input.len) {
            const end = @min(index + 5552, input.len);
            while (index < end) : (index += 1) {
                low += input[index];
                high += low;
            }
            low %= 65521;
            high %= 65521;
        }
        self.state = (high << 16) | low;
    }

    pub fn final(self: *const Adler32) u32 {
        return self.state;
    }
};

pub fn adler32(input: []const u8) u32 {
    var hasher = Adler32.init();
    hasher.update(input);
    return hasher.final();
}

const xxh32_prime1: u32 = 2654435761;
const xxh32_prime2: u32 = 2246822519;
const xxh32_prime3: u32 = 3266489917;
const xxh32_prime4: u32 = 668265263;
const xxh32_prime5: u32 = 374761393;

fn xxh32Round(acc: u32, lane: u32) u32 {
    return std.math.rotl(u32, acc +% lane *% xxh32_prime2, 13) *% xxh32_prime1;
}

pub const XxHash32 = struct {
    seed: u32,
    total: u64,
    acc1: u32,
    acc2: u32,
    acc3: u32,
    acc4: u32,
    buffer: [16]u8,
    buffer_len: usize,

    pub fn init(seed: u32) XxHash32 {
        return .{
            .seed = seed,
            .total = 0,
            .acc1 = seed +% xxh32_prime1 +% xxh32_prime2,
            .acc2 = seed +% xxh32_prime2,
            .acc3 = seed,
            .acc4 = seed -% xxh32_prime1,
            .buffer = undefined,
            .buffer_len = 0,
        };
    }

    pub fn update(self: *XxHash32, input: []const u8) void {
        self.total += input.len;
        var data = input;
        if (self.buffer_len != 0) {
            const want = 16 - self.buffer_len;
            const take = @min(want, data.len);
            @memcpy(self.buffer[self.buffer_len..][0..take], data[0..take]);
            self.buffer_len += take;
            data = data[take..];
            if (self.buffer_len == 16) {
                self.consume(&self.buffer);
                self.buffer_len = 0;
            }
        }
        while (data.len >= 16) {
            self.consume(data[0..16]);
            data = data[16..];
        }
        if (data.len != 0) {
            @memcpy(self.buffer[0..data.len], data);
            self.buffer_len = data.len;
        }
    }

    fn consume(self: *XxHash32, lanes: []const u8) void {
        self.acc1 = xxh32Round(self.acc1, std.mem.readInt(u32, lanes[0..4], .little));
        self.acc2 = xxh32Round(self.acc2, std.mem.readInt(u32, lanes[4..8], .little));
        self.acc3 = xxh32Round(self.acc3, std.mem.readInt(u32, lanes[8..12], .little));
        self.acc4 = xxh32Round(self.acc4, std.mem.readInt(u32, lanes[12..16], .little));
    }

    pub fn final(self: *const XxHash32) u32 {
        var hash: u32 = undefined;
        if (self.total >= 16) {
            hash = std.math.rotl(u32, self.acc1, 1) +% std.math.rotl(u32, self.acc2, 7) +% std.math.rotl(u32, self.acc3, 12) +% std.math.rotl(u32, self.acc4, 18);
        } else {
            hash = self.seed +% xxh32_prime5;
        }
        hash +%= @truncate(self.total);
        var rest: []const u8 = if (self.buffer_len != 0) self.buffer[0..self.buffer_len] else &.{};
        var index: usize = 0;
        while (index + 4 <= rest.len) : (index += 4) {
            hash = std.math.rotl(u32, hash +% std.mem.readInt(u32, rest[index..][0..4], .little) *% xxh32_prime3, 17) *% xxh32_prime4;
        }
        while (index < rest.len) : (index += 1) {
            hash = std.math.rotl(u32, hash +% @as(u32, rest[index]) *% xxh32_prime5, 11) *% xxh32_prime1;
        }
        hash ^= hash >> 15;
        hash *%= xxh32_prime2;
        hash ^= hash >> 13;
        hash *%= xxh32_prime3;
        hash ^= hash >> 16;
        return hash;
    }
};

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

test "xxh64 matches the published vectors" {
    try std.testing.expectEqual(@as(u64, 0xEF46DB3751D8E999), xxh64(""));
    try std.testing.expectEqual(@as(u64, 0xD24EC4F1A98C6E5B), xxh64("a"));
    var hasher = XxHash64.init(0);
    hasher.update("hello ");
    hasher.update("world");
    try std.testing.expectEqual(xxh64("hello world"), hasher.final());
}
