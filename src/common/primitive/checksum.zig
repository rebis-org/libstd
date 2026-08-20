const std = @import("std");
const builtin = @import("builtin");
const options = @import("options");

extern fn stdk_crc32_le(crc: u32, data: [*]const u8, len: usize) u32;

pub const Crc32 = TableCrc(u32, 0xedb8_8320, true);

pub fn crc32(input: []const u8) u32 {
    var hash = Crc32.init();
    hash.update(input);
    return hash.final();
}

pub const XxHash64 = struct {
    acc1: u64,
    acc2: u64,
    acc3: u64,
    acc4: u64,
    buffer: [32]u8 = undefined,
    buffered: usize = 0,
    total: u64 = 0,

    const p1: u64 = 0x9e37_79b1_85eb_ca87;
    const p2: u64 = 0xc2b2_ae3d_27d4_eb4f;
    const p3: u64 = 0x1656_67b1_9e37_79f9;
    const p4: u64 = 0x85eb_ca77_c2b2_ae63;
    const p5: u64 = 0x27d4_eb2f_1656_67c5;

    pub fn init(seed: u64) XxHash64 {
        return .{
            .acc1 = seed +% p1 +% p2,
            .acc2 = seed +% p2,
            .acc3 = seed,
            .acc4 = seed -% p1,
        };
    }

    fn round(acc: u64, input: u64) u64 {
        return std.math.rotl(u64, acc +% (input *% p2), 31) *% p1;
    }

    fn mergeAcc(acc: u64, input: u64) u64 {
        return (acc ^ round(0, input)) *% p1 +% p4;
    }

    fn consumeStripe(self: *XxHash64, bytes: *const [32]u8) void {
        self.acc1 = round(self.acc1, std.mem.readInt(u64, bytes[0..8], .little));
        self.acc2 = round(self.acc2, std.mem.readInt(u64, bytes[8..16], .little));
        self.acc3 = round(self.acc3, std.mem.readInt(u64, bytes[16..24], .little));
        self.acc4 = round(self.acc4, std.mem.readInt(u64, bytes[24..32], .little));
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
            std.math.rotl(u64, self.acc1, 1) +%
                std.math.rotl(u64, self.acc2, 7) +%
                std.math.rotl(u64, self.acc3, 12) +%
                std.math.rotl(u64, self.acc4, 18)
        else
            self.acc3 +% p5;
        if (self.total >= 32) {
            hash = mergeAcc(hash, self.acc1);
            hash = mergeAcc(hash, self.acc2);
            hash = mergeAcc(hash, self.acc3);
            hash = mergeAcc(hash, self.acc4);
        }
        hash +%= self.total;
        var tail = self.buffer[0..self.buffered];
        while (tail.len >= 8) {
            hash ^= round(0, std.mem.readInt(u64, tail[0..8], .little));
            hash = std.math.rotl(u64, hash, 27) *% p1 +% p4;
            tail = tail[8..];
        }
        if (tail.len >= 4) {
            hash ^= @as(u64, std.mem.readInt(u32, tail[0..4], .little)) *% p1;
            hash = std.math.rotl(u64, hash, 23) *% p2 +% p3;
            tail = tail[4..];
        }
        while (tail.len != 0) {
            hash ^= @as(u64, tail[0]) *% p5;
            hash = std.math.rotl(u64, hash, 11) *% p1;
            tail = tail[1..];
        }
        hash ^= hash >> 33;
        hash *%= p2;
        hash ^= hash >> 29;
        hash *%= p3;
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
                if (comptime !options.force_fallback and builtin.cpu.arch == .aarch64) {
                    self.state = stdk_crc32_le(self.state, input.ptr, input.len);
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
pub const XZCrc64 = TableCrc(u64, 0xc96c5795d7870f42, true);
