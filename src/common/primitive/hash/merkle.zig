const std = @import("std");

// Merkle-Damgård skeleton shared by the short FIPS 180 digests: 64-byte blocks,
// 0x80 padding, 64-bit big-endian bit length, big-endian state words out.
pub fn Digest(
    comptime state_len: usize,
    comptime digest_len: usize,
    comptime initial: [state_len]u32,
    comptime compress: *const fn (state: *align(16) [state_len]u32, block: *const [64]u8) void,
) type {
    return struct {
        const Self = @This();

        pub const block_length = 64;
        pub const digest_length = digest_len;
        pub const Options = struct {};

        state: [state_len]u32 align(16),
        buffer: [64]u8 = undefined,
        buffered: u8 = 0,
        total: u64 = 0,

        pub fn init(_: Options) Self {
            return .{ .state = initial };
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
                compress(&self.state, &self.buffer);
                self.buffered = 0;
                remaining = remaining[take..];
            }
            while (remaining.len >= 64) {
                compress(&self.state, remaining[0..64]);
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
                compress(&self.state, &self.buffer);
                self.buffered = 0;
            }
            @memset(self.buffer[self.buffered..56], 0);
            std.mem.writeInt(u64, self.buffer[56..64], bit_length, .big);
            compress(&self.state, &self.buffer);
            for (self.state, 0..) |word, index| {
                std.mem.writeInt(u32, out[4 * index ..][0..4], word, .big);
            }
        }

        pub fn finalResult(self: *Self) [digest_length]u8 {
            var out: [digest_length]u8 = undefined;
            self.final(&out);
            return out;
        }
    };
}
