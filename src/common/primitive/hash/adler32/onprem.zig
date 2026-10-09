const std = @import("std");

// RFC 1950.
// The 16-way unrolled inner loop defers the modulo to one reduction per NMAX bytes.

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

    fn permute(state: u32, input: []const u8) u32 {
        var s1 = state & 0xffff;
        var s2 = (state >> 16) & 0xffff;

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
                    comptime var j: usize = 0;
                    inline while (j < 16) : (j += 1) {
                        s1 +%= input[index + j];
                        s2 +%= s1;
                    }
                    index += 16;
                }
                s1 %= base;
                s2 %= base;
            }
            while (index + 16 <= input.len) : (index += 16) {
                comptime var j: usize = 0;
                inline while (j < 16) : (j += 1) {
                    s1 +%= input[index + j];
                    s2 +%= s1;
                }
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
