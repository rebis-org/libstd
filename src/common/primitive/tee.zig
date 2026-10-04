const std = @import("std");

const checksum = @import("checksum.zig");

/// Checksum algorithms a CountingTee instance computes while passing bytes
/// through. Selecting kinds is a comptime EnumSet-style packed struct so a
/// new kind (e.g. CRC32C) adds one field here and one line in `per_kind`,
/// not a new bool parameter at every call site.
pub const Kinds = packed struct {
    crc32: bool = false,
    crc64: bool = false,
    adler32: bool = false,
};

pub const Kind = enum { crc32, crc64, adler32 };

const kind_fields = std.enums.values(Kind);

pub fn CountingTee(comptime kinds: Kinds) type {
    return struct {
        writer: std.Io.Writer,
        downstream: ?*std.Io.Writer,
        crc32: checksum.Crc32,
        crc64: checksum.XZCrc64,
        adler32: checksum.Adler32,
        size: u64,

        pub fn init(downstream: ?*std.Io.Writer) @This() {
            return .{
                .writer = .{ .vtable = &vtable, .buffer = &.{}, .end = 0 },
                .downstream = downstream,
                .crc32 = checksum.Crc32.init(),
                .crc64 = checksum.XZCrc64.init(),
                .adler32 = checksum.Adler32.init(),
                .size = 0,
            };
        }

        pub fn written(self: *const @This()) u64 {
            return self.size;
        }

        pub fn crc32Value(self: *const @This()) u32 {
            return self.crc32.final();
        }

        pub fn adler32Value(self: *const @This()) u32 {
            return self.adler32.final();
        }

        pub fn crc64Value(self: *const @This()) u64 {
            return self.crc64.final();
        }

        fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", writer);
            if (data.len == 0) return 0;
            var total: usize = 0;
            for (data[0 .. data.len - 1]) |chunk| total += chunk.len;
            total += data[data.len - 1].len * splat;
            if (total == 0) return 0;
            if (self.downstream) |out| {
                for (data[0 .. data.len - 1]) |chunk| out.writeAll(chunk) catch return error.WriteFailed;
                const last = data[data.len - 1];
                for (0..splat) |_| out.writeAll(last) catch return error.WriteFailed;
            }
            inline for (kind_fields) |kind| {
                if (comptime @field(kinds, @tagName(kind))) {
                    const hasher = &@field(self, @tagName(kind));
                    for (data[0 .. data.len - 1]) |chunk| hasher.update(chunk);
                    const last = data[data.len - 1];
                    for (0..splat) |_| hasher.update(last);
                }
            }
            self.size = std.math.add(u64, self.size, total) catch return error.WriteFailed;
            return total;
        }

        pub const vtable = std.Io.Writer.VTable{
            .drain = drain,
            .flush = std.Io.Writer.noopFlush,
            .rebase = std.Io.Writer.failingRebase,
        };
    };
}

pub const Tee = CountingTee(.{ .crc32 = true, .crc64 = true });
