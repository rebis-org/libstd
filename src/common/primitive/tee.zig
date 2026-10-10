const std = @import("std");

const checksum = @import("checksum.zig");
const seam = @import("seam");

// Selecting kinds through a comptime packed struct means a new checksum adds
// one field here and one line in `per_kind`, not a new bool parameter at every
// call site.
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
        crc64: checksum.XzCrc64,
        adler32: checksum.Adler32,
        size: u64,

        pub fn init(downstream: ?*std.Io.Writer) @This() {
            return initWithProvider(downstream, seam.default_provider);
        }

        pub fn initWithProvider(downstream: ?*std.Io.Writer, provider: seam.Provider) @This() {
            return .{
                .writer = .{ .vtable = &vtable, .buffer = &.{}, .end = 0 },
                .downstream = downstream,
                .crc32 = checksum.Crc32.bind(provider),
                .crc64 = checksum.XzCrc64.bind(provider),
                .adler32 = checksum.Adler32.bind(provider),
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

        fn feed(self: *@This(), part: []const u8) std.Io.Writer.Error!void {
            if (self.downstream) |out| out.writeAll(part) catch return error.WriteFailed;
            inline for (kind_fields) |kind| {
                if (comptime @field(kinds, @tagName(kind))) @field(self, @tagName(kind)).update(part);
            }
        }

        fn drain(writer: *std.Io.Writer, chunks: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", writer);
            if (chunks.len == 0) return 0;
            var total: usize = 0;
            for (chunks[0 .. chunks.len - 1]) |part| total += part.len;
            total += chunks[chunks.len - 1].len * splat;
            if (total == 0) return 0;
            for (chunks[0 .. chunks.len - 1]) |part| try self.feed(part);
            const last = chunks[chunks.len - 1];
            for (0..splat) |_| try self.feed(last);
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
