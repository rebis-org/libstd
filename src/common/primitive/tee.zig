const std = @import("std");

const seam = @import("seam");

const checksum = @import("checksum.zig");

// A new checksum adds one field here and one on the tee, not a bool per
// call site.
pub const Kinds = packed struct {
    crc32: bool = false,
    crc64: bool = false,
    adler32: bool = false,
    xxh64: bool = false,
};

pub fn CountingTee(comptime kinds: Kinds) type {
    return struct {
        writer: std.Io.Writer,
        downstream: ?*std.Io.Writer,
        crc32: checksum.Crc32,
        crc64: checksum.XzCrc64,
        adler32: checksum.Adler32,
        xxh64: checksum.XxHash64,
        size: u64,

        pub fn init(downstream: ?*std.Io.Writer) @This() {
            return initWithProvider(downstream, seam.default_provider);
        }

        pub fn initWithProvider(downstream: ?*std.Io.Writer, provider: seam.Provider) @This() {
            return .{
                .writer = .{ .vtable = &vtable, .buffer = &.{}, .end = 0 },
                .downstream = downstream,
                .crc32 = checksum.Crc32.bind(provider, {}),
                .crc64 = checksum.XzCrc64.bind(provider, {}),
                .adler32 = checksum.Adler32.bind(provider, {}),
                .xxh64 = checksum.XxHash64.bind(provider, 0),
                .size = 0,
            };
        }

        pub fn written(self: *const @This()) u64 {
            return self.size;
        }

        pub fn crc32Value(self: *const @This()) u32 {
            return self.crc32.final({});
        }

        pub fn adler32Value(self: *const @This()) u32 {
            return self.adler32.final({});
        }

        pub fn crc64Value(self: *const @This()) u64 {
            return self.crc64.final({});
        }

        pub fn xxh64Value(self: *@This()) u64 {
            return self.xxh64.final({});
        }

        fn feed(self: *@This(), part: []const u8) std.Io.Writer.Error!void {
            if (self.downstream) |out| out.writeAll(part) catch return error.WriteFailed;
            inline for (comptime @typeInfo(Kinds).@"struct".field_names) |name| {
                if (@field(kinds, name)) @field(self, name).update(part);
            }
        }

        fn drain(writer: *std.Io.Writer, chunks: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            // std.Io.Writer aligns below u64 fields on wasm32 and arm32;
            // the parent pointer is always naturally aligned in practice.
            const self: *@This() = @alignCast(@fieldParentPtr("writer", writer));
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
