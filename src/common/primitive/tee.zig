const std = @import("std");

const checksum = @import("checksum.zig");

pub fn CountingTee(comptime has_crc32: bool, comptime has_crc64: bool) type {
    return struct {
        writer: std.Io.Writer,
        downstream: ?*std.Io.Writer,
        crc32: checksum.Crc32,
        crc64: checksum.XZCrc64,
        size: u64,

        pub fn init(downstream: ?*std.Io.Writer) @This() {
            return .{
                .writer = .{ .vtable = &vtable, .buffer = &.{}, .end = 0 },
                .downstream = downstream,
                .crc32 = checksum.Crc32.init(),
                .crc64 = checksum.XZCrc64.init(),
                .size = 0,
            };
        }

        pub fn written(self: *const @This()) u64 {
            return self.size;
        }

        pub fn crc32Value(self: *const @This()) u32 {
            return self.crc32.final();
        }

        pub fn crc64Value(self: *const @This()) u64 {
            return self.crc64.final();
        }

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @fieldParentPtr("writer", w);
            if (data.len == 0) return 0;
            var total: usize = 0;
            for (data[0 .. data.len - 1]) |buf| total += buf.len;
            total += data[data.len - 1].len * splat;
            if (total == 0) return 0;
            if (self.downstream) |out| {
                for (data[0 .. data.len - 1]) |buf| out.writeAll(buf) catch return error.WriteFailed;
                const last = data[data.len - 1];
                for (0..splat) |_| out.writeAll(last) catch return error.WriteFailed;
            }
            if (comptime has_crc32) {
                for (data[0 .. data.len - 1]) |buf| self.crc32.update(buf);
                const last = data[data.len - 1];
                for (0..splat) |_| self.crc32.update(last);
            }
            if (comptime has_crc64) {
                for (data[0 .. data.len - 1]) |buf| self.crc64.update(buf);
                const last = data[data.len - 1];
                for (0..splat) |_| self.crc64.update(last);
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

pub const Tee = CountingTee(true, true);
