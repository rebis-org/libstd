const std = @import("std");

const seam = @import("seam");

const checksum = @import("checksum.zig");
const exception = @import("exception.zig");

const Exception = exception.Exception;

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
        poisoned: bool,
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
                .poisoned = false,
                .crc32 = checksum.Crc32.bind(provider, {}),
                .crc64 = checksum.XzCrc64.bind(provider, {}),
                .adler32 = checksum.Adler32.bind(provider, {}),
                .xxh64 = checksum.XxHash64.bind(provider, 0),
                .size = 0,
            };
        }

        // A partial downstream write desynchronizes every tally from what the
        // sink actually consumed, so each reading accessor refuses a poisoned
        // tee rather than return a count that no longer describes the sink.
        // The refusal is an error, not an assert: ReleaseFast must never read
        // a stale tally silently, and the downstream WriteFailed is capacity
        // per exception.fromStd.
        pub fn written(self: *const @This()) Exception!u64 {
            if (self.poisoned) return error.CapacityException;
            return self.size;
        }

        pub fn crc32Value(self: *const @This()) Exception!u32 {
            if (self.poisoned) return error.CapacityException;
            return self.crc32.final({});
        }

        pub fn adler32Value(self: *const @This()) Exception!u32 {
            if (self.poisoned) return error.CapacityException;
            return self.adler32.final({});
        }

        pub fn crc64Value(self: *const @This()) Exception!u64 {
            if (self.poisoned) return error.CapacityException;
            return self.crc64.final({});
        }

        pub fn xxh64Value(self: *const @This()) Exception!u64 {
            if (self.poisoned) return error.CapacityException;
            return self.xxh64.final({});
        }

        fn feed(self: *@This(), part: []const u8) std.Io.Writer.Error!void {
            if (self.downstream) |out| out.writeAll(part) catch {
                self.poisoned = true;
                return error.WriteFailed;
            };
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
            for (chunks[0 .. chunks.len - 1]) |part| {
                total = std.math.add(usize, total, part.len) catch return error.WriteFailed;
            }
            const tail = std.math.mul(usize, chunks[chunks.len - 1].len, splat) catch return error.WriteFailed;
            total = std.math.add(usize, total, tail) catch return error.WriteFailed;
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

const FailingSink = struct {
    writer: std.Io.Writer,

    fn drain(writer: *std.Io.Writer, chunks: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        _ = writer;
        _ = chunks;
        _ = splat;
        return error.WriteFailed;
    }

    const vtable = std.Io.Writer.VTable{
        .drain = drain,
        .flush = std.Io.Writer.noopFlush,
        .rebase = std.Io.Writer.failingRebase,
    };
};

test "counting tee tallies a healthy flow" {
    var tee = Tee.init(null);
    try tee.writer.writeAll("hello ");
    try tee.writer.writeAll("world");
    try std.testing.expectEqual(@as(u64, 11), try tee.written());
    try std.testing.expectEqual(std.hash.Crc32.hash("hello world"), try tee.crc32Value());
    try std.testing.expect(!tee.poisoned);
}

test "counting tee poisons after a downstream failure" {
    var failing: FailingSink = .{ .writer = .{ .vtable = &FailingSink.vtable, .buffer = &.{}, .end = 0 } };
    var tee = Tee.init(&failing.writer);
    try std.testing.expectError(error.WriteFailed, tee.writer.writeAll("hello"));
    try std.testing.expect(tee.poisoned);
}

test "counting tee accessors refuse a poisoned tally" {
    var failing: FailingSink = .{ .writer = .{ .vtable = &FailingSink.vtable, .buffer = &.{}, .end = 0 } };
    var tee = Tee.init(&failing.writer);
    try std.testing.expectError(error.WriteFailed, tee.writer.writeAll("hello"));
    try std.testing.expectError(error.CapacityException, tee.written());
    try std.testing.expectError(error.CapacityException, tee.crc32Value());
    try std.testing.expectError(error.CapacityException, tee.adler32Value());
    try std.testing.expectError(error.CapacityException, tee.crc64Value());
}
