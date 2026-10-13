const std = @import("std");

// Decode-only: stdlib's compressor cannot express this leaf's option surface,
// so an offprem encode tag fails unsupported instead of falling back.

pub const Decompress = struct {
    inner: std.compress.flate.Decompress,
    // Owns the fixed reader slice constructions bind stdlib flate to: a
    // constructor-local reader would dangle the moment init returned.
    fixed_input: std.Io.Reader,
    slice_bound: bool,

    pub fn init(input: *std.Io.Reader, history: []u8) @This() {
        std.debug.assert(history.len >= 10);
        return .{ .inner = std.compress.flate.Decompress.init(input, .raw, history), .fixed_input = undefined, .slice_bound = false };
    }

    pub fn initSliceInPlace(self: *@This(), data: []const u8, history: []u8) void {
        std.debug.assert(history.len >= 10);
        self.slice_bound = true;
        self.fixed_input = .fixed(data);
        self.inner = std.compress.flate.Decompress.init(&self.fixed_input, .raw, history);
    }

    pub fn initSliceBoundInPlace(self: *@This(), provider: anytype, data: []const u8, history: []u8) error{UnsupportedFailure}!void {
        if (provider != .offprem) return error.UnsupportedFailure;
        self.initSliceInPlace(data, history);
    }

    // The fixed reader's seek is the consumed byte position; the stream
    // bits consumed inside the current byte ride in consumed_bits. Valid
    // only for initSlice constructions: streaming callers measure
    // consumption from their own source reader (e.g. source.seek).
    pub fn inputBitsConsumed(self: *const @This()) usize {
        std.debug.assert(self.slice_bound);
        return self.inner.input.seek * 8 + self.inner.consumed_bits;
    }

    // Seam binding points: the tag binds at construction and the decode
    // loop never dispatches. A mismatched tag is unsupported, never a
    // silent fallback. `anytype` keeps the arm free of module imports.
    pub fn initBound(provider: anytype, input: *std.Io.Reader, history: []u8) error{UnsupportedFailure}!@This() {
        if (provider != .offprem) return error.UnsupportedFailure;
        return init(input, history);
    }

    // Resume a fresh member at a byte position the framing already read
    // ahead to (session drivers). Both fields are fresh-construction state.
    pub fn setFramePos(self: *@This(), pos: usize) void {
        self.inner.input.seek = pos;
        self.inner.consumed_bits = 0;
    }

    // Session-driver surface: same pokes the onprem arm exposes,
    // over the fixed reader stdlib flate keeps its input in.
    pub fn streamPosition(self: *const @This()) usize {
        return self.inner.input.seek;
    }

    pub fn restage(self: *@This(), data: []const u8, pos: usize) void {
        // Mid-member restage: consumed_bits belongs to the byte at `pos`
        // after compaction and must survive (see the onprem arm).
        self.inner.input.buffer = @constCast(data);
        self.inner.input.end = data.len;
        self.inner.input.seek = pos;
    }

    pub fn atEnd(self: *const @This()) bool {
        return switch (self.inner.state) {
            .end => true,
            else => false,
        };
    }

    pub fn clearFailure(self: *@This()) void {
        self.inner.err = null;
    }

    pub fn readerPtr(self: *@This()) *std.Io.Reader {
        return &self.inner.reader;
    }

    // stdlib's stream entry ignores the writer and decodes into the history buffer instead.
    pub fn streamTo(self: *@This(), writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const reader = &self.inner.reader;
        var produced: usize = 0;
        while (true) {
            const emitted = reader.stream(writer, limit) catch |err| return err;
            produced += emitted;
            if (produced >= @backingInt(limit)) break;
            // A pull that neither moved nor staged cannot move again.
            if (emitted == 0 and reader.seek >= reader.end) break;
        }
        return produced;
    }
};

test "offprem arm decodes byte-identical to onprem across shapes" {
    const onprem = @import("onprem.zig");
    const alloc = std.testing.allocator;

    const input = try alloc.alloc(u8, 70000);
    defer alloc.free(input);
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    prng.random().bytes(input);
    // Zeros beside the random stretch force stored blocks next to dynamic
    // ones; sizes below sweep empty, tails, one window, and multi-block.
    @memset(input[30000..65000], 0);

    const compressed = try alloc.alloc(u8, 80000);
    defer alloc.free(compressed);
    const onprem_out = try alloc.alloc(u8, 70000);
    defer alloc.free(onprem_out);
    const offprem_out = try alloc.alloc(u8, 70000);
    defer alloc.free(offprem_out);
    const history = try alloc.alloc(u8, onprem.history_size);
    defer alloc.free(history);
    const window = try alloc.alloc(u8, onprem.history_size);
    defer alloc.free(window);

    const sizes = [_]usize{ 0, 1, 2, 3, 17, 258, 259, 4096, 32768, 65535, 65536, 70000 };
    for (sizes) |size| {
        var downstream = std.Io.Writer.fixed(compressed);
        var compressor = try onprem.Compress.init(&downstream, history, .{
            .good = 8,
            .nice = 258,
            .lazy = 16,
            .chain = 128,
        });
        compressor.writer.writeAll(input[0..size]) catch return error.TestUnexpectedResult;
        compressor.finish() catch return error.TestUnexpectedResult;
        const compressed_len = downstream.end;

        var onprem_inflater = onprem.Decompress.initSlice(compressed[0..compressed_len], history);
        var onprem_counting = std.Io.Writer.fixed(onprem_out);
        const produced_on = onprem_inflater.readerPtr().streamRemaining(&onprem_counting) catch return error.TestUnexpectedResult;
        const consumed_on = (onprem_inflater.inputBitsConsumed() + 7) / 8;

        var offprem_inflater: Decompress = undefined;
        offprem_inflater.initSliceInPlace(compressed[0..compressed_len], window);
        var offprem_counting = std.Io.Writer.fixed(offprem_out);
        const produced_off = offprem_inflater.readerPtr().streamRemaining(&offprem_counting) catch return error.TestUnexpectedResult;
        const consumed_off = (offprem_inflater.inputBitsConsumed() + 7) / 8;

        try std.testing.expectEqual(produced_on, produced_off);
        try std.testing.expectEqual(consumed_on, consumed_off);
        try std.testing.expectEqual(size, produced_on);
        try std.testing.expectEqual(compressed_len, consumed_on);
        try std.testing.expectEqualSlices(u8, input[0..size], offprem_out[0..produced_off]);
    }
}
