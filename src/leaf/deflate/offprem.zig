const std = @import("std");

// Offprem arm of the deflate decode seam: std.compress.flate (0.17) over
// the raw container, with the caller's history span as the inflate window
// so the seam keeps the caller-owned storage contract. Decode-only: std's
// compressor cannot express this leaf's option surface, so encode requests
// under an offprem tag fail explicit `unsupported` at the call site rather
// than falling back silently.

pub const Decompress = struct {
    inner: std.compress.flate.Decompress,
    slice_bound: bool,

    pub fn init(input: *std.Io.Reader, history: []u8) @This() {
        std.debug.assert(history.len >= 10);
        return .{ .inner = std.compress.flate.Decompress.init(input, .raw, history), .slice_bound = false };
    }

    pub fn initSlice(data: []const u8, history: []u8) @This() {
        std.debug.assert(history.len >= 10);
        var reader: std.Io.Reader = .fixed(data);
        return .{ .inner = std.compress.flate.Decompress.init(&reader, .raw, history), .slice_bound = true };
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
    pub fn initBound(provider: anytype, input: *std.Io.Reader, history: []u8) error{Unsupported}!@This() {
        if (provider != .offprem) return error.Unsupported;
        return init(input, history);
    }

    pub fn initSliceBound(provider: anytype, data: []const u8, history: []u8) error{Unsupported}!@This() {
        if (provider != .offprem) return error.Unsupported;
        return initSlice(data, history);
    }

    // Resume a fresh member at a byte position the framing already read
    // ahead to (session drivers). Both fields are fresh-construction state.
    pub fn setFramePos(self: *@This(), pos: usize) void {
        self.inner.input.seek = pos;
        self.inner.consumed_bits = 0;
    }

    // Session-driver surface (src/compose/drivers.zig): same pokes the
    // onprem arm exposes, over the fixed reader std flate keeps its input in.
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
};

test "offprem arm decodes byte-identical to onprem across shapes" {
    const onprem = @import("onprem.zig");
    const alloc = std.testing.allocator;

    var rng: u64 = 0x9e3779b97f4a7c15;
    const input = try alloc.alloc(u8, 70000);
    defer alloc.free(input);
    for (input) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @truncate(rng >> 32);
    }
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

        var offprem_inflater = Decompress.initSlice(compressed[0..compressed_len], window);
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
