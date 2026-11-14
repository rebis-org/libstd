const std = @import("std");

const onprem = @import("onprem.zig");

// Accepted gap in the Zig 0.17.1 stdlib arm: enabling verification panics
// (Decompress.zig:373); no dictionary hook; onprem verifies and carries dictionaries.

// The reader vtable folds decoder errors into ReadFailed; WriteFailed is the
// sink rejecting bytes, an I/O fault.
fn mapStreamError(err: std.Io.Reader.StreamError) onprem.DecodeError {
    return switch (err) {
        error.WriteFailed => error.IoException,
        error.ReadFailed, error.EndOfStream => error.DataException,
    };
}

// The caller's span filling reports the same WriteFailed; the onprem arm
// answers ResourceException, and the arms must agree.
fn mapFixedStreamError(err: std.Io.Reader.StreamError) onprem.DecodeError {
    return switch (err) {
        error.WriteFailed => error.ResourceException,
        error.ReadFailed, error.EndOfStream => error.DataException,
    };
}

fn preflight(options: onprem.Options, history: ?[]u8) onprem.DecodeError!void {
    if (options.dictionary != null) return error.UnsupportedException;
    if (options.window_size < onprem.window_size_min or options.window_size > onprem.window_size_max) return error.UnsupportedException;
    if (history) |buffer| {
        if (buffer.len < @as(usize, options.window_size) + onprem.block_size_max) return error.UnsupportedException;
    }
}

pub fn decodeStream(input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    try preflight(options, history);
    var decoder = std.compress.zstd.Decompress.init(input, history, .{ .window_len = options.window_size });
    return decoder.reader.streamRemaining(output) catch |err| mapStreamError(err);
}

pub fn decodeInPlace(input: *std.Io.Reader, output: []u8, options: onprem.Options) onprem.DecodeError!usize {
    // The span carries the output plus window slack, as onprem states; stdlib's
    // direct mode windows from the writer buffer.
    if (output.len < @as(usize, options.window_size) + onprem.block_size_max) return error.UnsupportedException;
    try preflight(options, null);
    var fixed = std.Io.Writer.fixed(output);
    var decoder = std.compress.zstd.Decompress.init(input, &.{}, .{ .window_len = options.window_size });
    return decoder.reader.streamRemaining(&fixed) catch |err| mapFixedStreamError(err);
}

pub fn decodedSize(input: []const u8, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    try preflight(options, history);
    var reader = std.Io.Reader.fixed(input);
    var counter = @import("../../../common/primitive/measurement.zig").Counter.init(null);
    var decoder = std.compress.zstd.Decompress.init(&reader, history, .{ .window_len = options.window_size });
    _ = decoder.reader.streamRemaining(&counter.writer) catch |err| return mapStreamError(err);
    return std.math.cast(usize, counter.written()) orelse error.ResourceException;
}

test "offprem zstd decodes byte-identical to onprem across shapes" {
    const alloc = std.testing.allocator;
    const measurement = @import("../../../common/primitive/measurement.zig");

    const input = try alloc.alloc(u8, 300000);
    defer alloc.free(input);
    var prng = std.Random.DefaultPrng.init(0x9e3779b97f4a7c15);
    prng.random().bytes(input);
    @memset(input[100000..250000], 0);

    const compressed = try alloc.alloc(u8, 320000);
    defer alloc.free(compressed);
    const onprem_out = try alloc.alloc(u8, 300000);
    defer alloc.free(onprem_out);
    const offprem_out = try alloc.alloc(u8, 300000);
    defer alloc.free(offprem_out);
    const history = try alloc.alloc(u8, (1 << 22) + onprem.block_size_max);
    defer alloc.free(history);
    const window = try alloc.alloc(u8, (1 << 22) + onprem.block_size_max);
    defer alloc.free(window);

    const sizes = [_]usize{ 0, 1, 17, 4096, 131072, 262144, 300000 };
    for (sizes) |size| {
        const frame_options: onprem.Options = .{ .window_size = 1 << 21 };
        const workspace = try alloc.alloc(u32, onprem.encoderWorkspaceU32Count(0, 1 << 26, frame_options));
        defer alloc.free(workspace);
        var sink = std.Io.Writer.fixed(compressed);
        _ = try onprem.encodeFrame(&sink, input[0..size], workspace, frame_options, 0);
        const frame_len = sink.end;

        var counter = measurement.Counter.init(null);
        var onprem_source = std.Io.Reader.fixed(compressed[0..frame_len]);
        const produced_on = try onprem.decodeStream(&onprem_source, &counter.writer, history, frame_options);

        var offprem_source = std.Io.Reader.fixed(compressed[0..frame_len]);
        var offprem_sink = std.Io.Writer.fixed(offprem_out);
        const produced_off = try decodeStream(&offprem_source, &offprem_sink, window, frame_options);

        const counted = try decodedSize(compressed[0..frame_len], window, frame_options);

        var onprem_sink = std.Io.Writer.fixed(onprem_out);
        var again = std.Io.Reader.fixed(compressed[0..frame_len]);
        _ = try onprem.decodeStream(&again, &onprem_sink, history, frame_options);

        try std.testing.expectEqual(produced_on, produced_off);
        try std.testing.expectEqual(produced_on, counted);
        try std.testing.expectEqual(size, produced_on);
        try std.testing.expectEqualSlices(u8, input[0..size], offprem_out[0..produced_off]);
        try std.testing.expectEqualSlices(u8, onprem_out[0..produced_on], offprem_out[0..produced_off]);
    }
}

test "offprem zstd limitations stay explicit" {
    const alloc = std.testing.allocator;
    const options = onprem.Options{ .window_size = 1 << 20 };
    const history = try alloc.alloc(u8, @as(usize, options.window_size) + onprem.block_size_max + 16);
    defer alloc.free(history);
    // A dictionary option has no stdlib hook and is rejected up front.
    {
        var src = std.Io.Reader.fixed(&[_]u8{});
        var out: [16]u8 = undefined;
        var sink = std.Io.Writer.fixed(&out);
        try std.testing.expectError(error.UnsupportedException, decodeStream(&src, &sink, history, .{ .window_size = options.window_size, .dictionary = "x" }));
    }
    // Frame.init rejects any dictID-bearing frame; it surfaces as DataException.
    {
        const frame = [_]u8{ 0x28, 0xb5, 0x2f, 0xfd, 0x21, 0x2a, 0x04, 0x21, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
        var src = std.Io.Reader.fixed(&frame);
        var out: [16]u8 = undefined;
        var sink = std.Io.Writer.fixed(&out);
        try std.testing.expectError(error.DataException, decodeStream(&src, &sink, history, options));
    }
    // Recorded gap: this arm cannot verify checksums, so a corrupted one
    // is accepted; onprem rejects it.
    {
        var input: [256]u8 = undefined;
        for (&input, 0..) |*byte, i| byte.* = 'a' + @as(u8, @intCast(i % 7));
        const ws = try alloc.alloc(u32, onprem.encoderWorkspaceU32Count(0, 1 << 20, options));
        defer alloc.free(ws);
        const encoded = try alloc.alloc(u8, 1 << 16);
        defer alloc.free(encoded);
        var writer = std.Io.Writer.fixed(encoded);
        const len = try onprem.encodeFrame(&writer, &input, ws, options, 0);
        encoded[len - 1] ^= 0xFF;
        {
            var src = std.Io.Reader.fixed(encoded[0..len]);
            const out = try alloc.alloc(u8, input.len + 16);
            defer alloc.free(out);
            var sink = std.Io.Writer.fixed(out);
            const produced = try decodeStream(&src, &sink, history, options);
            try std.testing.expectEqual(input.len, produced);
        }
        {
            var src = std.Io.Reader.fixed(encoded[0..len]);
            const out = try alloc.alloc(u8, input.len + 16);
            defer alloc.free(out);
            var sink = std.Io.Writer.fixed(out);
            try std.testing.expectError(error.IntegrityException, onprem.decodeStream(&src, &sink, history, options));
        }
    }
}
