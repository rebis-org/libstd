const std = @import("std");

const onprem = @import("onprem.zig");

// std's verify_checksum panics instead of verifying, so the arm leaves
// checksums off; dictionaries are unsupported. Both pick onprem.

// The reader vtable folds every decoder error into ReadFailed; a WriteFailed is
// the sink rejecting bytes, which is an I/O fault against the caller's own
// writer.
fn mapStreamError(err: std.Io.Reader.StreamError) onprem.DecodeError {
    return switch (err) {
        error.WriteFailed => error.IoFailure,
        error.ReadFailed, error.EndOfStream => error.DataFailure,
    };
}

// A fixed writer reports the same WriteFailed when the caller's span fills, and
// there the cause is capacity, so it answers as a capacity shortfall.
fn mapFixedStreamError(err: std.Io.Reader.StreamError) onprem.DecodeError {
    return switch (err) {
        error.WriteFailed => error.CapacityFailure,
        error.ReadFailed, error.EndOfStream => error.DataFailure,
    };
}

fn preflight(options: onprem.Options, history: ?[]u8) onprem.DecodeError!void {
    if (options.dictionary != null) return error.UnsupportedFailure;
    if (options.window_size < onprem.window_size_min or options.window_size > onprem.window_size_max) return error.UnsupportedFailure;
    if (history) |buffer| {
        if (buffer.len < @as(usize, options.window_size) + onprem.block_size_max) return error.UnsupportedFailure;
    }
}

pub fn decodeStream(input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    try preflight(options, history);
    var decoder = std.compress.zstd.Decompress.init(input, history, .{ .window_len = options.window_size });
    return decoder.reader.streamRemaining(output) catch |err| mapStreamError(err);
}

pub fn decodeInPlace(input: *std.Io.Reader, output: []u8, options: onprem.Options) onprem.DecodeError!usize {
    // Same precondition the onprem arm states: the span carries the output
    // plus one block of window slack. std zstd's direct mode drives the
    // window from the writer buffer, so no separate history is passed.
    if (output.len < @as(usize, options.window_size) + onprem.block_size_max) return error.UnsupportedFailure;
    try preflight(options, null);
    var fixed = std.Io.Writer.fixed(output);
    var decoder = std.compress.zstd.Decompress.init(input, &.{}, .{ .window_len = options.window_size });
    return decoder.reader.streamRemaining(&fixed) catch |err| mapFixedStreamError(err);
}

pub fn decodedSize(input: []const u8, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    try preflight(options, history);
    var reader = std.Io.Reader.fixed(input);
    var counter = @import("../../common/primitive/measurement.zig").Counter.init(null);
    var decoder = std.compress.zstd.Decompress.init(&reader, history, .{ .window_len = options.window_size });
    _ = decoder.reader.streamRemaining(&counter.writer) catch |err| return mapStreamError(err);
    return counter.written();
}

test "offprem zstd decodes byte-identical to onprem across shapes" {
    const alloc = std.testing.allocator;
    const measurement = @import("../../common/primitive/measurement.zig");

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
        _ = onprem.encodeFrame(&sink, input[0..size], workspace, frame_options, 0) catch return error.TestUnexpectedResult;
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
