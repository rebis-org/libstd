const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const measurement = @import("../../../common/primitive/measurement.zig");
const tee = @import("../../../common/primitive/tee.zig");
const zstd = @import("../../leaf/zstd/onprem.zig");

const Exception = exception_prim.Exception;
pub const frame_size_max: u32 = zstd.encoder_frame_size_max;
pub const frame_size_min: u32 = zstd.window_size_min;

const frame_magic: u32 = 0xFD2FB528;
const skippable_magic: u32 = 0x184D2A5E;
const seekable_magic: u32 = 0x8F92EAB1;
const footer_size = 9;
const entry_size = 8;

pub const frame_size_default: u32 = 1 << 20;

pub const Options = struct {
    frame_size: u32 = frame_size_default,
    window_size: u32 = 1 << 20,
    hash_bits: u32 = 17,
    max_chain: u32 = 32,
    nice_len: u32 = 64,
    search_window: u32 = 8,
    provider: checksum.Provider = checksum.default_provider,
};

pub fn frameOptions(options: Options) zstd.Options {
    // Sizing must not trap on a caller parameter, so the width clamps here;
    // the encoder rejects the same value with CallException before it writes.
    const window_size: u32 = @max(options.window_size, zstd.window_size_min);
    return .{
        .window_size = window_size,
        .hash_bits = @intCast(@min(options.hash_bits, std.math.maxInt(u5))),
        .max_chain = options.max_chain,
        .nice_len = options.nice_len,
        .search_window = options.search_window,
        .provider = options.provider,
    };
}

fn tableSize(frame_count: usize) usize {
    return 8 + frame_count * entry_size + footer_size;
}

pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    return zstd.encodedSizeBound(input_len, frameOptions(options)) + tableSize(frameCountFor(input_len, options));
}

pub const FrameInfo = struct {
    frame_count: u32,
    has_checksums: bool,
};

// The footer magic must be at the end of the input. Each table entry is checked
// against the frame magic at its compressed offset.
pub fn inspect(input: []const u8) Exception!FrameInfo {
    if (input.len < 8 + footer_size) return error.DataException;
    if (std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little) != seekable_magic) return error.DataException;
    const frame_count = std.mem.readInt(u32, input[input.len - footer_size ..][0..4], .little);
    const descriptor = input[input.len - 5];
    if (descriptor & 0x7C != 0) return error.UnsupportedException;
    const has_checksums = (descriptor & 0x80) != 0;
    // The frame count comes off the wire, so the table arithmetic runs in u64:
    // on 32-bit targets a hostile count would otherwise wrap the entry product
    // or the length sum before the checks below can reject the input.
    const entry_bytes: u64 = @as(u64, frame_count) * (entry_size + @as(u64, if (has_checksums) 4 else 0));
    if (@as(u64, input.len) < 8 + entry_bytes + footer_size) return error.DataException;
    const table_start: usize = @intCast(@as(u64, input.len) - footer_size - entry_bytes);
    const table = input[table_start .. input.len - footer_size];
    if (std.mem.readInt(u32, input[table_start - 4 ..][0..4], .little) != entry_bytes + footer_size) return error.DataException;
    if (std.mem.readInt(u32, input[table_start - 8 ..][0..4], .little) != skippable_magic) return error.DataException;
    var offset: usize = 0;
    for (0..frame_count) |index| {
        const entry = table[index * (entry_size + @as(usize, if (has_checksums) 4 else 0)) ..][0..entry_size];
        const compressed_size = std.mem.readInt(u32, entry[0..4], .little);
        if (compressed_size == 0) return error.DataException;
        if (@as(u64, offset) + compressed_size > table_start - 8) return error.DataException;
        const magic = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (magic != frame_magic and !(magic >= 0x184D2A50 and magic <= 0x184D2A5F)) return error.DataException;
        offset += compressed_size;
    }
    if (offset != table_start - 8) return error.DataException;
    return .{ .frame_count = frame_count, .has_checksums = has_checksums };
}

pub fn decodedSize(input: []const u8, history: []u8, options: Options) Exception!usize {
    _ = try inspect(input);
    var counter = measurement.Counter.init(null);
    try decode(input, &counter.writer, history, options);
    return measurement.measuredLength(&counter);
}

pub const FrameEntry = struct { compressed_size: u32, decompressed_size: u32 };

pub fn frameCountFor(input_len: usize, options: Options) usize {
    // A frame size below the format minimum can never be written; clamping up
    // keeps the count an upper bound instead of dividing by zero.
    return input_len / @max(options.frame_size, frame_size_min) + 1;
}

pub fn encodeToWriter(input: []const u8, output: *std.Io.Writer, history: []u8, workspace: []u32, entries: []FrameEntry, options: Options) Exception!void {
    if (options.frame_size < frame_size_min or options.frame_size > frame_size_max) return error.CallException;
    if (options.hash_bits > std.math.maxInt(u5)) return error.CallException;
    if (entries.len < frameCountFor(input.len, options)) return error.CapacityException;
    const frame_options = frameOptions(options);
    const needed_history = @as(usize, frame_options.window_size) + zstd.block_size_max;
    if (history.len < needed_history) return error.CapacityException;
    if (workspace.len < zstd.encoderWorkspaceU32Count(0, options.frame_size, frame_options)) return error.CapacityException;
    var frame_count: usize = 0;
    var offset: usize = 0;
    while (offset < input.len or (input.len == 0 and frame_count == 0)) {
        const chunk_len: usize = if (input.len == 0) 0 else @min(input.len - offset, options.frame_size);
        const chunk = input[offset .. offset + chunk_len];
        const written = zstd.encodeFrame(output, chunk, workspace, frame_options, 0) catch |err| switch (err) {
            error.DataException => return error.CallException,
            error.ResourceException, error.IoException => |e| return e,
        };
        entries[frame_count] = .{
            .compressed_size = std.math.cast(u32, written) orelse return error.ResourceException,
            .decompressed_size = std.math.cast(u32, chunk_len) orelse return error.ResourceException,
        };
        frame_count += 1;
        offset += chunk_len;
        if (input.len == 0) break;
    }
    // The seek table is a skippable frame. Descriptor 0 stores no per-entry checksums.
    const table_len = tableSize(frame_count);
    output.writeInt(u32, skippable_magic, .little) catch return error.IoException;
    output.writeInt(u32, std.math.cast(u32, table_len - 8) orelse return error.ResourceException, .little) catch return error.IoException;
    for (entries[0..frame_count]) |entry| {
        output.writeInt(u32, entry.compressed_size, .little) catch return error.IoException;
        output.writeInt(u32, entry.decompressed_size, .little) catch return error.IoException;
    }
    output.writeInt(u32, std.math.cast(u32, frame_count) orelse return error.ResourceException, .little) catch return error.IoException;
    output.writeByte(0) catch return error.IoException;
    output.writeInt(u32, seekable_magic, .little) catch return error.IoException;
}

pub fn encode(input: []const u8, output: []u8, history: []u8, workspace: []u32, entries: []FrameEntry, options: Options) Exception!usize {
    var writer = std.Io.Writer.fixed(output);
    try encodeToWriter(input, &writer, history, workspace, entries, options);
    return writer.end;
}

pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8, options: Options) Exception!void {
    const info = try inspect(input);
    const frame_options = frameOptions(options);
    if (!info.has_checksums) {
        var source = std.Io.Reader.fixed(input);
        _ = zstd.decodeStream(&source, output, history, frame_options) catch |err| return err;
        return;
    }
    // With checksums, decode frame by frame so each entry's output is hashed
    // and compared against its stored low 32 bits of XXH64 (the format's
    // integrity contract; the reference decoder verifies the same field). A
    // mismatch fails the whole decode before later frames are touched.
    const stride = entry_size + 4;
    const table_start = input.len - footer_size - @as(usize, info.frame_count) * stride;
    var offset: usize = 0;
    for (0..info.frame_count) |index| {
        const entry = input[table_start + index * stride ..][0 .. entry_size + 4];
        const compressed_size = std.mem.readInt(u32, entry[0..4], .little);
        const expected_size = std.mem.readInt(u32, entry[4..8], .little);
        const expected_hash = std.mem.readInt(u32, entry[entry_size..][0..4], .little);
        var frame_tee = tee.CountingTee(.{ .xxh64 = true }).init(output);
        var frame_source = std.Io.Reader.fixed(input[offset .. offset + compressed_size]);
        _ = zstd.decodeStream(&frame_source, &frame_tee.writer, history, frame_options) catch |err| return err;
        // The table entry states both the content hash and the exact size the
        // frame must produce; either disagreement is corruption, not a format
        // error.
        if (frame_tee.size != expected_size) return error.IntegrityException;
        if (@as(u32, @truncate(frame_tee.xxh64Value())) != expected_hash) return error.IntegrityException;
        offset += compressed_size;
    }
}

test "zstd seekable round trip restores the original input" {
    const options: Options = .{};
    var prng = std.Random.DefaultPrng.init(0xbeef);
    const random = prng.random();
    const input = try std.testing.allocator.alloc(u8, 300000);
    defer std.testing.allocator.free(input);
    for (input, 0..) |*byte, i| {
        byte.* = if (i % 89 < 50) @as(u8, @truncate(i / 8192)) else random.int(u8);
    }
    const frame_options = frameOptions(options);
    const history = try std.testing.allocator.alloc(u8, @as(usize, frame_options.window_size) + zstd.block_size_max);
    defer std.testing.allocator.free(history);
    const workspace = try std.testing.allocator.alloc(u32, zstd.encoderWorkspaceU32Count(0, options.frame_size, frame_options));
    defer std.testing.allocator.free(workspace);
    const encoded = try std.testing.allocator.alloc(u8, encodedSizeBound(input.len, options));
    defer std.testing.allocator.free(encoded);
    const entries = try std.testing.allocator.alloc(FrameEntry, frameCountFor(input.len, options));
    defer std.testing.allocator.free(entries);
    const encoded_len = try encode(input, encoded, history, workspace, entries, options);
    const info = try inspect(encoded[0..encoded_len]);
    try std.testing.expectEqual(@as(u32, 1), info.frame_count);
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    var sink = std.Io.Writer.fixed(decoded);
    try decode(encoded[0..encoded_len], &sink, history, options);
    try std.testing.expectEqualSlices(u8, input, decoded[0..sink.end]);
    // The payload without its table is not a seekable stream.
    try std.testing.expectError(error.DataException, inspect(encoded[0 .. encoded_len - footer_size]));
}

test "seek table checksums verify each frame" {
    const options: Options = .{};
    const frame_options = frameOptions(options);
    const payloads = [_][]const u8{
        "first checksummed frame carries compressible text repeated repeated",
        "second frame differs so per-frame bookkeeping cannot be short-circuited",
    };
    const history = try std.testing.allocator.alloc(u8, @as(usize, frame_options.window_size) + zstd.block_size_max);
    defer std.testing.allocator.free(history);
    const workspace = try std.testing.allocator.alloc(u32, zstd.encoderWorkspaceU32Count(0, options.frame_size, frame_options));
    defer std.testing.allocator.free(workspace);
    // Two frames, then a hand-built table with checksums (descriptor 0x80)
    // exactly as the reference seekable compressor writes it.
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    var compressed_sizes: [payloads.len]u32 = undefined;
    for (payloads, 0..) |payload, index| {
        const before = writer.end;
        _ = try zstd.encodeFrame(&writer, payload, workspace, frame_options, 0);
        compressed_sizes[index] = @intCast(writer.end - before);
    }
    try writer.writeInt(u32, skippable_magic, .little);
    try writer.writeInt(u32, payloads.len * (entry_size + 4) + footer_size, .little);
    for (payloads, 0..) |payload, index| {
        var hasher = checksum.XxHash64.bind(checksum.default_provider, 0);
        hasher.update(payload);
        try writer.writeInt(u32, compressed_sizes[index], .little);
        try writer.writeInt(u32, @intCast(payload.len), .little);
        try writer.writeInt(u32, @truncate(hasher.final()), .little);
    }
    try writer.writeInt(u32, payloads.len, .little);
    try writer.writeByte(0x80);
    try writer.writeInt(u32, seekable_magic, .little);
    const input = buffer[0..writer.end];
    const info = try inspect(input);
    try std.testing.expectEqual(@as(u32, payloads.len), info.frame_count);
    try std.testing.expect(info.has_checksums);
    var decoded: [1024]u8 = undefined;
    var sink = std.Io.Writer.fixed(&decoded);
    try decode(input, &sink, history, options);
    try std.testing.expectEqualSlices(u8, payloads[0], decoded[0..payloads[0].len]);
    try std.testing.expectEqualSlices(u8, payloads[1], decoded[payloads[0].len..][0..payloads[1].len]);
    try std.testing.expectEqual(payloads[0].len + payloads[1].len, try decodedSize(input, history, options));
    // A corrupted stored checksum fails decode and the decodedSize preflight.
    const table_start = input.len - footer_size - payloads.len * (entry_size + 4);
    input[table_start + entry_size] ^= 0xff;
    var corrupt_sink = std.Io.Writer.fixed(&decoded);
    try std.testing.expectError(error.IntegrityException, decode(input, &corrupt_sink, history, options));
    try std.testing.expectError(error.IntegrityException, decodedSize(input, history, options));
    input[table_start + entry_size] ^= 0xff;
    // Reserved descriptor bits are refused; unused bits are ignored.
    input[input.len - 5] = 0x84;
    try std.testing.expectError(error.UnsupportedException, inspect(input));
    input[input.len - 5] = 0x81;
    var unused_sink = std.Io.Writer.fixed(&decoded);
    try decode(input, &unused_sink, history, options);
    try std.testing.expectEqualSlices(u8, payloads[0], decoded[0..payloads[0].len]);
    input[input.len - 5] = 0x80;
}

test "hostile seek footer frame counts are rejected without overflow" {
    // A saturated frame count with checksums: the entry product alone is
    // 48 GiB, far past any 17-byte input, and must be refused by the u64
    // length check instead of wrapping a usize.
    var hostile: [17]u8 = @splat(0);
    std.mem.writeInt(u32, hostile[8..12], 0xFFFFFFFF, .little);
    hostile[12] = 0x80;
    std.mem.writeInt(u32, hostile[13..17], seekable_magic, .little);
    try std.testing.expectError(error.DataException, inspect(&hostile));
    // A frame count of 2^29 without checksums makes the bare entry product
    // exactly 2^32, the 32-bit wrap boundary.
    var wrapping: [17]u8 = @splat(0);
    std.mem.writeInt(u32, wrapping[8..12], 0x20000000, .little);
    std.mem.writeInt(u32, wrapping[13..17], seekable_magic, .little);
    try std.testing.expectError(error.DataException, inspect(&wrapping));
}

test "seekable sizing survives a zero frame size and a wide hash width" {
    // Both are caller-supplied parameters: sizing must stay a bound instead
    // of trapping on a division by zero or a narrowing cast.
    const options: Options = .{ .frame_size = 0, .hash_bits = 64 };
    _ = encodedSizeBound(1 << 20, options);
    try std.testing.expectEqual(@as(usize, (1 << 20) / frame_size_min + 1), frameCountFor(1 << 20, options));
    var buffer: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&buffer);
    var history: [1]u8 = undefined;
    var workspace: [1]u32 = undefined;
    var entries: [1]FrameEntry = undefined;
    try std.testing.expectError(error.CallException, encodeToWriter("x", &sink, &history, &workspace, &entries, options));
    try std.testing.expectError(error.CallException, encodeToWriter("x", &sink, &history, &workspace, &entries, .{ .hash_bits = 64 }));
}
