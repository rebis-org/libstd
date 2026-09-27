const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const measurement = @import("../common/primitive/measurement.zig");
const zstd = @import("../leaf/zstd.zig");

// Zstandard seekable format (contrib/seekable_format spec 0.1.0): independent
// zstd frames followed by a skippable frame carrying the seek table, whose
// footer magic must be the last bytes of the file.

const frame_magic: u32 = 0xFD2FB528;
const skippable_magic: u32 = 0x184D2A5E;
const seekable_magic: u32 = 0x8F92EAB1;
const footer_size = 9;
const entry_size = 8;

pub const frame_size_min: u32 = zstd.window_size_min;
pub const frame_size_max: u32 = zstd.encoder_frame_size_max;
pub const frame_size_default: u32 = 1 << 20;

pub const Options = struct {
    frame_size: u32 = frame_size_default,
    window: u32 = 1 << 20,
    hash_bits: u32 = 17,
    max_chain: u32 = 32,
    nice_len: u32 = 64,
    search_window: u32 = 8,
};

pub fn frameOptions(options: Options) zstd.Options {
    const window: u32 = @max(options.window, zstd.window_size_min);
    return .{
        .window_size = window,
        .hash_bits = @intCast(options.hash_bits),
        .max_chain = options.max_chain,
        .nice_len = options.nice_len,
        .search_window = options.search_window,
    };
}

fn tableSize(frame_count: usize) usize {
    return 8 + frame_count * entry_size + footer_size;
}

pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    const frames = input_len / options.frame_size + 1;
    return zstd.encodedSizeBound(input_len, frameOptions(options)) + tableSize(frames);
}

pub const FrameInfo = struct {
    frame_count: u32,
    has_checksums: bool,
};

// The table footer magic must be the file's last bytes. Table entries are
// validated against the frame magics at their compressed offsets.
pub fn inspect(input: []const u8) Failure!FrameInfo {
    if (input.len < 8 + footer_size) return error.InvalidData;
    if (std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little) != seekable_magic) return error.InvalidData;
    const frame_count = std.mem.readInt(u32, input[input.len - footer_size ..][0..4], .little);
    const descriptor = input[input.len - 5];
    if (descriptor & 0x7C != 0) return error.Unsupported;
    const has_checksums = (descriptor & 0x80) != 0;
    const entry_bytes = @as(usize, frame_count) * (entry_size + @as(usize, if (has_checksums) 4 else 0));
    if (input.len < 8 + entry_bytes + footer_size) return error.InvalidData;
    const table_start = input.len - footer_size - entry_bytes;
    const table = input[table_start .. input.len - footer_size];
    if (std.mem.readInt(u32, input[table_start - 4 ..][0..4], .little) != entry_bytes + footer_size) return error.InvalidData;
    if (std.mem.readInt(u32, input[table_start - 8 ..][0..4], .little) != skippable_magic) return error.InvalidData;
    var offset: usize = 0;
    for (0..frame_count) |index| {
        const entry = table[index * (entry_size + @as(usize, if (has_checksums) 4 else 0)) ..][0..entry_size];
        const compressed_size = std.mem.readInt(u32, entry[0..4], .little);
        if (compressed_size == 0) return error.InvalidData;
        if (offset + compressed_size > table_start - 8) return error.InvalidData;
        const magic = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (magic != frame_magic and !(magic >= 0x184D2A50 and magic <= 0x184D2A5F)) return error.InvalidData;
        offset += compressed_size;
    }
    if (offset != table_start - 8) return error.InvalidData;
    return .{ .frame_count = frame_count, .has_checksums = has_checksums };
}

pub fn decodedSize(input: []const u8, history: []u8, options: Options) Failure!usize {
    _ = try inspect(input);
    var counter = measurement.Counter.init(null);
    try decode(input, &counter.writer, history, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub const FrameEntry = struct { compressed: u32, decompressed: u32 };

pub fn frameCountFor(input_len: usize, options: Options) usize {
    return input_len / options.frame_size + 1;
}

pub fn encodeToWriter(input: []const u8, output: *std.Io.Writer, history: []u8, workspace: []u32, entries: []FrameEntry, options: Options) Failure!void {
    if (options.frame_size < frame_size_min or options.frame_size > frame_size_max) return error.InvalidCall;
    if (entries.len < frameCountFor(input.len, options)) return error.InsufficientCapacity;
    const frame_options = frameOptions(options);
    const needed_history = @as(usize, frame_options.window_size) + zstd.block_size_max;
    if (history.len < needed_history) return error.InsufficientCapacity;
    if (workspace.len < zstd.encoderWorkspaceU32Count(0, options.frame_size, frame_options)) return error.InsufficientCapacity;
    var frame_count: usize = 0;
    var offset: usize = 0;
    while (offset < input.len or (input.len == 0 and frame_count == 0)) {
        const chunk_len: usize = if (input.len == 0) 0 else @min(input.len - offset, options.frame_size);
        const chunk = input[offset .. offset + chunk_len];
        const written = zstd.encodeFrame(output, chunk, workspace, frame_options, 0) catch |err| switch (err) {
            error.InvalidData => return error.InvalidCall,
            error.ResourceLimit, error.IoFailure => |e| return e,
        };
        entries[frame_count] = .{
            .compressed = std.math.cast(u32, written) orelse return error.ResourceLimit,
            .decompressed = std.math.cast(u32, chunk_len) orelse return error.ResourceLimit,
        };
        frame_count += 1;
        offset += chunk_len;
        if (input.len == 0) break;
    }
    // Seek table in a skippable frame. No per-entry checksums (descriptor 0).
    const table_len = tableSize(frame_count);
    output.writeInt(u32, skippable_magic, .little) catch return error.IoFailure;
    output.writeInt(u32, std.math.cast(u32, table_len - 8) orelse return error.ResourceLimit, .little) catch return error.IoFailure;
    for (entries[0..frame_count]) |entry| {
        output.writeInt(u32, entry.compressed, .little) catch return error.IoFailure;
        output.writeInt(u32, entry.decompressed, .little) catch return error.IoFailure;
    }
    output.writeInt(u32, std.math.cast(u32, frame_count) orelse return error.ResourceLimit, .little) catch return error.IoFailure;
    output.writeByte(0) catch return error.IoFailure;
    output.writeInt(u32, seekable_magic, .little) catch return error.IoFailure;
}

pub fn encode(input: []const u8, output: []u8, history: []u8, workspace: []u32, entries: []FrameEntry, options: Options) Failure!usize {
    var fixed = std.Io.Writer.fixed(output);
    try encodeToWriter(input, &fixed, history, workspace, entries, options);
    return fixed.end;
}

pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8, options: Options) Failure!void {
    _ = try inspect(input);
    const frame_options = frameOptions(options);
    var source = std.Io.Reader.fixed(input);
    _ = zstd.decodeStream(&source, output, history, frame_options) catch |err| return err;
}

test "zstd seekable roundtrip" {
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
    try std.testing.expectError(error.InvalidData, inspect(encoded[0 .. encoded_len - footer_size]));
}
