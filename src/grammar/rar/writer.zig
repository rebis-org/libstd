const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bounds = @import("../../common/primitive/bounds.zig");
const checksum = @import("../../common/primitive/checksum.zig");
const pack50 = @import("pack50.zig");
const finder = @import("finder.zig");
const rar = @import("../rar.zig");

// RAR5 archive creation (store or LZ). The facade (../rar.zig) owns reading;
// this file owns writing: entry serialization, the packed region, and the
// block compressor handoff.

pub const RarEntry = struct {
    name: []const u8,
    data: []const u8 = &.{},
    mtime: u32 = 0,
    is_directory: bool = false,
    method: u8 = 0, // 0 = store, 1-5 = LZ level
};

pub const pack50Sizes = pack50.workspacesFor;
pub const LzToken = finder.LzToken;

// Write-side buffers, all caller-provided.
pub const WriteBuffers = struct {
    hash: []u32,
    hash2: []u32,
    hash3: []u32,
    bt_left: []u32,
    bt_right: []u32,
    tokens: []finder.LzToken,
    staging: []u8, // block compressor staging: 2x input + slack
    packed_buf: []u8, // all entries' packed data, laid out back to back
    packed_sizes: []usize,
};

// Per-entry packed-size bound used to lay out `packed`.
pub fn packedBound(entry: RarEntry) usize {
    if (entry.is_directory or entry.data.len == 0 or entry.method == 0) return entry.data.len;
    return entry.data.len * pack50.max_expansion + pack50.output_slack;
}

fn writeVint(value: u64, out: []u8) usize {
    var v = value;
    var i: usize = 0;
    while (true) {
        out[i] = @intCast(v & 0x7F);
        v >>= 7;
        if (v != 0) {
            out[i] |= 0x80;
            i += 1;
        } else {
            return i + 1;
        }
    }
}

fn vintSize(value: u64) usize {
    var v = value;
    var size: usize = 1;
    while (v > 0x7F) {
        v >>= 7;
        size += 1;
    }
    return size;
}

// compression_info: algo 0, solid 0, method 1-5, dict_bits 3 (1 MiB window).
fn compressionInfoVint(method: u3) u64 {
    return (@as(u64, method) << 7) | (@as(u64, 3) << 10);
}

const block_writer = struct {
    // Serialize `contents` (already starting with the type vint) as one
    // header: CRC32 over [size_vint .. end], little-endian, then the bytes.
    fn emitHeader(out: []u8, pos: usize, contents: []const u8) Failure!usize {
        var size_buf: [10]u8 = undefined;
        const size_len = writeVint(contents.len, &size_buf);
        // The header CRC covers the size vint plus the contents, matching the
        // reader, which checksums from the size field through the body end.
        var crc_state = checksum.Crc32.init();
        crc_state.update(size_buf[0..size_len]);
        crc_state.update(contents);
        const total = 4 + size_len + contents.len;
        if (out.len < pos + total) return error.InsufficientCapacity;
        std.mem.writeInt(u32, out[pos..][0..4], crc_state.final(), .little);
        var cursor = pos + 4;
        @memcpy(out[cursor..][0..size_len], size_buf[0..size_len]);
        cursor += size_len;
        @memcpy(out[cursor..][0..contents.len], contents);
        return pos + total;
    }

    fn mainBlockSize() usize {
        // type(1) + flags(1) + archive_flags(1) = 3 contents bytes; one-byte
        // size vint; 4 CRC bytes.
        return 4 + 1 + 3;
    }

    fn writeMainBlock(out: []u8, pos: usize) Failure!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_main, contents[c..]);
        c += writeVint(0, contents[c..]); // header flags
        c += writeVint(0, contents[c..]); // archive flags
        return emitHeader(out, pos, contents[0..c]);
    }

    fn endBlockSize() usize {
        // type(1) + flags(1) + end_flags(1) = 3 contents bytes.
        return 4 + 1 + 3;
    }

    fn writeEndBlock(out: []u8, pos: usize) Failure!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_end, contents[c..]);
        c += writeVint(0, contents[c..]); // header flags
        c += writeVint(0, contents[c..]); // end flags
        return emitHeader(out, pos, contents[0..c]);
    }

    // Header-only size for a file block carrying `packed_len` bytes of data.
    fn fileBlockSize(entry: RarEntry, packed_len: usize) usize {
        var file_flags: u64 = rar.rar5_file_mtime;
        if (entry.is_directory) {
            file_flags |= rar.rar5_file_directory;
        } else {
            file_flags |= rar.rar5_file_crc32;
        }
        const attributes: u64 = if (entry.is_directory) 0x10 else 0x20;

        var body: usize = 0;
        body += vintSize(file_flags);
        body += vintSize(if (entry.is_directory) 0 else entry.data.len);
        body += vintSize(attributes);
        body += 4; // mtime
        if (!entry.is_directory) body += 4; // crc32
        body += vintSize(if (entry.method == 0) 0 else compressionInfoVint(@intCast(entry.method)));
        body += vintSize(3); // host_os unix
        body += vintSize(entry.name.len);
        body += entry.name.len;

        var contents: usize = 0;
        contents += vintSize(rar.rar5_type_file);
        contents += vintSize(if (packed_len > 0) rar.rar5_flag_data else 0);
        if (packed_len > 0) contents += vintSize(packed_len);
        contents += body;

        return 4 + vintSize(contents) + contents + packed_len;
    }

    fn writeFileBlock(
        out: []u8,
        pos: usize,
        entry: RarEntry,
        packed_data: []const u8,
    ) Failure!usize {
        var file_flags: u64 = rar.rar5_file_mtime;
        if (entry.is_directory) {
            file_flags |= rar.rar5_file_directory;
        } else {
            file_flags |= rar.rar5_file_crc32;
        }
        const attributes: u64 = if (entry.is_directory) 0x10 else 0x20;
        const data_crc = if (entry.is_directory) 0 else checksum.crc32(entry.data);

        var body: [4200]u8 = undefined;
        var b: usize = 0;
        b += writeVint(file_flags, body[b..]);
        b += writeVint(if (entry.is_directory) 0 else entry.data.len, body[b..]);
        b += writeVint(attributes, body[b..]);
        std.mem.writeInt(u32, body[b..][0..4], entry.mtime, .little);
        b += 4;
        if (!entry.is_directory) {
            std.mem.writeInt(u32, body[b..][0..4], data_crc, .little);
            b += 4;
        }
        b += writeVint(if (entry.method == 0) 0 else compressionInfoVint(@intCast(entry.method)), body[b..]);
        b += writeVint(3, body[b..]);
        b += writeVint(entry.name.len, body[b..]);
        @memcpy(body[b..][0..entry.name.len], entry.name);
        b += entry.name.len;

        const data_size: usize = if (entry.is_directory) 0 else packed_data.len;
        var contents: [4400]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_file, contents[c..]);
        c += writeVint(if (data_size > 0) rar.rar5_flag_data else 0, contents[c..]);
        if (data_size > 0) c += writeVint(data_size, contents[c..]);
        @memcpy(contents[c..][0..b], body[0..b]);
        c += b;

        var cursor = try emitHeader(out, pos, contents[0..c]);
        if (data_size > 0) {
            if (out.len < cursor + packed_data.len) return error.InsufficientCapacity;
            @memcpy(out[cursor..][0..packed_data.len], packed_data);
            cursor += packed_data.len;
        }
        return cursor;
    }
};

fn checkWriteEntries(entries: []const RarEntry) Failure!void {
    for (entries) |entry| {
        if (entry.name.len > 4096) return error.InvalidCall;
        if (entry.method > 5) return error.InvalidCall;
    }
    if (entries.len > 65535) return error.ResourceLimit;
}

// Compress every LZ entry into its slot of the packed region, returning the
// total archive size. Shared by the sizing query and the commit pass (each
// runs it afresh — the two-pass shape the zip writer established).
fn packEntries(entries: []const RarEntry, ws: *WriteBuffers) Failure!usize {
    var total: usize = rar.rar5_signature.len + block_writer.mainBlockSize() + block_writer.endBlockSize();
    var packed_cursor: usize = 0;
    for (entries, 0..) |entry, i| {
        const packed_len: usize = if (entry.is_directory or entry.data.len == 0 or entry.method == 0) blk: {
            // Store entries' "packed" data is the raw bytes; lay them into
            // the packed region so the writer reads everything from there.
            if (ws.packed_buf.len - packed_cursor < entry.data.len) return error.InternalFailure;
            @memcpy(ws.packed_buf[packed_cursor .. packed_cursor + entry.data.len], entry.data);
            break :blk entry.data.len;
        } else blk: {
            const bound = packedBound(entry);
            if (ws.packed_buf.len - packed_cursor < bound) return error.InternalFailure;
            const slice = ws.packed_buf[packed_cursor .. packed_cursor + bound];
            const sizes = pack50.workspacesFor(entry.data.len);
            if (ws.hash.len < sizes.hash_words or ws.hash2.len < sizes.hash2_words or
                ws.hash3.len < sizes.hash3_words or ws.bt_left.len < sizes.bt_words or
                ws.bt_right.len < sizes.bt_words or ws.tokens.len < sizes.token_count or
                ws.staging.len < sizes.staging_bytes) return error.InternalFailure;
            const written = try pack50.compressBlock(entry.data, @intCast(entry.method), true, .{
                .hash = ws.hash,
                .hash2 = ws.hash2,
                .hash3 = ws.hash3,
                .bt_left = ws.bt_left,
                .bt_right = ws.bt_right,
                .tokens = ws.tokens,
                .staging = ws.staging,
            }, slice);
            break :blk written;
        };
        if (ws.packed_sizes.len < entries.len) return error.InternalFailure;
        ws.packed_sizes[i] = packed_len;
        packed_cursor = try bounds.add(packed_cursor, packed_len);
        total = try bounds.add(total, block_writer.fileBlockSize(entry, packed_len));
    }
    return total;
}

pub fn rarWriteSize(entries: []const RarEntry, ws: *WriteBuffers) Failure!usize {
    try checkWriteEntries(entries);
    return packEntries(entries, ws);
}

pub fn rarEncode(entries: []const RarEntry, output: []u8, ws: *WriteBuffers) Failure!usize {
    const required = try rarWriteSize(entries, ws);
    if (output.len < required) return error.InsufficientCapacity;

    var pos: usize = 0;
    @memcpy(output[pos..][0..rar.rar5_signature.len], &rar.rar5_signature);
    pos += rar.rar5_signature.len;
    pos = try block_writer.writeMainBlock(output, pos);

    var i: usize = 0;
    var cursor: usize = 0;
    while (i < entries.len) : (i += 1) {
        const entry = entries[i];
        const packed_len = ws.packed_sizes[i];
        const packed_slice = ws.packed_buf[cursor .. cursor + packed_len];
        pos = try block_writer.writeFileBlock(output, pos, entry, packed_slice);
        cursor = try bounds.add(cursor, packed_len);
    }

    pos = try block_writer.writeEndBlock(output, pos);
    return pos;
}

test "vint encoding matches the rar5 wire form" {
    var buf: [10]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), writeVint(0x42, &buf));
    try std.testing.expectEqual(@as(u8, 0x42), buf[0]);
    try std.testing.expectEqual(@as(usize, 2), writeVint(0x2101, &buf));
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x42), buf[1]);
    try std.testing.expectEqual(vintSize(0x2101), 2);
    try std.testing.expectEqual(vintSize(0), 1);
}

test "created archive round-trips through the facade reader (store and lz)" {
    const testing = std.testing;
    const data1 = "hello rar5 stored";
    const data2 = "The quick brown fox jumps over the lazy dog. " ** 8;
    const allocator = testing.allocator;

    const window = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(window);
    const state_store = try allocator.alloc(u64, (rar.max_state_bytes + 7) / 8);
    defer allocator.free(state_store);
    const table_pool = try allocator.alloc(u16, rar.table_pool_words);
    defer allocator.free(table_pool);
    const pending50 = try allocator.alloc(rar.PendingFilter50, rar.max_pending50);
    defer allocator.free(pending50);
    const pending29 = try allocator.alloc(rar.PendingFilter29, rar.max_pending29);
    defer allocator.free(pending29);
    const filter_scratch = try allocator.alloc(u8, window.len + rar.filter_scratch_extra);
    defer allocator.free(filter_scratch);
    const ppm_heap = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(ppm_heap);

    for ([_]u8{ 0, 3 }) |method| {
        const entries = [_]RarEntry{
            .{ .name = "m1.txt", .data = data1, .method = method },
            .{ .name = "m2.txt", .data = data2, .method = method },
        };
        const sizes = pack50.workspacesFor(@max(data1.len, data2.len));
        const hash = try allocator.alloc(u32, sizes.hash_words);
        defer allocator.free(hash);
        const hash2 = try allocator.alloc(u32, sizes.hash2_words);
        defer allocator.free(hash2);
        const hash3 = try allocator.alloc(u32, sizes.hash3_words);
        defer allocator.free(hash3);
        const bt_left = try allocator.alloc(u32, sizes.bt_words);
        defer allocator.free(bt_left);
        const bt_right = try allocator.alloc(u32, sizes.bt_words);
        defer allocator.free(bt_right);
        const tokens = try allocator.alloc(finder.LzToken, sizes.token_count);
        defer allocator.free(tokens);
        const staging = try allocator.alloc(u8, sizes.staging_bytes);
        defer allocator.free(staging);
        var packed_total: usize = 0;
        for (entries) |e| packed_total += packedBound(e);
        const packed_buf = try allocator.alloc(u8, packed_total);
        defer allocator.free(packed_buf);
        const packed_sizes = try allocator.alloc(usize, entries.len);
        defer allocator.free(packed_sizes);
        var ws = WriteBuffers{
            .hash = hash,
            .hash2 = hash2,
            .hash3 = hash3,
            .bt_left = bt_left,
            .bt_right = bt_right,
            .tokens = tokens,
            .staging = staging,
            .packed_buf = packed_buf,
            .packed_sizes = packed_sizes,
        };
        const required = try rarWriteSize(&entries, &ws);
        const archive = try allocator.alloc(u8, required);
        defer allocator.free(archive);
        const written = try rarEncode(&entries, archive, &ws);
        try testing.expectEqual(required, written);

        try testing.expectEqual(@as(usize, 2), try rar.rarInspectCount(archive, 128));
        const out1 = try allocator.alloc(u8, data1.len);
        defer allocator.free(out1);
        const out2 = try allocator.alloc(u8, data2.len);
        defer allocator.free(out2);
        const bufs = rar.DecodeBuffers{
            .state = std.mem.sliceAsBytes(state_store),
            .window = window,
            .table_pool = table_pool,
            .pending50 = pending50,
            .pending29 = pending29,
            .filter_scratch = filter_scratch,
            .ppm_heap = ppm_heap,
        };
        try testing.expectEqual(@as(usize, data1.len), try rar.rarDecodeOrdinal(archive, 0, out1, @constCast(&bufs)));
        try testing.expectEqualSlices(u8, data1, out1);
        try testing.expectEqual(@as(usize, data2.len), try rar.rarDecodeOrdinal(archive, 1, out2, @constCast(&bufs)));
        try testing.expectEqualSlices(u8, data2, out2);
    }
}
