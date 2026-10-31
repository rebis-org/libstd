const std = @import("std");

const entry_prim = @import("../../../common/entry.zig");
const session = @import("../../../common/session.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const cpio = @import("../cpio/onprem.zig");
const xar = @import("../xar/onprem.zig");
const xz = @import("../xz/onprem.zig");
const pbzx = @import("pbzx.zig");

pub const Entry = entry_prim.Entry;
const Exception = exception_prim.Exception;

// XIP: a XAR container whose Content member is a pbzx chunk stream of a
// cpio archive. Each chunk states its decoded size, so a read decodes
// only the chunks it touches.

pub const block_size_max: usize = 16 << 20;
// Writer chunk size: the last chunk pads to it, so a small one is cheap.
pub const block_size_write: u64 = 1 << 20;
// An in-place decode keeps no dictionary mirror, so this only seeds the
// workspace formula; the value is what pkgbuild writes.
pub const dictionary_seed: u32 = 8 << 20;
const name_max: usize = 4096;
pub const chunk_header_size: u64 = 16;
pub const pbzx_header_size: u64 = 12;
const member_name = "Content";
pub const xz_magic = [6]u8{ 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };

pub const scratch_size: usize = xar.scratch_size + block_size_max + xz.decodeInPlaceWorkspaceSize(dictionary_seed) + name_max;

// The read side is one session chain: XAR locates Content,
// pbzx decodes the chunks, cpio walks the records.
const Chain = session.Nested(xar.Outer, pbzx.Pbzx, cpio.Inner);

comptime {
    if (Chain.scratch_size != scratch_size) @compileError("xip: the session chain no longer matches the frozen scratch budget");
}

// The write side needs only the XML staging area; the check keeps the
// old whole-budget answer for a short buffer.
fn tocArea(scratch: []u8) Exception![]u8 {
    if (scratch.len < scratch_size) return error.ResourceException;
    return scratch[0..xar.scratch_size];
}

pub const EntryInfo = struct {
    name: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modification_time: u64,
    ordinal: u64,
    ino: u32,
    nlink: u32,
    // Set only by a collapsing cursor: the ordinal that owns the group data.
    link_ordinal: ?u64 = null,
};

pub const LinkMode = enum { records, collapse };

// Open-addressed group table: a zero `ordinal_plus_one` marks a free slot.
pub const Link = struct {
    ino: u32,
    ordinal_plus_one: u64,
};

// One forward pass over the members. A caller walks every entry in a
// single decode instead of one call per ordinal, which would rescan the
// payload each time. The reported name stays valid until the next call.
pub const Cursor = struct {
    inner: Chain.InnerCursor,
    pending: ?cpio.RecordInfo = null,
    mode: LinkMode = .records,
    links: []Link = &.{},
    link_count: usize = 0,

    pub fn init(archive: []const u8, scratch: []u8) Exception!Cursor {
        return initWithLinks(archive, scratch, .records, &.{});
    }

    // `links` is the caller's table for collapsing: a power-of-two slice,
    // sized past the number of distinct groups, cleared here.
    pub fn initWithLinks(archive: []const u8, scratch: []u8, mode: LinkMode, links: []Link) Exception!Cursor {
        if (mode == .collapse and (links.len == 0 or !std.math.isPowerOfTwo(links.len))) return error.CallException;
        if (mode == .collapse) {
            for (links) |*entry| entry.* = .{ .ino = 0, .ordinal_plus_one = 0 };
        }
        return .{
            .inner = try Chain.open(archive, member_name, scratch),
            .mode = mode,
            .links = links,
        };
    }

    // An unread member is skipped here, so a caller may walk names only.
    pub fn next(self: *Cursor) Exception!?EntryInfo {
        const record = (try self.inner.next()) orelse return null;
        var info = recordInfo(record);
        if (self.mode == .collapse and isLinkName(info)) {
            if (self.findLink(info.ino)) |owner| {
                // The group's first record owns the payload; this name links.
                _ = try self.inner.skipData();
                info.link_ordinal = owner;
                return info;
            }
            try self.insertLink(info.ino, info.ordinal);
        }
        self.pending = record;
        return info;
    }

    pub fn readData(self: *Cursor, destination: []u8) Exception!void {
        const record = self.pending orelse return error.CallException;
        if (destination.len < record.size) return error.CapacityException;
        const size: usize = std.math.cast(usize, record.size) orelse return error.ResourceException;
        var sink = std.Io.Writer.fixed(destination[0..size]);
        _ = try self.inner.readData(&sink);
        self.pending = null;
    }

    pub fn skipData(self: *Cursor) Exception!void {
        self.pending = null;
        _ = try self.inner.skipData();
    }

    // The observability counters prove what a walk decoded.
    pub fn decodedChunks(self: *Cursor) u64 {
        return self.inner.source.decodedChunks();
    }

    pub fn decodedBytes(self: *Cursor) u64 {
        return self.inner.source.decodedBytes();
    }

    fn recordInfo(record: cpio.RecordInfo) EntryInfo {
        return .{
            .name = record.name,
            .mode = record.mode,
            .uid = record.uid,
            .gid = record.gid,
            .size = record.size,
            .modification_time = record.modification_time,
            .ordinal = record.ordinal,
            .ino = record.ino,
            .nlink = record.nlink,
        };
    }

    fn slot(self: *Cursor, ino: u32) usize {
        return (@as(usize, ino) *% 0x9E37_79B1) & (self.links.len - 1);
    }

    fn findLink(self: *Cursor, ino: u32) ?u64 {
        var index = self.slot(ino);
        var probes: usize = 0;
        while (probes < self.links.len) : (probes += 1) {
            const entry = self.links[index];
            if (entry.ordinal_plus_one == 0) return null;
            if (entry.ino == ino) return entry.ordinal_plus_one - 1;
            index = (index + 1) & (self.links.len - 1);
        }
        return null;
    }

    fn insertLink(self: *Cursor, ino: u32, ordinal: u64) Exception!void {
        var index = self.slot(ino);
        var probes: usize = 0;
        while (probes < self.links.len) : (probes += 1) {
            if (self.links[index].ordinal_plus_one == 0) {
                self.links[index] = .{ .ino = ino, .ordinal_plus_one = ordinal + 1 };
                self.link_count += 1;
                return;
            }
            index = (index + 1) & (self.links.len - 1);
        }
        return error.ResourceException;
    }
};

// Folding applies to names that can share data. A directory carries its
// subdirectory count in nlink, and Apple writes nlink=1 for its dirs.
fn isLinkName(info: EntryInfo) bool {
    return info.nlink > 1 and info.mode & 0o170000 != 0o040000;
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    var cursor = try Cursor.init(archive, scratch);
    var count: u64 = 0;
    while (try cursor.next() != null) count = try bounds.addU64(count, 1);
    return count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    var cursor = try Cursor.init(archive, scratch);
    while (try cursor.next()) |info| {
        if (info.ordinal == ordinal) return info;
    }
    return error.DataException;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    var cursor = try Cursor.init(archive, scratch);
    while (try cursor.next()) |info| {
        if (info.ordinal != ordinal) continue;
        const size = std.math.cast(usize, info.size) orelse return error.ResourceException;
        if (output.len < size) return error.CapacityException;
        try cursor.readData(output[0..size]);
        return size;
    }
    return error.DataException;
}

const Layout = struct {
    xml: []const u8,
    toc_len: u64,
    total: u64,
};

// The TOC holds one member. Its offsets are heap-relative.
// The heap opens with the TOC digest, so the payload starts at 20.
fn writeToc(sink: *io.Sink, pbzx_len: u64) Exception!void {
    try sink.write(xar.xml_prolog);
    try sink.write("  <file id=\"1\">\n   <name>Content</name>\n   <type>file</type>\n   <mode>0755</mode>\n   <data>\n    <length>");
    try xar.writeNum(sink, "{d}", pbzx_len);
    try sink.write("</length>\n    <offset>20</offset>\n    <size>");
    try xar.writeNum(sink, "{d}", pbzx_len);
    try sink.write("</size>\n    <encoding style=\"application/octet-stream\"/>\n   </data>\n  </file>\n");
    try sink.write(xar.xml_epilog);
}

fn mulOrFail(left: u64, right: u64) Exception!u64 {
    return std.math.mul(u64, left, right) catch error.ResourceException;
}

fn layoutFor(entries: []const Entry, xml_area: []u8, block_size: u64) Exception!Layout {
    if (block_size == 0) return error.CapacityException;
    const content_len = try cpio.archiveSize(entries);
    const chunks = content_len / block_size + @intFromBool(content_len % block_size != 0);
    const padded = try mulOrFail(@max(1, chunks), block_size);
    const pbzx_len = try bounds.addU64(pbzx_header_size, try mulOrFail(@max(1, chunks), chunk_header_size));
    const pbzx_total = try bounds.addU64(pbzx_len, padded);
    var toc_sink = io.Sink{ .bytes = xml_area };
    try writeToc(&toc_sink, pbzx_total);
    const xml = xml_area[0..toc_sink.offset];
    const toc_len = try xar.zlibStoredLen(toc_sink.offset);
    var total = try bounds.addU64(xar.header_size, toc_len);
    total = try bounds.addU64(total, xar.sha1_len);
    total = try bounds.addU64(total, pbzx_total);
    return .{ .xml = xml, .toc_len = toc_len, .total = total };
}

// Stored chunks pad to the writer's block size, so each states one size.
// The last chunk is zero-filled past the cpio trailer.
const ChunkSink = struct {
    output: []u8,
    cursor: usize,
    block_size: usize,
    offset: u64 = 0,
    chunk_open: bool = false,
    chunk_filled: usize = 0,

    fn openChunk(self: *ChunkSink) Exception!void {
        if (self.cursor + chunk_header_size > self.output.len) return error.CapacityException;
        const header = self.output[self.cursor..][0..chunk_header_size];
        std.mem.writeInt(u64, header[0..8], self.block_size, .big);
        std.mem.writeInt(u64, header[8..16], self.block_size, .big);
        self.cursor += chunk_header_size;
        self.chunk_open = true;
        self.chunk_filled = 0;
    }

    fn begin(self: *ChunkSink) Exception!void {
        if (self.cursor + pbzx_header_size > self.output.len) return error.CapacityException;
        @memcpy(self.output[self.cursor..][0..4], "pbzx");
        std.mem.writeInt(u64, self.output[self.cursor..][4..12], self.block_size, .big);
        self.cursor += pbzx_header_size;
    }

    pub fn write(self: *ChunkSink, bytes: []const u8) Exception!void {
        var remaining = bytes;
        while (remaining.len > 0) {
            if (!self.chunk_open or self.chunk_filled == self.block_size) try self.openChunk();
            const room = self.block_size - self.chunk_filled;
            const step = @min(room, remaining.len);
            if (self.cursor + step > self.output.len) return error.CapacityException;
            @memcpy(self.output[self.cursor..][0..step], remaining[0..step]);
            self.cursor += step;
            self.chunk_filled += step;
            self.offset = try bounds.addU64(self.offset, step);
            remaining = remaining[step..];
        }
    }

    fn finish(self: *ChunkSink) Exception!void {
        const zeros: [4096]u8 = @splat(0);
        while (self.chunk_open and self.chunk_filled < self.block_size) {
            const count = @min(zeros.len, self.block_size - self.chunk_filled);
            try self.write(zeros[0..count]);
        }
    }
};

pub fn archiveSize(entries: []const Entry, scratch: []u8) Exception!u64 {
    return archiveSizeFor(entries, scratch, block_size_write);
}

fn archiveSizeFor(entries: []const Entry, scratch: []u8, block_size: u64) Exception!u64 {
    const layout = try layoutFor(entries, try tocArea(scratch), block_size);
    return layout.total;
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return encodeFor(entries, output, scratch, block_size_write);
}

fn encodeFor(entries: []const Entry, output: []u8, scratch: []u8, block_size: u64) Exception!usize {
    const layout = try layoutFor(entries, try tocArea(scratch), block_size);
    if (output.len < layout.total) return error.CapacityException;
    const block: usize = std.math.cast(usize, block_size) orelse return error.ResourceException;

    var sink = io.Sink{ .bytes = output };
    try xar.writeHeader(&sink, layout.toc_len, layout.xml.len);
    const toc_start = sink.offset;
    try xar.writeZlibStored(&sink, layout.xml, checksum.adler32With(checksum.default_provider, layout.xml));
    var digest: [xar.sha1_len]u8 = undefined;
    xar.sha1Digest(&digest, output[toc_start..sink.offset]);
    try sink.write(&digest);

    var chunks = ChunkSink{ .output = output, .cursor = sink.offset, .block_size = block };
    try chunks.begin();
    for (entries, 0..) |entry, index| {
        const ino: u32 = if (entry.ino == 0) @intCast(index + 1) else entry.ino;
        try cpio.writeNewcRecord(&chunks, entry, ino, 0);
    }
    try cpio.writeNewcTrailer(&chunks);
    try chunks.finish();
    if (chunks.cursor != layout.total) return error.InternalException;
    return chunks.cursor;
}

test "xip roundtrips entries through stored chunks" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "Xcode.app/Contents/MacOS/Xcode", .data = "binary payload", .uid = 501, .modification_time = 1700000000 },
        .{ .name = "Xcode.app/Info.plist", .data = "plist", .mode = 0o755 },
    };
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);
    try testing.expectEqual(try archiveSizeFor(&entries, scratch, 4096), written);
    try testing.expectEqualSlices(u8, "xar!", output[0..4]);

    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], scratch));
    const first = try inspectOrdinal(output[0..written], 0, scratch);
    try testing.expectEqualSlices(u8, "Xcode.app/Contents/MacOS/Xcode", first.name);
    try testing.expectEqual(@as(u64, 14), first.size);
    try testing.expectEqual(@as(u32, 501), first.uid);
    try testing.expectEqual(@as(u64, 1700000000), first.modification_time);
    var decoded: [32]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 0, &decoded, scratch);
    try testing.expectEqualSlices(u8, "binary payload", decoded[0..size]);
    const second = try decodeOrdinal(output[0..written], 1, &decoded, scratch);
    try testing.expectEqualSlices(u8, "plist", decoded[0..second]);
}

test "xip reads an entry whose data spans stored chunks" {
    const testing = std.testing;
    var payload: [9000]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index * 7 + 3);
    const entries = [_]Entry{.{ .name = "spans.bin", .data = &payload }};
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);
    var decoded: [9000]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 0, &decoded, scratch);
    try testing.expectEqual(@as(usize, payload.len), size);
    try testing.expectEqualSlices(u8, &payload, &decoded);
}

test "xip reads xz chunks the reference writer emits" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "first.txt", .data = "alpha" },
        .{ .name = "second.txt", .data = "beta gamma delta" },
    };
    var content: [8192]u8 = undefined;
    const content_len = try cpio.encode(&entries, &content);

    // pbzx: 4 KiB blocks, each an xz stream with a CRC32 check.
    const block_size: usize = 4096;
    var pbzx_stream: [32768]u8 = undefined;
    @memcpy(pbzx_stream[0..4], "pbzx");
    std.mem.writeInt(u64, pbzx_stream[4..12], block_size, .big);
    var pbzx_len: usize = 12;
    const encode_scratch = try testing.allocator.alloc(u8, xz.encodeWorkspaceSizeBt(1 << 20) + 64);
    defer testing.allocator.free(encode_scratch);
    var position: usize = 0;
    while (position < content_len) {
        const block_len = @min(block_size, content_len - position);
        const chunk = content[position..][0..block_len];
        var compressed: [block_size * 2]u8 = undefined;
        const compressed_len = try xz.encode(chunk, &compressed, encode_scratch, .{
            .dictionary_size = 1 << 20,
            .check = .crc32,
        });
        std.mem.writeInt(u64, pbzx_stream[pbzx_len..][0..8], block_len, .big);
        std.mem.writeInt(u64, pbzx_stream[pbzx_len..][8..16], compressed_len, .big);
        @memcpy(pbzx_stream[pbzx_len + 16 ..][0..compressed_len], compressed[0..compressed_len]);
        pbzx_len += 16 + compressed_len;
        position += block_len;
    }

    const xip_entries = [_]Entry{.{ .name = "Content", .data = pbzx_stream[0..pbzx_len] }};
    var output: [64 * 1024]u8 = undefined;
    var container_scratch: [96 * 1024]u8 = undefined;
    const written = try xar.encode(&xip_entries, &output, &container_scratch);

    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], scratch));
    const second = try inspectOrdinal(output[0..written], 1, scratch);
    try testing.expectEqualSlices(u8, "second.txt", second.name);
    var decoded: [32]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 1, &decoded, scratch);
    try testing.expectEqualSlices(u8, "beta gamma delta", decoded[0..size]);
}

test "xip skips chunks no read touches" {
    const testing = std.testing;
    var payload: [12 * 1024]u8 = undefined;
    // A byte no header field or name can hold marks the payload data.
    @memset(&payload, 0xAA);
    const entries = [_]Entry{
        .{ .name = "large.bin", .data = &payload },
        .{ .name = "tail.txt", .data = "tail" },
    };
    var output: [128 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    // Corrupt the first chunk's data. A reader that decodes it anyway
    // reports the first entry's bytes wrong, and this test reads past it.
    const range = try xar.findDataRange(output[0..written], "Content", scratch[0..xar.scratch_size]);
    const payload_start: usize = @intCast(range.offset + pbzx_header_size + chunk_header_size);
    for (output[payload_start..][0..4096]) |*byte| {
        if (byte.* == 0xAA) byte.* = 0xBB;
    }

    const tail = try inspectOrdinal(output[0..written], 1, scratch);
    try testing.expectEqualSlices(u8, "tail.txt", tail.name);
    var decoded: [8]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 1, &decoded, scratch);
    try testing.expectEqualSlices(u8, "tail", decoded[0..size]);
}

test "xip reads a portable odc payload" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "odc/first", .data = "one" },
        .{ .name = "odc/second", .data = "two two" },
    };
    var content: [4096]u8 = undefined;
    const content_len = try cpio.encodeOdc(&entries, &content);

    // Stored chunks: one per 1 KiB of the payload, no padding.
    var pbzx_stream: [8192]u8 = undefined;
    @memcpy(pbzx_stream[0..4], "pbzx");
    std.mem.writeInt(u64, pbzx_stream[4..12], 1024, .big);
    var pbzx_len: usize = 12;
    var position: usize = 0;
    while (position < content_len) {
        const chunk = content[position..][0..@min(1024, content_len - position)];
        std.mem.writeInt(u64, pbzx_stream[pbzx_len..][0..8], chunk.len, .big);
        std.mem.writeInt(u64, pbzx_stream[pbzx_len..][8..16], chunk.len, .big);
        @memcpy(pbzx_stream[pbzx_len + 16 ..][0..chunk.len], chunk);
        pbzx_len += 16 + chunk.len;
        position += chunk.len;
    }

    var output: [16 * 1024]u8 = undefined;
    var container_scratch: [96 * 1024]u8 = undefined;
    const written = try xar.encode(&.{.{ .name = "Content", .data = pbzx_stream[0..pbzx_len] }}, &output, &container_scratch);
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);

    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], scratch));
    const second = try inspectOrdinal(output[0..written], 1, scratch);
    try testing.expectEqualSlices(u8, "odc/second", second.name);
    try testing.expectEqual(@as(u64, 7), second.size);
    var decoded: [8]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 1, &decoded, scratch);
    try testing.expectEqualSlices(u8, "two two", decoded[0..size]);
}

test "xip decodes only the chunks a read needs" {
    const testing = std.testing;
    const payload = try testing.allocator.alloc(u8, 8 << 20);
    defer testing.allocator.free(payload);
    @memset(payload, 0x5A);
    const entries = [_]Entry{
        .{ .name = "big.bin", .data = payload },
        .{ .name = "s1", .data = "one" },
        .{ .name = "s2", .data = "two" },
    };
    const output = try testing.allocator.alloc(u8, 10 << 20);
    defer testing.allocator.free(output);
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, output, scratch, 1 << 20);

    // Nine chunks, but a name walk decodes only the two with headers.
    var walker = try Cursor.init(output[0..written], scratch);
    var names: usize = 0;
    while (try walker.next()) |_| names += 1;
    try testing.expectEqual(@as(usize, 3), names);
    try testing.expect(walker.decodedChunks() <= 3);
    try testing.expect(walker.decodedBytes() <= 3 << 20);

    // Reading the big entry proves the other side: its bytes are decoded.
    const destination = try testing.allocator.alloc(u8, 8 << 20);
    defer testing.allocator.free(destination);
    var reader = try Cursor.init(output[0..written], scratch);
    const big = try reader.next() orelse return error.UnexpectedEnd;
    try testing.expectEqual(@as(u64, 8 << 20), big.size);
    try reader.readData(destination);
    try testing.expect(reader.decodedBytes() >= 8 << 20);
    try testing.expectEqual(@as(u8, 0x5A), destination[0]);
    try testing.expectEqual(@as(u8, 0x5A), destination[destination.len - 1]);

    // The same pass through the public cursor: names only, and a read of
    // the one member whose bytes the caller wants.
    var cursor = try Cursor.init(output[0..written], scratch);
    var seen: usize = 0;
    while (try cursor.next()) |info| {
        seen += 1;
        if (std.mem.eql(u8, info.name, "s2")) {
            var data: [8]u8 = undefined;
            try cursor.readData(data[0..info.size]);
            try testing.expectEqualSlices(u8, "two", data[0..info.size]);
        }
    }
    try testing.expectEqual(@as(usize, 3), seen);

    const total = try inspectCount(output[0..written], scratch);
    try testing.expectEqual(@as(u64, 3), total);
}

test "xip rejects a corrupted toc digest and a truncated chunk stream" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a.txt", .data = "data" }};
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    var copy: [64 * 1024]u8 = undefined;
    @memcpy(copy[0..written], output[0..written]);
    // The digest sits at the heap start, after the compressed TOC.
    const toc_len: usize = @intCast(std.mem.readInt(u64, copy[8..16], .big));
    copy[xar.header_size + toc_len + xar.sha1_len - 1] ^= 0xFF;
    try testing.expectError(error.DataException, inspectCount(copy[0..written], scratch));

    // The TOC states the payload length, so a cut inside a chunk is caught
    // before the chunk header is read.
    try testing.expectError(error.DataException, inspectCount(output[0 .. written - 16], scratch));
}

test "xip rejects a member that is not a pbzx stream" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "Content", .data = "not pbzx at all" }};
    var output: [4096]u8 = undefined;
    var container_scratch: [96 * 1024]u8 = undefined;
    const written = try xar.encode(&entries, &output, &container_scratch);
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    try testing.expectError(error.UnsupportedException, inspectCount(output[0..written], scratch));
}

test "xip reports ino and nlink and folds groups only on request" {
    const testing = std.testing;
    // Two names, one group, and payloads that disagree: the shape a real
    // Apple image carries, where folding rewrites what the stream says.
    const entries = [_]Entry{
        .{ .name = "group/first.bin", .data = "first", .ino = 7, .nlink = 2 },
        .{ .name = "group/second.bin", .data = "second", .ino = 7, .nlink = 2 },
    };
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    var flat = try Cursor.init(output[0..written], scratch);
    var seen: usize = 0;
    var data: [8]u8 = undefined;
    while (try flat.next()) |info| {
        seen += 1;
        try testing.expectEqual(@as(u32, 7), info.ino);
        try testing.expectEqual(@as(u32, 2), info.nlink);
        try testing.expect(info.link_ordinal == null);
        try flat.readData(data[0..info.size]);
        try testing.expectEqualSlices(u8, if (info.ordinal == 0) "first" else "second", data[0..info.size]);
    }
    try testing.expectEqual(@as(usize, 2), seen);

    var links: [4]Link = undefined;
    var folded = try Cursor.initWithLinks(output[0..written], scratch, .collapse, &links);
    const owner = try folded.next() orelse return error.UnexpectedEnd;
    try testing.expect(owner.link_ordinal == null);
    const duplicate = try folded.next() orelse return error.UnexpectedEnd;
    try testing.expectEqual(@as(u64, 0), duplicate.link_ordinal.?);
    // Its payload was dropped with the fold, so a read is a caller error.
    try testing.expectError(error.CallException, folded.readData(data[0..duplicate.size]));
    try testing.expect(try folded.next() == null);

    // A table that is not a power of two cannot serve as the group index.
    try testing.expectError(error.CallException, Cursor.initWithLinks(output[0..written], scratch, .collapse, links[0..3]));
}

test "xip opens only with a full scratch budget" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a.txt", .data = "data" }};
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    // One byte short is a capacity failure, never a data error.
    try testing.expectError(error.CapacityException, Cursor.init(output[0..written], scratch[0 .. scratch.len - 1]));
    try testing.expectError(error.CapacityException, inspectCount(output[0..written], scratch[0 .. scratch.len - 1]));
}

test "xip rejects a stream truncated at every chunk boundary" {
    const testing = std.testing;
    var payload: [10 * 1024]u8 = undefined;
    @memset(&payload, 0x6C);
    const entries = [_]Entry{
        .{ .name = "mid.bin", .data = &payload },
        .{ .name = "tail.txt", .data = "tail" },
    };
    var output: [128 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    // The TOC states the member length, so every cut is a data failure.
    const range = try xar.findDataRange(output[0..written], "Content", scratch[0..xar.scratch_size]);
    try testing.expectError(error.DataException, inspectCount(output[0..@intCast(range.offset)], scratch));
    var cut: usize = @intCast(range.offset + pbzx_header_size);
    const stride: usize = @as(usize, @intCast(chunk_header_size)) + 4096;
    while (cut < written) : (cut += stride) {
        try testing.expectError(error.DataException, inspectCount(output[0..cut], scratch));
    }
    try testing.expectError(error.DataException, inspectCount(output[0 .. written - 1], scratch));
    // The intact archive still reads.
    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], scratch));
}

test "xip rejects a corrupted record header in a chunk" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "first.txt", .data = "alpha" },
        .{ .name = "second.txt", .data = "beta" },
    };
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    // The first chunk opens with the cpio record magic; one wrong byte
    // there fails the parse as damaged data.
    const range = try xar.findDataRange(output[0..written], "Content", scratch[0..xar.scratch_size]);
    const record_magic: usize = @intCast(range.offset + pbzx_header_size + chunk_header_size);
    output[record_magic] ^= 0xFF;
    try testing.expectError(error.DataException, inspectCount(output[0..written], scratch));
}

test "xip keeps the stored and compressed chunk distinction" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "only.txt", .data = "only" }};
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    // A compressed chunk without the xz magic is unsupported, not damaged.
    const range = try xar.findDataRange(output[0..written], "Content", scratch[0..xar.scratch_size]);
    const stored_field: usize = @intCast(range.offset + pbzx_header_size + 8);
    const stored = std.mem.readInt(u64, output[stored_field..][0..8], .big);
    std.mem.writeInt(u64, output[stored_field..][0..8], stored - 1, .big);
    try testing.expectError(error.UnsupportedException, inspectCount(output[0..written], scratch));
}

test "xip ends cleanly at the last chunk" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "one", .data = "one" },
        .{ .name = "two", .data = "two" },
    };
    var output: [64 * 1024]u8 = undefined;
    const scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(scratch);
    const written = try encodeFor(&entries, &output, scratch, 4096);

    var cursor = try Cursor.init(output[0..written], scratch);
    try testing.expect((try cursor.next()) != null);
    try testing.expect((try cursor.next()) != null);
    // The trailer ends the walk, and the call after stays ended.
    try testing.expect((try cursor.next()) == null);
    try testing.expect((try cursor.next()) == null);
    // The last chunk is short and padded; the walk decoded it once.
    try testing.expectEqual(@as(u64, 1), cursor.decodedChunks());
    try testing.expectEqual(@as(u64, 4096), cursor.decodedBytes());
}
