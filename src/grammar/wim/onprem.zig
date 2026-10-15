const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const failure_prim = @import("../../common/primitive/failure.zig");

const xpress = @import("xpress.zig");
const lzx = @import("lzx.zig");
const io = @import("../../common/primitive/io.zig");

const Failure = failure_prim.Failure;

// WIM store-mode slice: uncompressed resources, one image, flat files.
// Layout follows wimlib's on-disk headers.

// XPRESS/LZX/LZMS resource compression lands in follow-up slices.

pub const scratch_size: usize = 64 * 1024;

const wim_magic: u64 = 0x0000_004D_4957_534D; // "MSWIM\0\0\0" little-endian.
const wim_version: u32 = 0x10D00;
const chunk_size: u32 = 0x8000;
const header_disk_size = 208;
const dentry_disk_size = 102;
const stream_disk_size = 40;
const blob_disk_size = 50;
const reshdr_flag_metadata: u8 = 0x02;
const reshdr_flag_compressed: u8 = 0x04;
const flag_compress_xpress: u32 = 0x00020000;
const flag_compress_xpress_2: u32 = 0x00200000;
const flag_compress_lzx: u32 = 0x00040000;
const flag_compress_lzms: u32 = 0x00080000;
const flag_compression: u32 = 0x00000002;
const sha1_len = 20;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    name: []const u8,
    size: u64,
    hash: [sha1_len]u8,
    ordinal: u64,
};

const Reshdr = struct {
    size_in_wim: u64,
    flags: u8,
    offset: u64,
    uncompressed_size: u64 = 0,
};

fn readReshdr(data: []const u8, at: usize) Failure!Reshdr {
    var size: u64 = 0;
    var shift: u6 = 0;
    for (data[at..][0..7]) |byte| {
        size |= @as(u64, byte) << shift;
        shift += 8;
    }
    return .{
        .size_in_wim = size,
        .flags = data[at + 7],
        .offset = std.mem.readInt(u64, data[at + 8 ..][0..8], .little),
        .uncompressed_size = std.mem.readInt(u64, data[at + 16 ..][0..8], .little),
    };
}

fn writeReshdr(out: []u8, res: Reshdr) void {
    var size = res.size_in_wim;
    for (out[0..7]) |*byte| {
        byte.* = @truncate(size);
        size >>= 8;
    }
    out[7] = res.flags;
    std.mem.writeInt(u64, out[8..16], res.offset, .little);
    std.mem.writeInt(u64, out[16..24], res.uncompressed_size, .little);
}

fn utf16Len(name: []const u8) Failure!usize {
    var units: usize = 0;
    var i: usize = 0;
    while (i < name.len) {
        const len = std.unicode.utf8ByteSequenceLength(name[i]) catch return error.DataFailure;
        if (i + len > name.len) return error.DataFailure;
        const cp = std.unicode.utf8Decode(name[i..][0..len]) catch return error.DataFailure;
        units += if (cp >= 0x10000) 2 else 1;
        i += len;
    }
    return units;
}

fn writeUtf16Le(out: []u8, name: []const u8) Failure!usize {
    var written: usize = 0;
    var i: usize = 0;
    while (i < name.len) {
        const len = std.unicode.utf8ByteSequenceLength(name[i]) catch return error.DataFailure;
        const cp = std.unicode.utf8Decode(name[i..][0..len]) catch return error.DataFailure;
        i += len;
        if (cp >= 0x10000) {
            const v = cp - 0x10000;
            std.mem.writeInt(u16, out[written..][0..2], @intCast(0xD800 + (v >> 10)), .little);
            std.mem.writeInt(u16, out[written + 2 ..][0..2], @intCast(0xDC00 + (v & 0x3FF)), .little);
            written += 4;
        } else {
            std.mem.writeInt(u16, out[written..][0..2], @intCast(cp), .little);
            written += 2;
        }
    }
    return written;
}

fn dentryWireLen(name_units: usize) usize {
    const name_bytes = name_units * 2;
    const raw = dentry_disk_size + (if (name_bytes != 0) name_bytes + 2 else 0);
    return (raw + 7) & ~@as(usize, 7);
}

fn metadataLen(entries: []const Entry) Failure!u64 {
    var total: u64 = 8 + 104; // empty security data, root dentry, children
    for (entries) |entry| {
        const units = try utf16Len(entry.name);
        if (units == 0) return error.CallFailure;
        total = try bounds.addU64(total, dentryWireLen(units) + stream_disk_size);
    }
    return bounds.addU64(total, 8); // end-of-siblings marker
}

fn blobTableLen(entries: []const Entry) u64 {
    // One entry per file, one for the image metadata resource, then the
    // zero terminator.
    return @as(u64, (entries.len + 2) * blob_disk_size + 7) & ~@as(u64, 7);
}

fn xmlLen(entries: []const Entry) Failure!u64 {
    // TOTALBYTES needs the archive size, which depends on the XML length.
    // Iterate until the digit count stops moving.
    var total: u64 = 0;
    var iter: usize = 0;
    while (iter < 8) : (iter += 1) {
        var counter = CountSink{};
        try writeTocXml(&counter, entries, total);
        var size: u64 = header_disk_size + blobTableLen(entries) + counter.pos + (try metadataLen(entries));
        for (entries) |entry| size = try bounds.addU64(size, entry.data.len);
        if (size == total) break;
        total = size;
    }
    var counter = CountSink{};
    try writeTocXml(&counter, entries, total);
    return counter.pos;
}

pub fn archiveSize(entries: []const Entry) Failure!u64 {
    const xml = try xmlLen(entries);
    var total: u64 = header_disk_size;
    total = try bounds.addU64(total, blobTableLen(entries));
    total = try bounds.addU64(total, xml);
    total = try bounds.addU64(total, try metadataLen(entries));
    for (entries) |entry| total = try bounds.addU64(total, entry.data.len);
    return total;
}

fn writeDentry(out: []u8, name: []const u8, hash: *const [sha1_len]u8, subdir_offset: u64, data_len: u64) Failure!usize {
    const units = try utf16Len(name);
    const wire_len = dentryWireLen(units);
    @memset(out[0..wire_len], 0);
    std.mem.writeInt(u64, out[0..8], wire_len, .little);
    std.mem.writeInt(u32, out[8..12], 0x000000A0, .little); // archive | normal
    std.mem.writeInt(u32, out[12..16], 0xFFFFFFFF, .little); // no security descriptor
    std.mem.writeInt(u64, out[16..24], subdir_offset, .little);
    std.mem.writeInt(u64, out[40..48], 0, .little); // creation
    std.mem.writeInt(u64, out[48..56], 0, .little); // access
    std.mem.writeInt(u64, out[56..64], 0, .little); // write
    @memcpy(out[64..84], hash);
    std.mem.writeInt(u32, out[84..88], 0, .little); // unknown_0x54
    std.mem.writeInt(u64, out[88..96], 0, .little); // hard link group
    std.mem.writeInt(u16, out[96..98], 1, .little); // one stream (the unnamed data)
    std.mem.writeInt(u16, out[98..100], 0, .little); // no short name
    std.mem.writeInt(u16, out[100..102], @intCast(units * 2), .little);
    var pos: usize = dentry_disk_size;
    if (units != 0) {
        pos += writeUtf16Le(out[pos..], name) catch return error.DataFailure;
        pos += 2; // NUL terminator
    }
    // Extra stream entry for the unnamed data stream, on the 8-byte
    // boundary following the dentry proper.
    var stream: [stream_disk_size]u8 = @splat(0);
    std.mem.writeInt(u64, stream[0..8], stream_disk_size, .little);
    @memcpy(stream[16..36], hash);
    std.mem.writeInt(u16, stream[36..38], 0, .little);
    _ = data_len;
    @memcpy(out[wire_len..][0..stream_disk_size], &stream);
    return wire_len + stream_disk_size;
}

fn writeAscii16(sink: anytype, byte: u8) Failure!void {
    var pair: [2]u8 = .{ byte, 0 };
    try sink.write(&pair);
}

fn writeTocXml(sink: anytype, entries: []const Entry, total: u64) Failure!void {
    const text_parts = [_][]const u8{
        "<WIM><IMAGE INDEX=\"1\"><NAME>image</NAME><DIRCOUNT>0</DIRCOUNT><FILECOUNT>",
        "</FILECOUNT><TOTALBYTES>",
        "</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES></IMAGE><TOTALBYTES>",
        "</TOTALBYTES></WIM>",
    };
    var total_buf: [24]u8 = undefined;
    var file_buf: [24]u8 = undefined;
    const total_text = std.fmt.bufPrint(&total_buf, "{d}", .{total}) catch return error.CapacityFailure;
    const file_text = std.fmt.bufPrint(&file_buf, "{d}", .{entries.len}) catch return error.CapacityFailure;
    try sink.write(&[_]u8{ 0xFF, 0xFE });
    for (text_parts[0]) |byte| try writeAscii16(sink, byte);
    for (file_text) |byte| try writeAscii16(sink, byte);
    for (text_parts[1]) |byte| try writeAscii16(sink, byte);
    for (total_text) |byte| try writeAscii16(sink, byte);
    for (text_parts[2]) |byte| try writeAscii16(sink, byte);
    for (total_text) |byte| try writeAscii16(sink, byte);
    for (text_parts[3]) |byte| try writeAscii16(sink, byte);
}

const CountSink = struct {
    pos: u64 = 0,

    fn write(self: *CountSink, bytes: []const u8) Failure!void {
        self.pos = try bounds.addU64(self.pos, bytes.len);
    }
};

const RealSink = struct {
    bytes: []u8,
    pos: usize = 0,

    fn write(self: *RealSink, bytes: []const u8) Failure!void {
        if (self.pos + bytes.len > self.bytes.len) return error.CapacityFailure;
        @memcpy(self.bytes[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }
};

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    const metadata_len = try metadataLen(entries);
    if (scratch.len < metadata_len + 4096) return error.ResourceFailure;

    var sink = io.Sink{ .bytes = output };
    const blob_table_len = blobTableLen(entries);
    const xml_len = try xmlLen(entries);
    const blob_off: u64 = header_disk_size;
    const xml_off = try bounds.addU64(blob_off, blob_table_len);
    const metadata_off = try bounds.addU64(xml_off, xml_len);
    var data_off = try bounds.addU64(metadata_off, metadata_len);

    // Build the metadata resource first; the blob table carries its digest.
    @memset(scratch[0..@intCast(metadata_len)], 0);
    // Empty security data (total length 8), then the root.
    std.mem.writeInt(u32, scratch[0..4], 8, .little);
    std.mem.writeInt(u64, scratch[8..16], 104, .little);
    std.mem.writeInt(u32, scratch[16..20], 0x10, .little); // directory
    std.mem.writeInt(u32, scratch[20..24], 0xFFFFFFFF, .little);
    std.mem.writeInt(u64, scratch[24..32], 8 + 104, .little); // children at offset 112
    var md_pos: usize = 8 + 104;
    for (entries) |entry| {
        var hash: [sha1_len]u8 = undefined;
        std.crypto.hash.Sha1.hash(entry.data, &hash, .{});
        md_pos += try writeDentry(scratch[md_pos..], entry.name, &hash, 0, entry.data.len);
    }
    var metadata_hash: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(scratch[0..@intCast(metadata_len)], &metadata_hash, .{});

    var header: [header_disk_size]u8 = @splat(0);
    std.mem.writeInt(u64, header[0..8], wim_magic, .little);
    std.mem.writeInt(u32, header[8..12], header_disk_size, .little);
    std.mem.writeInt(u32, header[12..16], wim_version, .little);
    std.mem.writeInt(u32, header[16..20], 0, .little); // flags: uncompressed
    std.mem.writeInt(u32, header[20..24], 0, .little); // chunk size: none for uncompressed
    for (header[24..40], 0..) |*byte, i| byte.* = @intCast(0x5A + i);
    std.mem.writeInt(u16, header[40..42], 1, .little); // one image
    std.mem.writeInt(u16, header[42..44], 1, .little); // part number
    std.mem.writeInt(u32, header[44..48], 1, .little); // total parts
    writeReshdr(header[48..72], .{ .size_in_wim = blob_table_len, .flags = 0, .offset = blob_off, .uncompressed_size = blob_table_len });
    writeReshdr(header[72..96], .{ .size_in_wim = xml_len, .flags = 0, .offset = xml_off, .uncompressed_size = xml_len });
    writeReshdr(header[96..120], .{ .size_in_wim = 0, .flags = reshdr_flag_metadata, .offset = 0, .uncompressed_size = 0 });
    std.mem.writeInt(u32, header[120..124], 0, .little); // boot index
    writeReshdr(header[124..148], .{ .size_in_wim = 0, .flags = 0, .offset = 0, .uncompressed_size = 0 }); // no integrity table
    sink.write(&header) catch return error.CapacityFailure;

    var blob: [blob_disk_size]u8 = undefined;
    for (entries) |entry| {
        var hash: [sha1_len]u8 = undefined;
        std.crypto.hash.Sha1.hash(entry.data, &hash, .{});
        writeReshdr(blob[0..24], .{ .size_in_wim = entry.data.len, .flags = 0, .offset = data_off, .uncompressed_size = entry.data.len });
        std.mem.writeInt(u16, blob[24..26], 1, .little);
        std.mem.writeInt(u32, blob[26..30], 1, .little);
        @memcpy(blob[30..50], &hash);
        sink.write(&blob) catch return error.CapacityFailure;
        data_off = try bounds.addU64(data_off, entry.data.len);
    }
    writeReshdr(blob[0..24], .{ .size_in_wim = metadata_len, .flags = reshdr_flag_metadata, .offset = metadata_off, .uncompressed_size = metadata_len });
    std.mem.writeInt(u16, blob[24..26], 1, .little);
    std.mem.writeInt(u32, blob[26..30], 1, .little);
    @memcpy(blob[30..50], &metadata_hash);
    sink.write(&blob) catch return error.CapacityFailure;
    const zeros: [50]u8 = @splat(0);
    sink.write(&zeros) catch return error.CapacityFailure;
    var pad: [8]u8 = @splat(0);
    const blob_pad = blob_table_len - @as(u64, (entries.len + 2) * blob_disk_size);
    if (blob_pad > 0) sink.write(pad[0..blob_pad]) catch return error.CapacityFailure;

    var xml_sink = RealSink{ .bytes = scratch[@intCast(metadata_len)..@intCast(try bounds.addU64(metadata_len, xml_len))] };
    try writeTocXml(&xml_sink, entries, try archiveSize(entries));
    sink.write(scratch[@intCast(metadata_len)..][0..xml_sink.pos]) catch return error.CapacityFailure;

    sink.write(scratch[0..@intCast(metadata_len)]) catch return error.CapacityFailure;

    for (entries) |entry| {
        sink.write(entry.data) catch return error.CapacityFailure;
    }
    return sink.offset;
}


const Codec = enum { store, xpress, lzx, unsupported };

fn headerCodec(archive: []const u8) Failure!Codec {
    if (archive.len < 20) return error.DataFailure;
    const flags = std.mem.readInt(u32, archive[16..20], .little);
    if (flags & flag_compression == 0) return .store;
    if (flags & (flag_compress_xpress | flag_compress_xpress_2) != 0) return .xpress;
    if (flags & flag_compress_lzx != 0) return .lzx;
    return .unsupported;
}

// A compressed resource is a chunk table of u32 offsets, one fewer than
// the chunk count. Entries are relative to the first chunk's byte; every
// chunk but the last decodes to exactly 32 KiB.
fn readResource(archive: []const u8, res: Reshdr, codec: Codec, out: []u8) Failure!void {
    if (res.flags & reshdr_flag_compressed == 0) {
        const data = try bounds.slice(archive, res.offset, res.size_in_wim);
        if (data.len != out.len) return error.DataFailure;
        @memcpy(out, data);
        return;
    }
    const uncompressed = std.math.cast(usize, res.uncompressed_size) orelse return error.ResourceFailure;
    if (out.len < uncompressed) return error.CapacityFailure;
    const num_chunks = (uncompressed + chunk_size - 1) / chunk_size;
    if (num_chunks == 0) return error.DataFailure;
    const table_entries = num_chunks - 1;
    // The on-disk area begins at res.offset directly; the 24-byte reshdr is
    // header bookkeeping, not echoed in the file.
    const table = try bounds.slice(archive, res.offset, table_entries * 4);
    const area = try bounds.addU64(res.offset, table_entries * 4);
    const area_len = res.size_in_wim - table_entries * 4;
    for (0..num_chunks) |i| {
        const start_off: u64 = if (i == 0) 0 else std.mem.readInt(u32, table[(i - 1) * 4 ..][0..4], .little);
        const end_off: u64 = if (i == num_chunks - 1) area_len else std.mem.readInt(u32, table[i * 4 ..][0..4], .little);
        if (end_off < start_off or end_off > area_len) return error.DataFailure;
        const take = @min(chunk_size, uncompressed - i * chunk_size);
        const payload = try bounds.slice(archive, try bounds.addU64(area, start_off), end_off - start_off);
        switch (codec) {
            .xpress => try xpress.xpressDecode(payload, out[i * chunk_size ..][0..take]),
            .lzx => try lzx.lzxDecode(payload, out[i * chunk_size ..][0..take]),
            else => return error.UnsupportedFailure,
        }
    }
}

const BlobEntry = struct {
    hash: [sha1_len]u8,
    size: u64,
    res: Reshdr,
};

const Parsed = struct {
    blobs: []BlobEntry,
    metadata: []const u8,
};

fn parse(archive: []const u8, scratch: []u8) Failure!Parsed {
    if (archive.len < header_disk_size) return error.DataFailure;
    if (std.mem.readInt(u64, archive[0..8], .little) != wim_magic) return error.DataFailure;
    if (std.mem.readInt(u32, archive[12..16], .little) != wim_version) return error.DataFailure;
    const codec = try headerCodec(archive);
    const blobs_hdr = try readReshdr(archive, 48);
    if (blobs_hdr.flags & reshdr_flag_compressed != 0) return error.UnsupportedFailure;
    const blob_bytes = try bounds.slice(archive, blobs_hdr.offset, blobs_hdr.size_in_wim);
    // Entries fill the table's declared size; zeroed strides are padding.
    var count: usize = 0;
    var stride: usize = 0;
    while (stride + blob_disk_size <= blob_bytes.len) : (stride += blob_disk_size) {
        var all_zero = true;
        for (blob_bytes[stride .. stride + 50]) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (!all_zero) count += 1;
    }
    if (count * @sizeOf(BlobEntry) + 8 > scratch.len) return error.ResourceFailure;
    const base = (8 - (@intFromPtr(scratch.ptr) & 7)) & 7;
    const entries: []BlobEntry = @alignCast(std.mem.bytesAsSlice(BlobEntry, scratch[base .. base + count * @sizeOf(BlobEntry)]));
    var metadata: ?[]const u8 = null;
    var slot: usize = 0;
    stride = 0;
    while (stride + blob_disk_size <= blob_bytes.len) : (stride += blob_disk_size) {
        var all_zero = true;
        for (blob_bytes[stride .. stride + 50]) |byte| {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) continue;
        const entry = &entries[slot];
        slot += 1;
        entry.res = try readReshdr(blob_bytes, stride);
        @memcpy(&entry.hash, blob_bytes[stride + 30 ..][0..sha1_len]);
        entry.size = entry.res.uncompressed_size;
        if (entry.res.flags & reshdr_flag_metadata != 0) {
            if (metadata == null and codec != .unsupported) {
                const size = std.math.cast(usize, entry.res.uncompressed_size) orelse return error.ResourceFailure;
                if (scratch.len < base + count * @sizeOf(BlobEntry) + size) return error.ResourceFailure;
                const buf = scratch[base + count * @sizeOf(BlobEntry) .. base + count * @sizeOf(BlobEntry) + size];
                try readResource(archive, entry.res, codec, buf);
                metadata = buf;
            }
        }
    }
    if (metadata == null) {
        // Fall back to the boot metadata header slot.
        const boot = try readReshdr(archive, 96);
        if (boot.size_in_wim == 0) return error.DataFailure;
        const size = std.math.cast(usize, boot.uncompressed_size) orelse return error.ResourceFailure;
        if (scratch.len < base + count * @sizeOf(BlobEntry) + size) return error.ResourceFailure;
        const buf = scratch[base + count * @sizeOf(BlobEntry) .. base + count * @sizeOf(BlobEntry) + size];
        try readResource(archive, boot, codec, buf);
        metadata = buf;
    }
    return .{ .blobs = entries, .metadata = metadata.? };
}

fn utf16NameInto(buf: []u8, units: []const u8) Failure![]const u8 {
    var out_len: usize = 0;
    var i: usize = 0;
    while (i + 1 < units.len) : (i += 2) {
        const unit = std.mem.readInt(u16, units[i..][0..2], .little);
        const cp: u21 = if (unit >= 0xD800 and unit < 0xDC00) blk: {
            if (i + 3 >= units.len) return error.DataFailure;
            const low = std.mem.readInt(u16, units[i + 2 ..][0..2], .little);
            if (low < 0xDC00 or low > 0xDFFF) return error.DataFailure;
            i += 2;
            break :blk 0x10000 + ((@as(u21, unit) - 0xD800) << 10) + (@as(u21, low) - 0xDC00);
        } else unit;
        const n = std.unicode.utf8Encode(cp, buf[out_len..]) catch return error.DataFailure;
        out_len += n;
    }
    return buf[0..out_len];
}

// Security data length includes its own leading u32.
fn securityDataLen(metadata: []const u8) Failure!usize {
    if (metadata.len < 8) return error.DataFailure;
    const total = std.mem.readInt(u32, metadata[0..4], .little);
    if (total < 8 or total > metadata.len or total % 8 != 0) return error.DataFailure;
    return total;
}

// walk visits each file dentry in metadata order.
fn walk(metadata: []const u8, ctx: anytype, comptime visit: anytype) Failure!void {
    const root_at = try securityDataLen(metadata);
    if (root_at + dentry_disk_size > metadata.len) return error.DataFailure;
    const root_len = std.mem.readInt(u64, metadata[root_at..][0..8], .little);
    const root_aligned = (@as(usize, @intCast(root_len)) + 7) & ~@as(usize, 7);
    // Children live at the root's subdir offset.
    // Tagged metadata may sit between the root dentry and the first child.
    _ = root_aligned;
    const subdir = std.mem.readInt(u64, metadata[root_at + 16 ..][0..8], .little);
    if (subdir == 0) return;
    var pos: usize = @intCast(subdir);
    if (pos > metadata.len) return error.DataFailure;
    while (true) {
        if (pos + 8 > metadata.len) return error.DataFailure;
        const length = std.mem.readInt(u64, metadata[pos..][0..8], .little);
        const aligned = (length + 7) & ~@as(u64, 7);
        if (aligned <= 8) return; // end of siblings
        if (pos + aligned > metadata.len or aligned < dentry_disk_size) return error.DataFailure;
        const name_nbytes = std.mem.readInt(u16, metadata[pos + 100 ..][0..2], .little);
        const stream_count = std.mem.readInt(u16, metadata[pos + 96 ..][0..2], .little);
        var name_buf: [1024]u8 = undefined;
        var name: []const u8 = &.{};
        if (name_nbytes != 0) {
            if (pos + dentry_disk_size + name_nbytes > metadata.len) return error.DataFailure;
            name = try utf16NameInto(&name_buf, metadata[pos + dentry_disk_size ..][0..name_nbytes]);
        }
        const hash_off = pos + 64;
        var hash: [sha1_len]u8 = undefined;
        @memcpy(&hash, metadata[hash_off..][0..sha1_len]);
        const size = std.mem.readInt(u64, metadata[pos + 8 ..][0..8], .little);
        _ = size;
        try visit(ctx, name, &hash);
        pos += @intCast(aligned);
        for (0..stream_count) |_| {
            if (pos + 8 > metadata.len) return error.DataFailure;
            const stream_len = std.mem.readInt(u64, metadata[pos..][0..8], .little);
            const stream_aligned = (stream_len + 7) & ~@as(u64, 7);
            if (stream_len < stream_disk_size or pos + stream_aligned > metadata.len) return error.DataFailure;
            pos += @intCast(stream_aligned);
        }
    }
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Failure!u64 {
    const parsed = try parse(archive, scratch);
    var count: u64 = 0;
    const Ctx = struct { count: *u64 };
    var ctx = Ctx{ .count = &count };
    try walk(parsed.metadata, &ctx, struct {
        fn visit(c: *Ctx, _: []const u8, _: *const [sha1_len]u8) Failure!void {
            c.count.* = try bounds.addU64(c.count.*, 1);
        }
    }.visit);
    return count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Failure!EntryInfo {
    if (scratch.len < 2048) return error.ResourceFailure;
    const parsed = try parse(archive, scratch[0 .. scratch.len - 1024]);
    const Ctx = struct {
        ordinal: u64,
        index: u64 = 0,
        found: ?EntryInfo = null,
        name_buf: []u8,
    };
    var ctx = Ctx{ .ordinal = ordinal, .name_buf = scratch[scratch.len - 1024 ..] };
    try walk(parsed.metadata, &ctx, struct {
        fn visit(c: *Ctx, name: []const u8, hash: *const [sha1_len]u8) Failure!void {
            if (c.index == c.ordinal) {
                if (name.len > c.name_buf.len) return error.ResourceFailure;
                @memcpy(c.name_buf[0..name.len], name);
                c.found = .{ .name = c.name_buf[0..name.len], .size = 0, .hash = hash.*, .ordinal = c.index };
            }
            c.index += 1;
        }
    }.visit);
    if (ctx.found) |info| {
        var result = info;
        result.size = try blobSize(parsed.blobs, &result.hash);
        return result;
    }
    return error.DataFailure;
}

fn blobSize(blobs: []const BlobEntry, hash: *const [sha1_len]u8) Failure!u64 {
    for (blobs) |entry| {
        if (entry.res.flags & reshdr_flag_metadata != 0) continue;
        if (std.mem.eql(u8, &entry.hash, hash)) return entry.size;
    }
    return error.DataFailure;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Failure!usize {
    if (scratch.len < 2048) return error.ResourceFailure;
    const parts = scratch[scratch.len - 1024 ..];
    const parsed = try parse(archive, scratch[0 .. scratch.len - 1024]);
    var info: ?EntryInfo = null;
    const Ctx = struct {
        ordinal: u64,
        index: u64 = 0,
        found: *?EntryInfo,
        name_buf: []u8,
    };
    var ctx = Ctx{ .ordinal = ordinal, .found = &info, .name_buf = parts };
    try walk(parsed.metadata, &ctx, struct {
        fn visit(c: *Ctx, name: []const u8, hash: *const [sha1_len]u8) Failure!void {
            if (c.index == c.ordinal) {
                if (name.len > c.name_buf.len) return error.ResourceFailure;
                @memcpy(c.name_buf[0..name.len], name);
                c.found.* = .{ .name = c.name_buf[0..name.len], .size = 0, .hash = hash.*, .ordinal = c.index };
            }
            c.index += 1;
        }
    }.visit);
    const found = info orelse return error.DataFailure;
    const size = std.math.cast(usize, try blobSize(parsed.blobs, &found.hash)) orelse return error.ResourceFailure;
    if (output.len < size) return error.CapacityFailure;
    const codec = try headerCodec(archive);
    for (parsed.blobs) |entry| {
        if (entry.res.flags & reshdr_flag_metadata != 0) continue;
        if (std.mem.eql(u8, &entry.hash, &found.hash)) {
            try readResource(archive, entry.res, codec, output[0..size]);
            return size;
        }
    }
    return error.DataFailure;
}

test "wim store roundtrips flat files" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello world" },
        .{ .name = "nested.bin", .data = "payload" },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    const first = try inspectOrdinal(archive[0..written], 0, &scratch);
    try testing.expectEqualSlices(u8, "hello.txt", first.name);
    try testing.expectEqual(@as(u64, 11), first.size);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "payload", out[0..n]);
}


