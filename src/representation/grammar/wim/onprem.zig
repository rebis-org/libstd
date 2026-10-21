const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const lzms = @import("lzms.zig");
const lzx = @import("lzx.zig");
const xpress = @import("xpress.zig");

const Exception = exception_prim.Exception;

// Layout follows wimlib's on-disk headers.

pub const scratch_size: usize = 64 * 1024;

const wim_magic: u64 = 0x0000_004D_4957_534D; // "MSWIM\0\0\0" little-endian.
const wim_version: u32 = 0x10D00;
const wim_version_solid: u32 = 0x0E00;
const header_disk_size = 208;
const dentry_disk_size = 102;
const stream_disk_size = 40;
const blob_disk_size = 50;
const reshdr_flag_metadata: u8 = 0x02;
const reshdr_flag_compressed: u8 = 0x04;
const reshdr_flag_solid: u8 = 0x10;
const flag_compress_xpress: u32 = 0x00020000;
const flag_compress_xpress_2: u32 = 0x00200000;
const flag_compress_lzx: u32 = 0x00040000;
const flag_compress_lzms: u32 = 0x00080000;
const flag_compression: u32 = 0x00000002;
const sha1_len = 20;
const solid_resource_magic: u64 = 0x1_0000_0000;
const xpress_chunk_max: u64 = 65536;
const lzx_chunk_max: u64 = 1 << 21;
const lzms_chunk_max: u64 = 1 << 30;

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

fn readReshdr(data: []const u8, at: usize) Exception!Reshdr {
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

fn nextCodepoint(name: []const u8, i: *usize) Exception!u21 {
    const len = std.unicode.utf8ByteSequenceLength(name[i.*]) catch return error.DataException;
    if (i.* + len > name.len) return error.DataException;
    const bytes = name[i.*..][0..len];
    const cp: u21 = switch (len) {
        1 => bytes[0],
        2 => std.unicode.utf8Decode2(bytes[0..2].*) catch return error.DataException,
        3 => std.unicode.utf8Decode3(bytes[0..3].*) catch return error.DataException,
        4 => std.unicode.utf8Decode4(bytes[0..4].*) catch return error.DataException,
        else => unreachable,
    };
    i.* += len;
    return cp;
}

fn utf16Len(name: []const u8) Exception!usize {
    var units: usize = 0;
    var i: usize = 0;
    while (i < name.len) {
        const cp = try nextCodepoint(name, &i);
        units += if (cp >= 0x10000) 2 else 1;
    }
    return units;
}

fn writeUtf16Le(out: []u8, name: []const u8) Exception!usize {
    var written: usize = 0;
    var i: usize = 0;
    while (i < name.len) {
        const cp = try nextCodepoint(name, &i);
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

fn metadataLen(entries: []const Entry) Exception!u64 {
    var total: u64 = 8 + 104; // empty security data, root dentry, children
    for (entries) |entry| {
        const units = try utf16Len(entry.name);
        if (units == 0) return error.CallException;
        total = try bounds.addU64(total, dentryWireLen(units) + stream_disk_size);
    }
    return bounds.addU64(total, 8); // end-of-siblings marker
}

fn blobTableLen(entries: []const Entry) u64 {
    // One entry per file, one for the image metadata resource, then the
    // zero terminator.
    return @as(u64, (entries.len + 2) * blob_disk_size + 7) & ~@as(u64, 7);
}

fn xmlLen(entries: []const Entry) Exception!u64 {
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

pub fn archiveSize(entries: []const Entry) Exception!u64 {
    const xml = try xmlLen(entries);
    var total: u64 = header_disk_size;
    total = try bounds.addU64(total, blobTableLen(entries));
    total = try bounds.addU64(total, xml);
    total = try bounds.addU64(total, try metadataLen(entries));
    for (entries) |entry| total = try bounds.addU64(total, entry.data.len);
    return total;
}

fn writeDentry(out: []u8, name: []const u8, hash: *const [sha1_len]u8, subdir_offset: u64) Exception!usize {
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
        pos += writeUtf16Le(out[pos..], name) catch return error.DataException;
        pos += 2; // NUL terminator
    }
    // Extra stream entry for the unnamed data stream, on the 8-byte
    // boundary following the dentry proper.
    var stream: [stream_disk_size]u8 = @splat(0);
    std.mem.writeInt(u64, stream[0..8], stream_disk_size, .little);
    @memcpy(stream[16..36], hash);
    std.mem.writeInt(u16, stream[36..38], 0, .little);
    @memcpy(out[wire_len..][0..stream_disk_size], &stream);
    return wire_len + stream_disk_size;
}

fn writeBlobEntry(blob: *[blob_disk_size]u8, res: Reshdr, hash: *const [sha1_len]u8) void {
    writeReshdr(blob[0..24], res);
    std.mem.writeInt(u16, blob[24..26], 1, .little);
    std.mem.writeInt(u32, blob[26..30], 1, .little);
    @memcpy(blob[30..50], hash);
}

fn writeAscii16(sink: anytype, byte: u8) Exception!void {
    var pair: [2]u8 = .{ byte, 0 };
    try sink.write(&pair);
}

fn writeTocXml(sink: anytype, entries: []const Entry, total: u64) Exception!void {
    const text_parts = [_][]const u8{
        "<WIM><IMAGE INDEX=\"1\"><NAME>image</NAME><DIRCOUNT>0</DIRCOUNT><FILECOUNT>",
        "</FILECOUNT><TOTALBYTES>",
        "</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES></IMAGE><TOTALBYTES>",
        "</TOTALBYTES></WIM>",
    };
    var total_buf: [24]u8 = undefined;
    var file_buf: [24]u8 = undefined;
    const total_text = std.mem.print(&total_buf, "{d}", .{total}) catch return error.CapacityException;
    const file_text = std.mem.print(&file_buf, "{d}", .{entries.len}) catch return error.CapacityException;
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

    fn write(self: *CountSink, bytes: []const u8) Exception!void {
        self.pos = try bounds.addU64(self.pos, bytes.len);
    }
};

const RealSink = struct {
    bytes: []u8,
    pos: usize = 0,

    fn write(self: *RealSink, bytes: []const u8) Exception!void {
        if (self.pos + bytes.len > self.bytes.len) return error.CapacityException;
        @memcpy(self.bytes[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }
};

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    const metadata_len = try metadataLen(entries);
    if (scratch.len < metadata_len + 4096) return error.ResourceException;

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
        md_pos += try writeDentry(scratch[md_pos..], entry.name, &hash, 0);
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
    std.mem.writeInt(u16, header[40..42], 1, .little); // part number.
    std.mem.writeInt(u16, header[42..44], 1, .little); // total parts.
    std.mem.writeInt(u32, header[44..48], 1, .little); // one image.
    writeReshdr(header[48..72], .{ .size_in_wim = blob_table_len, .flags = 0, .offset = blob_off, .uncompressed_size = blob_table_len });
    writeReshdr(header[72..96], .{ .size_in_wim = xml_len, .flags = 0, .offset = xml_off, .uncompressed_size = xml_len });
    writeReshdr(header[96..120], .{ .size_in_wim = 0, .flags = reshdr_flag_metadata, .offset = 0, .uncompressed_size = 0 });
    std.mem.writeInt(u32, header[120..124], 0, .little); // boot index
    writeReshdr(header[124..148], .{ .size_in_wim = 0, .flags = 0, .offset = 0, .uncompressed_size = 0 }); // no integrity table
    sink.write(&header) catch return error.CapacityException;

    var blob: [blob_disk_size]u8 = undefined;
    for (entries) |entry| {
        var hash: [sha1_len]u8 = undefined;
        std.crypto.hash.Sha1.hash(entry.data, &hash, .{});
        writeBlobEntry(&blob, .{ .size_in_wim = entry.data.len, .flags = 0, .offset = data_off, .uncompressed_size = entry.data.len }, &hash);
        sink.write(&blob) catch return error.CapacityException;
        data_off = try bounds.addU64(data_off, entry.data.len);
    }
    writeBlobEntry(&blob, .{ .size_in_wim = metadata_len, .flags = reshdr_flag_metadata, .offset = metadata_off, .uncompressed_size = metadata_len }, &metadata_hash);
    sink.write(&blob) catch return error.CapacityException;
    const zeros: [50]u8 = @splat(0);
    sink.write(&zeros) catch return error.CapacityException;
    var pad: [8]u8 = @splat(0);
    const blob_pad = blob_table_len - @as(u64, (entries.len + 2) * blob_disk_size);
    if (blob_pad > 0) sink.write(pad[0..blob_pad]) catch return error.CapacityException;

    var xml_sink = RealSink{ .bytes = scratch[@intCast(metadata_len)..@intCast(try bounds.addU64(metadata_len, xml_len))] };
    try writeTocXml(&xml_sink, entries, try archiveSize(entries));
    sink.write(scratch[@intCast(metadata_len)..][0..xml_sink.pos]) catch return error.CapacityException;

    sink.write(scratch[0..@intCast(metadata_len)]) catch return error.CapacityException;

    for (entries) |entry| {
        sink.write(entry.data) catch return error.CapacityException;
    }
    return sink.offset;
}

const Codec = enum { store, xpress, lzx, lzms, unsupported };

fn headerCodec(archive: []const u8) Exception!Codec {
    if (archive.len < 20) return error.DataException;
    const flags = std.mem.readInt(u32, archive[16..20], .little);
    if (flags & flag_compression == 0) return .store;
    if (flags & (flag_compress_xpress | flag_compress_xpress_2) != 0) return .xpress;
    if (flags & flag_compress_lzx != 0) return .lzx;
    if (flags & flag_compress_lzms != 0) return .lzms;
    return .unsupported;
}

// A compressed resource is stored as chunks of at most chunk_size bytes,
// prefixed by a chunk table. A normal table lists the end offset of every
// chunk but the first and last; the last chunk size is derived from the
// resource area length. Solid resources use an alternate table: a 16-byte
// header followed by the compressed size of every chunk; offsets are the
// running sums and the last entry is ignored (wimlib resource.c).
const ChunkLoc = struct {
    offset: u64, // File offset of the compressed chunk bytes.
    start: u64, // Uncompressed offset of the chunk.
    csize: u64, // Compressed size.
    usize: u64, // Uncompressed size.
};

const ChunkedResource = struct {
    bytes: []const u8,
    table_off: u64,
    data_off: u64,
    area_len: u64,
    uncompressed_size: u64,
    chunk_size: u64,
    entry_size: u64,
    num_chunks: u64,
    entries: u64,
    solid: bool,

    fn init(bytes: []const u8, offset: u64, size_in_wim: u64, uncompressed_size: u64, chunk_size: u64, solid: bool) Exception!ChunkedResource {
        if (uncompressed_size == 0 or chunk_size == 0) return error.DataException;
        const num_chunks = uncompressed_size / chunk_size + @intFromBool(uncompressed_size % chunk_size != 0);
        const entry_size: u64 = if (solid or uncompressed_size <= std.math.maxInt(u32)) 4 else 8;
        const entries = num_chunks - @intFromBool(!solid);
        const table_bytes = std.math.mul(u64, entries, entry_size) catch return error.ResourceException;
        const header_len: u64 = if (solid) 16 else 0;
        const table_full = std.math.add(u64, table_bytes, header_len) catch return error.DataException;
        if (size_in_wim < table_full) return error.DataException;
        return .{
            .bytes = bytes,
            .table_off = try bounds.addU64(offset, header_len),
            .data_off = try bounds.addU64(offset, table_full),
            .area_len = size_in_wim - table_full,
            .uncompressed_size = uncompressed_size,
            .chunk_size = chunk_size,
            .entry_size = entry_size,
            .num_chunks = num_chunks,
            .entries = entries,
            .solid = solid,
        };
    }

    fn entryAt(res: *const ChunkedResource, index: u64) Exception!u64 {
        if (index >= res.entries) return error.DataException;
        const at = try bounds.addU64(res.table_off, std.math.mul(u64, index, res.entry_size) catch return error.ResourceException);
        const raw = try bounds.slice(res.bytes, at, res.entry_size);
        return if (res.entry_size == 4) std.mem.readInt(u32, raw[0..4], .little) else std.mem.readInt(u64, raw[0..8], .little);
    }
};

const ChunkIter = struct {
    res: *const ChunkedResource,
    index: u64 = 0,
    solid_off: u64 = 0,

    fn next(it: *ChunkIter) Exception!?ChunkLoc {
        const res = it.res;
        if (it.index >= res.num_chunks) return null;
        const i = it.index;
        const chunk_usize = if ((i + 1) * res.chunk_size > res.uncompressed_size) res.uncompressed_size - i * res.chunk_size else res.chunk_size;
        var offset: u64 = undefined;
        var csize: u64 = undefined;
        if (res.solid) {
            const base = it.solid_off;
            if (base > res.area_len) return error.DataException;
            offset = base;
            if (i + 1 != res.num_chunks) {
                csize = try res.entryAt(i);
                it.solid_off = std.math.add(u64, base, csize) catch return error.DataException;
            } else {
                csize = res.area_len - base;
            }
        } else {
            const start: u64 = if (i == 0) 0 else try res.entryAt(i - 1);
            const end: u64 = if (i + 1 == res.num_chunks) res.area_len else try res.entryAt(i);
            if (end < start or end > res.area_len) return error.DataException;
            offset = start;
            csize = end - start;
        }
        if (csize == 0 or csize > chunk_usize) return error.DataException;
        it.index += 1;
        return .{ .offset = try bounds.addU64(res.data_off, offset), .start = i * res.chunk_size, .csize = csize, .usize = chunk_usize };
    }
};

fn validateChunking(codec: Codec, chunk_size: u64) Exception!void {
    if (chunk_size == 0 or (chunk_size & (chunk_size - 1)) != 0) return error.DataException;
    const cap: u64 = switch (codec) {
        .xpress => xpress_chunk_max,
        .lzx => lzx_chunk_max,
        .lzms => lzms_chunk_max,
        .store => return error.DataException,
        .unsupported => return error.UnsupportedException,
    };
    if (chunk_size > cap) return error.DataException;
}

fn decodeChunk(codec: Codec, chunk_size: u64, payload: []const u8, out: []u8) Exception!void {
    switch (codec) {
        .xpress => try xpress.xpressDecode(payload, out),
        .lzx => try lzx.lzxDecode(@intCast(chunk_size), payload, out),
        .lzms => try lzms.lzmsDecode(payload, out),
        .store, .unsupported => return error.UnsupportedException,
    }
}

fn readResource(archive: []const u8, res: Reshdr, chunk_size: u32, codec: Codec, out: []u8) Exception!void {
    if (res.flags & reshdr_flag_solid != 0) return error.DataException;
    if (res.flags & reshdr_flag_compressed == 0) {
        const data = try bounds.slice(archive, res.offset, res.size_in_wim);
        if (data.len != out.len) return error.DataException;
        @memcpy(out, data);
        return;
    }
    const uncompressed = std.math.cast(usize, res.uncompressed_size) orelse return error.ResourceException;
    if (out.len != uncompressed) return error.CapacityException;
    if (uncompressed == 0) return;
    try validateChunking(codec, chunk_size);
    const chunked = try ChunkedResource.init(archive, res.offset, res.size_in_wim, uncompressed, chunk_size, false);
    var it = ChunkIter{ .res = &chunked };
    while (try it.next()) |loc| {
        const payload = try bounds.slice(archive, loc.offset, loc.csize);
        const out_slice = out[@intCast(loc.start)..@intCast(loc.start + loc.usize)];
        if (payload.len == loc.usize) {
            @memcpy(out_slice, payload);
        } else {
            try decodeChunk(codec, chunk_size, payload, out_slice);
        }
    }
}

const SolidRes = struct {
    offset: u64,
    size_in_wim: u64,
    uncompressed_size: u64,
    chunk_size: u64,
    codec: Codec,
};

// A solid resource begins with a 16-byte alternate header: uncompressed
// size, chunk size, and compression format (wimlib resource.h).
fn loadSolidRes(archive: []const u8, res: Reshdr) Exception!SolidRes {
    const header = try bounds.slice(archive, res.offset, 16);
    const format = std.mem.readInt(u32, header[12..16], .little);
    const codec: Codec = switch (format) {
        0 => .store,
        1 => .xpress,
        2 => .lzx,
        3 => .lzms,
        else => return error.DataException,
    };
    return .{
        .offset = res.offset,
        .size_in_wim = res.size_in_wim,
        .uncompressed_size = std.mem.readInt(u64, header[0..8], .little),
        .chunk_size = std.mem.readInt(u32, header[8..12], .little),
        .codec = codec,
    };
}

// Reads [blob_offset, blob_offset + out.len) from the uncompressed image of
// a solid resource, decoding only the chunks the range touches.
fn readSolidRange(archive: []const u8, sr: SolidRes, blob_offset: u64, out: []u8, temp: []u8) Exception!void {
    const out_len: u64 = std.math.cast(u64, out.len) orelse return error.ResourceException;
    const end = blob_offset +% out_len;
    if (end < out_len or end > sr.uncompressed_size) return error.DataException;
    if (out.len == 0) return;
    try validateChunking(sr.codec, sr.chunk_size);
    const chunked = try ChunkedResource.init(archive, sr.offset, sr.size_in_wim, sr.uncompressed_size, sr.chunk_size, true);
    var produced: u64 = 0;
    var it = ChunkIter{ .res = &chunked };
    while (try it.next()) |loc| {
        const chunk_end = loc.start + loc.usize;
        if (chunk_end <= blob_offset) continue;
        if (loc.start >= end) break;
        const isect_start = @max(blob_offset, loc.start);
        const isect_end = @min(end, chunk_end);
        const payload = try bounds.slice(archive, loc.offset, loc.csize);
        const out_from: usize = @intCast(isect_start - blob_offset);
        const out_to: usize = @intCast(isect_end - blob_offset);
        const in_from: usize = @intCast(isect_start - loc.start);
        const in_to: usize = @intCast(isect_end - loc.start);
        if (payload.len == loc.usize) {
            @memcpy(out[out_from..out_to], payload[in_from..in_to]);
        } else if (isect_start == loc.start and isect_end == chunk_end) {
            try decodeChunk(sr.codec, sr.chunk_size, payload, out[out_from..out_to]);
        } else {
            if (temp.len < loc.usize) return error.ResourceException;
            try decodeChunk(sr.codec, sr.chunk_size, payload, temp[0..@intCast(loc.usize)]);
            @memcpy(out[out_from..out_to], temp[in_from..in_to]);
        }
        produced += isect_end - isect_start;
        if (produced == out_len) break;
    }
    if (produced != out_len) return error.DataException;
}

const BlobEntry = struct {
    hash: [sha1_len]u8,
    size: u64,
    res: Reshdr,
    solid: bool = false,
    solid_index: u64 = 0,
    solid_offset: u64 = 0,
};

const BlobDisk = struct {
    res: Reshdr,
    part: u16,
    refcnt: u32,
    hash: [sha1_len]u8,
};

// On-disk blob entry: reshdr, part number, reference count, SHA-1.
fn readBlobEntry(table: []const u8, at: usize) Exception!BlobDisk {
    if (at + blob_disk_size > table.len) return error.DataException;
    return .{
        .res = try readReshdr(table, at),
        .part = std.mem.readInt(u16, table[at + 24 ..][0..2], .little),
        .refcnt = std.mem.readInt(u32, table[at + 26 ..][0..4], .little),
        .hash = table[at + 30 ..][0..sha1_len].*,
    };
}

fn isZeroHash(hash: *const [sha1_len]u8) bool {
    for (hash) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

const SolidFit = struct {
    index: u64,
    offset: u64,
};

// Locates the solid resource holding a member and the member's offset
// inside it. The member's reshdr offset addresses the concatenated
// uncompressed data of the run; a member may not span two resources.
fn assignSolid(run: []const SolidRes, res: Reshdr) Exception!SolidFit {
    const size = res.size_in_wim;
    var off = res.offset;
    for (run, 0..) |sr, i| {
        if (off +% size < size) return error.DataException;
        if (off + size <= sr.uncompressed_size) return .{ .index = i, .offset = off };
        if (off < sr.uncompressed_size) return error.DataException;
        off -= sr.uncompressed_size;
    }
    return error.DataException;
}

fn isDuplicate(blobs: []const BlobEntry, hash: *const [sha1_len]u8) bool {
    for (blobs) |entry| {
        if (std.mem.eql(u8, &entry.hash, hash)) return true;
    }
    return false;
}

fn appendBlob(blobs: []BlobEntry, filled: *usize, hash: *const [sha1_len]u8, size: u64, res: Reshdr, fit: ?SolidFit) void {
    blobs[filled.*] = .{
        .hash = hash.*,
        .size = size,
        .res = res,
        .solid = fit != null,
        .solid_index = if (fit) |f| f.index else 0,
        .solid_offset = if (fit) |f| f.offset else 0,
    };
    filled.* += 1;
}

fn blobLookup(blobs: []const BlobEntry, hash: [sha1_len]u8) Exception!BlobEntry {
    for (blobs) |entry| {
        if (std.mem.eql(u8, &entry.hash, &hash)) return entry;
    }
    return error.DataException;
}

const Verdict = enum { drop, take, err };

// Metadata gates in vendor order: unreferenced drop, multi-reference
// error, solid error, foreign-part drop, image-count drop, take.
fn metadataVerdict(refcnt: u32, entry_solid: bool, wim_part: u16, image_count: u32, image_index: u32) Verdict {
    if (refcnt == 0) return .drop;
    if (refcnt != 1) return .err;
    if (entry_solid) return .err;
    if (wim_part != 1) return .drop;
    if (image_index == image_count) return .drop;
    return .take;
}

// Loads the solid resources of one run: consecutive SOLID table strides
// led by a magic entry. Returns the number of resources loaded.
fn loadSolidRun(archive: []const u8, table: []const u8, start: usize, out: []SolidRes) Exception!usize {
    var count: usize = 0;
    var at = start;
    while (at + blob_disk_size <= table.len) : (at += blob_disk_size) {
        const disk = try readBlobEntry(table, at);
        if (disk.res.flags & reshdr_flag_solid == 0) break;
        if (disk.res.uncompressed_size == solid_resource_magic) {
            count += 1;
            if (count > out.len) return error.DataException;
        }
    }
    if (count == 0) return error.DataException;
    var filled: usize = 0;
    at = start;
    while (at + blob_disk_size <= table.len) : (at += blob_disk_size) {
        const disk = try readBlobEntry(table, at);
        if (disk.res.flags & reshdr_flag_solid == 0) break;
        if (disk.res.uncompressed_size != solid_resource_magic) continue;
        out[filled] = try loadSolidRes(archive, disk.res);
        filled += 1;
        if (filled == count) break;
    }
    if (filled != count) return error.DataException;
    return filled;
}

const Parsed = struct {
    blobs: []BlobEntry,
    solid_reses: []SolidRes,
    metadata: []const u8,
    temp: []u8,
};

fn parse(archive: []const u8, scratch: []u8) Exception!Parsed {
    if (archive.len < header_disk_size) return error.DataException;
    if (std.mem.readInt(u64, archive[0..8], .little) != wim_magic) return error.DataException;
    // wimlib stamps LZMS captures with the solid variant 0xE00.
    const version = std.mem.readInt(u32, archive[12..16], .little);
    if (version != wim_version and version != wim_version_solid) return error.DataException;
    const solid_wim = version == wim_version_solid;
    const codec = try headerCodec(archive);
    const chunk_size = std.mem.readInt(u32, archive[20..24], .little);
    // Split-WIM identity: this part's 1-based number at 0x28, total parts at 0x2A.
    const wim_part = std.mem.readInt(u16, archive[40..42], .little);
    const image_count = std.mem.readInt(u32, archive[44..48], .little);
    const blobs_hdr = try readReshdr(archive, 48);
    const table_usize = std.math.cast(usize, blobs_hdr.uncompressed_size) orelse return error.ResourceException;
    if (table_usize > scratch.len) return error.ResourceException;
    // The workspace scratch may start at any byte offset, so rebase to an
    // aligned sub-slice before carving typed arrays out of it. Rounding the
    // offsets alone cannot fix a misaligned base: a round-up is itself always
    // aligned, which would just reproduce the base's misalignment.
    const carve_align = @max(@alignOf(BlobEntry), @alignOf(SolidRes));
    const misalign = @intFromPtr(scratch.ptr) & (carve_align - 1);
    const align_pad = (carve_align - misalign) & (carve_align - 1);
    if (scratch.len < align_pad + table_usize) return error.ResourceException;
    const buf = scratch[align_pad..];
    const table = buf[0..table_usize];
    try readResource(archive, blobs_hdr, chunk_size, codec, table);
    // Pass 1 sizes the scratch carve and finds the first metadata image.
    var num_blobs: usize = 0;
    var num_solid_res: usize = 0;
    var candidate: ?Reshdr = null;
    var image_index: u32 = 0;
    var at: usize = 0;
    while (at + blob_disk_size <= table.len) : (at += blob_disk_size) {
        var disk = try readBlobEntry(table, at);
        if (!solid_wim) disk.res.flags &= ~reshdr_flag_solid;
        if (disk.res.flags & reshdr_flag_solid != 0 and disk.res.uncompressed_size == solid_resource_magic) {
            num_solid_res += 1;
            continue;
        }
        if (isZeroHash(&disk.hash)) continue;
        const blob_size: u64 = if (disk.res.flags & reshdr_flag_solid != 0) disk.res.size_in_wim else disk.res.uncompressed_size;
        if (blob_size == 0) continue;
        if (disk.part != wim_part) continue;
        if (disk.res.flags & reshdr_flag_metadata != 0) {
            if (candidate == null and metadataVerdict(disk.refcnt, disk.res.flags & reshdr_flag_solid != 0, wim_part, image_count, image_index) == .take) {
                candidate = disk.res;
                image_index += 1;
            }
        } else num_blobs += 1;
    }
    // The metadata resource: the taken table entry, else the boot slot.
    var md_res: Reshdr = undefined;
    if (candidate) |c| {
        md_res = c;
    } else {
        md_res = try readReshdr(archive, 96);
        if (md_res.size_in_wim == 0) return error.DataException;
    }
    const md_size = std.math.cast(usize, md_res.uncompressed_size) orelse return error.ResourceException;
    if (md_size == 0) return error.DataException;
    const blob_bytes = num_blobs * @sizeOf(BlobEntry);
    const solid_bytes = num_solid_res * @sizeOf(SolidRes);
    const blobs_off = (table_usize + 7) & ~@as(usize, 7);
    const solid_off = (blobs_off + blob_bytes + 7) & ~@as(usize, 7);
    const md_off = (solid_off + solid_bytes + 7) & ~@as(usize, 7);
    const temp_off = (md_off + md_size + 7) & ~@as(usize, 7);
    if (temp_off > buf.len) return error.ResourceException;
    const blobs: []BlobEntry = @alignCast(std.mem.bytesAsSlice(BlobEntry, buf[blobs_off..][0..blob_bytes]));
    const solid_reses: []SolidRes = @alignCast(std.mem.bytesAsSlice(SolidRes, buf[solid_off..][0..solid_bytes]));
    // Pass 2 fills the carve, mirroring pass 1's drops exactly.
    var filled: usize = 0;
    var res_filled: usize = 0;
    var run_base: usize = 0;
    var run: []const SolidRes = &.{};
    var in_run = false;
    image_index = 0;
    at = 0;
    while (at + blob_disk_size <= table.len) : (at += blob_disk_size) {
        var disk = try readBlobEntry(table, at);
        if (!solid_wim) disk.res.flags &= ~reshdr_flag_solid;
        const entry_solid = disk.res.flags & reshdr_flag_solid != 0;
        if (entry_solid and !in_run) {
            run_base = res_filled;
            res_filled += try loadSolidRun(archive, table, at, solid_reses[res_filled..]);
            run = solid_reses[run_base..res_filled];
            in_run = true;
        }
        if (entry_solid and disk.res.uncompressed_size == solid_resource_magic) continue;
        var fit: ?SolidFit = null;
        if (entry_solid) {
            var found_fit = try assignSolid(run, disk.res);
            found_fit.index += run_base;
            fit = found_fit;
        } else {
            in_run = false;
            if (disk.res.flags & reshdr_flag_compressed == 0 and disk.res.size_in_wim != disk.res.uncompressed_size) return error.DataException;
        }
        if (isZeroHash(&disk.hash)) continue;
        const blob_size: u64 = if (entry_solid) disk.res.size_in_wim else disk.res.uncompressed_size;
        if (blob_size == 0) continue;
        if (disk.part != wim_part) continue;
        if (disk.res.flags & reshdr_flag_metadata != 0) {
            switch (metadataVerdict(disk.refcnt, entry_solid, wim_part, image_count, image_index)) {
                .take => image_index += 1,
                .err => return error.DataException,
                .drop => {},
            }
            continue;
        }
        if (isDuplicate(blobs[0..filled], &disk.hash)) continue;
        appendBlob(blobs, &filled, &disk.hash, blob_size, disk.res, fit);
    }
    const md_buf = buf[md_off..][0..md_size];
    try readResource(archive, md_res, chunk_size, codec, md_buf);
    return .{
        .blobs = blobs[0..filled],
        .solid_reses = solid_reses[0..res_filled],
        .metadata = md_buf,
        .temp = buf[temp_off..],
    };
}

fn utf16NameInto(buf: []u8, units: []const u8) Exception![]const u8 {
    var out_len: usize = 0;
    var i: usize = 0;
    while (i + 1 < units.len) : (i += 2) {
        const unit = std.mem.readInt(u16, units[i..][0..2], .little);
        const cp: u21 = if (unit >= 0xD800 and unit < 0xDC00) blk: {
            if (i + 3 >= units.len) return error.DataException;
            const low = std.mem.readInt(u16, units[i + 2 ..][0..2], .little);
            if (low < 0xDC00 or low > 0xDFFF) return error.DataException;
            i += 2;
            break :blk 0x10000 + ((@as(u21, unit) - 0xD800) << 10) + (@as(u21, low) - 0xDC00);
        } else unit;
        const n = std.unicode.utf8Encode(cp, buf[out_len..]) catch return error.DataException;
        out_len += n;
    }
    return buf[0..out_len];
}

// Security data length includes its own leading u32.
fn securityDataLen(metadata: []const u8) Exception!usize {
    if (metadata.len < 8) return error.DataException;
    const total = std.mem.readInt(u32, metadata[0..4], .little);
    if (total < 8 or total > metadata.len or total % 8 != 0) return error.DataException;
    return total;
}

fn walk(metadata: []const u8, ctx: anytype, comptime visit: anytype) Exception!void {
    const root_at = try securityDataLen(metadata);
    if (root_at + dentry_disk_size > metadata.len) return error.DataException;
    // Children live at the root's subdir offset.
    // Tagged metadata may sit between the root dentry and the first child.
    const subdir = std.mem.readInt(u64, metadata[root_at + 16 ..][0..8], .little);
    if (subdir == 0) return;
    var pos: usize = @intCast(subdir);
    if (pos > metadata.len) return error.DataException;
    while (true) {
        if (pos + 8 > metadata.len) return error.DataException;
        const length = std.mem.readInt(u64, metadata[pos..][0..8], .little);
        const aligned = (length + 7) & ~@as(u64, 7);
        if (aligned <= 8) return; // end of siblings
        if (pos + aligned > metadata.len or aligned < dentry_disk_size) return error.DataException;
        const name_nbytes = std.mem.readInt(u16, metadata[pos + 100 ..][0..2], .little);
        const stream_count = std.mem.readInt(u16, metadata[pos + 96 ..][0..2], .little);
        var name_buf: [1024]u8 = undefined;
        var name: []const u8 = &.{};
        if (name_nbytes != 0) {
            if (pos + dentry_disk_size + name_nbytes > metadata.len) return error.DataException;
            name = try utf16NameInto(&name_buf, metadata[pos + dentry_disk_size ..][0..name_nbytes]);
        }
        const hash_off = pos + 64;
        var hash: [sha1_len]u8 = undefined;
        @memcpy(&hash, metadata[hash_off..][0..sha1_len]);
        if (pos + 16 > metadata.len) return error.DataException;
        // Sizes come from the blob table.
        _ = std.mem.readInt(u64, metadata[pos + 8 ..][0..8], .little);
        try visit(ctx, name, &hash);
        pos += @intCast(aligned);
        for (0..stream_count) |_| {
            if (pos + 8 > metadata.len) return error.DataException;
            const stream_len = std.mem.readInt(u64, metadata[pos..][0..8], .little);
            const stream_aligned = (stream_len + 7) & ~@as(u64, 7);
            if (stream_len < stream_disk_size or pos + stream_aligned > metadata.len) return error.DataException;
            pos += @intCast(stream_aligned);
        }
    }
}

fn recordOrdinal(ctx: anytype, name: []const u8, hash: *const [sha1_len]u8) Exception!void {
    if (ctx.index == ctx.ordinal) {
        if (name.len > ctx.name_buf.len) return error.ResourceException;
        @memcpy(ctx.name_buf[0..name.len], name);
        ctx.found.* = .{ .name = ctx.name_buf[0..name.len], .size = 0, .hash = hash.*, .ordinal = ctx.index };
    }
    ctx.index += 1;
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    const parsed = try parse(archive, scratch);
    var count: u64 = 0;
    const Ctx = struct { count: *u64 };
    var ctx = Ctx{ .count = &count };
    try walk(parsed.metadata, &ctx, struct {
        fn visit(c: *Ctx, _: []const u8, _: *const [sha1_len]u8) Exception!void {
            c.count.* = try bounds.addU64(c.count.*, 1);
        }
    }.visit);
    return count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    if (scratch.len < 2048) return error.ResourceException;
    const parsed = try parse(archive, scratch[0 .. scratch.len - 1024]);
    var info: ?EntryInfo = null;
    const Ctx = struct {
        ordinal: u64,
        index: u64 = 0,
        found: *?EntryInfo,
        name_buf: []u8,
    };
    var ctx = Ctx{ .ordinal = ordinal, .found = &info, .name_buf = scratch[scratch.len - 1024 ..] };
    try walk(parsed.metadata, &ctx, recordOrdinal);
    if (info) |*result| {
        result.size = (try blobLookup(parsed.blobs, result.hash)).size;
        return result.*;
    }
    return error.DataException;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    if (scratch.len < 2048) return error.ResourceException;
    const name_buf = scratch[scratch.len - 1024 ..];
    const parsed = try parse(archive, scratch[0 .. scratch.len - 1024]);
    var info: ?EntryInfo = null;
    const Ctx = struct {
        ordinal: u64,
        index: u64 = 0,
        found: *?EntryInfo,
        name_buf: []u8,
    };
    var ctx = Ctx{ .ordinal = ordinal, .found = &info, .name_buf = name_buf };
    try walk(parsed.metadata, &ctx, recordOrdinal);
    const found = info orelse return error.DataException;
    const blob = try blobLookup(parsed.blobs, found.hash);
    const size = std.math.cast(usize, blob.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;
    if (blob.solid) {
        const sr = parsed.solid_reses[@intCast(blob.solid_index)];
        try readSolidRange(archive, sr, blob.solid_offset, output[0..size], parsed.temp);
    } else {
        const codec = try headerCodec(archive);
        const chunk_size = std.mem.readInt(u32, archive[20..24], .little);
        try readResource(archive, blob.res, chunk_size, codec, output[0..size]);
    }
    return size;
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

test "wim header part and image count offsets" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a", .data = "b" }};
    var archive: [8192]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    // Vendor layout: part number u16 @0x28, total parts u16 @0x2A, image count u32 @0x2C.
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, archive[40..42], .little));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, archive[42..44], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, archive[44..48], .little));
    // The image count lives at 0x2C, not in the part-number slot.
    std.mem.writeInt(u32, archive[44..48], 0, .little);
    try testing.expectError(error.DataException, inspectCount(archive[0..written], &scratch));
    std.mem.writeInt(u32, archive[44..48], 1, .little);
    // Split identity: a foreign part number drops every blob and the image.
    std.mem.writeInt(u16, archive[40..42], 2, .little);
    try testing.expectError(error.DataException, inspectCount(archive[0..written], &scratch));
}

test "wim parse with unaligned workspace scratch" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello world" },
        .{ .name = "nested.bin", .data = "payload" },
    };
    var archive: [8192]u8 = undefined;
    var enc_scratch: [8192]u8 = undefined;
    const written = try encode(&entries, &archive, &enc_scratch);
    // The compose workspace hands out scratch at arbitrary byte offsets.
    var raw: [8192 + 8]u8 = undefined;
    const off: usize = if (@intFromPtr(&raw) & 1 == 0) 1 else 2;
    const scratch: []u8 = raw[off..][0..8192];
    try testing.expect(@intFromPtr(scratch.ptr) & 7 != 0);
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], scratch));
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, scratch);
    try testing.expectEqualSlices(u8, "payload", out[0..n]);
}

test "wim chunk entry sizing and table iteration" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u32, buf[0..4], 16, .little);
    std.mem.writeInt(u32, buf[4..8], 24, .little);
    const res = try ChunkedResource.init(buf[0..40], 0, 40, 48, 16, false);
    try testing.expectEqual(@as(u64, 3), res.num_chunks);
    try testing.expectEqual(@as(u64, 2), res.entries);
    try testing.expectEqual(@as(u64, 4), res.entry_size);
    try testing.expectEqual(@as(u64, 8), res.data_off);
    try testing.expectEqual(@as(u64, 32), res.area_len);
    var it = ChunkIter{ .res = &res };
    const loc0 = (try it.next()).?;
    try testing.expectEqual(@as(u64, 0), loc0.start);
    try testing.expectEqual(@as(u64, 16), loc0.csize);
    const loc1 = (try it.next()).?;
    try testing.expectEqual(@as(u64, 16), loc1.start);
    try testing.expectEqual(@as(u64, 8), loc1.csize);
    const loc2 = (try it.next()).?;
    try testing.expectEqual(@as(u64, 32), loc2.start);
    try testing.expectEqual(@as(u64, 8), loc2.csize);
    try testing.expectEqual(@as(?ChunkLoc, null), try it.next());
    // u64 entries once the uncompressed size exceeds 32 bits; solid
    // tables always use u32 entries and list every chunk.
    const big = try ChunkedResource.init(&.{}, 0, 0x1000_0000, 0x1_0000_1000, 0x1000, false);
    try testing.expectEqual(@as(u64, 8), big.entry_size);
    try testing.expectEqual(@as(u64, 0x100001), big.num_chunks);
    const solid_big = try ChunkedResource.init(&.{}, 0, 0x1000_0000, 0x1_0000_1000, 0x1000, true);
    try testing.expectEqual(@as(u64, 4), solid_big.entry_size);
    try testing.expectEqual(@as(u64, 0x100001), solid_big.num_chunks);
    try testing.expectError(error.DataException, ChunkedResource.init(&.{}, 0, 4, 48, 16, false));
    try testing.expectError(error.DataException, ChunkedResource.init(&.{}, 0, 16, 0, 16, false));
}

test "wim solid chunk table iteration" {
    const testing = std.testing;
    var buf: [52]u8 = undefined;
    @memset(&buf, 0);
    std.mem.writeInt(u64, buf[0..8], 24, .little);
    std.mem.writeInt(u32, buf[8..12], 8, .little);
    std.mem.writeInt(u32, buf[12..16], 1, .little);
    std.mem.writeInt(u32, buf[16..20], 8, .little);
    std.mem.writeInt(u32, buf[20..24], 8, .little);
    std.mem.writeInt(u32, buf[24..28], 99, .little); // last entry is ignored.
    const res = try ChunkedResource.init(buf[0..52], 0, 52, 24, 8, true);
    try testing.expectEqual(@as(u64, 3), res.num_chunks);
    try testing.expectEqual(@as(u64, 4), res.entry_size);
    try testing.expectEqual(@as(u64, 28), res.data_off);
    try testing.expectEqual(@as(u64, 24), res.area_len);
    var it = ChunkIter{ .res = &res };
    const offsets = [_]u64{ 28, 36, 44 };
    const csizes = [_]u64{ 8, 8, 8 };
    for (offsets, csizes) |want_off, want_csize| {
        const loc = (try it.next()).?;
        try testing.expectEqual(want_off, loc.offset);
        try testing.expectEqual(want_csize, loc.csize);
    }
    try testing.expectEqual(@as(?ChunkLoc, null), try it.next());
}

test "wim raw chunk read resource" {
    const testing = std.testing;
    var buf: [36]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(0x40 + i);
    std.mem.writeInt(u32, buf[0..4], 16, .little);
    const res = Reshdr{ .size_in_wim = 36, .flags = reshdr_flag_compressed, .offset = 0, .uncompressed_size = 32 };
    var out: [32]u8 = undefined;
    try readResource(&buf, res, 16, .lzx, &out);
    try testing.expectEqualSlices(u8, buf[4..36], &out);
}

test "wim solid range read spans raw chunks" {
    const testing = std.testing;
    var buf: [52]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(0x30 + i);
    std.mem.writeInt(u64, buf[0..8], 24, .little);
    std.mem.writeInt(u32, buf[8..12], 8, .little);
    std.mem.writeInt(u32, buf[12..16], 1, .little);
    std.mem.writeInt(u32, buf[16..20], 8, .little);
    std.mem.writeInt(u32, buf[20..24], 8, .little);
    const sr = SolidRes{ .offset = 0, .size_in_wim = 52, .uncompressed_size = 24, .chunk_size = 8, .codec = .xpress };
    var out: [8]u8 = undefined;
    var temp: [16]u8 = undefined;
    try readSolidRange(&buf, sr, 4, &out, &temp);
    try testing.expectEqualSlices(u8, buf[32..40], &out);
}

test "wim solid member placement" {
    const testing = std.testing;
    const run = [_]SolidRes{
        .{ .offset = 0, .size_in_wim = 0, .uncompressed_size = 10, .chunk_size = 8, .codec = .xpress },
        .{ .offset = 0, .size_in_wim = 0, .uncompressed_size = 10, .chunk_size = 8, .codec = .xpress },
    };
    const inside = try assignSolid(&run, .{ .size_in_wim = 4, .flags = 0, .offset = 6, .uncompressed_size = 0 });
    try testing.expectEqual(@as(u64, 0), inside.index);
    try testing.expectEqual(@as(u64, 6), inside.offset);
    const next = try assignSolid(&run, .{ .size_in_wim = 4, .flags = 0, .offset = 12, .uncompressed_size = 0 });
    try testing.expectEqual(@as(u64, 1), next.index);
    try testing.expectEqual(@as(u64, 2), next.offset);
    try testing.expectError(error.DataException, assignSolid(&run, .{ .size_in_wim = 8, .flags = 0, .offset = 6, .uncompressed_size = 0 }));
    try testing.expectError(error.DataException, assignSolid(&run, .{ .size_in_wim = 4, .flags = 0, .offset = 22, .uncompressed_size = 0 }));
}

// Comptime hex decode for embedded vendor fixture bytes (test-only). Zig 0.17
// multiline literals append a newline between consecutive \\ lines, so any
// non-hex character (the line separators) is skipped here.
fn hexNibble(comptime c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        else => @compileError("bad hex digit"),
    };
}

fn hexCount(comptime s: []const u8) usize {
    comptime {
        @setEvalBranchQuota(4 * s.len + 1000);
        var n: usize = 0;
        for (s) |c| {
            switch (c) {
                '0'...'9', 'a'...'f' => n += 1,
                else => {},
            }
        }
        return n;
    }
}

fn unhex(comptime s: []const u8) [hexCount(s) / 2]u8 {
    return comptime blk: {
        @setEvalBranchQuota(8 * s.len + 1000);
        var out: [hexCount(s) / 2]u8 = undefined;
        var at: usize = 0;
        var hi: ?u8 = null;
        for (s) |c| {
            switch (c) {
                '0'...'9', 'a'...'f' => {
                    const v = hexNibble(c);
                    if (hi) |h| {
                        out[at] = h * 16 + v;
                        at += 1;
                        hi = null;
                    } else {
                        hi = v;
                    }
                },
                else => {},
            }
        }
        break :blk out;
    };
}

test "wim vendor solid and chunked fixtures" {
    const testing = std.testing;
    // Captured with wimlib-imagex 1.14 (vendor) from a directory holding
    // big.txt (35000 bytes of a repeating sentence, spanning two chunks) and
    // small.txt (b"hello"). solid.wim was captured with --solid
    // --solid-compress=LZX --solid-chunk-size=32768; chunked.wim with
    // --compress=LZX --chunk-size=32768. Both decode byte-exact against
    // wimlib-imagex extract.
    const solid_wim = unhex(
        \\4d5357494d000000d0000000000e0000820008000000020014ec30fb1f12a5514cd7c2968e3cebdf0100010001000000
        \\c8000000000000023802000000000000c800000000000000fe020000000000020003000000000000fe02000000000000
        \\000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        \\000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        \\00000000000000000000000000000000bd880000000000000080000002000000780000005c0000000030000002000434
        \\32009f356364612c34c1d938fbb160f500000000600006001142c8f7becf00f00000000000008000f187ffbf16f8495b
        \\5e76fb7a2f9d9fae7aa73debf76512fed2b98df99fb4ef39edb41c5f9ca5557d55555555555555555555555555555555
        \\555555555555555555555555555500408b2000d00000000034144300cd4a58e93cba3284611a5f9fd5df008000000100
        \\18800801df473e23c0fb00000000000004000f42fcbfe2fb1652f7ccc0a833f89ba60f70314db0cb3e8b5ef4a871ec56
        \\a6374b57aaffaaaa3baa1044db780738fa78318a9bf8be5a4a2fa0a2c0c200000010bb6b55cd0610661534072031360d
        \\a5ba66b320ed3c78fb6a8ba217737718d3ab129f96d15974002e006700690062000ea3da9c13c96fecc5b6266a5f8660
        \\4ce3f72d18f0dc37b5d41706d0966d4b78d4006340f7d7fdce5c3e600a8067fd5b10da8e96d100087c00000000000006
        \\bc010000000000007801000000000000010001000000ea025f42c5b123cd138b16300a4e0fe8345f1b5dec0000000000
        \\0010d00000000000000000000000010000000100010000000000000000000000000000000000000000000000b8880000
        \\000000100000000000000000000000000000000001000100000073c060b7df8d3182197da89adb17b1bf244e736a0500
        \\000000000010b8880000000000000000000000000000010001000000aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        \\fffe3c00570049004d003e003c0049004d00410047004500200049004e004400450058003d002200310022003e003c00
        \\4e0041004d0045003e007300720063003c002f004e0041004d0045003e003c0044004900520043004f0055004e005400
        \\3e0031003c002f0044004900520043004f0055004e0054003e003c00460049004c00450043004f0055004e0054003e00
        \\32003c002f00460049004c00450043004f0055004e0054003e003c0054004f00540041004c0042005900540045005300
        \\3e00330035003000300035003c002f0054004f00540041004c00420059005400450053003e003c004800410052004400
        \\4c0049004e004b00420059005400450053003e0030003c002f0048004100520044004c0049004e004b00420059005400
        \\450053003e003c004300520045004100540049004f004e00540049004d0045003e003c00480049004700480050004100
        \\520054003e0030007800300031004400440035004600460037003c002f00480049004700480050004100520054003e00
        \\3c004c004f00570050004100520054003e0030007800370037003400430035003900380045003c002f004c004f005700
        \\50004100520054003e003c002f004300520045004100540049004f004e00540049004d0045003e003c004c0041005300
        \\54004d004f00440049004600490043004100540049004f004e00540049004d0045003e003c0048004900470048005000
        \\4100520054003e0030007800300031004400440035004600460037003c002f0048004900470048005000410052005400
        \\3e003c004c004f00570050004100520054003e0030007800370037003400430035004600420041003c002f004c004f00
        \\570050004100520054003e003c002f004c004100530054004d004f00440049004600490043004100540049004f004e00
        \\540049004d0045003e003c002f0049004d004100470045003e003c0054004f00540041004c0042005900540045005300
        \\3e003700360038003c002f0054004f00540041004c00420059005400450053003e003c002f00570049004d003e00
    );
    const chunked_wim = unhex(
        \\4d5357494d000000d0000000000d01008200040000800000a7b4b1c7916d11a57523503e259b27800100010001000000
        \\960000000000000255020000000000009600000000000000fe02000000000002eb02000000000000fe02000000000000
        \\000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        \\000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
        \\0000000000000000000000000000000078000000003000000200043432009f356364612c34c1d938fbb160f500000000
        \\600006001142c8f7becf00f00000000000008000f187ffbf16f8495b5e76fb7a2f9d9fae7aa73debf76512fed2b98df9
        \\9fb4ef39edb41c5f9ca5557d55555555555555555555555555555555555555555555555555555555555500408b200080
        \\00000000552242009f3928e9189d203a5d7bf75b80e5000000001800011847088bdf9f03e07d00000000000002000721
        \\fedff17d8d25935c70fc1e94e647243ce194940ed23d1bd539a7ee0c1e1b5ef6663e6666006468656c6c6f1720008300
        \\00020005252000914f81100c88886dcc884a6c40c6164083704886ed7c0d884c9cc650aec2d9d989851658abee3b2398
        \\b3005200000000002332000401f130b7682bf8fc7e00600000000002002220d2082303ff5bfeffc5b82d5e53b37f4579
        \\0190f3b9c98ac358c023de90ee462a2fbafd1fb4df49fdf407ce2c44be53f4ec208e3c68e3933ac2aa92d2aab9e406e6
        \\45ca220d67aa8efe9e33250f82a8631b34b07f00c2aa00000000000006ab010000000000007801000000000000010001
        \\000000668a52f78fcd547cdb53f119c1197db5556ba828d600000000000004d000000000000000b88800000000000001
        \\000100000073c060b7df8d3182197da89adb17b1bf244e736a0500000000000000a60100000000000005000000000000
        \\00010001000000aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434dfffe3c00570049004d003e003c0049004d00410047
        \\004500200049004e004400450058003d002200310022003e003c004e0041004d0045003e007300720063003c002f004e
        \\0041004d0045003e003c0044004900520043004f0055004e0054003e0031003c002f0044004900520043004f0055004e
        \\0054003e003c00460049004c00450043004f0055004e0054003e0032003c002f00460049004c00450043004f0055004e
        \\0054003e003c0054004f00540041004c00420059005400450053003e00330035003000300035003c002f0054004f0054
        \\0041004c00420059005400450053003e003c0048004100520044004c0049004e004b00420059005400450053003e0030
        \\003c002f0048004100520044004c0049004e004b00420059005400450053003e003c004300520045004100540049004f
        \\004e00540049004d0045003e003c00480049004700480050004100520054003e00300078003000310044004400350046
        \\00460037003c002f00480049004700480050004100520054003e003c004c004f00570050004100520054003e00300078
        \\00330042004100380043003700420034003c002f004c004f00570050004100520054003e003c002f0043005200450041
        \\00540049004f004e00540049004d0045003e003c004c004100530054004d004f00440049004600490043004100540049
        \\004f004e00540049004d0045003e003c00480049004700480050004100520054003e0030007800300031004400440035
        \\004600460037003c002f00480049004700480050004100520054003e003c004c004f00570050004100520054003e0030
        \\007800330042004100380043003900450045003c002f004c004f00570050004100520054003e003c002f004c00410053
        \\0054004d004f00440049004600490043004100540049004f004e00540049004d0045003e003c002f0049004d00410047
        \\0045003e003c0054004f00540041004c00420059005400450053003e003700340037003c002f0054004f00540041004c
        \\00420059005400450053003e003c002f00570049004d003e00
    );
    const sentence = "The quick brown fox jumps over the lazy dog. ";
    var big: [35000]u8 = undefined;
    var filled: usize = 0;
    while (filled < big.len) {
        const n = @min(sentence.len, big.len - filled);
        @memcpy(big[filled..][0..n], sentence[0..n]);
        filled += n;
    }
    var scratch: [scratch_size]u8 = undefined;

    for ([2][]const u8{ &solid_wim, &chunked_wim }) |archive| {
        try testing.expectEqual(@as(u64, 2), try inspectCount(archive, &scratch));
        const zeroth = try inspectOrdinal(archive, 0, &scratch);
        try testing.expectEqualStrings("big.txt", zeroth.name);
        try testing.expectEqual(@as(u64, 35000), zeroth.size);
        const first = try inspectOrdinal(archive, 1, &scratch);
        try testing.expectEqualStrings("small.txt", first.name);
        try testing.expectEqual(@as(u64, 5), first.size);
        var out: [35000]u8 = undefined;
        const n = try decodeOrdinal(archive, 0, &out, &scratch);
        try testing.expectEqual(@as(usize, 35000), n);
        try testing.expectEqualSlices(u8, &big, out[0..n]);
        var small: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 5), try decodeOrdinal(archive, 1, &small, &scratch));
        try testing.expectEqualSlices(u8, "hello", small[0..5]);
    }
}
