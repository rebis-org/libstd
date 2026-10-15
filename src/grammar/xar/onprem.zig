const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const failure_prim = @import("../../common/primitive/failure.zig");
const io = @import("../../common/primitive/io.zig");

const Failure = failure_prim.Failure;

// XAR: big-endian header, zlib-compressed XML TOC, heap at TOC-declared offsets.

// The writer uses stored-block zlib for the TOC.
// Analytic TOC sizing keeps the profile metadata_exact.

// References: vendor/xar/xar.txt and libarchive's xar reader.

pub const scratch_size: usize = 1 << 20;

const header_size = 28;
const cksum_sha1 = 1;
const sha1_len = 20;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
    mode: u32 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    modification_time: u64 = 0,
};

pub const EntryInfo = struct {
    name: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modification_time: u64,
    data_offset: u64,
    data_length: u64,
    stored: bool,
    ordinal: u64,
};

fn validateEntry(entry: Entry) Failure!void {
    if (entry.name.len == 0 or std.mem.findScalar(u8, entry.name, 0) != null) return error.CallFailure;
    if (bounds.isAbsoluteOrTraversal(entry.name)) return error.CallFailure;
    for (entry.name) |byte| {
        if (byte < 0x20 or byte == '<' or byte == '>' or byte == '&' or byte == '"' or byte == '\'') return error.UnsupportedFailure;
    }
}

const xml_prolog = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n <toc>\n  <checksum style=\"sha1\">\n   <offset>0</offset>\n   <size>20</size>\n  </checksum>\n";
const xml_epilog = " </toc>\n</xar>\n";

// CountSink measures what writeTocXml would emit without storing it.
const CountSink = struct {
    offset: u64 = 0,

    fn write(self: *CountSink, bytes: []const u8) !void {
        self.offset = try bounds.addU64(self.offset, bytes.len);
    }
};

fn writeNum(sink: anytype, comptime fmt: []const u8, value: anytype) Failure!void {
    var buf: [24]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, .{value}) catch return error.CapacityFailure;
    sink.write(text) catch return error.CapacityFailure;
}

fn writeTocXml(sink: anytype, entries: []const Entry) Failure!void {
    sink.write(xml_prolog) catch return error.CapacityFailure;
    // Offsets are heap-relative; the heap opens with the TOC digest.
    // File data starts past it; libarchive seeks from the digest.
    var offset: u64 = sha1_len;
    for (entries, 0..) |entry, index| {
        try validateEntry(entry);
        var digest_buf: [sha1_len * 2]u8 = undefined;
        sha1Hex(&digest_buf, entry.data);
        try sink.write("    <file id=\"");
        try writeNum(sink, "{d}", index + 1);
        try sink.write("\">\n      <name>");
        try sink.write(entry.name);
        try sink.write("</name>\n      <type>file</type>\n      <mode>");
        try writeNum(sink, "{o}", entry.mode);
        try sink.write("</mode>\n      <uid>");
        try writeNum(sink, "{d}", entry.uid);
        try sink.write("</uid>\n      <gid>");
        try writeNum(sink, "{d}", entry.gid);
        try sink.write("</gid>\n      <mtime>");
        try writeNum(sink, "{d}", entry.modification_time);
        try sink.write("</mtime>\n      <data>\n        <encoding style=\"application/octet-stream\"/>\n        <offset>");
        try writeNum(sink, "{d}", offset);
        try sink.write("</offset>\n        <length>");
        try writeNum(sink, "{d}", entry.data.len);
        try sink.write("</length>\n        <size>");
        try writeNum(sink, "{d}", entry.data.len);
        try sink.write("</size>\n        <archived-checksum method=\"sha1\">");
        try sink.write(&digest_buf);
        try sink.write("</archived-checksum>\n        <extracted-checksum method=\"sha1\">");
        try sink.write(&digest_buf);
        try sink.write("</extracted-checksum>\n      </data>\n    </file>\n");
        offset = try bounds.addU64(offset, entry.data.len);
    }
    sink.write(xml_epilog) catch return error.CapacityFailure;
}

fn zlibStoredLen(src_len: u64) Failure!u64 {
    const blocks = src_len / 65535 + 1;
    return bounds.addU64(6 + src_len + 5 * blocks, 0);
}

fn tocLayout(entries: []const Entry) Failure!struct { xml_len: u64, toc_len: u64, heap_start: u64 } {
    // TOC length depends on heap start, and heap start on TOC length.
    // Iterate until both stop moving; digit growth converges.
    var toc_len: u64 = 256;
    var iter: usize = 0;
    while (iter < 16) : (iter += 1) {
        var counter = CountSink{};
        try writeTocXml(&counter, entries);
        const new_toc = try zlibStoredLen(counter.offset);
        if (new_toc == toc_len) break;
        toc_len = new_toc;
    }
    var counter = CountSink{};
    try writeTocXml(&counter, entries);
    return .{
        .xml_len = counter.offset,
        .toc_len = toc_len,
        .heap_start = try bounds.addU64(header_size, toc_len),
    };
}

pub fn archiveSize(entries: []const Entry) Failure!u64 {
    const layout = try tocLayout(entries);
    var total = try bounds.addU64(layout.heap_start, sha1_len);
    for (entries) |entry| total = try bounds.addU64(total, entry.data.len);
    return total;
}

// Stored-block zlib over one slice; the size is deterministic.
fn writeZlibStored(sink: *io.Sink, src: []const u8, adler: u32) Failure!void {
    sink.write(&[_]u8{ 0x78, 0x01 }) catch return error.CapacityFailure;
    var pos: usize = 0;
    while (true) {
        const chunk = @min(65535, src.len - pos);
        const last = pos + chunk == src.len;
        sink.write(&[_]u8{if (last) 1 else 0}) catch return error.CapacityFailure;
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u16, len_buf[0..2], @intCast(chunk), .little);
        std.mem.writeInt(u16, len_buf[2..4], ~@as(u16, @intCast(chunk)), .little);
        sink.write(&len_buf) catch return error.CapacityFailure;
        sink.write(src[pos..][0..chunk]) catch return error.CapacityFailure;
        pos += chunk;
        if (last) break;
    }
    var adler_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &adler_buf, adler, .big);
    sink.write(&adler_buf) catch return error.CapacityFailure;
}

fn sha1Hex(out: *[sha1_len * 2]u8, data: []const u8) void {
    var digest: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(data, &digest, .{});
    const digits = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        out[i * 2] = digits[byte >> 4];
        out[i * 2 + 1] = digits[byte & 0xF];
    }
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    if (scratch.len < 4096) return error.CapacityFailure;
    const layout = try tocLayout(entries);
    if (scratch.len < layout.xml_len + 4 + sha1_len) return error.ResourceFailure;

    var toc_sink = io.Sink{ .bytes = scratch };
    try writeTocXml(&toc_sink, entries);
    const xml = scratch[0..toc_sink.offset];

    var sink = io.Sink{ .bytes = output };
    const compressed_len = try zlibStoredLen(xml.len);
    var header: [header_size]u8 = undefined;
    @memcpy(header[0..4], "xar!");
    std.mem.writeInt(u16, header[4..6], header_size, .big);
    // Header version 1: 16-bit version, then 64-bit TOC lengths, matching
    // the libarchive reference layout.
    std.mem.writeInt(u16, header[6..8], 1, .big);
    std.mem.writeInt(u64, header[8..16], compressed_len, .big);
    std.mem.writeInt(u64, header[16..24], xml.len, .big);
    std.mem.writeInt(u32, header[24..28], cksum_sha1, .big);
    sink.write(&header) catch return error.CapacityFailure;
    const toc_start = sink.offset;
    try writeZlibStored(&sink, xml, std.hash.Adler32.hash(xml));
    // The TOC checksum covers the compressed bytes.
    // libarchive hashes what sits on disk between header and digest.
    var digest: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(output[toc_start..sink.offset], &digest, .{});
    sink.write(&digest) catch return error.CapacityFailure;
    for (entries) |entry| {
        sink.write(entry.data) catch return error.CapacityFailure;
    }
    return sink.offset;
}


fn be32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .big);
}

fn be16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .big);
}

const Toc = struct {
    xml: []const u8,
    heap: []const u8,
    heap_start: u64,
};

fn inflateInto(src: []const u8, dst: []u8) Failure!usize {
    const container: std.compress.flate.Container = if (src.len >= 2 and src[0] == 0x1f and src[1] == 0x8b) .gzip else if (src.len >= 1 and src[0] == 0x78) .zlib else .raw;
    var reader = std.Io.Reader.fixed(src);
    var decomp = std.compress.flate.Decompress.init(&reader, container, &.{});
    var sink = std.Io.Writer.fixed(dst);
    const written = decomp.reader.stream(&sink, .unlimited) catch return error.DataFailure;
    return written;
}

fn inflateToc(archive: []const u8, scratch: []u8) Failure!Toc {
    if (archive.len < header_size) return error.DataFailure;
    if (!std.mem.eql(u8, archive[0..4], "xar!")) return error.DataFailure;
    const hlen: u64 = be16(archive, 4);
    if (hlen < 18 or hlen > archive.len) return error.DataFailure;
    var toc_comp: u64 = undefined;
    var toc_uncomp: u64 = undefined;
    var digest_len: u64 = 0;
    const remaining = archive.len - hlen;
    if (be16(archive, 6) == 1 and std.mem.readInt(u64, archive[8..16], .big) <= remaining) {
        // Version 1: 64-bit TOC lengths (the libarchive layout).
        toc_comp = std.mem.readInt(u64, archive[8..16], .big);
        toc_uncomp = std.mem.readInt(u64, archive[16..24], .big);
        digest_len = switch (be32(archive, 24)) {
            0 => 0,
            cksum_sha1 => sha1_len,
            else => return error.UnsupportedFailure,
        };
    } else {
        // Classic layout: 32-bit TOC lengths, digest inside the TOC stream.
        toc_comp = be32(archive, 6);
        toc_uncomp = be32(archive, 10);
    }
    // The TOC digest sits inside the heap.
    // File data offsets are relative to just past the compressed TOC.
    const heap_start = try bounds.addU64(hlen, toc_comp);
    if (heap_start + digest_len > archive.len) return error.DataFailure;
    const toc_bytes = try bounds.slice(archive, hlen, toc_comp);
    const uncomp_len = std.math.cast(usize, toc_uncomp) orelse return error.ResourceFailure;
    if (scratch.len < uncomp_len) return error.ResourceFailure;
    const xml_len = try inflateInto(toc_bytes, scratch[0..uncomp_len]);
    return .{ .xml = scratch[0..xml_len], .heap = archive[@intCast(heap_start)..], .heap_start = heap_start };
}

const XmlCursor = struct {
    data: []const u8,
    pos: usize = 0,
    limit: usize,

    fn find(self: *XmlCursor, needle: []const u8) Failure!usize {
        const at = std.mem.indexOfPos(u8, self.data[0..self.limit], self.pos, needle) orelse return error.DataFailure;
        self.pos = at + needle.len;
        return self.pos;
    }

    fn tagContent(self: *XmlCursor, tag: []const u8) Failure!?[]const u8 {
        var open_buf: [32]u8 = undefined;
        var close_buf: [34]u8 = undefined;
        const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return error.CapacityFailure;
        const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return error.CapacityFailure;
        const at = std.mem.indexOfPos(u8, self.data[0..self.limit], self.pos, open) orelse return null;
        const start = at + open.len;
        const end = std.mem.indexOfPos(u8, self.data[0..self.limit], start, close) orelse return error.DataFailure;
        self.pos = end + close.len;
        return self.data[start..end];
    }

    fn numberAfter(self: *XmlCursor, tag: []const u8) Failure!?u64 {
        const text = (try self.tagContent(tag)) orelse return null;
        return try parseNumber(std.mem.trim(u8, text, " \t\r\n"));
    }
};

fn unescapeXmlInPlace(name: []u8) Failure![]const u8 {
    if (std.mem.indexOfScalar(u8, name, '&') == null) return name;
    var w: usize = 0;
    var r: usize = 0;
    while (r < name.len) {
        if (name[r] == '&') {
            const semi = std.mem.indexOfScalarPos(u8, name, r, ';') orelse return error.DataFailure;
            const entity = name[r + 1 .. semi];
            const byte: u8 = if (std.mem.eql(u8, entity, "amp")) '&' else if (std.mem.eql(u8, entity, "lt")) '<' else if (std.mem.eql(u8, entity, "gt")) '>' else if (std.mem.eql(u8, entity, "quot")) '"' else if (std.mem.eql(u8, entity, "apos")) '\'' else return error.DataFailure;
            name[w] = byte;
            w += 1;
            r = semi + 1;
        } else {
            name[w] = name[r];
            w += 1;
            r += 1;
        }
    }
    return name[0..w];
}

fn parseNumber(text: []const u8) Failure!u64 {
    if (text.len == 0) return error.DataFailure;
    var value: u64 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.DataFailure;
        value = std.math.mul(u64, value, 10) catch return error.DataFailure;
        value = std.math.add(u64, value, byte - '0') catch return error.DataFailure;
    }
    return value;
}

fn parseMode(text: []const u8) Failure!u32 {
    if (text.len == 0) return error.DataFailure;
    var value: u32 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '7') return error.DataFailure;
        value = std.math.mul(u32, value, 8) catch return error.DataFailure;
        value = std.math.add(u32, value, byte - '0') catch return error.DataFailure;
    }
    return value;
}

const ScanResult = struct {
    count: u64,
    found: ?EntryInfo,
};

fn scanEntries(xml: []const u8, want: ?u64, name_buf: ?[]u8) Failure!ScanResult {
    var result = ScanResult{ .count = 0, .found = null };
    var cursor = XmlCursor{ .data = xml, .limit = xml.len };
    const toc_start = cursor.find("<toc>") catch 0;
    cursor.pos = toc_start;
    while (cursor.find("<file") catch null) |_| {
        var info: EntryInfo = undefined;
        info.ordinal = result.count;
        result.count += 1;
        info.mode = 0;
        info.uid = 0;
        info.gid = 0;
        info.modification_time = 0;
        info.data_offset = 0;
        info.data_length = 0;
        info.size = 0;
        info.stored = true;
        const name_raw = (try cursor.tagContent("name")) orelse return error.DataFailure;
        const type_text = (try cursor.tagContent("type")) orelse "file";
        if (try cursor.numberAfter("mode")) |mode_value| {
            info.mode = @intCast(mode_value);
        }
        if (try cursor.numberAfter("uid")) |uid_value| {
            info.uid = @intCast(uid_value);
        }
        if (try cursor.numberAfter("gid")) |gid_value| {
            info.gid = @intCast(gid_value);
        }
        if (try cursor.numberAfter("mtime")) |mtime_value| {
            info.modification_time = mtime_value;
        }
        if (std.mem.eql(u8, std.mem.trim(u8, type_text, " \t\r\n"), "file")) {
            _ = try cursor.find("<data>");
            const data_start = cursor.pos;
            const style_start = std.mem.indexOfPos(u8, xml, data_start, "style=\"") orelse xml.len;
            var style: []const u8 = "application/octet-stream";
            if (style_start != xml.len) {
                const q = style_start + 7;
                const qend = std.mem.indexOfScalarPos(u8, xml, q, '"') orelse return error.DataFailure;
                style = xml[q..qend];
            }
            // Field order inside <data> is not fixed by the spec; anchor the
            // searches at the data element start.
            cursor.pos = data_start;
            info.data_offset = (try cursor.numberAfter("offset")) orelse return error.DataFailure;
            cursor.pos = data_start;
            info.data_length = (try cursor.numberAfter("length")) orelse return error.DataFailure;
            cursor.pos = data_start;
            info.size = (try cursor.numberAfter("size")) orelse return error.DataFailure;
            info.stored = std.mem.eql(u8, style, "application/octet-stream");
        }
        if (want != null and want.? == info.ordinal) {
            if (name_buf) |buf| {
                if (buf.len < name_raw.len) return error.CapacityFailure;
                @memcpy(buf[0..name_raw.len], name_raw);
                info.name = try unescapeXmlInPlace(buf[0..name_raw.len]);
            } else {
                info.name = name_raw;
            }
            result.found = info;
            return result;
        }
        _ = try cursor.find("</file>");
    }
    return result;
}

fn splitScratch(scratch: []u8) Failure!struct { toc: []u8, name: []u8 } {
    if (scratch.len < 4096 + 512) return error.ResourceFailure;
    return .{ .toc = scratch[0 .. scratch.len - 512], .name = scratch[scratch.len - 512 ..] };
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Failure!u64 {
    const parts = try splitScratch(scratch);
    const toc = try inflateToc(archive, parts.toc);
    const result = try scanEntries(toc.xml, null, null);
    return result.count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Failure!EntryInfo {
    const parts = try splitScratch(scratch);
    const toc = try inflateToc(archive, parts.toc);
    const result = try scanEntries(toc.xml, ordinal, parts.name);
    if (result.found) |info| return info;
    return error.DataFailure;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Failure!usize {
    const parts = try splitScratch(scratch);
    const toc = try inflateToc(archive, parts.toc);
    const result = try scanEntries(toc.xml, ordinal, null);
    const info = result.found orelse return error.DataFailure;
    const size = std.math.cast(usize, info.size) orelse return error.ResourceFailure;
    if (output.len < size) return error.CapacityFailure;
    const payload = try bounds.slice(toc.heap, info.data_offset, info.data_length);
    if (info.stored) {
        if (payload.len != size) return error.DataFailure;
        @memcpy(output[0..size], payload);
        return size;
    }
    return inflateInto(payload, output[0..size]);
}

test "xar roundtrips entries through the envelope layout" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello world", .uid = 7, .modification_time = 123456789 },
        .{ .name = "dir/nested.bin", .data = "payload", .mode = 0o755 },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [16384]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqualSlices(u8, "xar!", archive[0..4]);
    const count = try inspectCount(archive[0..written], &scratch);
    try testing.expectEqual(@as(u64, 2), count);
    const first = try inspectOrdinal(archive[0..written], 0, &scratch);
    try testing.expectEqualSlices(u8, "hello.txt", first.name);
    try testing.expectEqual(@as(u64, 11), first.size);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "payload", out[0..n]);
}
