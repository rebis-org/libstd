const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");

const Exception = exception_prim.Exception;

// XAR: big-endian header, zlib-compressed XML TOC, heap at TOC-declared
// offsets. The TOC digest (sha1 over the compressed TOC bytes) is verified
// on every read; times travel as ISO 8601 like the vendor writes them.

// References: vendor/xar/xar.txt, the vendor library under vendor/xar/xar/lib,
// and libarchive's xar reader and writer.

pub const scratch_size: usize = 1 << 20;

const header_size = 28;
const cksum_sha1 = 1;
const sha1_len = 20;

// Last epoch second representable in the 20-character ISO 8601 form
// (9999-12-31T23:59:59Z).
const epoch_max_iso = 253402300799;

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

fn validateEntry(entry: Entry) Exception!void {
    if (entry.name.len == 0 or std.mem.findScalar(u8, entry.name, 0) != null) return error.CallException;
    if (bounds.isAbsoluteOrTraversal(entry.name)) return error.CallException;
    for (entry.name) |byte| {
        if (byte < 0x20 or byte == '<' or byte == '>' or byte == '&' or byte == '"' or byte == '\'') return error.UnsupportedException;
    }
}

const xml_prolog = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n <toc>\n  <checksum style=\"sha1\">\n   <offset>0</offset>\n   <size>20</size>\n  </checksum>\n";
const xml_epilog = " </toc>\n</xar>\n";

const CountSink = struct {
    offset: u64 = 0,

    fn write(self: *CountSink, bytes: []const u8) !void {
        self.offset = try bounds.addU64(self.offset, bytes.len);
    }
};

fn writeNum(sink: anytype, comptime fmt: []const u8, value: anytype) Exception!void {
    var buf: [24]u8 = undefined;
    const text = std.mem.print(&buf, fmt, .{value}) catch return error.CapacityException;
    sink.write(text) catch return error.CapacityException;
}

// xar times are ISO 8601 with a Z suffix; vendor writes strftime("%FT%TZ")
// and libarchive's reader requires exactly that 20-character shape.
fn writeTimeIso(sink: anytype, epoch: u64) Exception!void {
    if (epoch > epoch_max_iso) return error.UnsupportedException;
    const days: i64 = @intCast(epoch / 86400);
    const secs = epoch % 86400;
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const day = doy - @divFloor(153 * mp + 2, 5) + 1;
    const month = if (mp < 10) mp + 3 else mp - 9;
    const year = if (month <= 2) y + 1 else y;
    var buf: [20]u8 = undefined;
    const text = std.mem.print(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u64, @intCast(year)), @as(u64, @intCast(month)), @as(u64, @intCast(day)),
        secs / 3600,              (secs / 60) % 60,          secs % 60,
    }) catch return error.CapacityException;
    sink.write(text) catch return error.CapacityException;
}

fn writeTocXml(sink: anytype, entries: []const Entry) Exception!void {
    sink.write(xml_prolog) catch return error.CapacityException;
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
        try writeTimeIso(sink, entry.modification_time);
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
    sink.write(xml_epilog) catch return error.CapacityException;
}

fn zlibStoredLen(src_len: u64) Exception!u64 {
    const blocks = src_len / 65535 + 1;
    return bounds.addU64(6 + src_len + 5 * blocks, 0);
}

fn tocLayout(entries: []const Entry) Exception!struct { xml_len: u64, toc_len: u64, heap_start: u64 } {
    var counter = CountSink{};
    try writeTocXml(&counter, entries);
    const toc_len = try zlibStoredLen(counter.offset);
    return .{
        .xml_len = counter.offset,
        .toc_len = toc_len,
        .heap_start = try bounds.addU64(header_size, toc_len),
    };
}

pub fn archiveSize(entries: []const Entry) Exception!u64 {
    const layout = try tocLayout(entries);
    var total = try bounds.addU64(layout.heap_start, sha1_len);
    for (entries) |entry| total = try bounds.addU64(total, entry.data.len);
    return total;
}

fn writeZlibStored(sink: *io.Sink, src: []const u8, adler: u32) Exception!void {
    sink.write(&[_]u8{ 0x78, 0x01 }) catch return error.CapacityException;
    var pos: usize = 0;
    while (true) {
        const chunk = @min(65535, src.len - pos);
        const last = pos + chunk == src.len;
        sink.write(&[_]u8{if (last) 1 else 0}) catch return error.CapacityException;
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u16, len_buf[0..2], @intCast(chunk), .little);
        std.mem.writeInt(u16, len_buf[2..4], ~@as(u16, @intCast(chunk)), .little);
        sink.write(&len_buf) catch return error.CapacityException;
        sink.write(src[pos..][0..chunk]) catch return error.CapacityException;
        pos += chunk;
        if (last) break;
    }
    var adler_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &adler_buf, adler, .big);
    sink.write(&adler_buf) catch return error.CapacityException;
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

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    if (scratch.len < 4096) return error.CapacityException;
    const layout = try tocLayout(entries);
    if (scratch.len < layout.xml_len + 4 + sha1_len) return error.ResourceException;

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
    sink.write(&header) catch return error.CapacityException;
    const toc_start = sink.offset;
    try writeZlibStored(&sink, xml, std.hash.Adler32.hash(xml));
    // The TOC checksum covers the compressed bytes.
    // libarchive hashes what sits on disk between header and digest.
    var digest: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(output[toc_start..sink.offset], &digest, .{});
    sink.write(&digest) catch return error.CapacityException;
    for (entries) |entry| {
        sink.write(entry.data) catch return error.CapacityException;
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
    alg: u32,
};

fn inflateInto(src: []const u8, dst: []u8) Exception!usize {
    const container: std.compress.flate.Container = if (src.len >= 2 and src[0] == 0x1f and src[1] == 0x8b) .gzip else if (src.len >= 1 and src[0] == 0x78) .zlib else .raw;
    var reader = std.Io.Reader.fixed(src);
    var decomp = std.compress.flate.Decompress.init(&reader, container, &.{});
    var sink = std.Io.Writer.fixed(dst);
    const written = decomp.reader.stream(&sink, .unlimited) catch return error.DataException;
    return written;
}

fn inflateToc(archive: []const u8, scratch: []u8) Exception!Toc {
    if (archive.len < header_size) return error.DataException;
    if (!std.mem.eql(u8, archive[0..4], "xar!")) return error.DataException;
    const hlen: u64 = be16(archive, 4);
    if (hlen < header_size or hlen > archive.len) return error.DataException;
    // Header version 1 is the only version; neither reference reader
    // accepts another, and no 32-bit "classic" variant exists.
    if (be16(archive, 6) != 1) return error.UnsupportedException;
    const toc_comp = std.mem.readInt(u64, archive[8..16], .big);
    const toc_uncomp = std.mem.readInt(u64, archive[16..24], .big);
    const alg = be32(archive, 24);
    switch (alg) {
        0, cksum_sha1 => {},
        else => return error.UnsupportedException,
    }
    // The TOC digest sits inside the heap.
    // File data offsets are relative to just past the compressed TOC.
    if (toc_comp > std.math.maxInt(u64) - hlen) return error.DataException;
    const heap_start = hlen + toc_comp;
    if (heap_start > archive.len) return error.DataException;
    const toc_bytes = try bounds.slice(archive, hlen, toc_comp);
    const uncomp_len = std.math.cast(usize, toc_uncomp) orelse return error.ResourceException;
    if (scratch.len < uncomp_len) return error.ResourceException;
    const xml_len = try inflateInto(toc_bytes, scratch[0..uncomp_len]);
    if (xml_len != uncomp_len) return error.DataException;
    const toc = Toc{
        .xml = scratch[0..xml_len],
        .heap = archive[@intCast(heap_start)..],
        .alg = alg,
    };
    try verifyToc(&toc, toc_bytes);
    return toc;
}

fn verifyToc(toc: *const Toc, toc_bytes: []const u8) Exception!void {
    var cursor = XmlCursor{ .data = toc.xml, .limit = toc.xml.len };
    const tag_start = cursor.find("<checksum") catch {
        // No checksum element: valid only when the header says none.
        if (toc.alg == 0) return;
        return error.DataException;
    };
    const tag_end = std.mem.findScalarPos(u8, toc.xml, tag_start, '>') orelse return error.DataException;
    const tag = toc.xml[tag_start..tag_end];
    var style: []const u8 = "none";
    if (std.mem.findPos(u8, tag, 0, "style=\"")) |at| {
        const q = at + 7;
        const qend = std.mem.findScalarPos(u8, tag, q, '"') orelse return error.DataException;
        style = tag[q..qend];
    }
    // The header algorithm and the declared style must agree, or the digest
    // cannot be trusted (vendor rdar://problem/6134714).
    if (toc.alg == 0) {
        if (!std.mem.eql(u8, style, "none")) return error.DataException;
        return;
    }
    if (!std.mem.eql(u8, style, "sha1")) return error.DataException;
    const close_at = std.mem.findPos(u8, toc.xml, tag_end, "</checksum>") orelse return error.DataException;
    cursor.pos = tag_end + 1;
    cursor.limit = close_at;
    const offset = (try cursor.numberAfter("offset")) orelse 0;
    cursor.pos = tag_end + 1;
    const size = (try cursor.numberAfter("size")) orelse 0;
    if (size != sha1_len) return error.DataException;
    const stored = try bounds.slice(toc.heap, offset, sha1_len);
    var digest: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(toc_bytes, &digest, .{});
    if (!std.mem.eql(u8, stored, &digest)) return error.DataException;
}

const XmlCursor = struct {
    data: []const u8,
    pos: usize = 0,
    limit: usize,

    fn find(self: *XmlCursor, needle: []const u8) Exception!usize {
        const at = std.mem.findPos(u8, self.data[0..self.limit], self.pos, needle) orelse return error.DataException;
        self.pos = at + needle.len;
        return self.pos;
    }

    fn tagContent(self: *XmlCursor, tag: []const u8) Exception!?[]const u8 {
        var open_buf: [32]u8 = undefined;
        var close_buf: [34]u8 = undefined;
        const open = std.mem.print(&open_buf, "<{s}>", .{tag}) catch return error.CapacityException;
        const close = std.mem.print(&close_buf, "</{s}>", .{tag}) catch return error.CapacityException;
        const at = std.mem.findPos(u8, self.data[0..self.limit], self.pos, open) orelse return null;
        const start = at + open.len;
        const end = std.mem.findPos(u8, self.data[0..self.limit], start, close) orelse return error.DataException;
        self.pos = end + close.len;
        return self.data[start..end];
    }

    fn numberAfter(self: *XmlCursor, tag: []const u8) Exception!?u64 {
        const text = (try self.tagContent(tag)) orelse return null;
        return try parseNumber(std.mem.trim(u8, text, " \t\r\n"));
    }

    fn modeAfter(self: *XmlCursor, tag: []const u8) Exception!?u32 {
        const text = (try self.tagContent(tag)) orelse return null;
        return try parseMode(std.mem.trim(u8, text, " \t\r\n"));
    }

    fn timeAfter(self: *XmlCursor, tag: []const u8) Exception!?u64 {
        const text = (try self.tagContent(tag)) orelse return null;
        return parseTimeValue(std.mem.trim(u8, text, " \t\r\n"));
    }
};

fn unescapeXmlInPlace(name: []u8) Exception![]const u8 {
    if (std.mem.findScalar(u8, name, '&') == null) return name;
    var w: usize = 0;
    var r: usize = 0;
    while (r < name.len) {
        if (name[r] != '&') {
            name[w] = name[r];
            w += 1;
            r += 1;
            continue;
        }
        const semi = std.mem.findScalarPos(u8, name, r, ';') orelse return error.DataException;
        const entity = name[r + 1 .. semi];
        if (entity.len > 1 and entity[0] == '#') {
            // Numeric character reference, decimal or hex. The reference
            // text is never shorter than its UTF-8 encoding, so writing in
            // place cannot overwrite unread input.
            const value = if (entity[1] == 'x' or entity[1] == 'X')
                try parseBase(entity[2..], 16)
            else
                try parseBase(entity[1..], 10);
            const codepoint = std.math.cast(u21, value) orelse return error.DataException;
            const encoded = std.unicode.utf8Encode(codepoint, name[w..]) catch return error.DataException;
            w += encoded;
        } else {
            const byte: u8 = if (std.mem.eql(u8, entity, "amp")) '&' else if (std.mem.eql(u8, entity, "lt")) '<' else if (std.mem.eql(u8, entity, "gt")) '>' else if (std.mem.eql(u8, entity, "quot")) '"' else if (std.mem.eql(u8, entity, "apos")) '\'' else return error.DataException;
            name[w] = byte;
            w += 1;
        }
        r = semi + 1;
    }
    return name[0..w];
}

fn parseBase(text: []const u8, comptime base: u64) Exception!u64 {
    if (text.len == 0) return error.DataException;
    var value: u64 = 0;
    for (text) |byte| {
        const digit: u64 = switch (byte) {
            '0'...'9' => byte - '0',
            'a'...'f' => byte - 'a' + 10,
            'A'...'F' => byte - 'A' + 10,
            else => return error.DataException,
        };
        if (digit >= base) return error.DataException;
        value = std.math.mul(u64, value, base) catch return error.DataException;
        value = std.math.add(u64, value, digit) catch return error.DataException;
    }
    return value;
}

fn parseNumber(text: []const u8) Exception!u64 {
    return parseBase(text, 10);
}

fn parseMode(text: []const u8) Exception!u32 {
    return std.math.cast(u32, try parseBase(text, 8)) orelse return error.DataException;
}

// xar serializes times as ISO 8601 with a Z suffix; vendor writes
// strftime("%FT%T") plus "Z" and libarchive requires the same shape.
// Older archives (and our own former output) carry epoch integers, so
// accept both. Unparseable values fall back to zero like the readers do.
fn parseTimeValue(text: []const u8) u64 {
    if (text.len >= 19 and text[4] == '-' and text[7] == '-' and text[10] == 'T' and text[13] == ':' and text[16] == ':') {
        const year = parseBase(text[0..4], 10) catch return 0;
        const month = parseBase(text[5..7], 10) catch return 0;
        const day = parseBase(text[8..10], 10) catch return 0;
        const hour = parseBase(text[11..13], 10) catch return 0;
        const minute = parseBase(text[14..16], 10) catch return 0;
        const second = parseBase(text[17..19], 10) catch return 0;
        if (month < 1 or month > 12 or day < 1 or day > 31) return 0;
        if (hour > 23 or minute > 59 or second > 60) return 0;
        return civilToEpoch(year, month, day, hour, minute, second);
    }
    return parseNumber(text) catch 0;
}

// Days-from-civil over the proleptic Gregorian calendar; pre-epoch results
// clamp to zero because entry times are unsigned.
fn civilToEpoch(year: u64, month: u64, day: u64, hour: u64, minute: u64, second: u64) u64 {
    const y: i64 = if (month <= 2) @as(i64, @intCast(year)) - 1 else @intCast(year);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (month > 2) @as(i64, @intCast(month)) - 3 else @as(i64, @intCast(month)) + 9;
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, @intCast(day)) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    const epoch = days * 86400 + @as(i64, @intCast(hour)) * 3600 + @as(i64, @intCast(minute)) * 60 + @as(i64, @intCast(second));
    if (epoch < 0) return 0;
    return @intCast(epoch);
}

const ScanResult = struct {
    count: u64,
    found: ?EntryInfo,
};

// Index just past the </file> closing the element whose open tag ends at
// `start`; nested <file> elements count toward the depth.
fn findFileElementEnd(xml: []const u8, start: usize, limit: usize) Exception!usize {
    var depth: usize = 1;
    var pos = start;
    while (depth > 0) {
        const open = std.mem.findPos(u8, xml[0..limit], pos, "<file");
        const close = std.mem.findPos(u8, xml[0..limit], pos, "</file>") orelse return error.DataException;
        if (open != null and open.? < close) {
            depth += 1;
            pos = open.? + "<file".len;
        } else {
            depth -= 1;
            pos = close + "</file>".len;
        }
    }
    return pos;
}

const ScanState = struct {
    xml: []const u8,
    want: ?u64,
    name_buf: ?[]u8,
    count: u64 = 0,
    found: ?EntryInfo = null,
    depth: usize = 0,
    segments: [64][]const u8 = undefined,

    fn walk(self: *ScanState, start: usize, limit: usize) Exception!void {
        var cursor = XmlCursor{ .data = self.xml, .pos = start, .limit = limit };
        while (cursor.find("<file") catch null) |_| {
            const file_start = cursor.pos;
            const file_end = try findFileElementEnd(self.xml, file_start, limit);
            try self.visitFile(file_start, file_end);
            if (self.found != null) return;
            cursor.pos = file_end;
        }
    }

    fn visitFile(self: *ScanState, file_start: usize, file_end: usize) Exception!void {
        // A file's own elements precede any nested child; bound the field
        // scan so a child's fields cannot leak into the parent.
        const field_limit = std.mem.findPos(u8, self.xml[0..file_end], file_start, "<file") orelse file_end;
        var file = XmlCursor{ .data = self.xml, .pos = file_start, .limit = field_limit };
        var info: EntryInfo = undefined;
        info.ordinal = self.count;
        self.count += 1;
        info.mode = 0;
        info.uid = 0;
        info.gid = 0;
        info.modification_time = 0;
        info.data_offset = 0;
        info.data_length = 0;
        info.size = 0;
        info.stored = true;
        const name_raw = (try file.tagContent("name")) orelse return error.DataException;
        const type_text = (try file.tagContent("type")) orelse "file";
        if (try file.modeAfter("mode")) |mode_value| {
            info.mode = mode_value;
        }
        if (try file.numberAfter("uid")) |uid_value| {
            info.uid = std.math.cast(u32, uid_value) orelse return error.DataException;
        }
        if (try file.numberAfter("gid")) |gid_value| {
            info.gid = std.math.cast(u32, gid_value) orelse return error.DataException;
        }
        if (try file.timeAfter("mtime")) |mtime_value| {
            info.modification_time = mtime_value;
        }
        if (std.mem.eql(u8, std.mem.trim(u8, type_text, " \t\r\n"), "file") and
            std.mem.findPos(u8, self.xml[file_start..field_limit], 0, "<data>") != null)
        {
            // The data element is optional: libarchive omits it for empty
            // files, leaving the zero-length defaults in place.
            var data = XmlCursor{ .data = self.xml, .pos = file_start, .limit = field_limit };
            _ = try data.find("<data>");
            const data_start = data.pos;
            var style: []const u8 = "application/octet-stream";
            if (std.mem.findPos(u8, self.xml[data_start..field_limit], 0, "style=\"")) |style_at| {
                const q = data_start + style_at + 7;
                const qend = std.mem.findScalarPos(u8, self.xml[0..field_limit], q, '"') orelse return error.DataException;
                style = self.xml[q..qend];
            }
            // Field order inside <data> is not fixed by the spec; anchor the
            // searches at the data element start.
            data.pos = data_start;
            info.data_offset = (try data.numberAfter("offset")) orelse return error.DataException;
            data.pos = data_start;
            info.data_length = (try data.numberAfter("length")) orelse return error.DataException;
            data.pos = data_start;
            info.size = (try data.numberAfter("size")) orelse return error.DataException;
            info.stored = std.mem.eql(u8, style, "application/octet-stream");
        }
        if (self.want != null and self.want.? == info.ordinal) {
            info.name = try self.joinName(name_raw);
            self.found = info;
            return;
        }
        if (field_limit == file_end) return;
        // xar nests a directory's children inside the parent element; walk
        // them with this file's name as the next path segment.
        if (self.depth == self.segments.len) return error.DataException;
        self.segments[self.depth] = name_raw;
        self.depth += 1;
        defer self.depth -= 1;
        try self.walk(file_start, file_end);
    }

    fn joinName(self: *ScanState, name_raw: []const u8) Exception![]const u8 {
        const buf = self.name_buf orelse return name_raw;
        var len: usize = name_raw.len;
        for (self.segments[0..self.depth]) |segment| len += segment.len + 1;
        if (buf.len < len) return error.CapacityException;
        var w: usize = 0;
        for (self.segments[0..self.depth]) |segment| {
            @memcpy(buf[w..][0..segment.len], segment);
            w += segment.len;
            buf[w] = '/';
            w += 1;
        }
        @memcpy(buf[w..][0..name_raw.len], name_raw);
        w += name_raw.len;
        return try unescapeXmlInPlace(buf[0..w]);
    }
};

fn scanEntries(xml: []const u8, want: ?u64, name_buf: ?[]u8) Exception!ScanResult {
    var state = ScanState{ .xml = xml, .want = want, .name_buf = name_buf };
    var cursor = XmlCursor{ .data = xml, .limit = xml.len };
    _ = try cursor.find("<toc>");
    try state.walk(cursor.pos, cursor.limit);
    return .{ .count = state.count, .found = state.found };
}

fn splitScratch(scratch: []u8) Exception!struct { toc: []u8, name: []u8 } {
    if (scratch.len < 4096 + 512) return error.ResourceException;
    return .{ .toc = scratch[0 .. scratch.len - 512], .name = scratch[scratch.len - 512 ..] };
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    const parts = try splitScratch(scratch);
    const toc = try inflateToc(archive, parts.toc);
    const result = try scanEntries(toc.xml, null, null);
    return result.count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    const parts = try splitScratch(scratch);
    const toc = try inflateToc(archive, parts.toc);
    const result = try scanEntries(toc.xml, ordinal, parts.name);
    if (result.found) |info| return info;
    return error.DataException;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    const parts = try splitScratch(scratch);
    const toc = try inflateToc(archive, parts.toc);
    const result = try scanEntries(toc.xml, ordinal, parts.name);
    const info = result.found orelse return error.DataException;
    const size = std.math.cast(usize, info.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;
    const payload = try bounds.slice(toc.heap, info.data_offset, info.data_length);
    if (info.stored) {
        if (payload.len != size) return error.DataException;
        @memcpy(output[0..size], payload);
        return size;
    }
    const written = try inflateInto(payload, output[0..size]);
    if (written != size) return error.DataException;
    return written;
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
    try testing.expectEqual(@as(u32, 0o644), first.mode);
    try testing.expectEqual(@as(u32, 7), first.uid);
    try testing.expectEqual(@as(u64, 123456789), first.modification_time);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "payload", out[0..n]);
    const second = try inspectOrdinal(archive[0..written], 1, &scratch);
    try testing.expectEqual(@as(u32, 0o755), second.mode);
}

test "xar formats and parses iso 8601 times" {
    const testing = std.testing;
    var buf: [24]u8 = undefined;
    var sink = io.Sink{ .bytes = &buf };
    try writeTimeIso(&sink, 1131553581);
    try testing.expectEqualSlices(u8, "2005-11-09T16:26:21Z", buf[0..sink.offset]);
    try testing.expectEqual(@as(u64, 1131553581), parseTimeValue("2005-11-09T16:26:21Z"));
    try testing.expectEqual(@as(u64, 123456789), parseTimeValue("1973-11-29T21:33:09Z"));
    try testing.expectEqual(@as(u64, 123456789), parseTimeValue("123456789"));
    try testing.expectEqual(@as(u64, 0), parseTimeValue("1969-07-20T20:17:40Z"));
    try testing.expectEqual(@as(u64, 0), parseTimeValue("2005-13-09T16:26:21Z"));
    try testing.expectEqual(@as(u64, 0), parseTimeValue("bogus"));
    sink = .{ .bytes = &buf };
    try testing.expectError(error.UnsupportedException, writeTimeIso(&sink, epoch_max_iso + 1));
    sink = .{ .bytes = &buf };
    try writeTimeIso(&sink, epoch_max_iso);
    try testing.expectEqualSlices(u8, "9999-12-31T23:59:59Z", buf[0..sink.offset]);
}

test "xar unescapes xml entities including numeric references" {
    const testing = std.testing;
    const cases = .{
        .{ "a&#98;c&#x21;", "abc!" },
        .{ "&amp;&lt;&#65;", "&<A" },
        .{ "&quot;&#39;", "\"'" },
        .{ "&#x1F600;", "\u{1F600}" },
    };
    inline for (cases) |case| {
        var buf: [64]u8 = undefined;
        @memcpy(buf[0..case[0].len], case[0]);
        try testing.expectEqualSlices(u8, case[1], try unescapeXmlInPlace(buf[0..case[0].len]));
    }
    var bad: [64]u8 = undefined;
    @memcpy(bad[0..7], "&bogus;");
    try testing.expectError(error.DataException, unescapeXmlInPlace(bad[0..7]));
    @memcpy(bad[0..10], "&#x110000;");
    try testing.expectError(error.DataException, unescapeXmlInPlace(bad[0..10]));
    @memcpy(bad[0..8], "&#xD800;");
    try testing.expectError(error.DataException, unescapeXmlInPlace(bad[0..8]));
    @memcpy(bad[0..2], "&;");
    try testing.expectError(error.DataException, unescapeXmlInPlace(bad[0..2]));
}

test "xar rejects malformed headers and corrupted toc digests" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a.txt", .data = "data" }};
    var archive: [8192]u8 = undefined;
    var scratch: [16384]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);

    var copy: [8192]u8 = undefined;
    @memcpy(copy[0..written], archive[0..written]);
    copy[7] = 2;
    try testing.expectError(error.UnsupportedException, inspectCount(copy[0..written], &scratch));

    @memcpy(copy[0..written], archive[0..written]);
    std.mem.writeInt(u64, copy[8..16], 0xFFFF_FFFF_FFFF_FFE0, .big);
    try testing.expectError(error.DataException, inspectCount(copy[0..written], &scratch));

    // The digest is the 20 bytes between the compressed TOC and the file data.
    @memcpy(copy[0..written], archive[0..written]);
    copy[written - 24] ^= 0xFF;
    try testing.expectError(error.DataException, inspectCount(copy[0..written], &scratch));

    // Header algorithm none with a sha1 checksum style declared is a mismatch.
    @memcpy(copy[0..written], archive[0..written]);
    std.mem.writeInt(u32, copy[24..28], 0, .big);
    try testing.expectError(error.DataException, inspectCount(copy[0..written], &scratch));

    // Truncating inside the TOC must fail, not read past the buffer.
    const toc_comp = std.mem.readInt(u64, archive[8..16], .big);
    const toc_cut: usize = @intCast(header_size + toc_comp / 2);
    try testing.expectError(error.DataException, inspectCount(archive[0..toc_cut], &scratch));

    // Truncating the data tail is caught when the entry data is read.
    var out: [16]u8 = undefined;
    try testing.expectError(error.DataException, decodeOrdinal(archive[0 .. written - 2], 0, &out, &scratch));
}

test "xar rejects out of range uid and gid without trapping" {
    const testing = std.testing;
    const xml =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<xar><toc>
        \\  <checksum style="sha1"><offset>0</offset><size>20</size></checksum>
        \\  <file id="1"><name>a</name><type>file</type><uid>4294967296</uid><gid>7</gid>
        \\   <data><length>1</length><offset>20</offset><size>1</size><encoding style="application/octet-stream"/></data>
        \\  </file>
        \\</toc></xar>
    ;
    var toc_buf: [4096]u8 = undefined;
    var toc_sink = io.Sink{ .bytes = &toc_buf };
    try writeZlibStored(&toc_sink, xml, std.hash.Adler32.hash(xml));
    const toc_comp = toc_sink.offset;
    var archive: [8192]u8 = undefined;
    @memcpy(archive[0..4], "xar!");
    std.mem.writeInt(u16, archive[4..6], header_size, .big);
    std.mem.writeInt(u16, archive[6..8], 1, .big);
    std.mem.writeInt(u64, archive[8..16], toc_comp, .big);
    std.mem.writeInt(u64, archive[16..24], xml.len, .big);
    std.mem.writeInt(u32, archive[24..28], cksum_sha1, .big);
    @memcpy(archive[28..][0..toc_comp], toc_buf[0..toc_comp]);
    var digest: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(archive[28..][0..toc_comp], &digest, .{});
    @memcpy(archive[28 + toc_comp ..][0..sha1_len], &digest);
    archive[28 + toc_comp + sha1_len] = 'x';
    const total = 29 + toc_comp + sha1_len;
    var scratch: [16384]u8 = undefined;
    try testing.expectError(error.DataException, inspectOrdinal(archive[0..total], 0, &scratch));
}

test "xar decodes libarchive-style nested and empty-file tocs" {
    const testing = std.testing;
    const xml =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<xar>
        \\ <toc>
        \\  <checksum style="sha1">
        \\   <offset>0</offset>
        \\   <size>20</size>
        \\  </checksum>
        \\  <file id="1">
        \\   <name>dir</name>
        \\   <type>directory</type>
        \\   <mtime>2005-11-09T16:26:21Z</mtime>
        \\   <file id="2">
        \\    <name>empty.txt</name>
        \\    <type>file</type>
        \\    <mtime>2005-11-09T16:26:21Z</mtime>
        \\   </file>
        \\   <file id="3">
        \\    <name>nested.txt</name>
        \\    <type>file</type>
        \\    <data>
        \\     <length>4</length>
        \\     <offset>20</offset>
        \\     <size>4</size>
        \\     <encoding style="application/octet-stream"/>
        \\    </data>
        \\   </file>
        \\  </file>
        \\ </toc>
        \\</xar>
        \\
    ;
    var toc_buf: [4096]u8 = undefined;
    var toc_sink = io.Sink{ .bytes = &toc_buf };
    try writeZlibStored(&toc_sink, xml, std.hash.Adler32.hash(xml));
    const toc_comp = toc_sink.offset;
    var archive: [8192]u8 = undefined;
    @memcpy(archive[0..4], "xar!");
    std.mem.writeInt(u16, archive[4..6], header_size, .big);
    std.mem.writeInt(u16, archive[6..8], 1, .big);
    std.mem.writeInt(u64, archive[8..16], toc_comp, .big);
    std.mem.writeInt(u64, archive[16..24], xml.len, .big);
    std.mem.writeInt(u32, archive[24..28], cksum_sha1, .big);
    @memcpy(archive[28..][0..toc_comp], toc_buf[0..toc_comp]);
    var digest: [sha1_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(archive[28..][0..toc_comp], &digest, .{});
    @memcpy(archive[28 + toc_comp ..][0..sha1_len], &digest);
    @memcpy(archive[28 + toc_comp + sha1_len ..][0..4], "data");
    const total = 28 + toc_comp + sha1_len + 4;
    var scratch: [16384]u8 = undefined;

    try testing.expectEqual(@as(u64, 3), try inspectCount(archive[0..total], &scratch));
    const dir = try inspectOrdinal(archive[0..total], 0, &scratch);
    try testing.expectEqualSlices(u8, "dir", dir.name);
    try testing.expectEqual(@as(u64, 1131553581), dir.modification_time);
    const empty = try inspectOrdinal(archive[0..total], 1, &scratch);
    try testing.expectEqualSlices(u8, "dir/empty.txt", empty.name);
    try testing.expectEqual(@as(u64, 0), empty.size);
    const nested = try inspectOrdinal(archive[0..total], 2, &scratch);
    try testing.expectEqualSlices(u8, "dir/nested.txt", nested.name);
    try testing.expectEqual(@as(u64, 4), nested.size);
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try decodeOrdinal(archive[0..total], 1, &out, &scratch));
    try testing.expectEqualSlices(u8, "data", out[0..try decodeOrdinal(archive[0..total], 2, &out, &scratch)]);
}
