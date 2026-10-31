const std = @import("std");

const entry_prim = @import("../../../common/entry.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");

pub const Entry = entry_prim.Entry;
const Exception = exception_prim.Exception;

pub const Format = enum { bin_le, bin_be, odc, newc, crc };

pub const EntryInfo = struct {
    name: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modification_time: u64,
    ino: u32,
    nlink: u32,
    devmajor: u32,
    devminor: u32,
    format: Format,
    ordinal: u64,
    header_offset: u64,
    data_offset: u64,
};

pub const trailer_name = "TRAILER!!!";

pub const record_header_size: usize = 110;

// The fixed newc header, shared by this reader and the xip member walk:
// both decode the same 13 hex fields from the same offsets.
pub const NewcHeader = struct {
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    modification_time: u64,
    data_size: u64,
    check: u32,
    namesize: u64,
    is_crc: bool,
};

pub fn parseNewcHeader(bytes: []const u8) Exception!NewcHeader {
    if (bytes.len < record_header_size) return error.DataException;
    if (!std.mem.eql(u8, bytes[0..6], "070701") and !std.mem.eql(u8, bytes[0..6], "070702")) return error.DataException;
    return .{
        .ino = @intCast(try parseHex(bytes[6..14])),
        .mode = @intCast(try parseHex(bytes[14..22])),
        .uid = @intCast(try parseHex(bytes[22..30])),
        .gid = @intCast(try parseHex(bytes[30..38])),
        .nlink = @intCast(try parseHex(bytes[38..46])),
        .modification_time = try parseHex(bytes[46..54]),
        .data_size = try parseHex(bytes[54..62]),
        .check = @intCast(try parseHex(bytes[102..110])),
        .namesize = try parseHex(bytes[94..102]),
        .is_crc = bytes[5] == '2',
    };
}

// A record name carries its NUL terminator on the wire; nothing else may
// appear before it. Newc and odc use the same name convention.
pub fn parseRecordName(bytes: []const u8) Exception![]const u8 {
    if (bytes.len == 0) return error.DataException;
    const name = bytes[0 .. bytes.len - 1];
    if (std.mem.findScalar(u8, name, 0) != null) return error.DataException;
    try entry_prim.validateName(name);
    return name;
}

pub const odc_header_size: usize = 76;

pub const OdcHeader = struct {
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    modification_time: u64,
    data_size: u64,
    namesize: u64,
};

// The portable ASCII header. The xip reader accepts it as well as newc,
// because a payload may carry either.
pub fn parseOdcHeader(bytes: []const u8) Exception!OdcHeader {
    if (bytes.len < odc_header_size) return error.DataException;
    if (!std.mem.eql(u8, bytes[0..6], "070707")) return error.DataException;
    var mode: u32 = @intCast(try parseOctal(bytes[18..24]));
    // PWB archives leave inode bits above the mode field. Keep every bit
    // a mode can hold: 0o67777 clears the type and turns symlinks into files.
    mode &= 0o177777;
    if (mode & 0o170000 == 0) mode |= 0o100000;
    return .{
        .ino = @intCast(try parseOctal(bytes[12..18])),
        .mode = mode,
        .uid = @intCast(try parseOctal(bytes[24..30])),
        .gid = @intCast(try parseOctal(bytes[30..36])),
        .nlink = @intCast(try parseOctal(bytes[36..42])),
        .modification_time = try parseOctal(bytes[48..59]),
        .namesize = try parseOctal(bytes[59..65]),
        .data_size = try parseOctal(bytes[65..76]),
    };
}

fn entryMode(entry: Entry) u32 {
    return if (entry.mode & 0o170000 == 0) entry.mode | 0o100000 else entry.mode;
}

fn nameZ(entry: Entry) usize {
    // The wire namesize counts the trailing NUL.
    return entry.name.len + 1;
}

pub fn archiveSize(entries: []const Entry) Exception!u64 {
    return archiveSizeWith(.newc, entries);
}

pub fn archiveSizeOdc(entries: []const Entry) Exception!u64 {
    return archiveSizeWith(.odc, entries);
}

fn archiveSizeWith(comptime format: Format, entries: []const Entry) Exception!u64 {
    const header_size: u64 = switch (format) {
        .newc, .crc => 110,
        .odc => 76,
        else => return error.UnsupportedException,
    };
    // Alignment applies to the running offset, not a field; the 110-byte
    // newc header leaves it at 2 mod 4.
    var total: u64 = 0;
    for (entries) |entry| {
        try validateEntry(entry);
        total = try bounds.addU64(total, header_size);
        total = try bounds.addU64(total, nameZ(entry));
        if (format != .odc) total = try alignUp(total, 4);
        total = try bounds.addU64(total, entry.data.len);
        if (format != .odc) total = try alignUp(total, 4);
    }
    total = try bounds.addU64(total, header_size);
    total = try bounds.addU64(total, trailer_name.len + 1);
    if (format != .odc) {
        total = try alignUp(total, 4);
        total = try alignUp(total, 512);
    }
    return total;
}

fn alignUp(value: u64, alignment: u64) Exception!u64 {
    const rem = value % alignment;
    return if (rem == 0) value else bounds.addU64(value, alignment - rem);
}

fn validateEntry(entry: Entry) Exception!void {
    // The odc name field is six octal digits wide; nothing longer can be written.
    if (entry.name.len > 0xFFFF) return error.CallException;
    if (std.mem.eql(u8, entry.name, trailer_name)) return error.CallException;
    try entry_prim.validateName(entry.name);
}

pub fn encode(entries: []const Entry, output: []u8) Exception!usize {
    return encodeWith(.newc, entries, output);
}

pub fn encodeOdc(entries: []const Entry, output: []u8) Exception!usize {
    return encodeWith(.odc, entries, output);
}

fn encodeWith(comptime format: Format, entries: []const Entry, output: []u8) Exception!usize {
    var sink = io.Sink{ .bytes = output };
    for (entries, 0..) |entry, index| {
        const ino: u32 = if (entry.ino == 0) @intCast(index + 1) else entry.ino;
        switch (format) {
            .newc => try writeNewcRecord(&sink, entry, ino, 0),
            .odc => {
                try validateEntry(entry);
                try writeOdcHeader(&sink, entry, ino);
                try sink.write(entry.name);
                try sink.write("\x00");
                try sink.write(entry.data);
            },
            else => return error.UnsupportedException,
        }
    }
    // Newc archives close on a 512 multiple.
    switch (format) {
        .newc => try writeNewcTrailer(&sink),
        .odc => {
            const zero = Entry{ .name = trailer_name, .data = &.{} };
            try writeOdcHeader(&sink, zero, 0);
            try sink.write(trailer_name);
            try sink.write("\x00");
        },
        else => return error.UnsupportedException,
    }
    return sink.offset;
}

fn writePad(sink: anytype, offset: u64, alignment: u64) Exception!void {
    const rem = offset % alignment;
    if (rem == 0) return;
    const zeros: [512]u8 = @splat(0);
    sink.write(zeros[0..@as(usize, @intCast(alignment - rem))]) catch return error.CapacityException;
}

// A value that does not fit the width is a caller error; a truncated
// header would disagree with the data.
fn writeDigits(sink: anytype, comptime base: u8, width: usize, value: u64) Exception!void {
    const digits: []const u8 = if (base == 16) "0123456789abcdef" else "01234567";
    var buf: [11]u8 = undefined;
    var v = value;
    var i = width;
    while (i > 0) {
        i -= 1;
        buf[i] = digits[@intCast(v % base)];
        v /= base;
    }
    if (v != 0) return error.UnsupportedException;
    sink.write(buf[0..width]) catch return error.CapacityException;
}

fn writeNewcHeader(sink: anytype, entry: Entry, ino: u32, comptime magic: []const u8, check: u32) Exception!void {
    sink.write(magic) catch return error.CapacityException;
    const fields = [13]u64{
        ino,
        entryMode(entry),
        entry.uid,
        entry.gid,
        entry.nlink,
        entry.modification_time,
        entry.data.len,
        entry.devmajor,
        entry.devminor,
        entry.rdevmajor,
        entry.rdevminor,
        nameZ(entry),
        check,
    };
    for (fields) |field| try writeDigits(sink, 16, 8, field);
}

// One complete newc record: the fixed header, the name, and the data.
// The xip writer streams these straight into its chunk framing.
pub fn writeNewcRecord(sink: anytype, entry: Entry, ino: u32, check: u32) Exception!void {
    try validateEntry(entry);
    try writeNewcHeader(sink, entry, ino, "070701", check);
    try sink.write(entry.name);
    try sink.write("\x00");
    try writePad(sink, sink.offset, 4);
    try sink.write(entry.data);
    try writePad(sink, sink.offset, 4);
}

pub fn writeNewcTrailer(sink: anytype) Exception!void {
    const zero = Entry{ .name = trailer_name, .data = &.{} };
    try writeNewcHeader(sink, zero, 0, "070701", 0);
    try sink.write(trailer_name);
    try sink.write("\x00");
    try writePad(sink, sink.offset, 4);
    try writePad(sink, sink.offset, 512);
}

fn writeOdcHeader(sink: anytype, entry: Entry, ino: u32) Exception!void {
    sink.write("070707") catch return error.CapacityException;
    const fields = .{
        .{ 6, @as(u64, 0) },
        .{ 6, ino },
        .{ 6, entryMode(entry) },
        .{ 6, entry.uid },
        .{ 6, entry.gid },
        .{ 6, entry.nlink },
        .{ 6, @as(u64, 0) },
        .{ 11, entry.modification_time },
        .{ 6, nameZ(entry) },
        .{ 11, entry.data.len },
    };
    inline for (fields) |field| try writeDigits(sink, 8, field[0], field[1]);
}

fn parseDigits(field: []const u8, comptime base: u64, to_digit: *const fn (u8) Exception!u64) Exception!u64 {
    if (field.len == 0) return error.DataException;
    var value: u64 = 0;
    for (field) |byte| {
        value = std.math.mul(u64, value, base) catch return error.DataException;
        value = std.math.add(u64, value, try to_digit(byte)) catch return error.DataException;
    }
    return value;
}

fn octDigit(byte: u8) Exception!u64 {
    if (byte < '0' or byte > '7') return error.DataException;
    return byte - '0';
}

fn hexDigit(byte: u8) Exception!u64 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => return error.DataException,
    };
}

fn parseOctal(field: []const u8) Exception!u64 {
    return parseDigits(field, 8, octDigit);
}

fn parseHex(field: []const u8) Exception!u64 {
    return parseDigits(field, 16, hexDigit);
}

fn readU16(data: []const u8, offset: usize, big: bool) u32 {
    if (big) return std.mem.readInt(u16, data[offset..][0..2], .big);
    return std.mem.readInt(u16, data[offset..][0..2], .little);
}

fn readU32(data: []const u8, offset: usize, big: bool) u64 {
    if (big) return std.mem.readInt(u32, data[offset..][0..4], .big);
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

const Reader = struct {
    archive: []const u8,
    offset: u64 = 0,
    ordinal: u64 = 0,

    fn parseHeader(self: *Reader) Exception!?EntryInfo {
        if (self.offset >= self.archive.len) return null;
        const rest = self.archive[@intCast(self.offset)..];
        if (rest.len < 2) return error.DataException;
        var info: EntryInfo = undefined;
        info.header_offset = self.offset;
        var namesize: u64 = 0;
        var data_size: u64 = 0;
        var check: u64 = 0;
        var name_align: u64 = 2;
        var data_align: u64 = 2;
        if (rest.len >= 6 and std.mem.eql(u8, rest[0..6], "070707")) {
            const header = try parseOdcHeader(rest);
            info.format = .odc;
            info.ino = header.ino;
            info.mode = header.mode;
            info.uid = header.uid;
            info.gid = header.gid;
            info.nlink = header.nlink;
            info.modification_time = header.modification_time;
            namesize = header.namesize;
            data_size = header.data_size;
            info.devmajor = 0;
            info.devminor = 0;
            name_align = 1;
            data_align = 1;
            self.offset = try bounds.addU64(self.offset, odc_header_size);
        } else if (rest.len >= 6 and (std.mem.eql(u8, rest[0..6], "070701") or std.mem.eql(u8, rest[0..6], "070702"))) {
            const header = try parseNewcHeader(rest);
            info.format = if (header.is_crc) .crc else .newc;
            info.ino = header.ino;
            info.mode = header.mode;
            info.uid = header.uid;
            info.gid = header.gid;
            info.nlink = header.nlink;
            info.modification_time = header.modification_time;
            data_size = header.data_size;
            info.devmajor = @intCast(try parseHex(rest[62..70]));
            info.devminor = @intCast(try parseHex(rest[70..78]));
            namesize = header.namesize;
            check = header.check;
            self.offset = try bounds.addU64(self.offset, record_header_size);
            name_align = 4;
            data_align = 4;
        } else {
            const le = readU16(rest, 0, false);
            const be = readU16(rest, 0, true);
            const big = if (be == 0o070707) true else if (le == 0o070707) false else return error.DataException;
            if (rest.len < 26) return error.DataException;
            info.format = if (big) .bin_be else .bin_le;
            info.ino = readU16(rest, 4, big);
            info.mode = readU16(rest, 6, big) & 0o177777;
            if (info.mode & 0o170000 == 0) info.mode |= 0o100000;
            info.uid = readU16(rest, 8, big);
            info.gid = readU16(rest, 10, big);
            info.nlink = readU16(rest, 12, big);
            info.devmajor = 0;
            info.devminor = 0;
            info.modification_time = readU32(rest, 16, big);
            namesize = readU16(rest, 20, big);
            data_size = readU32(rest, 22, big);
            self.offset = try bounds.addU64(self.offset, 26);
        }
        if (namesize == 0) return error.DataException;
        const data_start = try alignUp(try bounds.addU64(self.offset, namesize), name_align);
        const name = try bounds.slice(self.archive, self.offset, namesize - 1);
        if (std.mem.findScalar(u8, name, 0) != null) return error.DataException;
        info.name = name;
        info.size = data_size;
        info.data_offset = data_start;
        const data_end = try alignUp(try bounds.addU64(data_start, data_size), data_align);
        if (data_end > self.archive.len) return error.DataException;
        if (info.format == .crc) {
            // The checksum covers the file data, which begins after the
            // name field and its padding, not right after the header.
            const data = try bounds.slice(self.archive, data_start, data_size);
            var sum: u64 = 0;
            for (data) |byte| sum += byte;
            if ((sum & 0xFFFFFFFF) != check) return error.DataException;
        }
        info.ordinal = self.ordinal;
        self.ordinal = try bounds.addU64(self.ordinal, 1);
        self.offset = data_end;
        if (std.mem.eql(u8, name, trailer_name)) {
            if (data_size != 0) return error.DataException;
            return null;
        }
        return info;
    }
};

pub fn inspectCount(archive: []const u8) Exception!u64 {
    var reader = Reader{ .archive = archive };
    var count: u64 = 0;
    while (try reader.parseHeader()) |info| {
        _ = info;
        count = try bounds.addU64(count, 1);
    }
    return count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64) Exception!EntryInfo {
    var reader = Reader{ .archive = archive };
    while (try reader.parseHeader()) |info| {
        if (info.ordinal == ordinal) return info;
    }
    return error.DataException;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8) Exception!usize {
    const info = try inspectOrdinal(archive, ordinal);
    const size = std.math.cast(usize, info.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;
    const data = try bounds.slice(archive, info.data_offset, info.size);
    @memcpy(output[0..size], data);
    return size;
}

// Fields a forward walk can state; EntryInfo keeps the offsets.
pub const RecordInfo = struct {
    name: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modification_time: u64,
    ordinal: u64,
    ino: u32,
    nlink: u32,
};

fn paddingTo(offset: u64, alignment: u64) u64 {
    const rem = offset % alignment;
    return if (rem == 0) 0 else alignment - rem;
}

const RecordHeader = struct {
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    modification_time: u64,
    data_size: u64,
    namesize: u64,
    nlink: u32,
    name_align: u64,
    data_align: u64,
    check: u32,
    is_crc: bool,
};

// The session Inner role: a forward-only cursor over any source.
// Skipped records sink through discard, never through a decode.
pub fn Inner(comptime Source: type) type {
    return struct {
        const Self = @This();

        // The name buffer: the size a nested container must accept.
        pub const scratch_size: usize = 4096;

        source: *Source,
        name_buf: []u8,
        ordinal: u64 = 0,
        // The decoded-stream position drives the padding arithmetic.
        stream_pos: u64 = 0,
        pending: bool = false,
        data_size: u64 = 0,
        data_align: u64 = 0,
        check: u32 = 0,
        is_crc: bool = false,
        done: bool = false,

        pub fn open(source: *Source, scratch: []u8) Exception!Self {
            if (scratch.len < scratch_size) return error.CapacityException;
            return .{ .source = source, .name_buf = scratch[0..scratch_size] };
        }

        pub fn next(self: *Self) Exception!?RecordInfo {
            // A stream ends at its trailer; a later call stays ended.
            if (self.done) return null;
            // An unconsumed record is finished here so every next() starts
            // at a record boundary.
            if (self.pending) _ = try self.skipData();
            var magic: [6]u8 = undefined;
            try self.readExact(&magic);
            const header = try self.readHeader(magic);
            if (header.namesize == 0 or header.namesize > self.name_buf.len) return error.DataException;
            const name_bytes = self.name_buf[0..@intCast(header.namesize)];
            try self.readExact(name_bytes);
            if (name_bytes[name_bytes.len - 1] != 0) return error.DataException;
            const name = try parseRecordName(name_bytes);
            try self.discardPadding(header.name_align);
            if (std.mem.eql(u8, name, trailer_name)) {
                if (header.data_size != 0) return error.DataException;
                self.done = true;
                return null;
            }
            const info = RecordInfo{
                .name = name,
                .mode = header.mode,
                .uid = header.uid,
                .gid = header.gid,
                .size = header.data_size,
                .modification_time = header.modification_time,
                .ordinal = self.ordinal,
                .ino = header.ino,
                .nlink = header.nlink,
            };
            self.ordinal = try bounds.addU64(self.ordinal, 1);
            self.pending = true;
            self.data_size = header.data_size;
            self.data_align = header.data_align;
            self.check = header.check;
            self.is_crc = header.is_crc;
            return info;
        }

        pub fn readData(self: *Self, writer: *std.Io.Writer) Exception!usize {
            if (!self.pending) return error.CallException;
            const budget: usize = std.math.cast(usize, self.data_size) orelse return error.ResourceException;
            var staged: [512]u8 = undefined;
            var total: usize = 0;
            var sum: u32 = 0;
            while (total < budget) {
                const want = @min(budget - total, staged.len);
                const got = try self.source.take(staged[0..want]);
                // A source that stops inside the record is truncated.
                if (got == 0) return error.DataException;
                if (self.is_crc) {
                    for (staged[0..got]) |byte| sum +%= byte;
                }
                writer.writeAll(staged[0..got]) catch |err| switch (err) {
                    error.WriteFailed => return error.IoException,
                };
                total += got;
                self.stream_pos += got;
            }
            self.pending = false;
            if (self.is_crc and sum != self.check) return error.IntegrityException;
            try self.discardPadding(self.data_align);
            return total;
        }

        // The sink is Source.discard, never pull-and-drop; a skipped
        // record carries no checksum.
        pub fn skipData(self: *Self) Exception!usize {
            if (!self.pending) return 0;
            const n: usize = std.math.cast(usize, self.data_size) orelse return error.ResourceException;
            try self.source.discard(n);
            self.stream_pos = try bounds.addU64(self.stream_pos, n);
            self.pending = false;
            try self.discardPadding(self.data_align);
            return n;
        }

        // Both ASCII headers: a payload may carry newc or the portable odc.
        fn readHeader(self: *Self, magic: [6]u8) Exception!RecordHeader {
            if (std.mem.eql(u8, &magic, "070707")) {
                var bytes: [odc_header_size]u8 = undefined;
                @memcpy(bytes[0..6], &magic);
                try self.readExact(bytes[6..]);
                const header = try parseOdcHeader(&bytes);
                return .{
                    .ino = header.ino,
                    .mode = header.mode,
                    .uid = header.uid,
                    .gid = header.gid,
                    .modification_time = header.modification_time,
                    .data_size = header.data_size,
                    .namesize = header.namesize,
                    .nlink = header.nlink,
                    .name_align = 1,
                    .data_align = 1,
                    .check = 0,
                    .is_crc = false,
                };
            }
            if (!std.mem.eql(u8, &magic, "070701") and !std.mem.eql(u8, &magic, "070702")) return error.DataException;
            var bytes: [record_header_size]u8 = undefined;
            @memcpy(bytes[0..6], &magic);
            try self.readExact(bytes[6..]);
            const header = try parseNewcHeader(&bytes);
            return .{
                .ino = header.ino,
                .mode = header.mode,
                .uid = header.uid,
                .gid = header.gid,
                .modification_time = header.modification_time,
                .data_size = header.data_size,
                .namesize = header.namesize,
                .nlink = header.nlink,
                .name_align = 4,
                .data_align = 4,
                .check = header.check,
                .is_crc = header.is_crc,
            };
        }

        fn readExact(self: *Self, destination: []u8) Exception!void {
            var written: usize = 0;
            while (written < destination.len) {
                const got = try self.source.take(destination[written..]);
                // A source that stops inside a fixed field is truncated.
                if (got == 0) return error.DataException;
                written += got;
                self.stream_pos += got;
            }
        }

        fn discardPadding(self: *Self, alignment: u64) Exception!void {
            const pad = paddingTo(self.stream_pos, alignment);
            if (pad == 0) return;
            try self.source.discard(pad);
            self.stream_pos += pad;
        }
    };
}

test "cpio newc roundtrips entries and metadata" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello world", .uid = 7, .modification_time = 123456789 },
        .{ .name = "dir/nested.bin", .data = "payload", .mode = 0o100755, .ino = 42 },
    };
    var archive: [4096]u8 = undefined;
    const written = try encode(&entries, &archive);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqualSlices(u8, "070701", archive[0..6]);
    const count = try inspectCount(archive[0..written]);
    try testing.expectEqual(@as(u64, 2), count);
    const first = try inspectOrdinal(archive[0..written], 0);
    try testing.expectEqualSlices(u8, "hello.txt", first.name);
    try testing.expectEqual(@as(u32, 7), first.uid);
    try testing.expectEqual(@as(u64, 123456789), first.modification_time);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out);
    try testing.expectEqualSlices(u8, "payload", out[0..n]);
    const second = try inspectOrdinal(archive[0..written], 1);
    try testing.expectEqual(@as(u32, 42), second.ino);
}

test "cpio odc roundtrips" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a", .data = "odd" },
    };
    var archive: [1024]u8 = undefined;
    const written = try encodeOdc(&entries, &archive);
    try testing.expectEqualSlices(u8, "070707", archive[0..6]);
    try testing.expectEqual(@as(u64, 1), try inspectCount(archive[0..written]));
    var out: [8]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 0, &out);
    try testing.expectEqualSlices(u8, "odd", out[0..n]);
}

test "cpio reads little-endian binary archives" {
    const testing = std.testing;
    var archive: [128]u8 = @splat(0);
    std.mem.writeInt(u16, archive[0..2], 0o070707, .little);
    std.mem.writeInt(u16, archive[2..4], 0, .little);
    std.mem.writeInt(u16, archive[4..6], 9, .little);
    std.mem.writeInt(u16, archive[6..8], 0o100644, .little);
    std.mem.writeInt(u16, archive[8..10], 5, .little);
    std.mem.writeInt(u16, archive[10..12], 6, .little);
    std.mem.writeInt(u16, archive[12..14], 1, .little);
    std.mem.writeInt(u16, archive[14..16], 0, .little);
    std.mem.writeInt(u32, archive[16..20], 77, .little);
    std.mem.writeInt(u16, archive[20..22], 2, .little);
    std.mem.writeInt(u32, archive[22..26], 4, .little);
    archive[26] = 'f';
    archive[27] = 0;
    @memcpy(archive[28..32], "data");
    const count = try inspectCount(archive[0..32]);
    try testing.expectEqual(@as(u64, 1), count);
    const info = try inspectOrdinal(archive[0..32], 0);
    try testing.expectEqualSlices(u8, "f", info.name);
    try testing.expectEqual(Format.bin_le, info.format);
    try testing.expectEqual(@as(u32, 0o100644), info.mode);
    try testing.expectEqual(@as(u32, 5), info.uid);
    var out: [4]u8 = undefined;
    const n = try decodeOrdinal(archive[0..32], 0, &out);
    try testing.expectEqualSlices(u8, "data", out[0..n]);
}

test "cpio sizing matches encoder across alignment and 512 boundaries" {
    const testing = std.testing;
    var archive: [4096]u8 = undefined;
    var name_buf: [9]u8 = undefined;
    var data_buf: [600]u8 = undefined;
    @memset(&data_buf, 0x61);
    for (1..10) |name_len| {
        @memset(name_buf[0..name_len], 'n');
        for (0..601) |data_len| {
            const entries = [_]Entry{.{ .name = name_buf[0..name_len], .data = data_buf[0..data_len] }};
            const written = try encode(&entries, &archive);
            try testing.expectEqual(try archiveSize(&entries), written);
            const written_odc = try encodeOdc(&entries, &archive);
            try testing.expectEqual(try archiveSizeOdc(&entries), written_odc);
        }
    }
}

test "cpio rejects a header field that does not fit its width" {
    // A newc number field carries 32 bits; an odc date field carries 33.
    const entries = [_]Entry{.{ .name = "f", .data = "x", .modification_time = 1 << 36 }};
    var archive: [512]u8 = undefined;
    try std.testing.expectError(error.UnsupportedException, encode(&entries, &archive));
    try std.testing.expectError(error.UnsupportedException, encodeOdc(&entries, &archive));
}

test "cpio keeps non-regular type bits in odc and binary records" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "link", .data = "target", .mode = 0o120755 },
        .{ .name = "fifo", .data = &.{}, .mode = 0o010644 },
    };
    var archive: [1024]u8 = undefined;
    const written = try encodeOdc(&entries, &archive);
    try testing.expectEqual(@as(u32, 0o120755), (try inspectOrdinal(archive[0..written], 0)).mode);
    try testing.expectEqual(@as(u32, 0o010644), (try inspectOrdinal(archive[0..written], 1)).mode);

    // The binary reader carried the same mask, so it broke symlinks too.
    var binary_archive: [128]u8 = @splat(0);
    std.mem.writeInt(u16, binary_archive[0..2], 0o070707, .little);
    std.mem.writeInt(u16, binary_archive[4..6], 9, .little);
    std.mem.writeInt(u16, binary_archive[6..8], 0o120755, .little);
    std.mem.writeInt(u16, binary_archive[12..14], 1, .little);
    std.mem.writeInt(u16, binary_archive[20..22], 5, .little);
    std.mem.writeInt(u32, binary_archive[22..26], 6, .little);
    @memcpy(binary_archive[26..31], "link\x00");
    @memcpy(binary_archive[32..38], "target");
    const count = try inspectCount(binary_archive[0..38]);
    try testing.expectEqual(@as(u64, 1), count);
    const info = try inspectOrdinal(binary_archive[0..38], 0);
    try testing.expectEqual(@as(u32, 0o120755), info.mode);
}

test "cpio crc format validates checksum over file data" {
    const testing = std.testing;
    const entry = Entry{ .name = "f", .data = "data" };
    const sum: u32 = 'd' + 'a' + 't' + 'a';
    var archive: [512]u8 = undefined;
    var bad: [512]u8 = undefined;
    {
        var sink = io.Sink{ .bytes = &archive };
        try writeNewcHeader(&sink, entry, 1, "070702", sum);
        try sink.write("f");
        try sink.write("\x00");
        try sink.write("data");
        const zero = Entry{ .name = trailer_name, .data = &.{} };
        try writeNewcHeader(&sink, zero, 0, "070702", 0);
        try sink.write(trailer_name);
        try sink.write("\x00");
        try writePad(&sink, sink.offset, 4);
        try writePad(&sink, sink.offset, 512);
    }
    {
        var sink = io.Sink{ .bytes = &bad };
        try writeNewcHeader(&sink, entry, 1, "070702", sum + 1);
        try sink.write("f");
        try sink.write("\x00");
        try sink.write("data");
        const zero = Entry{ .name = trailer_name, .data = &.{} };
        try writeNewcHeader(&sink, zero, 0, "070702", 0);
        try sink.write(trailer_name);
        try sink.write("\x00");
        try writePad(&sink, sink.offset, 4);
        try writePad(&sink, sink.offset, 512);
    }
    try testing.expectEqual(@as(u64, 1), try inspectCount(&archive));
    const info = try inspectOrdinal(&archive, 0);
    try testing.expectEqual(Format.crc, info.format);
    try testing.expectEqualSlices(u8, "f", info.name);
    var out: [4]u8 = undefined;
    const n = try decodeOrdinal(&archive, 0, &out);
    try testing.expectEqualSlices(u8, "data", out[0..n]);
    try testing.expectError(error.DataException, inspectCount(&bad));
}

// A test source whose take and discard counters prove where a skip sinks.
const TestSource = struct {
    bytes: []const u8,
    pos: usize = 0,
    takes: usize = 0,
    discards: usize = 0,

    fn take(self: *TestSource, buf: []u8) Exception!usize {
        self.takes += 1;
        const n = @min(self.bytes.len - self.pos, buf.len);
        @memcpy(buf[0..n], self.bytes[self.pos..][0..n]);
        self.pos += n;
        return n;
    }

    fn discard(self: *TestSource, n: u64) Exception!void {
        self.discards += 1;
        const count = std.math.cast(usize, n) orelse return error.DataException;
        if (count > self.bytes.len - self.pos) return error.DataException;
        self.pos += count;
    }
};

test "cpio Inner walks a newc stream to its trailer" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "first.txt", .data = "one", .uid = 3 },
        .{ .name = "second.bin", .data = "two two", .mode = 0o100755 },
    };
    var archive: [4096]u8 = undefined;
    const written = try encode(&entries, &archive);
    var source = TestSource{ .bytes = archive[0..written] };
    var scratch: [Inner(TestSource).scratch_size]u8 = undefined;
    var cursor = try Inner(TestSource).open(&source, &scratch);

    const first = (try cursor.next()) orelse return error.UnexpectedEnd;
    try testing.expectEqualSlices(u8, "first.txt", first.name);
    try testing.expectEqual(@as(u64, 3), first.size);
    try testing.expectEqual(@as(u32, 3), first.uid);
    var decoded: [16]u8 = undefined;
    var sink = std.Io.Writer.fixed(&decoded);
    try testing.expectEqual(@as(usize, 3), try cursor.readData(&sink));
    try testing.expectEqualSlices(u8, "one", decoded[0..3]);

    // A skip sinks through discard, never pull-and-drop.
    const second = (try cursor.next()) orelse return error.UnexpectedEnd;
    try testing.expectEqualSlices(u8, "second.bin", second.name);
    try testing.expectEqual(@as(u64, 7), second.size);
    const takes_before = source.takes;
    try testing.expectEqual(@as(usize, 7), try cursor.skipData());
    try testing.expectEqual(takes_before, source.takes);
    try testing.expect(source.discards > 0);

    // The trailer ends the stream, and a later call stays ended.
    try testing.expect(try cursor.next() == null);
    try testing.expect(try cursor.next() == null);
}

test "cpio Inner walks an odc stream" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "odc/entry", .data = "odd" }};
    var archive: [1024]u8 = undefined;
    const written = try encodeOdc(&entries, &archive);
    var source = TestSource{ .bytes = archive[0..written] };
    var scratch: [Inner(TestSource).scratch_size]u8 = undefined;
    var cursor = try Inner(TestSource).open(&source, &scratch);
    const info = (try cursor.next()) orelse return error.UnexpectedEnd;
    try testing.expectEqualSlices(u8, "odc/entry", info.name);
    try testing.expectEqual(@as(u64, 3), info.size);
    var decoded: [8]u8 = undefined;
    var sink = std.Io.Writer.fixed(&decoded);
    try testing.expectEqual(@as(usize, 3), try cursor.readData(&sink));
    try testing.expectEqualSlices(u8, "odd", decoded[0..3]);
    try testing.expect(try cursor.next() == null);
}

test "cpio Inner rejects a stream that ends without a trailer" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a", .data = "data" }};
    var archive: [1024]u8 = undefined;
    const written = try encode(&entries, &archive);
    // The cuts land before the trailer, inside its header, and inside its name.
    const info = try inspectOrdinal(archive[0..written], 0);
    const record_end = std.mem.alignForward(u64, info.data_offset + info.size, 4);
    for ([_]u64{ record_end, record_end + 50, record_end + 113 }) |cut| {
        var source = TestSource{ .bytes = archive[0..@intCast(cut)] };
        var scratch: [Inner(TestSource).scratch_size]u8 = undefined;
        var cursor = try Inner(TestSource).open(&source, &scratch);
        _ = try cursor.next();
        try testing.expectError(error.DataException, cursor.next());
    }
}

test "cpio Inner rejects a short scratch" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a", .data = "b" }};
    var archive: [1024]u8 = undefined;
    const written = try encode(&entries, &archive);
    var source = TestSource{ .bytes = archive[0..written] };
    var short: [16]u8 = undefined;
    try testing.expectError(error.CapacityException, Inner(TestSource).open(&source, &short));
}
