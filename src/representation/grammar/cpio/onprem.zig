const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");

const Exception = exception_prim.Exception;

pub const scratch_size: usize = 256;

pub const Format = enum { bin_le, bin_be, odc, newc, crc };

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
    mode: u32 = 0o100644,
    uid: u32 = 0,
    gid: u32 = 0,
    modification_time: u64 = 0,
    ino: u32 = 0,
    nlink: u32 = 1,
    devmajor: u32 = 0,
    devminor: u32 = 0,
    rdevmajor: u32 = 0,
    rdevminor: u32 = 0,
};

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

const trailer_name = "TRAILER!!!";

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
    var total: u64 = 0;
    for (entries) |entry| {
        try validateEntry(entry);
        const header_size: u64 = switch (format) {
            .newc, .crc => 110,
            .odc => 76,
            else => return error.UnsupportedException,
        };
        total = try bounds.addU64(total, header_size);
        const name_padded = switch (format) {
            .newc, .crc => try alignUp(nameZ(entry), 4),
            .odc => nameZ(entry),
            else => unreachable,
        };
        total = try bounds.addU64(total, name_padded);
        const data_padded = switch (format) {
            .newc, .crc => try alignUp(entry.data.len, 4),
            .odc => entry.data.len,
            else => unreachable,
        };
        total = try bounds.addU64(total, data_padded);
    }
    total = try bounds.addU64(total, switch (format) {
        .newc, .crc => 112,
        .odc => 78,
        else => unreachable,
    });
    if (format == .newc or format == .crc) total = try bounds.addU64(total, 512 - (total % 512));
    return total;
}

fn alignUp(value: u64, alignment: u64) Exception!u64 {
    const rem = value % alignment;
    return if (rem == 0) value else bounds.addU64(value, alignment - rem);
}

fn validateEntry(entry: Entry) Exception!void {
    if (entry.name.len == 0 or entry.name.len > 0xFFFF) return error.CallException;
    if (std.mem.eql(u8, entry.name, trailer_name)) return error.CallException;
    if (bounds.isAbsoluteOrTraversal(entry.name) or std.mem.findScalar(u8, entry.name, 0) != null) return error.CallException;
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return encodeWith(.newc, entries, output, scratch);
}

pub fn encodeOdc(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return encodeWith(.odc, entries, output, scratch);
}

fn encodeWith(comptime format: Format, entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    if (scratch.len < scratch_size) return error.CapacityException;
    var sink = io.Sink{ .bytes = output };
    for (entries, 0..) |entry, index| {
        try validateEntry(entry);
        const ino: u32 = if (entry.ino == 0) @intCast(index + 1) else entry.ino;
        switch (format) {
            .newc => try writeNewcHeader(&sink, entry, ino, "070701", 0),
            .odc => try writeOdcHeader(&sink, entry, ino),
            else => return error.UnsupportedException,
        }
        try sink.write(entry.name);
        try sink.write("\x00");
        if (format != .odc) try writePad(&sink, sink.offset, 4);
        try sink.write(entry.data);
        if (format != .odc) try writePad(&sink, sink.offset, 4);
    }
    // Newc archives close on a 512 multiple.
    switch (format) {
        .newc => {
            const zero = Entry{ .name = trailer_name, .data = &.{} };
            try writeNewcHeader(&sink, zero, 0, "070701", 0);
            try sink.write(trailer_name);
            try sink.write("\x00");
            try writePad(&sink, sink.offset, 4);
            try writePad(&sink, sink.offset, 512);
        },
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

fn writePad(sink: *io.Sink, offset: u64, alignment: u64) Exception!void {
    const rem = offset % alignment;
    if (rem == 0) return;
    const zeros: [512]u8 = @splat(0);
    sink.write(zeros[0 .. alignment - rem]) catch return error.CapacityException;
}

fn writeHex8(sink: *io.Sink, value: u64) Exception!void {
    var buf: [8]u8 = undefined;
    const digits = "0123456789abcdef";
    var v = value;
    var i: usize = 8;
    while (i > 0) {
        i -= 1;
        buf[i] = digits[v & 0xF];
        v >>= 4;
    }
    sink.write(&buf) catch return error.CapacityException;
}

fn writeOctal(sink: *io.Sink, width: usize, value: u64) Exception!void {
    var buf: [11]u8 = @splat(0);
    var v = value;
    var i: usize = width;
    while (i > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v & 7));
        v >>= 3;
    }
    if (v != 0) return error.UnsupportedException;
    sink.write(buf[0..width]) catch return error.CapacityException;
}

fn writeNewcHeader(sink: *io.Sink, entry: Entry, ino: u32, comptime magic: []const u8, check: u32) Exception!void {
    sink.write(magic) catch return error.CapacityException;
    try writeHex8(sink, ino);
    try writeHex8(sink, entryMode(entry));
    try writeHex8(sink, entry.uid);
    try writeHex8(sink, entry.gid);
    try writeHex8(sink, entry.nlink);
    try writeHex8(sink, entry.modification_time);
    try writeHex8(sink, entry.data.len);
    try writeHex8(sink, entry.devmajor);
    try writeHex8(sink, entry.devminor);
    try writeHex8(sink, entry.rdevmajor);
    try writeHex8(sink, entry.rdevminor);
    try writeHex8(sink, nameZ(entry));
    try writeHex8(sink, check);
}

fn writeOdcHeader(sink: *io.Sink, entry: Entry, ino: u32) Exception!void {
    sink.write("070707") catch return error.CapacityException;
    try writeOctal(sink, 6, 0);
    try writeOctal(sink, 6, ino);
    try writeOctal(sink, 6, entryMode(entry));
    try writeOctal(sink, 6, entry.uid);
    try writeOctal(sink, 6, entry.gid);
    try writeOctal(sink, 6, entry.nlink);
    try writeOctal(sink, 6, 0);
    try writeOctal(sink, 11, entry.modification_time);
    try writeOctal(sink, 6, nameZ(entry));
    try writeOctal(sink, 11, entry.data.len);
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
        var name_align: u64 = 2;
        var data_align: u64 = 2;
        if (rest.len >= 6 and std.mem.eql(u8, rest[0..6], "070707")) {
            if (rest.len < 76) return error.DataException;
            info.format = .odc;
            info.mode = @intCast(try parseOctal(rest[18..24]));
            // PWB archives leave inode bits in the type field.
            info.mode &= 0o67777;
            if (info.mode & 0o170000 == 0) info.mode |= 0o100000;
            info.uid = @intCast(try parseOctal(rest[24..30]));
            info.gid = @intCast(try parseOctal(rest[30..36]));
            info.nlink = @intCast(try parseOctal(rest[36..42]));
            info.modification_time = try parseOctal(rest[48..59]);
            namesize = try parseOctal(rest[59..65]);
            data_size = try parseOctal(rest[65..76]);
            info.ino = @intCast(try parseOctal(rest[12..18]));
            info.devmajor = 0;
            info.devminor = 0;
            name_align = 1;
            data_align = 1;
            self.offset = try bounds.addU64(self.offset, 76);
        } else if (rest.len >= 6 and (std.mem.eql(u8, rest[0..6], "070701") or std.mem.eql(u8, rest[0..6], "070702"))) {
            if (rest.len < 110) return error.DataException;
            info.format = if (rest[5] == '2') .crc else .newc;
            info.ino = @intCast(try parseHex(rest[6..14]));
            info.mode = @intCast(try parseHex(rest[14..22]));
            info.uid = @intCast(try parseHex(rest[22..30]));
            info.gid = @intCast(try parseHex(rest[30..38]));
            info.nlink = @intCast(try parseHex(rest[38..46]));
            info.modification_time = try parseHex(rest[46..54]);
            data_size = try parseHex(rest[54..62]);
            info.devmajor = @intCast(try parseHex(rest[62..70]));
            info.devminor = @intCast(try parseHex(rest[70..78]));
            namesize = try parseHex(rest[94..102]);
            const check = try parseHex(rest[102..110]);
            self.offset = try bounds.addU64(self.offset, 110);
            name_align = 4;
            data_align = 4;
            if (info.format == .crc) {
                const data = try bounds.slice(self.archive, self.offset, data_size);
                var sum: u64 = 0;
                for (data) |byte| sum += byte;
                if ((sum & 0xFFFFFFFF) != check) return error.DataException;
            }
        } else {
            const le = readU16(rest, 0, false);
            const be = readU16(rest, 0, true);
            const big = if (be == 0o070707) true else if (le == 0o070707) false else return error.DataException;
            if (rest.len < 26) return error.DataException;
            info.format = if (big) .bin_be else .bin_le;
            info.ino = readU16(rest, 4, big);
            info.mode = readU16(rest, 6, big) & 0o67777;
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

test "cpio newc roundtrips entries and metadata" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello world", .uid = 7, .modification_time = 123456789 },
        .{ .name = "dir/nested.bin", .data = "payload", .mode = 0o100755, .ino = 42 },
    };
    var archive: [4096]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
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
    var scratch: [scratch_size]u8 = undefined;
    const written = try encodeOdc(&entries, &archive, &scratch);
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
