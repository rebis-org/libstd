const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const failure_prim = @import("../../common/primitive/failure.zig");

const Failure = failure_prim.Failure;

// ISO 9660 slice: one root directory of regular files.
// Read prefers a Joliet supplementary descriptor.

// Rock Ridge entries are ignored; layout is unchanged.
// Write emits a 1999-layout descriptor with Rock Ridge NM/PX.

pub const scratch_size: usize = 4096;

const sector_size: usize = 2048;
const pvd_sector: u64 = 16;
const descriptor_terminator: u8 = 255;
const descriptor_primary: u8 = 1;
const descriptor_supplementary: u8 = 2;
const volume_descriptor_magic = "CD001";

const flag_directory: u8 = 1 << 1;

const joliet_escape_1 = [3]u8{ '%', '/', '@' };
const joliet_escape_2 = [3]u8{ '%', '/', 'C' };
const joliet_escape_3 = [3]u8{ '%', '/', 'E' };

const max_entries = 256;
const path_table_lba: u32 = 18;
const dir_lba: u32 = 20;
const file_start_lba: u32 = 21;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    size: u64,
    ordinal: u64,
};

const Descriptor = struct {
    block_size: u32,
    root_extent: u32,
    root_size: u32,
    joliet: bool,
};

fn bothEndianU32(raw: []const u8) Failure!u32 {
    const le = std.mem.readInt(u32, raw[0..4], .little);
    const be = std.mem.readInt(u32, raw[4..8], .big);
    if (le != be) return error.DataFailure;
    return le;
}

fn bothEndianU16(raw: []const u8) Failure!u16 {
    const le = std.mem.readInt(u16, raw[0..2], .little);
    const be = std.mem.readInt(u16, raw[2..4], .big);
    if (le != be) return error.DataFailure;
    return le;
}

fn findDescriptor(archive: []const u8, want: u8) Failure!?Descriptor {
    var sector: u64 = pvd_sector;
    while (true) {
        const base = std.math.mul(u64, sector, sector_size) catch return error.DataFailure;
        const sec = try bounds.slice(archive, base, sector_size);
        const dtype = sec[0];
        if (!std.mem.eql(u8, sec[1..6], volume_descriptor_magic)) return error.DataFailure;
        if (dtype == descriptor_terminator) return null;
        if (dtype == want) {
            const block_size = try bothEndianU16(sec[128..132]);
            if (block_size != sector_size) return error.UnsupportedFailure;
            const escape = sec[88..120];
            const joliet = std.mem.eql(u8, escape[0..3], &joliet_escape_1) or
                std.mem.eql(u8, escape[0..3], &joliet_escape_2) or
                std.mem.eql(u8, escape[0..3], &joliet_escape_3);
            const root = sec[156..190];
            if (root[0] == 0) return error.DataFailure;
            return .{
                .block_size = block_size,
                .root_extent = try bothEndianU32(root[2..10]),
                .root_size = try bothEndianU32(root[10..18]),
                .joliet = joliet,
            };
        }
        sector += 1;
        if (sector > pvd_sector + 16) return error.DataFailure;
    }
}

fn chosenDescriptor(archive: []const u8) Failure!Descriptor {
    if (try findDescriptor(archive, descriptor_supplementary)) |svd| {
        if (svd.joliet) return svd;
    }
    return (try findDescriptor(archive, descriptor_primary)) orelse error.DataFailure;
}

const Record = struct {
    extent: u32,
    size: u32,
    flags: u8,
    skip: usize,
    is_dot: bool,
    is_dotdot: bool,
};

fn parseRecord(dir: []const u8, at: usize) Failure!?Record {
    if (at >= dir.len) return null;
    const len = dir[at];
    if (len == 0) return null;
    if (at + len > dir.len or len < 33 + 1) return error.DataFailure;
    const raw = dir[at .. at + len];
    const name_len = raw[32];
    if (33 + name_len > len) return error.DataFailure;
    return .{
        .extent = try bothEndianU32(raw[2..10]),
        .size = try bothEndianU32(raw[10..18]),
        .flags = raw[25],
        .skip = len,
        .is_dot = name_len == 1 and raw[33] == 0,
        .is_dotdot = name_len == 1 and raw[33] == 1,
    };
}

const Target = union(enum) {
    count,
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8 },
};

fn walkRoot(archive: []const u8, desc: Descriptor, target: Target) Failure!u64 {
    const dir = try bounds.slice(archive, std.math.mul(u64, desc.root_extent, sector_size) catch return error.DataFailure, desc.root_size);
    const dot = (try parseRecord(dir, 0)) orelse return error.DataFailure;
    if (!dot.is_dot) return error.DataFailure;
    const dotdot = (try parseRecord(dir, dot.skip)) orelse return error.DataFailure;
    if (!dotdot.is_dotdot) return error.DataFailure;
    var pos: usize = dot.skip + dotdot.skip;
    var ordinal: u64 = 0;
    while (pos < dir.len) {
        const rec = (try parseRecord(dir, pos)) orelse break;
        pos += rec.skip;
        if (rec.is_dot or rec.is_dotdot) continue;
        if (rec.flags & flag_directory != 0) return error.UnsupportedFailure;
        switch (target) {
            .count => {},
            .resolve => |res| {
                if (ordinal == res.ordinal) {
                    res.info.size = rec.size;
                    res.info.ordinal = ordinal;
                    if (res.output) |out| {
                        if (out.len < rec.size) return error.CapacityFailure;
                        const data = try bounds.slice(archive, std.math.mul(u64, rec.extent, sector_size) catch return error.DataFailure, rec.size);
                        @memcpy(out[0..rec.size], data);
                    }
                    return ordinal;
                }
            },
        }
        ordinal += 1;
    }
    return switch (target) {
        .count => ordinal,
        .resolve => error.DataFailure,
    };
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Failure!u64 {
    _ = scratch;
    return walkRoot(archive, try chosenDescriptor(archive), .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Failure!EntryInfo {
    _ = scratch;
    var info: EntryInfo = undefined;
    _ = try walkRoot(archive, try chosenDescriptor(archive), .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Failure!usize {
    _ = scratch;
    var info: EntryInfo = undefined;
    _ = try walkRoot(archive, try chosenDescriptor(archive), .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output } });
    return @intCast(info.size);
}

const Layout = struct {
    total: u64,
    count: usize,
    sorted: [max_entries]u16,
    file_lba: [max_entries]u32,
    dir_size: usize,
};

fn validateName(name: []const u8) Failure!void {
    if (name.len == 0 or name.len > 250) return error.CallFailure;
    if (std.mem.findScalar(u8, name, '/') != null) return error.CallFailure;
    if (std.mem.findScalar(u8, name, ';') != null) return error.CallFailure;
}

// The interchange name carries the ";1" version suffix.
// Even-length names take a padding byte.
fn isoNameArea(name_len: usize) usize {
    const with_version = name_len + 2;
    return with_version + (1 - (with_version & 1));
}

fn rrSizeNm(name_len: usize) usize {
    const total = 4 + 1 + name_len;
    return total + (total & 1);
}

const rr_size_px: usize = 44;

fn dirRecordSize(name_len: usize, has_nm: bool) usize {
    var size = 33 + isoNameArea(name_len) + rr_size_px;
    if (has_nm) size += rrSizeNm(name_len);
    return size;
}

fn layoutEntries(entries: []const Entry) Failure!Layout {
    if (entries.len == 0 or entries.len > max_entries) return error.UnsupportedFailure;
    var lay: Layout = undefined;
    lay.count = entries.len;
    for (0..entries.len) |rank| {
        try validateName(entries[rank].name);
        if (entries[rank].data.len > std.math.maxInt(u32)) return error.UnsupportedFailure;
        var best: ?usize = null;
        for (entries, 0..) |entry, i| {
            var taken = false;
            for (lay.sorted[0..rank]) |used| taken = taken or used == i;
            if (taken) continue;
            if (best == null or std.mem.order(u8, entry.name, entries[best.?].name) == .lt) best = i;
        }
        lay.sorted[rank] = @intCast(best.?);
    }
    for (0..entries.len - 1) |rank| {
        if (std.mem.eql(u8, entries[lay.sorted[rank]].name, entries[lay.sorted[rank + 1]].name)) return error.CallFailure;
    }
    var dir_size: usize = 0;
    dir_size += 33 + 1 + rr_size_dot_sua;
    dir_size += 33 + 1;
    for (0..entries.len) |rank| {
        dir_size += dirRecordSize(entries[lay.sorted[rank]].name.len, true);
    }
    if (dir_size > sector_size) return error.UnsupportedFailure;
    lay.dir_size = dir_size;
    var lba: u32 = file_start_lba;
    for (0..entries.len) |rank| {
        lay.file_lba[rank] = lba;
        const bytes = entries[lay.sorted[rank]].data.len;
        lba += @intCast((bytes + sector_size - 1) / sector_size);
    }
    // libarchive's bid reads the reserved area plus eight descriptor sectors.
    // Shorter images never reach the parser; pad to 32 sectors.
    lay.total = @as(u64, @max(lba, 32)) * sector_size;
    return lay;
}

pub fn archiveSize(entries: []const Entry) Failure!u64 {
    const lay = try layoutEntries(entries);
    return lay.total;
}

fn writeU16Both(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .little);
    std.mem.writeInt(u16, out[2..4], value, .big);
}

fn writeU32Both(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .little);
    std.mem.writeInt(u32, out[4..8], value, .big);
}

const stamp = "2026010100000000";

fn writeTimestamp(out: []u8) void {
    @memcpy(out[0..16], stamp);
    out[16] = 0;
}

fn writeFixedText(out: []u8) void {
    @memset(out, ' ');
}

fn writePvd(out: []u8, lay: *const Layout) void {
    @memset(out, 0);
    out[0] = descriptor_primary;
    @memcpy(out[1..6], volume_descriptor_magic);
    out[6] = 1;
    writeFixedText(out[8..40]);
    writeFixedText(out[40..72]);
    @memcpy(out[40..48], "LIBSTD10");
    const total_sectors: u32 = @intCast(lay.total / sector_size);
    writeU32Both(out[80..88], total_sectors);
    writeU16Both(out[120..124], 1);
    writeU16Both(out[124..128], 1);
    writeU16Both(out[128..132], @intCast(sector_size));
    writeU32Both(out[132..140], 10);
    std.mem.writeInt(u32, out[140..144], path_table_lba, .little);
    std.mem.writeInt(u32, out[144..148], 0, .little);
    std.mem.writeInt(u32, out[148..152], path_table_lba + 1, .big);
    std.mem.writeInt(u32, out[152..156], 0, .big);
    writeBaseRecord(out[156..190], dir_lba, @intCast(lay.dir_size), true, 1, 0);
    writeFixedText(out[190..318]);
    writeFixedText(out[318..446]);
    writeFixedText(out[446..574]);
    writeFixedText(out[574..702]);
    writeFixedText(out[702..739]);
    writeFixedText(out[739..776]);
    writeFixedText(out[776..813]);
    writeTimestamp(out[813..830]);
    writeTimestamp(out[830..847]);
    writeTimestamp(out[847..864]);
    writeTimestamp(out[864..881]);
    out[881] = 1;
}

fn writeBaseRecord(out: []u8, extent: u32, size: u32, directory: bool, name_len: u8, name_byte: u8) void {
    @memset(out[0..34], 0);
    out[0] = 34;
    out[1] = 0;
    writeU32Both(out[2..10], extent);
    writeU32Both(out[10..18], size);
    const rec_date = [_]u8{ 126, 1, 1, 0, 0, 0, 0 };
    @memcpy(out[18..25], &rec_date);
    out[25] = if (directory) flag_directory else 0;
    out[26] = 0;
    out[27] = 0;
    writeU16Both(out[28..32], 1);
    out[32] = name_len;
    out[33] = name_byte;
}

// One root path table entry: one-byte identifier, padded to even length.
fn writePathTable(sector: []u8, big_endian: bool) void {
    @memset(sector, 0);
    sector[0] = 1;
    sector[1] = 0;
    if (big_endian) {
        std.mem.writeInt(u32, sector[2..6], dir_lba, .big);
        std.mem.writeInt(u16, sector[6..8], 1, .big);
    } else {
        std.mem.writeInt(u32, sector[2..6], dir_lba, .little);
        std.mem.writeInt(u16, sector[6..8], 1, .little);
    }
    sector[8] = 0;
}

const rr_size_sp: usize = 7;
// The ER payload mirrors the reference writer, keeping Rock Ridge readers satisfied.
const rr_er_payload = "IEEE_P1282" ++
    "THE IEEE P1282 PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS." ++
    "PLEASE CONTACT THE IEEE STANDARDS DEPARTMENT, PISCATAWAY, NJ, USA FOR THE P1282 SPECIFICATION.";
const rr_size_er: usize = 4 + 4 + rr_er_payload.len;
const rr_size_dot_sua: usize = rr_size_sp + rr_size_er;

fn writeRrSp(out: []u8) usize {
    out[0] = 'S';
    out[1] = 'P';
    out[2] = rr_size_sp;
    out[3] = 1;
    out[4] = 0xbe;
    out[5] = 0xef;
    out[6] = 0;
    return rr_size_sp;
}

fn writeRrEr(out: []u8) usize {
    out[0] = 'E';
    out[1] = 'R';
    out[2] = rr_size_er;
    out[3] = 1;
    out[4] = 10;
    out[5] = 73;
    out[6] = @intCast(rr_er_payload.len - 73 - 10);
    out[7] = 0;
    @memcpy(out[8..][0..rr_er_payload.len], rr_er_payload);
    return rr_size_er;
}

fn writeRrPx(out: []u8, serial: u32) usize {
    out[0] = 'P';
    out[1] = 'X';
    out[2] = rr_size_px;
    out[3] = 1;
    writeU32Both(out[4..12], 0o100644);
    writeU32Both(out[12..20], 1);
    writeU32Both(out[20..28], 0);
    writeU32Both(out[28..36], 0);
    writeU32Both(out[36..44], serial);
    return rr_size_px;
}

fn writeRrNm(out: []u8, name: []const u8) usize {
    const total = 4 + 1 + name.len;
    const len = total + (total & 1);
    out[0] = 'N';
    out[1] = 'M';
    out[2] = @intCast(len);
    out[3] = 1;
    out[4] = 0;
    @memcpy(out[5 .. 5 + name.len], name);
    if (total & 1 != 0) out[total] = 0;
    return len;
}

// One directory record: 33-byte header, stored name, even-name padding,
// then the Rock Ridge system-use area.
fn writeDirRecord(
    block: []u8,
    pos: *usize,
    extent: u32,
    size: u32,
    directory: bool,
    stored_name: []const u8,
    stored_name_len: u8,
    rr_name: ?[]const u8,
    serial: u32,
) Failure!void {
    var sua: [320]u8 = undefined;
    var sua_len: usize = 0;
    // A PX mode there would override the directory mode and hide every child.
    // The dot record carries only SUSP and ER.

    // The dot-dot record carries nothing.

    // The dot-dot record carries nothing.
    if (directory and stored_name_len == 1 and stored_name[0] == 0) {
        sua_len += writeRrSp(&sua);
        sua_len += writeRrEr(sua[sua_len..]);
    } else if (!(directory and stored_name_len == 1 and stored_name[0] == 1)) {
        sua_len += writeRrPx(sua[sua_len..], serial);
        if (rr_name) |name| sua_len += writeRrNm(sua[sua_len..], name);
    }
    // Directory records are even length; zero-pad an odd system-use area.
    if (sua_len & 1 != 0) {
        sua[sua_len] = 0;
        sua_len += 1;
    }
    const pad: usize = if (stored_name_len & 1 == 0) 1 else 0;
    const record_len = 33 + stored_name_len + pad + sua_len;
    if (record_len > 255) return error.UnsupportedFailure;
    const at = pos.*;
    writeBaseRecord(block[at .. at + 34], extent, size, directory, stored_name_len, stored_name[0]);
    block[at] = @intCast(record_len);
    var off = at + 33;
    @memcpy(block[off .. off + stored_name_len], stored_name);
    off += stored_name_len;
    if (pad != 0) {
        block[off] = 0;
        off += 1;
    }
    @memcpy(block[off .. off + sua_len], sua[0..sua_len]);
    pos.* = at + record_len;
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    _ = scratch;
    const lay = try layoutEntries(entries);
    if (output.len < lay.total) return error.CapacityFailure;
    @memset(output[0..lay.total], 0);
    writePvd(output[16 * sector_size ..][0..sector_size], &lay);
    const vdst = output[17 * sector_size ..][0..sector_size];
    @memset(vdst, 0);
    vdst[0] = descriptor_terminator;
    @memcpy(vdst[1..6], volume_descriptor_magic);
    vdst[6] = 1;
    writePathTable(output[18 * sector_size ..][0..sector_size], false);
    writePathTable(output[19 * sector_size ..][0..sector_size], true);
    var dir: [sector_size]u8 = undefined;
    @memset(&dir, 0);
    var pos: usize = 0;
    try writeDirRecord(&dir, &pos, dir_lba, @intCast(lay.dir_size), true, "\x00", 1, null, 1);
    try writeDirRecord(&dir, &pos, dir_lba, @intCast(lay.dir_size), true, "\x01", 1, null, 1);
    for (0..lay.count) |rank| {
        const entry = entries[lay.sorted[rank]];
        var stored: [252]u8 = undefined;
        if (entry.name.len + 2 > stored.len) return error.UnsupportedFailure;
        @memcpy(stored[0..entry.name.len], entry.name);
        stored[entry.name.len] = ';';
        stored[entry.name.len + 1] = '1';
        try writeDirRecord(&dir, &pos, lay.file_lba[rank], @intCast(entry.data.len), false, stored[0 .. entry.name.len + 2], @intCast(entry.name.len + 2), entry.name, @intCast(rank + 2));
    }
    @memcpy(output[20 * sector_size ..][0..sector_size], &dir);
    for (0..lay.count) |rank| {
        const entry = entries[lay.sorted[rank]];
        const at = std.math.mul(u64, lay.file_lba[rank], sector_size) catch return error.DataFailure;
        @memcpy(output[at .. at + entry.data.len], entry.data);
    }
    return @intCast(lay.total);
}

test "iso prefers a joliet supplementary descriptor" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello iso" },
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
    };
    var archive: [32 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    // Hand-built Joliet fixture: an SVD with the escape sequence.
    // It shares the primary descriptor's directory tree.
    const svd = archive[17 * sector_size ..][0..sector_size];
    @memcpy(svd[0..], archive[16 * sector_size ..][0..sector_size]);
    svd[0] = descriptor_supplementary;
    svd[88] = '%';
    svd[89] = '/';
    svd[90] = '@';
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello iso", out[0..n]);
}

test "iso store roundtrips flat files" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello iso" },
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
    };
    var archive: [32 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    const first = try inspectOrdinal(archive[0..written], 0, &scratch);
    try testing.expectEqual(@as(u64, 12), first.size);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello iso", out[0..n]);
}
