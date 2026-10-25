const std = @import("std");

const entry_prim = @import("../../../common/entry.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");

pub const Entry = entry_prim.Entry;
const Exception = exception_prim.Exception;

const block_size: u64 = 512;
pub const scratch_size: usize = @intCast(block_size);
pub const typeflag_regular: u8 = '0';
const typeflag_gnu_long_name: u8 = 'L';
const typeflag_gnu_long_link: u8 = 'K';
const typeflag_gnu_sparse: u8 = 'S';
const typeflag_pax: u8 = 'x';
const typeflag_global_pax: u8 = 'g';
const max_sparse_segments = 1024;

pub const SparseSegment = struct {
    offset: u64,
    num_bytes: u64,
};

pub const SparseInfo = struct {
    realsize: u64,
    segment_count: usize,
    segments: [max_sparse_segments]SparseSegment,
};

pub const EntryInfo = struct {
    name: []const u8,
    prefix: []const u8,
    link_name: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    sparse: ?SparseInfo = null,
    modification_time: u64,
    typeflag: u8,
    devmajor: u32,
    devminor: u32,
    ordinal: u64,
    header_offset: u64,
    data_offset: u64,
};

const NameParts = struct {
    name: []const u8,
    prefix: []const u8,
    uses_long_name: bool,
};

pub const Format = enum { posix, gnu };

pub fn archiveSize(entries: []const Entry) Exception!u64 {
    return archiveSizeWith(.posix, entries);
}

pub fn archiveSizeGnu(entries: []const Entry) Exception!u64 {
    return archiveSizeWith(.gnu, entries);
}

fn archiveSizeWith(comptime format: Format, entries: []const Entry) Exception!u64 {
    var counter = CountSink{};
    var scratch: [scratch_size]u8 = undefined;
    try layout(format, entries, &counter, &scratch);
    return counter.total;
}

// Size and bytes come from one traversal, so the two cannot disagree
// about a header, a long-name entry, or padding.
const CountSink = struct {
    total: u64 = 0,

    fn write(self: *CountSink, bytes: []const u8) Exception!void {
        self.total = try bounds.addU64(self.total, bytes.len);
    }
};

fn layout(comptime format: Format, entries: []const Entry, sink: anytype, scratch: []u8) Exception!void {
    for (entries) |entry| {
        const parts = try tarNameParts(entry.name);
        if (std.mem.findScalar(u8, entry.link_name, 0) != null) return error.CallException;
        if ((entry.typeflag == '1' or entry.typeflag == '2') and entry.link_name.len == 0) return error.CallException;
        const data_size = try tarDataSize(entry.typeflag, entry.data);
        if (format == .posix) {
            var numbers: [5][32]u8 = undefined;
            var records: [7]PaxRecord = undefined;
            const record_count = paxRecords(entry, data_size, parts.uses_long_name, &numbers, &records);
            var pax_len: u64 = 0;
            for (records[0..record_count]) |record| pax_len = try bounds.addU64(pax_len, paxRecordLen(record.key, record.text));
            if (pax_len > 0) {
                try tarWriteHeader(.posix, sink, scratch, "././@PaxHeader", &.{}, &.{}, 0o644, 0, 0, 0, typeflag_pax, pax_len, 0, 0);
                for (records[0..record_count]) |record| try paxWriteRecord(sink, record.key, record.text);
                try tarWritePadding(sink, scratch, pax_len);
            }
            try tarWriteHeader(.posix, sink, scratch, parts.name, parts.prefix, if (entry.link_name.len > 100) &.{} else entry.link_name, entry.mode, entry.uid, entry.gid, entry.modification_time, entry.typeflag, data_size, entry.devmajor, entry.devminor);
        } else {
            if (entry.name.len > 100) {
                const long_size: u64 = @as(u64, entry.name.len) + 1;
                try tarWriteHeader(.gnu, sink, scratch, "././@LongLink", &.{}, &.{}, 0o644, 0, 0, 0, typeflag_gnu_long_name, long_size, 0, 0);
                try sink.write(entry.name);
                try sink.write("\x00");
                try tarWritePadding(sink, scratch, long_size);
            }
            if (entry.link_name.len > 100) {
                const long_size: u64 = @as(u64, entry.link_name.len) + 1;
                try tarWriteHeader(.gnu, sink, scratch, "././@LongLink", &.{}, &.{}, 0o644, 0, 0, 0, typeflag_gnu_long_link, long_size, 0, 0);
                try sink.write(entry.link_name);
                try sink.write("\x00");
                try tarWritePadding(sink, scratch, long_size);
            }
            try tarWriteHeader(.gnu, sink, scratch, parts.name, &.{}, if (entry.link_name.len > 100) &.{} else entry.link_name, entry.mode, entry.uid, entry.gid, entry.modification_time, entry.typeflag, data_size, entry.devmajor, entry.devminor);
        }
        try sink.write(entry.data);
        try tarWritePadding(sink, scratch, data_size);
    }
    @memset(scratch[0..scratch_size], 0);
    try sink.write(scratch[0..scratch_size]);
    try sink.write(scratch[0..scratch_size]);
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return encodeWith(.posix, entries, output, scratch);
}

// GNU variant: the "ustar  \0" magic and 'L'/'K' long-name entries
// instead of pax records.
pub fn encodeGnu(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return encodeWith(.gnu, entries, output, scratch);
}

fn encodeWith(comptime format: Format, entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    if (scratch.len < scratch_size) return error.CapacityException;
    var sink = io.Sink{ .bytes = output };
    try layout(format, entries, &sink, scratch);
    return sink.offset;
}

const PaxRecord = struct { key: []const u8, text: []const u8 };

fn decimal(buffer: *[32]u8, value: u64) []const u8 {
    var count: usize = 0;
    var remaining = value;
    while (true) {
        buffer[count] = '0' + @as(u8, @truncate(remaining % 10));
        count += 1;
        remaining /= 10;
        if (remaining == 0) break;
    }
    var index: usize = 0;
    while (index < count / 2) : (index += 1) {
        const swap = buffer[index];
        buffer[index] = buffer[count - 1 - index];
        buffer[count - 1 - index] = swap;
    }
    return buffer[0..count];
}

// One list decides which fields need a pax record; size and write passes
// both read it, so they cannot drift.
fn paxRecords(entry: Entry, data_size: u64, uses_long_name: bool, numbers: *[5][32]u8, out: *[7]PaxRecord) usize {
    var count: usize = 0;
    if (uses_long_name) {
        out[count] = .{ .key = "path", .text = entry.name };
        count += 1;
    }
    if (entry.link_name.len > 100) {
        out[count] = .{ .key = "linkpath", .text = entry.link_name };
        count += 1;
    }
    if (entry.mode > 0o7777777) {
        out[count] = .{ .key = "mode", .text = decimal(&numbers[0], entry.mode) };
        count += 1;
    }
    if (entry.uid > 0o7777777) {
        out[count] = .{ .key = "uid", .text = decimal(&numbers[1], entry.uid) };
        count += 1;
    }
    if (entry.gid > 0o7777777) {
        out[count] = .{ .key = "gid", .text = decimal(&numbers[2], entry.gid) };
        count += 1;
    }
    if (data_size > 0o7777777777) {
        out[count] = .{ .key = "size", .text = decimal(&numbers[3], data_size) };
        count += 1;
    }
    if (entry.modification_time > 0o7777777777) {
        out[count] = .{ .key = "mtime", .text = decimal(&numbers[4], entry.modification_time) };
        count += 1;
    }
    return count;
}

fn paxRecordLen(key: []const u8, text: []const u8) u64 {
    const content_len = key.len + 1 + text.len + 1;
    return @as(u64, paxPrefixLen(content_len)) + 1 + content_len;
}

fn paxPrefixLen(content_len: usize) usize {
    var len_count: usize = 1;
    while (true) {
        const total_est = len_count + 1 + content_len;
        var m = total_est;
        var count: usize = 0;
        while (true) {
            count += 1;
            m /= 10;
            if (m == 0) break;
        }
        if (count == len_count) break;
        len_count = count;
    }
    return len_count;
}

fn paxWriteRecord(sink: anytype, key: []const u8, text: []const u8) Exception!void {
    const content_len = key.len + 1 + text.len + 1;
    const len_count = paxPrefixLen(content_len);
    var digits: [20]u8 = undefined;
    var remaining = len_count + 1 + content_len;
    var index = len_count;
    while (index > 0) {
        index -= 1;
        digits[index] = '0' + @as(u8, @truncate(remaining % 10));
        remaining /= 10;
    }
    try sink.write(digits[0..len_count]);
    try sink.write(" ");
    try sink.write(key);
    try sink.write("=");
    try sink.write(text);
    try sink.write("\n");
}

pub fn inspectCount(archive: []const u8) Exception!u64 {
    var reader = Reader{ .archive = archive };
    var count: u64 = 0;
    while (try reader.next()) |_| count = try bounds.addU64(count, 1);
    return count;
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64) Exception!EntryInfo {
    var reader = Reader{ .archive = archive };
    while (try reader.next()) |entry| {
        if (entry.ordinal == ordinal) return entry;
    }
    return error.DataException;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8) Exception!usize {
    const entry = try inspectOrdinal(archive, ordinal);
    const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;
    if (entry.sparse) |sparse| {
        if (size == 0) return 0;
        @memset(output[0..size], 0);
        var stream_offset: u64 = 0;
        for (sparse.segments[0..sparse.segment_count]) |segment| {
            const start = std.math.cast(usize, segment.offset) orelse return error.DataException;
            const count = std.math.cast(usize, segment.num_bytes) orelse return error.DataException;
            if (start > size or count > size - start) return error.DataException;
            const chunk = try bounds.slice(archive, try bounds.addU64(entry.data_offset, stream_offset), count);
            @memcpy(output[start..][0..count], chunk);
            stream_offset = try bounds.addU64(stream_offset, segment.num_bytes);
        }
        return size;
    }
    const data = try bounds.slice(archive, entry.data_offset, entry.size);
    @memcpy(output[0..size], data);
    return size;
}

fn isZeroBlock(block: []const u8) bool {
    return std.mem.allEqual(u8, block, 0);
}

fn tarAligned(size: u64) Exception!u64 {
    const remainder = size % block_size;
    return if (remainder == 0) size else bounds.addU64(size, block_size - remainder);
}

fn tarField(field: []const u8) []const u8 {
    return field[0 .. std.mem.findScalar(u8, field, 0) orelse field.len];
}

fn tarNumber(field: []const u8) Exception!u64 {
    if (field.len == 0) return error.DataException;
    if (field[0] & 0x80 != 0) {
        if (field[0] & 0x40 != 0) return error.DataException;
        var value: u64 = field[0] & 0x7f;
        for (field[1..]) |byte| {
            value = std.math.mul(u64, value, 256) catch return error.DataException;
            value = std.math.add(u64, value, byte) catch return error.DataException;
        }
        return value;
    }
    var start: usize = 0;
    while (start < field.len and (field[start] == ' ' or field[start] == 0)) : (start += 1) {}
    if (start == field.len) return 0;
    var value: u64 = 0;
    var index = start;
    while (index < field.len and field[index] >= '0' and field[index] <= '7') : (index += 1) {
        value = std.math.mul(u64, value, 8) catch return error.DataException;
        value = std.math.add(u64, value, field[index] - '0') catch return error.DataException;
    }
    if (index == start) return error.DataException;
    while (index < field.len) : (index += 1) {
        if (field[index] != 0 and field[index] != ' ') return error.DataException;
    }
    return value;
}

fn tarWriteNumber(field: []u8, value: u64) void {
    @memset(field, 0);
    const octal_bits = (field.len - 1) * 3;
    if (octal_bits < 64 and value < (@as(u64, 1) << @intCast(octal_bits))) {
        var remaining = value;
        var index = field.len - 1;
        while (index > 0) {
            index -= 1;
            field[index] = '0' + @as(u8, @truncate(remaining & 7));
            remaining >>= 3;
        }
        return;
    }
    var remaining = value;
    var index = field.len;
    while (index > 1) {
        index -= 1;
        field[index] = @truncate(remaining);
        remaining >>= 8;
    }
    field[0] = 0x80 | @as(u8, @truncate(remaining));
}

fn tarWriteField(field: []u8, value: []const u8) void {
    @memset(field, 0);
    @memcpy(field[0..value.len], value);
}

fn tarChecksum(block: []const u8) u64 {
    var sum: u64 = 0;
    for (block, 0..) |byte, index| sum += if (index >= 148 and index < 156) ' ' else byte;
    return sum;
}

fn tarValidName(name: []const u8) Exception!void {
    if (bounds.isAbsoluteOrTraversal(name) or std.mem.findScalar(u8, name, 0) != null) return error.CallException;
    const trimmed = if (name[name.len - 1] == '/') name[0 .. name.len - 1] else name;
    if (trimmed.len == 0) return error.CallException;
    var components = std.mem.splitScalar(u8, trimmed, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.CallException;
    }
}

fn tarNameParts(name: []const u8) Exception!NameParts {
    try tarValidName(name);
    if (name.len <= 100) return .{ .name = name, .prefix = &.{}, .uses_long_name = false };
    var index = name.len;
    while (index != 0) {
        index -= 1;
        if (name[index] != '/') continue;
        if (index <= 155 and name.len - index - 1 > 0 and name.len - index - 1 <= 100) {
            return .{ .name = name[index + 1 ..], .prefix = name[0..index], .uses_long_name = false };
        }
    }
    return .{ .name = "././@LongLink", .prefix = &.{}, .uses_long_name = true };
}

fn tarDataSize(typeflag: u8, data: []const u8) Exception!u64 {
    return switch (typeflag) {
        0, typeflag_regular, '7' => data.len,
        '1', '2', '3', '4', '5', '6' => if (data.len == 0) 0 else error.CallException,
        else => error.CallException,
    };
}

// Formats one 512-byte header block; the streaming driver and the slice
// encode share it, so both emit byte-identical headers.
pub fn formatHeaderBlock(format: Format, name: []const u8, prefix: []const u8, link_name: []const u8, mode: u32, uid: u32, gid: u32, modification_time: u64, typeflag: u8, size: u64, devmajor: u32, devminor: u32, out: *[512]u8) Exception!void {
    var block: [512]u8 = undefined;
    var sink = io.Sink{ .bytes = out[0..512] };
    try tarWriteHeader(format, &sink, &block, name, prefix, link_name, mode, uid, gid, modification_time, typeflag, size, devmajor, devminor);
}

// The driver reads the data length back from the emitted header; octal
// or GNU base-256, same as the slice reader.
pub fn parseHeaderDataSize(block: *const [512]u8) Exception!u64 {
    return tarNumber(block[124..136]);
}

fn tarWriteHeader(format: Format, sink: anytype, scratch: []u8, name: []const u8, prefix: []const u8, link_name: []const u8, mode: u32, uid: u32, gid: u32, modification_time: u64, typeflag: u8, size: u64, devmajor: u32, devminor: u32) Exception!void {
    if (scratch.len < scratch_size) return error.CapacityException;
    const block = scratch[0..scratch_size];
    @memset(block, 0);
    tarWriteField(block[0..100], name);
    tarWriteNumber(block[100..108], mode);
    tarWriteNumber(block[108..116], uid);
    tarWriteNumber(block[116..124], gid);
    tarWriteNumber(block[124..136], size);
    tarWriteNumber(block[136..148], modification_time);
    block[156] = typeflag;
    tarWriteField(block[157..257], link_name);
    if (format == .posix) {
        tarWriteField(block[257..263], "ustar");
        tarWriteField(block[263..265], "00");
    } else {
        tarWriteField(block[257..265], "ustar  ");
    }
    if (typeflag == '3' or typeflag == '4') {
        tarWriteNumber(block[329..337], devmajor);
        tarWriteNumber(block[337..345], devminor);
    }
    if (format == .posix) tarWriteField(block[345..500], prefix);
    tarSealHeader(block);
    try sink.write(block);
}

// The checksum field carries six octal digits, a NUL, and a space.
fn tarSealHeader(block: *[512]u8) void {
    var checksum = tarChecksum(block);
    var index: usize = 154;
    while (index > 148) {
        index -= 1;
        block[index] = '0' + @as(u8, @truncate(checksum & 7));
        checksum >>= 3;
    }
    block[154] = 0;
    block[155] = ' ';
}

fn tarWritePadding(sink: anytype, scratch: []u8, size: u64) Exception!void {
    const padding = (block_size - size % block_size) % block_size;
    if (padding != 0) {
        if (scratch.len < scratch_size) return error.CapacityException;
        @memset(scratch[0..scratch_size], 0);
        try sink.write(scratch[0..@intCast(padding)]);
    }
}

const Pax = struct {
    path: ?[]const u8 = null,
    link_name: ?[]const u8 = null,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    size: ?u64 = null,
    modification_time: ?u64 = null,
    sparse_major: ?u64 = null,
    sparse_minor: ?u64 = null,
    sparse_name: ?[]const u8 = null,
    sparse_size: ?u64 = null,
    sparse_realsize: ?u64 = null,
    sparse_numblocks: ?u64 = null,
    sparse_map: ?[]const u8 = null,
    sparse_pax: ?[]const u8 = null,
};

const Reader = struct {
    archive: []const u8,
    offset: u64 = 0,
    ordinal: u64 = 0,
    long_name: ?[]const u8 = null,
    long_link: ?[]const u8 = null,
    global_pax: Pax = .{},
    local_pax: Pax = .{},

    fn readHeader(self: *Reader) Exception!EntryInfo {
        const header = try bounds.slice(self.archive, self.offset, block_size);
        const recorded_checksum = try tarNumber(header[148..156]);
        if (recorded_checksum != tarChecksum(header)) return error.IntegrityException;
        const size = try tarNumber(header[124..136]);
        const data_offset = try bounds.addU64(self.offset, block_size);
        // Device fields are ustar-only; V7 carries unrelated data.
        // The prefix is POSIX-only; GNU stores atime and ctime in its place.
        const ustar = std.mem.eql(u8, header[257..262], "ustar");
        const posix = ustar and std.mem.eql(u8, header[263..265], "00");
        return .{
            .name = tarField(header[0..100]),
            .prefix = if (posix) tarField(header[345..500]) else &.{},
            .link_name = tarField(header[157..257]),
            .mode = std.math.cast(u32, try tarNumber(header[100..108])) orelse return error.DataException,
            .uid = std.math.cast(u32, try tarNumber(header[108..116])) orelse return error.DataException,
            .gid = std.math.cast(u32, try tarNumber(header[116..124])) orelse return error.DataException,
            .size = size,
            .modification_time = try tarNumber(header[136..148]),
            .typeflag = header[156],
            .devmajor = if (ustar) std.math.cast(u32, try tarNumber(header[329..337])) orelse return error.DataException else 0,
            .devminor = if (ustar) std.math.cast(u32, try tarNumber(header[337..345])) orelse return error.DataException else 0,
            .ordinal = 0,
            .header_offset = self.offset,
            .data_offset = data_offset,
        };
    }

    fn advance(self: *Reader, size: u64) Exception!void {
        self.offset = try bounds.addU64(try bounds.addU64(self.offset, block_size), try tarAligned(size));
        if (self.offset > self.archive.len) return error.DataException;
    }

    fn parseOldGnuSparse(self: *Reader, entry: *EntryInfo) Exception!SparseInfo {
        var info = SparseInfo{ .realsize = 0, .segment_count = 0, .segments = undefined };
        const header = try bounds.slice(self.archive, entry.header_offset, block_size);
        info.realsize = try tarNumber(header[483..495]);
        var chunk_sum: u64 = 0;
        try parseSparseEntries(&info, &chunk_sum, header[386..482], 4);
        var is_extended = header[482];
        var extension_blocks: u64 = 0;
        var extension_offset = try bounds.addU64(entry.header_offset, block_size);
        while (is_extended != 0) {
            const extension = try bounds.slice(self.archive, extension_offset, block_size);
            try parseSparseEntries(&info, &chunk_sum, extension[0..504], 21);
            is_extended = extension[504];
            extension_blocks += 1;
            extension_offset = try bounds.addU64(extension_offset, block_size);
        }
        if (chunk_sum != entry.size) return error.DataException;
        if (info.realsize == 0) {
            for (info.segments[0..info.segment_count]) |segment| {
                info.realsize = @max(info.realsize, try bounds.addU64(segment.offset, segment.num_bytes));
            }
        }
        try validateSparseInfo(info);
        entry.data_offset = try bounds.addU64(entry.header_offset, (extension_blocks + 1) * block_size);
        self.offset = try bounds.addU64(entry.data_offset, try tarAligned(entry.size));
        if (self.offset > self.archive.len) return error.DataException;
        return info;
    }

    fn sparseFromPax(self: *Reader, entry: *EntryInfo, pax: Pax) Exception!?SparseInfo {
        if (pax.sparse_major == null and pax.sparse_size == null and pax.sparse_realsize == null and pax.sparse_map == null and pax.sparse_pax == null) return null;
        // Every branch assigns info wholesale before any field is read, so undefined init is safe.
        var info: SparseInfo = undefined;
        const realsize = pax.sparse_realsize orelse pax.sparse_size orelse return error.DataException;
        if (pax.sparse_map) |map| {
            info = try parseSparseMapString(map, realsize);
        } else if (pax.sparse_pax) |pax_data| {
            info = try parseSparsePaxPairs(pax_data, realsize);
        } else {
            info = .{ .realsize = realsize, .segment_count = 0, .segments = undefined };
        }
        if (pax.sparse_major) |major| {
            if (major != 1) return error.UnsupportedException;
            const minor = pax.sparse_minor orelse return error.DataException;
            if (minor != 0) return error.UnsupportedException;
            const map_start = entry.data_offset;
            const map_bytes = try readSparseMapData(self.archive, map_start, &info);
            const map_padded = try tarAligned(map_bytes);
            entry.data_offset = try bounds.addU64(entry.data_offset, map_padded);
            if (entry.size < map_padded) return error.DataException;
            entry.size -= map_padded;
        }
        if (pax.sparse_numblocks) |count| {
            if (count != info.segment_count) return error.DataException;
        }
        try validateSparseInfo(info);
        if (pax.sparse_name) |name| {
            entry.name = name;
            entry.prefix = &.{};
        }
        entry.sparse = info;
        return info;
    }

    fn next(self: *Reader) Exception!?EntryInfo {
        while (self.offset < self.archive.len) {
            const block = try bounds.slice(self.archive, self.offset, block_size);
            if (isZeroBlock(block)) {
                const remaining = try bounds.slice(self.archive, self.offset, self.archive.len - @as(usize, @intCast(self.offset)));
                if (remaining.len < 1024 or !isZeroBlock(remaining)) return error.DataException;
                return null;
            }
            var entry = try self.readHeader();
            const physical_size = entry.size;
            const data = try bounds.slice(self.archive, entry.data_offset, physical_size);
            switch (entry.typeflag) {
                typeflag_gnu_long_name => {
                    if (self.long_name != null) return error.DataException;
                    self.long_name = tarField(data);
                    try self.advance(physical_size);
                },
                typeflag_gnu_long_link => {
                    if (self.long_link != null) return error.DataException;
                    self.long_link = tarField(data);
                    try self.advance(physical_size);
                },
                typeflag_pax => {
                    if (!tarPaxEmpty(self.local_pax)) return error.DataException;
                    self.local_pax = try tarParsePax(data);
                    try self.advance(physical_size);
                },
                typeflag_global_pax => {
                    tarMergePax(&self.global_pax, try tarParsePax(data));
                    try self.advance(physical_size);
                },
                typeflag_gnu_sparse => {
                    const sparse = try self.parseOldGnuSparse(&entry);
                    entry.size = sparse.realsize;
                    entry.sparse = sparse;
                    if (self.long_name) |name| {
                        entry.name = name;
                        entry.prefix = &.{};
                    }
                    if (self.long_link) |link_name| entry.link_name = link_name;
                    try tarValidateEntryName(entry);
                    entry.ordinal = self.ordinal;
                    self.ordinal = try bounds.addU64(self.ordinal, 1);
                    self.long_name = null;
                    self.long_link = null;
                    self.local_pax = .{};
                    return entry;
                },
                else => {
                    try tarValidateType(entry.typeflag);
                    try tarApplyPax(&entry, self.global_pax);
                    try tarApplyPax(&entry, self.local_pax);
                    const sparse = if (self.local_pax.sparse_major != null or self.local_pax.sparse_size != null or self.local_pax.sparse_realsize != null or self.local_pax.sparse_map != null or self.local_pax.sparse_pax != null)
                        try self.sparseFromPax(&entry, self.local_pax)
                    else if (self.global_pax.sparse_major != null or self.global_pax.sparse_size != null or self.global_pax.sparse_realsize != null or self.global_pax.sparse_map != null or self.global_pax.sparse_pax != null)
                        try self.sparseFromPax(&entry, self.global_pax)
                    else
                        null;
                    var advance_size = physical_size;
                    if (sparse) |info| {
                        entry.sparse = info;
                        entry.size = info.realsize;
                    } else if (self.local_pax.size != null or self.global_pax.size != null) {
                        advance_size = entry.size;
                        _ = try bounds.slice(self.archive, entry.data_offset, advance_size);
                    }
                    if (self.long_name) |name| {
                        entry.name = name;
                        entry.prefix = &.{};
                    }
                    if (self.long_link) |link_name| entry.link_name = link_name;
                    try tarValidateEntryName(entry);
                    entry.ordinal = self.ordinal;
                    self.ordinal = try bounds.addU64(self.ordinal, 1);
                    try self.advance(advance_size);
                    self.long_name = null;
                    self.long_link = null;
                    self.local_pax = .{};
                    return entry;
                },
            }
        }
        return error.DataException;
    }
};

fn parseSparseEntries(info: *SparseInfo, chunk_sum: *u64, bytes: []const u8, count: usize) Exception!void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const entry_bytes = bytes[index * 24 ..][0..24];
        const offset = try tarNumber(entry_bytes[0..12]);
        const num_bytes = try tarNumber(entry_bytes[12..24]);
        if (offset == 0 and num_bytes == 0) continue;
        try addSparseSegment(info, chunk_sum, offset, num_bytes);
    }
}

fn addSparseSegment(info: *SparseInfo, chunk_sum: *u64, offset: u64, num_bytes: u64) Exception!void {
    if (num_bytes == 0) return error.DataException;
    if (info.segment_count >= max_sparse_segments) return error.UnsupportedException;
    info.segments[info.segment_count] = .{ .offset = offset, .num_bytes = num_bytes };
    info.segment_count += 1;
    chunk_sum.* = try bounds.addU64(chunk_sum.*, num_bytes);
}

fn validateSparseInfo(info: SparseInfo) Exception!void {
    var previous_end: u64 = 0;
    for (info.segments[0..info.segment_count]) |segment| {
        if (segment.num_bytes == 0 or segment.offset < previous_end) return error.DataException;
        const end = try bounds.addU64(segment.offset, segment.num_bytes);
        if (end > info.realsize) return error.DataException;
        previous_end = end;
    }
}

fn parseSparseMapString(map: []const u8, realsize: u64) Exception!SparseInfo {
    var info = SparseInfo{ .realsize = realsize, .segment_count = 0, .segments = undefined };
    var chunk_sum: u64 = 0;
    var pending_offset: ?u64 = null;
    var tokens = std.mem.splitScalar(u8, map, ',');
    while (tokens.next()) |token| {
        const value = try tarDecimal(token);
        if (pending_offset) |offset| {
            try addSparseSegment(&info, &chunk_sum, offset, value);
            pending_offset = null;
        } else {
            pending_offset = value;
        }
    }
    if (pending_offset != null) return error.DataException;
    return info;
}

fn parseSparsePaxPairs(data: []const u8, realsize: u64) Exception!SparseInfo {
    var info = SparseInfo{ .realsize = realsize, .segment_count = 0, .segments = undefined };
    var chunk_sum: u64 = 0;
    var offset: usize = 0;
    var pending_offset: ?u64 = null;
    while (offset < data.len) {
        const length_start = offset;
        while (offset < data.len and data[offset] >= '0' and data[offset] <= '9') : (offset += 1) {}
        if (offset == length_start or offset == data.len or data[offset] != ' ') return error.DataException;
        const record_length = try tarDecimal(data[length_start..offset]);
        const length = std.math.cast(usize, record_length) orelse return error.ResourceException;
        if (length > data.len - length_start or length <= offset - length_start + 2) return error.DataException;
        const record = data[length_start .. length_start + length];
        if (record[record.len - 1] != '\n') return error.DataException;
        const assignment = record[offset - length_start + 1 .. record.len - 1];
        const equals = std.mem.findScalar(u8, assignment, '=') orelse return error.DataException;
        const key = assignment[0..equals];
        const value = assignment[equals + 1 ..];
        if (std.mem.eql(u8, key, "GNU.sparse.offset")) {
            if (pending_offset != null) return error.DataException;
            pending_offset = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.numbytes")) {
            const segment_offset = pending_offset orelse return error.DataException;
            try addSparseSegment(&info, &chunk_sum, segment_offset, try tarDecimal(value));
            pending_offset = null;
        }
        offset = length_start + length;
    }
    if (pending_offset != null) return error.DataException;
    return info;
}

fn readSparseMapData(archive: []const u8, start: u64, info: *SparseInfo) Exception!u64 {
    var offset = start;
    const count = try readSparseLine(archive, &offset);
    if (count > max_sparse_segments) return error.UnsupportedException;
    var chunk_sum: u64 = 0;
    var index: u64 = 0;
    while (index < count) : (index += 1) {
        const segment_offset = try readSparseLine(archive, &offset);
        const num_bytes = try readSparseLine(archive, &offset);
        try addSparseSegment(info, &chunk_sum, segment_offset, num_bytes);
    }
    if (count != info.segment_count) return error.DataException;
    return offset - start;
}

fn readSparseLine(archive: []const u8, offset: *u64) Exception!u64 {
    var value: u64 = 0;
    var digits: usize = 0;
    while (true) {
        if (offset.* >= archive.len) return error.DataException;
        const byte = archive[@intCast(offset.*)];
        offset.* += 1;
        if (byte == '\n') {
            if (digits == 0) return error.DataException;
            return value;
        }
        if (byte < '0' or byte > '9') return error.DataException;
        digits += 1;
        value = std.math.mul(u64, value, 10) catch return error.DataException;
        value = std.math.add(u64, value, byte - '0') catch return error.DataException;
    }
}

// Decode-side parity with ZIP: refuse traversal, absolute, backslash, and
// embedded-NUL member names.
fn tarValidateEntryName(entry: EntryInfo) Exception!void {
    if (bounds.isAbsoluteOrTraversal(entry.name) or (entry.prefix.len > 0 and bounds.isAbsoluteOrTraversal(entry.prefix)) or std.mem.findScalar(u8, entry.name, 0) != null) return error.DataException;
}

fn tarValidateType(typeflag: u8) Exception!void {
    switch (typeflag) {
        0, typeflag_regular, '1', '2', '3', '4', '5', '6', '7' => {},
        else => return error.UnsupportedException,
    }
}

fn tarPaxEmpty(attributes: Pax) bool {
    return attributes.path == null and attributes.link_name == null and attributes.mode == null and attributes.uid == null and attributes.gid == null and attributes.size == null and attributes.modification_time == null and attributes.sparse_major == null and attributes.sparse_minor == null and attributes.sparse_name == null and attributes.sparse_size == null and attributes.sparse_realsize == null and attributes.sparse_numblocks == null and attributes.sparse_map == null and attributes.sparse_pax == null;
}

fn tarMergePax(target: *Pax, updates: Pax) void {
    if (updates.path) |value| target.path = value;
    if (updates.link_name) |value| target.link_name = value;
    if (updates.mode) |value| target.mode = value;
    if (updates.uid) |value| target.uid = value;
    if (updates.gid) |value| target.gid = value;
    if (updates.size) |value| target.size = value;
    if (updates.modification_time) |value| target.modification_time = value;
    if (updates.sparse_major) |value| target.sparse_major = value;
    if (updates.sparse_minor) |value| target.sparse_minor = value;
    if (updates.sparse_name) |value| target.sparse_name = value;
    if (updates.sparse_size) |value| target.sparse_size = value;
    if (updates.sparse_realsize) |value| target.sparse_realsize = value;
    if (updates.sparse_numblocks) |value| target.sparse_numblocks = value;
    if (updates.sparse_map) |value| target.sparse_map = value;
    if (updates.sparse_pax) |value| target.sparse_pax = value;
}

fn tarDecimal(value: []const u8) Exception!u64 {
    if (value.len == 0) return error.DataException;
    var result: u64 = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.DataException;
        result = std.math.mul(u64, result, 10) catch return error.DataException;
        result = std.math.add(u64, result, byte - '0') catch return error.DataException;
    }
    return result;
}

fn tarParsePax(data: []const u8) Exception!Pax {
    var attributes: Pax = .{};
    var offset: usize = 0;
    while (offset < data.len) {
        const length_start = offset;
        while (offset < data.len and data[offset] >= '0' and data[offset] <= '9') : (offset += 1) {}
        if (offset == length_start or offset == data.len or data[offset] != ' ') return error.DataException;
        const record_length = try tarDecimal(data[length_start..offset]);
        const length = std.math.cast(usize, record_length) orelse return error.ResourceException;
        if (length > data.len - length_start or length <= offset - length_start + 2) return error.DataException;
        const record = data[length_start .. length_start + length];
        if (record[record.len - 1] != '\n') return error.DataException;
        const assignment = record[offset - length_start + 1 .. record.len - 1];
        const equals = std.mem.findScalar(u8, assignment, '=') orelse return error.DataException;
        const key = assignment[0..equals];
        const value = assignment[equals + 1 ..];
        if (std.mem.eql(u8, key, "path")) {
            if (attributes.path != null) return error.DataException;
            attributes.path = value;
        } else if (std.mem.eql(u8, key, "linkpath")) {
            if (attributes.link_name != null) return error.DataException;
            attributes.link_name = value;
        } else if (std.mem.eql(u8, key, "size")) {
            if (attributes.size != null) return error.DataException;
            attributes.size = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "uid")) {
            if (attributes.uid != null) return error.DataException;
            attributes.uid = std.math.cast(u32, try tarDecimal(value)) orelse return error.DataException;
        } else if (std.mem.eql(u8, key, "gid")) {
            if (attributes.gid != null) return error.DataException;
            attributes.gid = std.math.cast(u32, try tarDecimal(value)) orelse return error.DataException;
        } else if (std.mem.eql(u8, key, "mode")) {
            if (attributes.mode != null) return error.DataException;
            attributes.mode = std.math.cast(u32, try tarDecimal(value)) orelse return error.DataException;
        } else if (std.mem.eql(u8, key, "mtime")) {
            if (attributes.modification_time != null) return error.DataException;
            const seconds_end = std.mem.findScalar(u8, value, '.') orelse value.len;
            attributes.modification_time = try tarDecimal(value[0..seconds_end]);
        } else if (std.mem.eql(u8, key, "GNU.sparse.major")) {
            if (attributes.sparse_major != null) return error.DataException;
            attributes.sparse_major = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.minor")) {
            if (attributes.sparse_minor != null) return error.DataException;
            attributes.sparse_minor = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.name")) {
            if (attributes.sparse_name != null) return error.DataException;
            attributes.sparse_name = value;
        } else if (std.mem.eql(u8, key, "GNU.sparse.size")) {
            if (attributes.sparse_size != null) return error.DataException;
            attributes.sparse_size = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.realsize")) {
            if (attributes.sparse_realsize != null) return error.DataException;
            attributes.sparse_realsize = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.numblocks")) {
            if (attributes.sparse_numblocks != null) return error.DataException;
            attributes.sparse_numblocks = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.map")) {
            if (attributes.sparse_map != null) return error.DataException;
            attributes.sparse_map = value;
        } else if (std.mem.startsWith(u8, key, "GNU.sparse.offset") or std.mem.startsWith(u8, key, "GNU.sparse.numbytes")) {
            if (attributes.sparse_pax == null) attributes.sparse_pax = data;
        }
        offset = length_start + length;
    }
    return attributes;
}

fn tarApplyPax(entry: *EntryInfo, attributes: Pax) Exception!void {
    if (attributes.path) |path| {
        if (path.len == 0 or std.mem.findScalar(u8, path, 0) != null) return error.DataException;
        entry.name = path;
        entry.prefix = &.{};
    }
    if (attributes.link_name) |link_name| entry.link_name = link_name;
    if (attributes.mode) |mode| entry.mode = mode;
    if (attributes.uid) |uid| entry.uid = uid;
    if (attributes.gid) |gid| entry.gid = gid;
    if (attributes.size) |size| entry.size = size;
    if (attributes.modification_time) |modification_time| entry.modification_time = modification_time;
}

test "tar gnu format roundtrips long names through LongLink entries" {
    const testing = std.testing;
    var long_name: [140]u8 = undefined;
    @memset(&long_name, 'x');
    @memcpy(long_name[0..14], "gnu-long-name-");
    @memcpy(long_name[136..140], ".txt");
    const entries = [_]Entry{
        .{ .name = &long_name, .data = "gnu payload" },
        .{ .name = "plain.txt", .data = "plain payload" },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    const written = try encodeGnu(&entries, &archive, &scratch);
    // The GNU magic sits in the version bytes too.
    try testing.expectEqualSlices(u8, "ustar  \x00", archive[257..265]);
    const info = try inspectOrdinal(archive[0..written], 0);
    try testing.expectEqualSlices(u8, &long_name, info.name);
    var out: [16]u8 = undefined;
    const size = try decodeOrdinal(archive[0..written], 0, &out);
    try testing.expectEqualSlices(u8, "gnu payload", out[0..size]);
    const second = try inspectOrdinal(archive[0..written], 1);
    try testing.expectEqualSlices(u8, "plain.txt", second.name);
}

test "tar reads V7 headers without the ustar magic" {
    // V7 predates the magic, the prefix, and the device fields.
    // Those bytes carry unrelated data that must not be parsed.
    const testing = std.testing;
    var block: [512]u8 = @splat(0);
    const name = "v7file.txt";
    @memcpy(block[0..name.len], name);
    tarWriteNumber(block[100..108], 0o644);
    tarWriteNumber(block[108..116], 7);
    tarWriteNumber(block[116..124], 8);
    tarWriteNumber(block[124..136], 6);
    tarWriteNumber(block[136..148], 9);
    block[157] = 0;
    block[156] = 0;
    // Deliberately hostile prefix and device fields for a V7 reader.
    @memcpy(block[345..350], "9zzzz");
    @memcpy(block[329..334], "8yyyy");
    var checksum: u64 = 8 * ' ';
    for (block, 0..) |byte, index| {
        if (index < 148 or index >= 156) checksum += byte;
    }
    var index: usize = 154;
    while (index > 148) {
        index -= 1;
        block[index] = '0' + @as(u8, @truncate(checksum & 7));
        checksum >>= 3;
    }
    block[154] = 0;
    block[155] = ' ';
    var archive: [1024]u8 = @splat(0);
    @memcpy(archive[0..512], &block);
    @memcpy(archive[512..518], "v7data");
    const info = try inspectOrdinal(&archive, 0);
    try testing.expectEqualSlices(u8, name, info.name);
    try testing.expectEqualSlices(u8, "", info.prefix);
    try testing.expectEqual(@as(u64, 6), info.size);
    try testing.expectEqual(@as(u32, 0), info.devmajor);
    var out: [8]u8 = undefined;
    const size = try decodeOrdinal(&archive, 0, &out);
    try testing.expectEqualSlices(u8, "v7data", out[0..size]);
}

test "tar device entries roundtrip devmajor and devminor" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "dev/null", .data = &.{}, .typeflag = '3', .mode = 0o666, .devmajor = 1, .devminor = 3 },
        .{ .name = "regular.txt", .data = "hello", .typeflag = '0' },
    };
    var archive: [4096]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    const info = try inspectOrdinal(archive[0..written], 0);
    try testing.expectEqual(@as(u8, '3'), info.typeflag);
    try testing.expectEqual(@as(u32, 1), info.devmajor);
    try testing.expectEqual(@as(u32, 3), info.devminor);
    const plain = try inspectOrdinal(archive[0..written], 1);
    try testing.expectEqual(@as(u32, 0), plain.devmajor);
    try testing.expectEqual(@as(u32, 0), plain.devminor);
}

test "tar pax records roundtrip long names and out of octal fields" {
    const testing = std.testing;
    var long_name: [124]u8 = undefined;
    @memset(&long_name, 'a');
    const entries = [_]Entry{
        .{ .name = &long_name, .data = "long payload", .mode = 0o10000000, .uid = 0o20000000, .modification_time = 0o200000000000 },
        .{ .name = "regular.txt", .data = "hello" },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written]));
    const info = try inspectOrdinal(archive[0..written], 0);
    try testing.expectEqualSlices(u8, &long_name, info.name);
    try testing.expectEqual(@as(u32, 0o10000000), info.mode);
    try testing.expectEqual(@as(u32, 0o20000000), info.uid);
    try testing.expectEqual(@as(u64, 0o200000000000), info.modification_time);
    var out: [64]u8 = undefined;
    const size = try decodeOrdinal(archive[0..written], 0, &out);
    try testing.expectEqualStrings("long payload", out[0..size]);
}

test "tar pax records keep embedded newlines and equals signs in long names" {
    // Pax values are length-prefixed, so a path containing '\n' or '=' must
    // survive the record round trip untouched.
    const testing = std.testing;
    var long_name: [120]u8 = undefined;
    @memset(&long_name, 'a');
    long_name[40] = '\n';
    long_name[80] = '=';
    const entries = [_]Entry{
        .{ .name = &long_name, .data = "payload" },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    const info = try inspectOrdinal(archive[0..written], 0);
    try testing.expectEqualSlices(u8, &long_name, info.name);
    var out: [16]u8 = undefined;
    const size = try decodeOrdinal(archive[0..written], 0, &out);
    try testing.expectEqualStrings("payload", out[0..size]);
}

fn tarSealTestHeader(block: *[512]u8) void {
    var checksum = tarChecksum(block);
    var index: usize = 154;
    while (index > 148) {
        index -= 1;
        block[index] = '0' + @as(u8, @truncate(checksum & 7));
        checksum >>= 3;
    }
    block[154] = 0;
    block[155] = ' ';
}

test "tar posix prefix split stays inside the ustar header" {
    const testing = std.testing;
    var long_name: [151]u8 = undefined;
    @memset(&long_name, 'p');
    long_name[130] = '/';
    @memcpy(long_name[131..139], "leaf.txt");
    const entries = [_]Entry{
        .{ .name = &long_name, .data = "prefix payload" },
    };
    var archive: [4096]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(@as(u64, written), try archiveSize(&entries));
    try testing.expect(std.mem.indexOf(u8, archive[0..written], "path=") == null);
    const info = try inspectOrdinal(archive[0..written], 0);
    try testing.expectEqualSlices(u8, long_name[0..130], info.prefix);
    try testing.expectEqualSlices(u8, long_name[131..], info.name);
    var out: [16]u8 = undefined;
    const size = try decodeOrdinal(archive[0..written], 0, &out);
    try testing.expectEqualStrings("prefix payload", out[0..size]);
}

test "tar rejects unsafe ustar prefix fields" {
    const testing = std.testing;
    var block: [512]u8 = @splat(0);
    @memcpy(block[0..6], "ok.txt");
    tarWriteNumber(block[100..108], 0o644);
    tarWriteNumber(block[124..136], 3);
    block[156] = '0';
    @memcpy(block[257..262], "ustar");
    block[262] = 0;
    @memcpy(block[263..265], "00");
    @memcpy(block[345..352], "../evil");
    tarSealTestHeader(&block);
    var archive: [2560]u8 = @splat(0);
    @memcpy(archive[0..512], &block);
    @memcpy(archive[512..515], "abc");
    try testing.expectError(error.DataException, inspectOrdinal(&archive, 0));

    @memset(block[345..354], 0);
    @memcpy(block[345..354], "/abs/evil");
    tarSealTestHeader(&block);
    @memcpy(archive[0..512], &block);
    try testing.expectError(error.DataException, inspectOrdinal(&archive, 0));

    @memset(block[345..354], 0);
    @memcpy(block[345..352], "dir/sub");
    tarSealTestHeader(&block);
    @memcpy(archive[0..512], &block);
    const info = try inspectOrdinal(&archive, 0);
    try testing.expectEqualSlices(u8, "ok.txt", info.name);
    try testing.expectEqualSlices(u8, "dir/sub", info.prefix);
    var out: [4]u8 = undefined;
    const size = try decodeOrdinal(&archive, 0, &out);
    try testing.expectEqualStrings("abc", out[0..size]);
}
