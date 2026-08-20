const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");

const tar_block_size: u64 = 512;
pub const tar_scratch_size: usize = @intCast(tar_block_size);
const tar_type_regular: u8 = '0';
const tar_type_gnu_long_name: u8 = 'L';
const tar_type_gnu_long_link: u8 = 'K';
const tar_type_gnu_sparse: u8 = 'S';
const tar_type_pax: u8 = 'x';
const tar_type_global_pax: u8 = 'g';
const tar_type_gnu_sparse_extension: u8 = 'X';
const max_sparse_segments = 1024;

pub const SparseSegment = struct {
    offset: u64,
    num_bytes: u64,
};

pub const SparseInfo = struct {
    realsize: u64,
    segment_count: usize,
    segments: [max_sparse_segments]SparseSegment = undefined,
};

pub const TarEntry = struct {
    name: []const u8,
    data: []const u8,
    link_name: []const u8 = &.{},
    mode: u32 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    modification_time: u64 = 0,
    typeflag: u8 = tar_type_regular,
};

pub const TarEntryInfo = struct {
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
    ordinal: u64,
    header_offset: u64,
    data_offset: u64,
};

const TarNameParts = struct {
    name: []const u8,
    prefix: []const u8,
    uses_long_name: bool,
};

pub fn tarArchiveSize(entries: []const TarEntry) Failure!u64 {
    var total: u64 = 1024;
    for (entries) |entry| {
        const parts = try tarNameParts(entry.name);
        if (std.mem.indexOfScalar(u8, entry.link_name, 0) != null) return error.InvalidCall;
        if ((entry.typeflag == '1' or entry.typeflag == '2') and entry.link_name.len == 0) return error.InvalidCall;
        const data_size = try tarDataSize(entry.typeflag, entry.data);
        var pax_buffer: [512]u8 = undefined;
        const pax_len = try tarPaxRecords(entry, data_size, parts.uses_long_name, &pax_buffer);
        if (pax_len > 0) total = try bounds.add64(total, try bounds.add64(tar_block_size, try tarAligned(pax_len)));
        total = try bounds.add64(total, tar_block_size);
        total = try bounds.add64(total, try tarAligned(data_size));
    }
    return total;
}

pub fn tarEncode(entries: []const TarEntry, output: []u8, scratch: []u8) Failure!usize {
    const required = try tarArchiveSize(entries);
    if (output.len < required) return error.InsufficientCapacity;
    if (scratch.len < tar_scratch_size) return error.InsufficientCapacity;
    var sink = io.Sink{ .bytes = output };
    for (entries) |entry| {
        const parts = try tarNameParts(entry.name);
        if (std.mem.indexOfScalar(u8, entry.link_name, 0) != null) return error.InvalidCall;
        if ((entry.typeflag == '1' or entry.typeflag == '2') and entry.link_name.len == 0) return error.InvalidCall;
        const data_size = try tarDataSize(entry.typeflag, entry.data);
        var pax_buffer: [512]u8 = undefined;
        const pax_len = try tarPaxRecords(entry, data_size, parts.uses_long_name, &pax_buffer);
        if (pax_len > 0) {
            try tarWriteHeader(&sink, scratch, "././@PaxHeader", &.{}, &.{}, 0o644, 0, 0, 0, tar_type_pax, pax_len);
            try sink.write(pax_buffer[0..pax_len]);
            try tarWritePadding(&sink, scratch, pax_len);
        }
        try tarWriteHeader(&sink, scratch, parts.name, parts.prefix, if (entry.link_name.len > 100) &.{} else entry.link_name, entry.mode, entry.uid, entry.gid, entry.modification_time, entry.typeflag, data_size);
        try sink.write(entry.data);
        try tarWritePadding(&sink, scratch, data_size);
    }
    @memset(scratch[0..tar_scratch_size], 0);
    try sink.write(scratch[0..tar_scratch_size]);
    try sink.write(scratch[0..tar_scratch_size]);
    return sink.offset;
}

fn tarPaxRecords(entry: TarEntry, data_size: u64, uses_long_name: bool, buffer: []u8) Failure!usize {
    var written: usize = 0;
    if (uses_long_name) written = try paxStringRecord(buffer, "path", entry.name);
    if (entry.link_name.len > 100) {
        written += try paxStringRecord(buffer[written..], "linkpath", entry.link_name);
    }
    if (entry.mode > 0o7777777) written += try paxNumberRecord(buffer[written..], "mode", entry.mode, 8);
    if (entry.uid > 0o7777777) {
        written += try paxNumberRecord(buffer[written..], "uid", entry.uid, 10);
    }
    if (entry.gid > 0o7777777) {
        written += try paxNumberRecord(buffer[written..], "gid", entry.gid, 10);
    }
    if (data_size > 0o7777777777) {
        written += try paxNumberRecord(buffer[written..], "size", data_size, 10);
    }
    if (entry.modification_time > 0o7777777777) {
        written += try paxNumberRecord(buffer[written..], "mtime", entry.modification_time, 10);
    }
    return written;
}

fn paxStringRecord(buffer: []u8, key: []const u8, value: []const u8) Failure!usize {
    const content_len = key.len + 1 + value.len + 1;
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
    var len_digits: [32]u8 = undefined;
    const total = len_count + 1 + content_len;
    var m = total;
    var len_index = len_count;
    while (true) {
        len_index -= 1;
        len_digits[len_index] = '0' + @as(u8, @truncate(m % 10));
        m /= 10;
        if (len_index == 0) break;
    }
    if (total > buffer.len) return error.InvalidCall;
    var pos: usize = 0;
    for (0..len_count) |i| {
        buffer[pos] = len_digits[i];
        pos += 1;
    }
    buffer[pos] = ' ';
    pos += 1;
    @memcpy(buffer[pos..][0..key.len], key);
    pos += key.len;
    buffer[pos] = '=';
    pos += 1;
    @memcpy(buffer[pos..][0..value.len], value);
    pos += value.len;
    buffer[pos] = '\n';
    pos += 1;
    return pos;
}

fn paxNumberRecord(buffer: []u8, key: []const u8, value: u64, base: u8) Failure!usize {
    var digits: [32]u8 = undefined;
    var n = value;
    var digit_count: usize = 0;
    while (true) {
        digits[digit_count] = "0123456789"[@intCast(n % base)];
        digit_count += 1;
        n /= base;
        if (n == 0) break;
    }
    const content_len = key.len + 1 + digit_count + 1;
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
    var len_digits: [32]u8 = undefined;
    const total = len_count + 1 + content_len;
    var m = total;
    var len_index = len_count;
    while (true) {
        len_index -= 1;
        len_digits[len_index] = '0' + @as(u8, @truncate(m % 10));
        m /= 10;
        if (len_index == 0) break;
    }
    if (total > buffer.len) return error.InvalidCall;
    var pos: usize = 0;
    for (0..len_count) |i| {
        buffer[pos] = len_digits[i];
        pos += 1;
    }
    buffer[pos] = ' ';
    pos += 1;
    @memcpy(buffer[pos..][0..key.len], key);
    pos += key.len;
    buffer[pos] = '=';
    pos += 1;
    while (digit_count > 0) {
        digit_count -= 1;
        buffer[pos] = digits[digit_count];
        pos += 1;
    }
    buffer[pos] = '\n';
    pos += 1;
    return pos;
}

pub fn tarInspectCount(archive: []const u8) Failure!u64 {
    var reader = TarReader{ .archive = archive };
    var count: u64 = 0;
    while (try reader.next()) |_| count = try bounds.add64(count, 1);
    return count;
}

pub fn tarInspectOrdinal(archive: []const u8, ordinal: u64) Failure!TarEntryInfo {
    var reader = TarReader{ .archive = archive };
    while (try reader.next()) |entry| {
        if (entry.ordinal == ordinal) return entry;
    }
    return error.InvalidData;
}

pub fn tarDecodeOrdinal(archive: []const u8, ordinal: u64, output: []u8) Failure!usize {
    const entry = try tarInspectOrdinal(archive, ordinal);
    const size = std.math.cast(usize, entry.size) orelse return error.ResourceLimit;
    if (output.len < size) return error.InsufficientCapacity;
    if (entry.sparse) |sparse| {
        if (size == 0) return 0;
        @memset(output[0..size], 0);
        var stream_offset: u64 = 0;
        for (sparse.segments[0..sparse.segment_count]) |segment| {
            const start = std.math.cast(usize, segment.offset) orelse return error.InvalidData;
            const count = std.math.cast(usize, segment.num_bytes) orelse return error.InvalidData;
            if (start > size or count > size - start) return error.InvalidData;
            const chunk = try bounds.slice(archive, try bounds.add64(entry.data_offset, stream_offset), count);
            @memcpy(output[start..][0..count], chunk);
            stream_offset = try bounds.add64(stream_offset, segment.num_bytes);
        }
        return size;
    }
    const data = try bounds.slice(archive, entry.data_offset, entry.size);
    @memcpy(output[0..size], data);
    return size;
}

fn tarIsZeroBlock(block: []const u8) bool {
    return std.mem.allEqual(u8, block, 0);
}

fn tarAligned(size: u64) Failure!u64 {
    const remainder = size % tar_block_size;
    return if (remainder == 0) size else bounds.add64(size, tar_block_size - remainder);
}

fn tarField(field: []const u8) []const u8 {
    return field[0 .. std.mem.indexOfScalar(u8, field, 0) orelse field.len];
}

fn tarNumber(field: []const u8) Failure!u64 {
    if (field.len == 0) return error.InvalidData;
    if (field[0] & 0x80 != 0) {
        if (field[0] & 0x40 != 0) return error.InvalidData;
        var value: u64 = field[0] & 0x7f;
        for (field[1..]) |byte| {
            value = std.math.mul(u64, value, 256) catch return error.InvalidData;
            value = std.math.add(u64, value, byte) catch return error.InvalidData;
        }
        return value;
    }
    var start: usize = 0;
    while (start < field.len and (field[start] == ' ' or field[start] == 0)) : (start += 1) {}
    if (start == field.len) return 0;
    var value: u64 = 0;
    var index = start;
    while (index < field.len and field[index] >= '0' and field[index] <= '7') : (index += 1) {
        value = std.math.mul(u64, value, 8) catch return error.InvalidData;
        value = std.math.add(u64, value, field[index] - '0') catch return error.InvalidData;
    }
    if (index == start) return error.InvalidData;
    while (index < field.len) : (index += 1) {
        if (field[index] != 0 and field[index] != ' ') return error.InvalidData;
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

fn tarValidName(name: []const u8) Failure!void {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidCall;
    if (name[0] == '/' or std.mem.indexOfScalar(u8, name, '\\') != null) return error.InvalidCall;
    const trimmed = if (name[name.len - 1] == '/') name[0 .. name.len - 1] else name;
    if (trimmed.len == 0) return error.InvalidCall;
    var components = std.mem.splitScalar(u8, trimmed, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidCall;
    }
}

fn tarNameParts(name: []const u8) Failure!TarNameParts {
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

fn tarDataSize(typeflag: u8, data: []const u8) Failure!u64 {
    return switch (typeflag) {
        0, tar_type_regular, '7' => data.len,
        '1', '2', '3', '4', '5', '6' => if (data.len == 0) 0 else error.InvalidCall,
        else => error.InvalidCall,
    };
}

fn tarExtensionSize(value: []const u8) Failure!u64 {
    return bounds.add64(tar_block_size, try tarAligned(try bounds.add64(value.len, 1)));
}

fn tarWriteHeader(sink: *io.Sink, scratch: []u8, name: []const u8, prefix: []const u8, link_name: []const u8, mode: u32, uid: u32, gid: u32, modification_time: u64, typeflag: u8, size: u64) Failure!void {
    if (scratch.len < tar_scratch_size) return error.InsufficientCapacity;
    const block = scratch[0..tar_scratch_size];
    @memset(block, 0);
    tarWriteField(block[0..100], name);
    tarWriteNumber(block[100..108], mode);
    tarWriteNumber(block[108..116], uid);
    tarWriteNumber(block[116..124], gid);
    tarWriteNumber(block[124..136], size);
    tarWriteNumber(block[136..148], modification_time);
    block[156] = typeflag;
    tarWriteField(block[157..257], link_name);
    tarWriteField(block[257..263], "ustar");
    tarWriteField(block[263..265], "00");
    tarWriteField(block[345..500], prefix);
    var checksum = tarChecksum(block);
    var index: usize = 154;
    while (index > 148) {
        index -= 1;
        block[index] = '0' + @as(u8, @truncate(checksum & 7));
        checksum >>= 3;
    }
    block[154] = 0;
    block[155] = ' ';
    try sink.write(block);
}

fn tarWritePadding(sink: *io.Sink, scratch: []u8, size: u64) Failure!void {
    const padding = (tar_block_size - size % tar_block_size) % tar_block_size;
    if (padding != 0) {
        if (scratch.len < tar_scratch_size) return error.InsufficientCapacity;
        @memset(scratch[0..tar_scratch_size], 0);
        try sink.write(scratch[0..@intCast(padding)]);
    }
}

fn tarWriteExtension(sink: *io.Sink, scratch: []u8, typeflag: u8, value: []const u8) Failure!void {
    const size = try bounds.add64(value.len, 1);
    try tarWriteHeader(sink, scratch, "././@LongLink", &.{}, &.{}, 0, 0, 0, 0, typeflag, size);
    try sink.write(value);
    try sink.write(&.{0});
    try tarWritePadding(sink, scratch, size);
}

const TarPax = struct {
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

const TarReader = struct {
    archive: []const u8,
    offset: u64 = 0,
    ordinal: u64 = 0,
    long_name: ?[]const u8 = null,
    long_link: ?[]const u8 = null,
    global_pax: TarPax = .{},
    local_pax: TarPax = .{},

    fn readHeader(self: *TarReader) Failure!TarEntryInfo {
        const header = try bounds.slice(self.archive, self.offset, tar_block_size);
        const recorded_checksum = try tarNumber(header[148..156]);
        if (recorded_checksum != tarChecksum(header)) return error.IntegrityFailure;
        const size = try tarNumber(header[124..136]);
        const data_offset = try bounds.add64(self.offset, tar_block_size);
        return .{
            .name = tarField(header[0..100]),
            .prefix = tarField(header[345..500]),
            .link_name = tarField(header[157..257]),
            .mode = std.math.cast(u32, try tarNumber(header[100..108])) orelse return error.InvalidData,
            .uid = std.math.cast(u32, try tarNumber(header[108..116])) orelse return error.InvalidData,
            .gid = std.math.cast(u32, try tarNumber(header[116..124])) orelse return error.InvalidData,
            .size = size,
            .modification_time = try tarNumber(header[136..148]),
            .typeflag = header[156],
            .ordinal = 0,
            .header_offset = self.offset,
            .data_offset = data_offset,
        };
    }

    fn advance(self: *TarReader, size: u64) Failure!void {
        self.offset = try bounds.add64(try bounds.add64(self.offset, tar_block_size), try tarAligned(size));
        if (self.offset > self.archive.len) return error.InvalidData;
    }

    fn parseOldGnuSparse(self: *TarReader, entry: *TarEntryInfo) Failure!SparseInfo {
        var info = SparseInfo{ .realsize = 0, .segment_count = 0 };
        const header = try bounds.slice(self.archive, entry.header_offset, tar_block_size);
        info.realsize = try tarNumber(header[483..495]);
        var chunk_sum: u64 = 0;
        try parseSparseEntries(&info, &chunk_sum, header[386..482], 4);
        var is_extended = header[482];
        var extension_blocks: u64 = 0;
        var extension_offset = try bounds.add64(entry.header_offset, tar_block_size);
        while (is_extended != 0) {
            const extension = try bounds.slice(self.archive, extension_offset, tar_block_size);
            try parseSparseEntries(&info, &chunk_sum, extension[0..504], 21);
            is_extended = extension[504];
            extension_blocks += 1;
            extension_offset = try bounds.add64(extension_offset, tar_block_size);
        }
        if (chunk_sum != entry.size) return error.InvalidData;
        if (info.realsize == 0) {
            for (info.segments[0..info.segment_count]) |segment| {
                info.realsize = @max(info.realsize, try bounds.add64(segment.offset, segment.num_bytes));
            }
        }
        try validateSparseInfo(info);
        entry.data_offset = try bounds.add64(entry.header_offset, (extension_blocks + 1) * tar_block_size);
        self.offset = try bounds.add64(entry.data_offset, try tarAligned(entry.size));
        if (self.offset > self.archive.len) return error.InvalidData;
        return info;
    }

    fn sparseFromPax(self: *TarReader, entry: *TarEntryInfo, pax: TarPax) Failure!?SparseInfo {
        if (pax.sparse_major == null and pax.sparse_size == null and pax.sparse_realsize == null and pax.sparse_map == null and pax.sparse_pax == null) return null;
        var info: SparseInfo = undefined;
        const realsize = pax.sparse_realsize orelse pax.sparse_size orelse return error.InvalidData;
        if (pax.sparse_map) |map| {
            info = try parseSparseMapString(map, realsize);
        } else if (pax.sparse_pax) |pax_data| {
            info = try parseSparsePaxPairs(pax_data, realsize);
        } else {
            info = .{ .realsize = realsize, .segment_count = 0 };
        }
        if (pax.sparse_major) |major| {
            if (major != 1) return error.Unsupported;
            const minor = pax.sparse_minor orelse return error.InvalidData;
            if (minor != 0) return error.Unsupported;
            const map_start = entry.data_offset;
            const map_bytes = try readSparseMapData(self.archive, map_start, &info);
            const map_padded = try tarAligned(map_bytes);
            entry.data_offset = try bounds.add64(entry.data_offset, map_padded);
            if (entry.size < map_padded) return error.InvalidData;
            entry.size -= map_padded;
        }
        if (pax.sparse_numblocks) |count| {
            if (count != info.segment_count) return error.InvalidData;
        }
        try validateSparseInfo(info);
        if (pax.sparse_name) |name| {
            entry.name = name;
            entry.prefix = &.{};
        }
        entry.sparse = info;
        return info;
    }

    fn next(self: *TarReader) Failure!?TarEntryInfo {
        while (self.offset < self.archive.len) {
            const block = try bounds.slice(self.archive, self.offset, tar_block_size);
            if (tarIsZeroBlock(block)) {
                const remaining = try bounds.slice(self.archive, self.offset, self.archive.len - @as(usize, @intCast(self.offset)));
                if (remaining.len < 1024 or !tarIsZeroBlock(remaining)) return error.InvalidData;
                return null;
            }
            var entry = try self.readHeader();
            const physical_size = entry.size;
            const data = try bounds.slice(self.archive, entry.data_offset, physical_size);
            switch (entry.typeflag) {
                tar_type_gnu_long_name => {
                    if (self.long_name != null) return error.InvalidData;
                    self.long_name = tarField(data);
                    try self.advance(physical_size);
                },
                tar_type_gnu_long_link => {
                    if (self.long_link != null) return error.InvalidData;
                    self.long_link = tarField(data);
                    try self.advance(physical_size);
                },
                tar_type_pax => {
                    if (!tarPaxEmpty(self.local_pax)) return error.InvalidData;
                    self.local_pax = try tarParsePax(data);
                    try self.advance(physical_size);
                },
                tar_type_global_pax => {
                    tarMergePax(&self.global_pax, try tarParsePax(data));
                    try self.advance(physical_size);
                },
                tar_type_gnu_sparse => {
                    try tarValidateSparseHeader(entry);
                    const sparse = try self.parseOldGnuSparse(&entry);
                    entry.size = sparse.realsize;
                    entry.sparse = sparse;
                    if (self.long_name) |name| {
                        entry.name = name;
                        entry.prefix = &.{};
                    }
                    if (self.long_link) |link_name| entry.link_name = link_name;
                    entry.ordinal = self.ordinal;
                    self.ordinal = try bounds.add64(self.ordinal, 1);
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
                    entry.ordinal = self.ordinal;
                    self.ordinal = try bounds.add64(self.ordinal, 1);
                    try self.advance(advance_size);
                    self.long_name = null;
                    self.long_link = null;
                    self.local_pax = .{};
                    return entry;
                },
            }
        }
        return error.InvalidData;
    }
};

fn tarValidateSparseHeader(entry: TarEntryInfo) Failure!void {
    _ = entry;
}

fn parseSparseEntries(info: *SparseInfo, chunk_sum: *u64, bytes: []const u8, count: usize) Failure!void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const entry_bytes = bytes[index * 24 ..][0..24];
        const offset = try tarNumber(entry_bytes[0..12]);
        const num_bytes = try tarNumber(entry_bytes[12..24]);
        if (offset == 0 and num_bytes == 0) continue;
        try addSparseSegment(info, chunk_sum, offset, num_bytes);
    }
}

fn addSparseSegment(info: *SparseInfo, chunk_sum: *u64, offset: u64, num_bytes: u64) Failure!void {
    if (num_bytes == 0) return error.InvalidData;
    if (info.segment_count >= max_sparse_segments) return error.Unsupported;
    info.segments[info.segment_count] = .{ .offset = offset, .num_bytes = num_bytes };
    info.segment_count += 1;
    chunk_sum.* = try bounds.add64(chunk_sum.*, num_bytes);
}

fn validateSparseInfo(info: SparseInfo) Failure!void {
    var previous_end: u64 = 0;
    for (info.segments[0..info.segment_count]) |segment| {
        if (segment.num_bytes == 0 or segment.offset < previous_end) return error.InvalidData;
        const end = try bounds.add64(segment.offset, segment.num_bytes);
        if (end > info.realsize) return error.InvalidData;
        previous_end = end;
    }
}

fn parseSparseMapString(map: []const u8, realsize: u64) Failure!SparseInfo {
    var info = SparseInfo{ .realsize = realsize, .segment_count = 0 };
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
    if (pending_offset != null) return error.InvalidData;
    return info;
}

fn parseSparsePaxPairs(data: []const u8, realsize: u64) Failure!SparseInfo {
    var info = SparseInfo{ .realsize = realsize, .segment_count = 0 };
    var chunk_sum: u64 = 0;
    var offset: usize = 0;
    var pending_offset: ?u64 = null;
    while (offset < data.len) {
        const length_start = offset;
        while (offset < data.len and data[offset] >= '0' and data[offset] <= '9') : (offset += 1) {}
        if (offset == length_start or offset == data.len or data[offset] != ' ') return error.InvalidData;
        const record_length = try tarDecimal(data[length_start..offset]);
        const length = std.math.cast(usize, record_length) orelse return error.ResourceLimit;
        if (length > data.len - length_start or length <= offset - length_start + 2) return error.InvalidData;
        const record = data[length_start .. length_start + length];
        if (record[record.len - 1] != '\n') return error.InvalidData;
        const assignment = record[offset - length_start + 1 .. record.len - 1];
        const equals = std.mem.indexOfScalar(u8, assignment, '=') orelse return error.InvalidData;
        const key = assignment[0..equals];
        const value = assignment[equals + 1 ..];
        if (std.mem.eql(u8, key, "GNU.sparse.offset")) {
            if (pending_offset != null) return error.InvalidData;
            pending_offset = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.numbytes")) {
            const segment_offset = pending_offset orelse return error.InvalidData;
            try addSparseSegment(&info, &chunk_sum, segment_offset, try tarDecimal(value));
            pending_offset = null;
        }
        offset = length_start + length;
    }
    if (pending_offset != null) return error.InvalidData;
    return info;
}

fn readSparseMapData(archive: []const u8, start: u64, info: *SparseInfo) Failure!u64 {
    var offset = start;
    const count = try readSparseLine(archive, &offset);
    if (count > max_sparse_segments) return error.Unsupported;
    var chunk_sum: u64 = 0;
    var index: u64 = 0;
    while (index < count) : (index += 1) {
        const segment_offset = try readSparseLine(archive, &offset);
        const num_bytes = try readSparseLine(archive, &offset);
        try addSparseSegment(info, &chunk_sum, segment_offset, num_bytes);
    }
    if (count != info.segment_count) return error.InvalidData;
    return offset - start;
}

fn readSparseLine(archive: []const u8, offset: *u64) Failure!u64 {
    var value: u64 = 0;
    var digits: usize = 0;
    while (true) {
        if (offset.* >= archive.len) return error.InvalidData;
        const byte = archive[@intCast(offset.*)];
        offset.* += 1;
        if (byte == '\n') {
            if (digits == 0) return error.InvalidData;
            return value;
        }
        if (byte < '0' or byte > '9') return error.InvalidData;
        digits += 1;
        value = std.math.mul(u64, value, 10) catch return error.InvalidData;
        value = std.math.add(u64, value, byte - '0') catch return error.InvalidData;
    }
}

fn tarValidateType(typeflag: u8) Failure!void {
    switch (typeflag) {
        0, tar_type_regular, '1', '2', '3', '4', '5', '6', '7' => {},
        else => return error.Unsupported,
    }
}

fn tarPaxEmpty(attributes: TarPax) bool {
    return attributes.path == null and attributes.link_name == null and attributes.mode == null and attributes.uid == null and attributes.gid == null and attributes.size == null and attributes.modification_time == null and attributes.sparse_major == null and attributes.sparse_minor == null and attributes.sparse_name == null and attributes.sparse_size == null and attributes.sparse_realsize == null and attributes.sparse_numblocks == null and attributes.sparse_map == null and attributes.sparse_pax == null;
}

fn tarMergePax(target: *TarPax, updates: TarPax) void {
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

fn tarDecimal(value: []const u8) Failure!u64 {
    if (value.len == 0) return error.InvalidData;
    var result: u64 = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidData;
        result = std.math.mul(u64, result, 10) catch return error.InvalidData;
        result = std.math.add(u64, result, byte - '0') catch return error.InvalidData;
    }
    return result;
}

fn tarParsePax(data: []const u8) Failure!TarPax {
    var attributes: TarPax = .{};
    var offset: usize = 0;
    while (offset < data.len) {
        const length_start = offset;
        while (offset < data.len and data[offset] >= '0' and data[offset] <= '9') : (offset += 1) {}
        if (offset == length_start or offset == data.len or data[offset] != ' ') return error.InvalidData;
        const record_length = try tarDecimal(data[length_start..offset]);
        const length = std.math.cast(usize, record_length) orelse return error.ResourceLimit;
        if (length > data.len - length_start or length <= offset - length_start + 2) return error.InvalidData;
        const record = data[length_start .. length_start + length];
        if (record[record.len - 1] != '\n') return error.InvalidData;
        const assignment = record[offset - length_start + 1 .. record.len - 1];
        const equals = std.mem.indexOfScalar(u8, assignment, '=') orelse return error.InvalidData;
        const key = assignment[0..equals];
        const value = assignment[equals + 1 ..];
        if (std.mem.eql(u8, key, "path")) {
            if (attributes.path != null) return error.InvalidData;
            attributes.path = value;
        } else if (std.mem.eql(u8, key, "linkpath")) {
            if (attributes.link_name != null) return error.InvalidData;
            attributes.link_name = value;
        } else if (std.mem.eql(u8, key, "size")) {
            if (attributes.size != null) return error.InvalidData;
            attributes.size = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "uid")) {
            if (attributes.uid != null) return error.InvalidData;
            attributes.uid = std.math.cast(u32, try tarDecimal(value)) orelse return error.InvalidData;
        } else if (std.mem.eql(u8, key, "gid")) {
            if (attributes.gid != null) return error.InvalidData;
            attributes.gid = std.math.cast(u32, try tarDecimal(value)) orelse return error.InvalidData;
        } else if (std.mem.eql(u8, key, "mode")) {
            if (attributes.mode != null) return error.InvalidData;
            attributes.mode = std.math.cast(u32, try tarDecimal(value)) orelse return error.InvalidData;
        } else if (std.mem.eql(u8, key, "mtime")) {
            if (attributes.modification_time != null) return error.InvalidData;
            const seconds_end = std.mem.indexOfScalar(u8, value, '.') orelse value.len;
            attributes.modification_time = try tarDecimal(value[0..seconds_end]);
        } else if (std.mem.eql(u8, key, "GNU.sparse.major")) {
            if (attributes.sparse_major != null) return error.InvalidData;
            attributes.sparse_major = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.minor")) {
            if (attributes.sparse_minor != null) return error.InvalidData;
            attributes.sparse_minor = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.name")) {
            if (attributes.sparse_name != null) return error.InvalidData;
            attributes.sparse_name = value;
        } else if (std.mem.eql(u8, key, "GNU.sparse.size")) {
            if (attributes.sparse_size != null) return error.InvalidData;
            attributes.sparse_size = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.realsize")) {
            if (attributes.sparse_realsize != null) return error.InvalidData;
            attributes.sparse_realsize = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.numblocks")) {
            if (attributes.sparse_numblocks != null) return error.InvalidData;
            attributes.sparse_numblocks = try tarDecimal(value);
        } else if (std.mem.eql(u8, key, "GNU.sparse.map")) {
            if (attributes.sparse_map != null) return error.InvalidData;
            attributes.sparse_map = value;
        } else if (std.mem.startsWith(u8, key, "GNU.sparse.offset") or std.mem.startsWith(u8, key, "GNU.sparse.numbytes")) {
            if (attributes.sparse_pax == null) attributes.sparse_pax = data;
        }
        offset = length_start + length;
    }
    return attributes;
}

fn tarApplyPax(entry: *TarEntryInfo, attributes: TarPax) Failure!void {
    if (attributes.path) |path| {
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidData;
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
