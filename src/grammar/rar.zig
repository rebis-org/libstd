const std = @import("std");

const binary = @import("../common/primitive/binary.zig");
const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");

const signature = [8]u8{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };
const sfx_scan_limit: usize = 1024 * 1024;
const header_type_main: u64 = 1;
const header_type_file: u64 = 2;
const header_type_service: u64 = 3;
const header_type_encryption: u64 = 4;
const header_type_end: u64 = 5;
const header_flag_extra_area: u64 = 0x0001;
const header_flag_data_area: u64 = 0x0002;
const header_flag_skip_unknown: u64 = 0x0004;
const header_flag_data_continues_prev: u64 = 0x0008;
const header_flag_data_continues_next: u64 = 0x0010;
const header_flag_solid_dependency: u64 = 0x0020;
const header_flag_preserve_child: u64 = 0x0040;
const archive_flag_volume: u64 = 0x0001;
const archive_flag_volume_number: u64 = 0x0002;
const archive_flag_solid: u64 = 0x0004;
const archive_flag_recovery: u64 = 0x0008;
const archive_flag_locked: u64 = 0x0010;
const file_flag_directory: u64 = 0x0001;
const file_flag_mtime: u64 = 0x0002;
const file_flag_crc32: u64 = 0x0004;
const file_flag_size_unknown: u64 = 0x0008;
const fhextra_crypt: u64 = 0x01;
const fhextra_redir: u64 = 0x05;
const compression_method_mask: u64 = 0x0380;
const compression_method_shift: u6 = 7;
const compression_solid_flag: u64 = 0x0040;
const compression_version_mask: u64 = 0x003f;

pub const RarInfo = struct {
    name: []const u8,
    size: u64,
    data_offset: u64,
    packed_size: u64,
    crc: u32,
    ordinal: usize,
};

pub fn rarInspectCount(archive: []const u8, max_entries: u64) Failure!usize {
    var state = try ArchiveState.init(archive);
    var count: usize = 0;
    while (try state.nextHeader()) |header| {
        if (header.header_type == header_type_file) {
            if (!header.is_directory) {
                if (count >= max_entries) return error.ResourceLimit;
                count = try bounds.add(count, 1);
            }
        }
    }
    return count;
}

pub fn rarInspectOrdinal(archive: []const u8, ordinal: usize, max_entries: u64) Failure!RarInfo {
    var state = try ArchiveState.init(archive);
    var current: usize = 0;
    var found: ?RarInfo = null;
    while (try state.nextHeader()) |header| {
        if (header.header_type != header_type_file or header.is_directory) continue;
        if (current >= max_entries) return error.ResourceLimit;
        if (found == null and current == ordinal) {
            found = header.info;
        }
        current = try bounds.add(current, 1);
    }
    if (found) |info| return info;
    return error.InvalidData;
}

pub fn rarDecodeOrdinal(archive: []const u8, ordinal: usize, output: []u8, max_entries: u64) Failure!usize {
    const info = try rarInspectOrdinal(archive, ordinal, max_entries);
    const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
    if (output.len < size) return error.InsufficientCapacity;
    const packed_data = try bounds.slice(archive, info.data_offset, info.packed_size);
    if (packed_data.len != size) return error.InvalidData;
    if (checksum.crc32(packed_data) != info.crc) return error.IntegrityFailure;
    @memcpy(output[0..size], packed_data);
    return size;
}

const HeaderInfo = struct {
    header_type: u64,
    is_directory: bool,
    info: RarInfo,
};

const ArchiveState = struct {
    archive: []const u8,
    cursor: usize,
    ordinal: usize,
    seen_main: bool,

    fn init(archive: []const u8) Failure!ArchiveState {
        const offset = try locateSignature(archive);
        return .{ .archive = archive, .cursor = offset + signature.len, .ordinal = 0, .seen_main = false };
    }

    fn nextHeader(self: *ArchiveState) Failure!?HeaderInfo {
        while (self.cursor < self.archive.len) {
            const header = try parseBlock(self.archive, &self.cursor);
            switch (header.header_type) {
                header_type_encryption => return error.Unsupported,
                header_type_main => {
                    try validateMainHeader(&header);
                    self.seen_main = true;
                    continue;
                },
                header_type_service => {
                    if (!self.seen_main) return error.InvalidData;
                    return error.Unsupported;
                },
                header_type_end => {
                    if (!self.seen_main) return error.InvalidData;
                    if (header.archive_flags & archive_flag_volume != 0) return error.Unsupported;
                    return null;
                },
                header_type_file => {
                    if (!self.seen_main) return error.InvalidData;
                    if (header.is_directory) continue;
                    var info = header.file_info.?;
                    info.ordinal = self.ordinal;
                    self.ordinal = try bounds.add(self.ordinal, 1);
                    return .{ .header_type = header.header_type, .is_directory = header.is_directory, .info = info };
                },
                else => {
                    if (!self.seen_main) return error.InvalidData;
                    if (header.header_flags & header_flag_skip_unknown != 0) continue;
                    return error.Unsupported;
                },
            }
        }
        return error.InvalidData;
    }
};

const ParsedHeader = struct {
    header_type: u64,
    header_flags: u64,
    archive_flags: u64 = 0,
    is_directory: bool = false,
    file_info: ?RarInfo = null,
};

fn parseBlock(archive: []const u8, cursor: *usize) Failure!ParsedHeader {
    const crc_offset = cursor.*;
    const crc_bytes = try bounds.slice(archive, crc_offset, 4);
    cursor.* = try bounds.add(cursor.*, 4);
    const header_start = cursor.*;
    const size = try readVint(archive, cursor);
    if (size == 0 or size > 2 * 1024 * 1024) return error.InvalidData;
    const header_body_start = cursor.*;
    const header_body_end = try bounds.add(header_body_start, std.math.cast(usize, size) orelse return error.ResourceLimit);
    if (header_body_end > archive.len) return error.InvalidData;
    const recorded_crc = std.mem.readInt(u32, crc_bytes[0..4], .little);
    const computed_crc = checksum.crc32(archive[header_start..header_body_end]);
    if (computed_crc != recorded_crc) return error.IntegrityFailure;
    var sub = binary.ReadCursor.init(archive[header_body_start..header_body_end]);
    const htype = try sub.readULEB128();
    const flags = try sub.readULEB128();
    var extra_size: u64 = 0;
    if (flags & header_flag_extra_area != 0) extra_size = try sub.readULEB128();
    var data_size: u64 = 0;
    if (flags & header_flag_data_area != 0) data_size = try sub.readULEB128();
    var result: ParsedHeader = .{ .header_type = htype, .header_flags = flags };
    switch (htype) {
        header_type_main => {
            const archive_flags = try sub.readULEB128();
            result.archive_flags = archive_flags;
            if (archive_flags & archive_flag_volume_number != 0) {
                _ = try sub.readULEB128(); // volume number
            }
        },
        header_type_file, header_type_service => {
            if (flags & (header_flag_data_continues_prev | header_flag_data_continues_next | header_flag_solid_dependency | header_flag_preserve_child) != 0) return error.Unsupported;
            const file_flags = try sub.readULEB128();
            const unpacked_size = try sub.readULEB128();
            const attributes = try sub.readULEB128();
            _ = attributes;
            if (file_flags & file_flag_mtime != 0) {
                _ = try sub.readU32le();
            }
            var data_crc: u32 = 0;
            if (file_flags & file_flag_crc32 != 0) {
                data_crc = try sub.readU32le();
            }
            const compression = try sub.readULEB128();
            const host_os = try sub.readULEB128();
            _ = host_os;
            const name_length = try sub.readULEB128();
            const name = try sub.readSlice(std.math.cast(usize, name_length) orelse return error.ResourceLimit);
            if (flags & header_flag_extra_area != 0) {
                const extra_size_usize = std.math.cast(usize, extra_size) orelse return error.ResourceLimit;
                var extra_remaining: usize = extra_size_usize;
                while (extra_remaining > 0) {
                    const record_start = sub.pos;
                    const record_size = try sub.readULEB128();
                    const type_start = sub.pos;
                    const record_type = try sub.readULEB128();
                    const type_size = sub.pos - type_start;
                    if (record_size < type_size) return error.InvalidData;
                    const record_data_size = std.math.cast(usize, record_size - type_size) orelse return error.ResourceLimit;
                    const header_consumed = sub.pos - record_start;
                    const consumed = try bounds.add(header_consumed, record_data_size);
                    if (consumed > extra_remaining) return error.InvalidData;
                    switch (record_type) {
                        fhextra_redir, fhextra_crypt => return error.Unsupported,
                        else => _ = try sub.readSlice(record_data_size),
                    }
                    extra_remaining -= consumed;
                }
            }
            result.is_directory = file_flags & file_flag_directory != 0;
            if (htype == header_type_file and !result.is_directory) {
                const method = (compression & compression_method_mask) >> compression_method_shift;
                if (method != 0) return error.Unsupported;
                if (compression & compression_solid_flag != 0) return error.Unsupported;
                if (compression & compression_version_mask != 0) return error.Unsupported;
                if (file_flags & file_flag_size_unknown != 0) return error.Unsupported;
                if (file_flags & file_flag_crc32 == 0) return error.Unsupported;
                if (flags & header_flag_data_area == 0) return error.Unsupported;
                if (data_size != unpacked_size) return error.Unsupported;
                result.file_info = .{
                    .name = name,
                    .size = unpacked_size,
                    .data_offset = std.math.cast(u64, header_body_end) orelse return error.ResourceLimit,
                    .packed_size = data_size,
                    .crc = data_crc,
                    .ordinal = 0,
                };
            }
        },
        header_type_encryption => {},
        header_type_end => {
            result.archive_flags = try sub.readULEB128();
        },
        else => {
            if (flags & header_flag_skip_unknown == 0) return error.Unsupported;
        },
    }
    const data_size_usize = std.math.cast(usize, data_size) orelse return error.ResourceLimit;
    const data_end = try bounds.add(header_body_end, data_size_usize);
    if (data_end > archive.len) return error.InvalidData;
    cursor.* = data_end;
    return result;
}

fn validateMainHeader(header: *const ParsedHeader) Failure!void {
    const flags = header.archive_flags;
    if (flags & (archive_flag_volume | archive_flag_volume_number | archive_flag_solid | archive_flag_recovery | archive_flag_locked) != 0) return error.Unsupported;
    if (header.header_flags & (header_flag_data_area | header_flag_data_continues_prev | header_flag_data_continues_next | header_flag_solid_dependency | header_flag_preserve_child) != 0) return error.Unsupported;
}

fn locateSignature(archive: []const u8) Failure!usize {
    if (archive.len < signature.len) return error.InvalidData;
    const limit = @min(archive.len, sfx_scan_limit);
    var offset: usize = 0;
    while (offset <= limit - signature.len) : (offset += 1) {
        if (!std.mem.eql(u8, archive[offset..][0..signature.len], &signature)) continue;
        if (offset == 0) return 0;
        var cursor = offset + signature.len;
        const header = parseBlock(archive, &cursor) catch continue;
        if (header.header_type == header_type_main) return offset;
    }
    return error.InvalidData;
}

fn readVint(archive: []const u8, cursor: *usize) Failure!u64 {
    var sub = binary.ReadCursor.init(archive[cursor.*..]);
    const value = try sub.readULEB128();
    cursor.* = try bounds.add(cursor.*, sub.pos);
    return value;
}
