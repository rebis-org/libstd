const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const crypto = @import("../../../common/primitive/crypto.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const limits_prim = @import("../../../common/primitive/limits.zig");
const measurement = @import("../../../common/primitive/measurement.zig");
const bzip2 = @import("../../leaf/bzip2/onprem.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const deflate_seam = @import("../../leaf/deflate/seam.zig");
const lzma = @import("../../leaf/lzma/onprem.zig");
const lzma_seam = @import("../../leaf/lzma/seam.zig");
const ppmd_zip = @import("../../leaf/ppmd/zip.zig");
const zstd = @import("../../leaf/zstd/onprem.zig");
const xz = @import("../xz/onprem.zig");

const winzip_aes_hmac_length = crypto.winzip_hmac_length;
const winzip_aes_verify_length = crypto.winzip_verify_length;
const Exception = exception_prim.Exception;
const Limits = limits_prim.Limits;
pub const deflate64_decode_history_size = deflate.deflate64_decode_history_size;
pub const deflate64_history_size = deflate.deflate64_history_size;
pub const deflate_history_size = deflate.history_size;
pub const deflate_measurement_buffer_size = deflate.measurement_buffer_size;
const ppmd_restore_default = ppmd_zip.restore_restart;

const deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 128 };
const bzip2_block_default = 100_000;
const lzma_props_default: lzma.Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 20 };
const zstd_window_default = 1 << 20;
const zstd_history_default = std.mem.alignForward(usize, zstd_window_default + zstd.block_size_max, 4);
const xz_dictionary_default = 1 << 20;
const ppmd_order_default = 8;
const ppmd_mem_default = 4 << 20;
const local_signature: u32 = 0x0403_4b50;
const central_signature: u32 = 0x0201_4b50;
const end_signature: u32 = 0x0605_4b50;
const zip64_end_signature: u32 = 0x0606_4b50;
const zip64_locator_signature: u32 = 0x0706_4b50;
const zip64_extra_id: u16 = 0x0001;
const winzip_aes_method: u16 = 99;
const winzip_aes_extra_id: u16 = 0x9901;
const winzip_aes_version: u16 = 2;
const winzip_aes_vendor = "AE";
const winzip_aes_version_needed: u16 = 51;
const winzip_aes_extra_data_length: usize = 7;
const winzip_aes_extra_record_length: usize = winzip_aes_extra_data_length + 4;
pub const Entry = struct {
    name: []const u8,
    data: []const u8,
    extra: []const u8 = &.{},
    comment: []const u8 = &.{},
    method: u16 = 8,
    flags: u16 = 0x0800,
    dos_time: u16 = 0,
    dos_date: u16 = 0,
    version_made_by: u16 = 0x0314,
    internal_attributes: u16 = 0,
    external_attributes: u32 = 0,
    encrypted: bool = false,
    zipcrypto: bool = false,
    password: []const u8 = &.{},
    salt: [16]u8 = @splat(0),
    salt_length: u8 = 0,
    aes_strength: u8 = 3,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
};

pub fn requiredSize(entries: []const Entry, archive_comment: []const u8, history: []u8, measurement_buffer: []u8, scratch: []u8, failure_cause: *crypto.FailureCause) Exception!usize {
    failure_cause.* = .none;
    if (archive_comment.len > std.math.maxInt(u16)) return error.ResourceException;
    var local_total: usize = 0;
    var central_total: usize = 0;
    for (entries) |entry| {
        try validateEntry(entry);
        if (entry.encrypted and entry.kdf_rounds_limit != 0 and entry.kdf_rounds_limit < crypto.winzip_pbkdf2_rounds) {
            failure_cause.* = .kdf_limit;
            return error.ResourceException;
        }
        const compressed = try compressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try aesOverhead(entry);
        if (entry.encrypted and entry.password_lifetime != 0 and compressed > entry.password_lifetime) {
            failure_cause.* = .password_lifetime;
            return error.ResourceException;
        }
        const local_offset = local_total;
        const descriptor = entry.flags & 0x0008 != 0 and !(entry.encrypted and !entry.zipcrypto);
        central_total = try bounds.addUsize(central_total, 46 + entry.name.len + entry.extra.len + centralZip64Length(try bounds.addUsize(compressed, overhead), entry.data.len, local_offset) + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0) + entry.comment.len);
        local_total = try bounds.addUsize(local_total, try bounds.addUsize(30 + entry.name.len + entry.extra.len + localZip64Length(try bounds.addUsize(compressed, overhead), entry.data.len, descriptor) + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0) + dataDescriptorLength(try bounds.addUsize(compressed, overhead), entry.data.len, descriptor), try bounds.addUsize(compressed, overhead)));
    }
    const needs_zip64 = entries.len >= std.math.maxInt(u16) or central_total >= std.math.maxInt(u32) or local_total >= std.math.maxInt(u32);
    return try bounds.addUsize(try bounds.addUsize(local_total, central_total), try bounds.addUsize(22 + archive_comment.len, if (needs_zip64) 76 else 0));
}

pub fn encode(entries: []const Entry, archive_comment: []const u8, output: []u8, provider: crypto.Provider, history: []u8, measurement_buffer: []u8, staging: []u8, scratch: []u8, failure_cause: *crypto.FailureCause) Exception!usize {
    const required = try requiredSize(entries, archive_comment, history, measurement_buffer, scratch, failure_cause);
    if (output.len < required) return error.CapacityException;
    var sink = io.Sink{ .bytes = output[0..required] };
    var offsets: usize = 0;
    for (entries) |entry| {
        const compressed = try compressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try aesOverhead(entry);
        const stored_size = try bounds.addUsize(compressed, overhead);
        const zip64 = stored_size >= std.math.maxInt(u32) or entry.data.len >= std.math.maxInt(u32);
        const descriptor = entry.flags & 0x0008 != 0 and !(entry.encrypted and !entry.zipcrypto);
        const descriptor_len = dataDescriptorLength(stored_size, entry.data.len, descriptor);
        const extra_length = try bounds.addUsize(try bounds.addUsize(entry.extra.len, if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0), localZip64Length(stored_size, entry.data.len, descriptor));
        try putU32(&sink, local_signature);
        try putU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_version_needed else if (zip64) 45 else zipVersionNeeded(entry.method));
        try putU16(&sink, effectiveFlags(entry));
        try putU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_method else entry.method);
        try putU16(&sink, entry.dos_time);
        try putU16(&sink, entry.dos_date);
        try putU32(&sink, if (entry.encrypted and !entry.zipcrypto) 0 else if (descriptor) 0 else checksum.crc32With(provider, entry.data));
        try putU32(&sink, if (descriptor) 0 else if (zip64) std.math.maxInt(u32) else std.math.cast(u32, stored_size) orelse return error.ResourceException);
        try putU32(&sink, if (descriptor) 0 else if (zip64) std.math.maxInt(u32) else std.math.cast(u32, entry.data.len) orelse return error.ResourceException);
        try putU16(&sink, @intCast(entry.name.len));
        try putU16(&sink, std.math.cast(u16, extra_length) orelse return error.ResourceException);
        try sink.write(entry.name);
        try writeLocalZip64(&sink, stored_size, entry.data.len, descriptor);
        try sink.write(entry.extra);
        if (entry.encrypted and !entry.zipcrypto) try writeAesExtra(&sink, entry);
        try writeData(&sink, entry, provider, history, staging, scratch);
        if (descriptor) try writeDataDescriptor(&sink, entry, stored_size, checksum.crc32With(provider, entry.data), provider);
        offsets = try bounds.addUsize(offsets, 30 + entry.name.len + extra_length + stored_size + descriptor_len);
    }
    const central_offset = offsets;
    var local_offset: usize = 0;
    for (entries) |entry| {
        const compressed = try compressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try aesOverhead(entry);
        const stored_size = try bounds.addUsize(compressed, overhead);
        const zip64 = stored_size >= std.math.maxInt(u32) or entry.data.len >= std.math.maxInt(u32) or local_offset >= std.math.maxInt(u32);
        const descriptor = entry.flags & 0x0008 != 0 and !(entry.encrypted and !entry.zipcrypto);
        const local_extra = localZip64Length(stored_size, entry.data.len, descriptor);
        const central_extra = centralZip64Length(stored_size, entry.data.len, local_offset);
        const extra_length = try bounds.addUsize(try bounds.addUsize(entry.extra.len, if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0), central_extra);
        try putU32(&sink, central_signature);
        try putU16(&sink, entry.version_made_by);
        try putU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_version_needed else if (zip64) 45 else zipVersionNeeded(entry.method));
        try putU16(&sink, effectiveFlags(entry));
        try putU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_method else entry.method);
        try putU16(&sink, entry.dos_time);
        try putU16(&sink, entry.dos_date);
        try putU32(&sink, if (entry.encrypted and !entry.zipcrypto) 0 else checksum.crc32With(provider, entry.data));
        try putU32(&sink, if (stored_size >= std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(stored_size));
        try putU32(&sink, if (entry.data.len >= std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(entry.data.len));
        try putU16(&sink, @intCast(entry.name.len));
        try putU16(&sink, std.math.cast(u16, extra_length) orelse return error.ResourceException);
        try putU16(&sink, @intCast(entry.comment.len));
        try putU16(&sink, 0);
        try putU16(&sink, entry.internal_attributes);
        try putU32(&sink, entry.external_attributes);
        try putU32(&sink, if (local_offset >= std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(local_offset));
        try sink.write(entry.name);
        try writeCentralZip64(&sink, stored_size, entry.data.len, local_offset);
        try sink.write(entry.extra);
        if (entry.encrypted and !entry.zipcrypto) try writeAesExtra(&sink, entry);
        try sink.write(entry.comment);
        local_offset = try bounds.addUsize(local_offset, 30 + entry.name.len + entry.extra.len + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0) + local_extra + stored_size + dataDescriptorLength(stored_size, entry.data.len, descriptor));
    }
    const central_size = sink.offset - central_offset;
    const needs_zip64 = entries.len >= std.math.maxInt(u16) or central_size >= std.math.maxInt(u32) or central_offset >= std.math.maxInt(u32);
    if (needs_zip64) {
        const record_offset = sink.offset;
        try putU32(&sink, zip64_end_signature);
        try putU64(&sink, 44);
        try putU16(&sink, 45);
        try putU16(&sink, 45);
        try putU32(&sink, 0);
        try putU32(&sink, 0);
        try putU64(&sink, entries.len);
        try putU64(&sink, entries.len);
        try putU64(&sink, central_size);
        try putU64(&sink, central_offset);
        try putU32(&sink, zip64_locator_signature);
        try putU32(&sink, 0);
        try putU64(&sink, record_offset);
        try putU32(&sink, 1);
    }
    try putU32(&sink, end_signature);
    try putU16(&sink, 0);
    try putU16(&sink, 0);
    try putU16(&sink, if (needs_zip64) std.math.maxInt(u16) else @intCast(entries.len));
    try putU16(&sink, if (needs_zip64) std.math.maxInt(u16) else @intCast(entries.len));
    try putU32(&sink, if (needs_zip64) std.math.maxInt(u32) else @intCast(central_size));
    try putU32(&sink, if (needs_zip64) std.math.maxInt(u32) else @intCast(central_offset));
    try putU16(&sink, @intCast(archive_comment.len));
    try sink.write(archive_comment);
    return sink.offset;
}

pub const SpannedResult = struct { total_len: usize, volumes: u64 };

const spanning_signature: u32 = 0x0807_4b50;

// Info-ZIP "zip -s" conventions, verified against system zip and 7zz:
// record headers never straddle disk boundaries; all offsets are disk-relative.
pub fn encodeSpanned(entries: []const Entry, archive_comment: []const u8, output: []u8, volume_size: u64, provider: crypto.Provider, history: []u8, measurement_buffer: []u8, staging: []u8, scratch: []u8, failure_cause: *crypto.FailureCause, plan_scratch: []usize) Exception!SpannedResult {
    if (volume_size < 4096) return error.CallException;
    const vs: usize = std.math.cast(usize, volume_size) orelse return error.ResourceException;
    const required = try requiredSize(entries, archive_comment, history, measurement_buffer, scratch, failure_cause);
    const total = try bounds.addUsize(required, 4);
    if (output.len < total) return error.CapacityException;

    // Plan the disks: fill each to capacity, splitting only inside file
    // data regions.
    if (plan_scratch.len < entries.len * 2 + 8) return error.CapacityException;
    const boundaries = plan_scratch;
    var boundary_count: usize = 0;
    var pos: usize = 0; // Logical position, signature excluded.
    var remaining: usize = vs - 4;
    var central_disk_start: usize = 0;
    var central_total: usize = 0;
    for (entries) |entry| {
        const compressed = try compressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try aesOverhead(entry);
        const stored = try bounds.addUsize(compressed, overhead);
        const descriptor = entry.flags & 0x0008 != 0 and !(entry.encrypted and !entry.zipcrypto);
        const header_len = try bounds.addUsize(30 + entry.name.len + entry.extra.len + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0), localZip64Length(stored, entry.data.len, descriptor));
        const record_len = try bounds.addUsize(header_len, try bounds.addUsize(stored, dataDescriptorLength(stored, entry.data.len, descriptor)));
        central_total = try bounds.addUsize(central_total, 46 + entry.name.len + entry.extra.len + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0) + entry.comment.len + centralZip64Length(stored, entry.data.len, pos));
        if (record_len <= remaining) {
            pos = try bounds.addUsize(pos, record_len);
            remaining -= record_len;
            continue;
        }
        if (header_len < remaining and stored > 0) {
            // Header fits; the data fills this disk and continues raw on
            // the next one (no per-continuation marker, like zip -s).
            pos = try bounds.addUsize(pos, header_len);
            remaining -= header_len;
            var data_left = stored;
            while (data_left > remaining) {
                data_left -= remaining;
                pos = try bounds.addUsize(pos, remaining);
                boundaries[boundary_count] = pos;
                boundary_count += 1;
                remaining = vs;
            }
            pos = try bounds.addUsize(pos, data_left);
            remaining -= data_left;
            pos = try bounds.addUsize(pos, dataDescriptorLength(stored, entry.data.len, descriptor));
            remaining -= dataDescriptorLength(stored, entry.data.len, descriptor);
            continue;
        }
        // The whole record moves to the next disk.
        boundaries[boundary_count] = pos;
        boundary_count += 1;
        remaining = vs;
        if (record_len <= remaining) {
            pos = try bounds.addUsize(pos, record_len);
            remaining -= record_len;
            continue;
        }
        return error.ResourceException; // One record larger than a whole disk.
    }
    const eocd_len = 22 + archive_comment.len + blk: {
        const needs_zip64 = entries.len >= std.math.maxInt(u16) or central_total >= std.math.maxInt(u32) or pos >= std.math.maxInt(u32);
        break :blk @as(usize, if (needs_zip64) 76 else 0);
    };
    if (try bounds.addUsize(central_total, eocd_len) > remaining) {
        boundaries[boundary_count] = pos;
        boundary_count += 1;
    }
    central_disk_start = boundaries[boundary_count - 1];

    // Emit: signature, then the ordinary single-volume encode shifted by 4.
    std.mem.writeInt(u32, output[0..4], spanning_signature, .little);
    const written = try encode(entries, archive_comment, output[4..], provider, history, measurement_buffer, staging, scratch, failure_cause);
    if (written != required) return error.InternalException;

    // Central offsets were written against the shifted base; patch them to
    // the Info-ZIP convention: relative to each disk's first byte.
    {
        var cursor: usize = 4 + pos;
        for (entries) |_| {
            if (readU32(output, cursor) != central_signature) return error.InternalException;
            const name_length = readU16(output, cursor + 28);
            const extra_length = readU16(output, cursor + 30);
            const comment_length = readU16(output, cursor + 32);
            const header_disk_u16 = readU16(output, cursor + 34);
            if (header_disk_u16 == std.math.maxInt(u16)) return error.UnsupportedException;
            const rel = readU32(output, cursor + 42);
            const absolute = if (rel != std.math.maxInt(u32)) try bounds.addUsize(rel, 4) else blk: {
                var field: usize = cursor + 46 + name_length;
                const extra_end = field + extra_length;
                var found = false;
                var wide: usize = 0;
                while (field + 4 <= extra_end) {
                    const tag = readU16(output, field);
                    const size = readU16(output, field + 2);
                    if (field + 4 + size > extra_end) break;
                    if (tag == 0x0001) {
                        var value_offset = field + 4;
                        if (readU32(output, cursor + 20) == std.math.maxInt(u32)) value_offset += 8; // Uncompressed.
                        if (readU32(output, cursor + 24) == std.math.maxInt(u32)) value_offset += 8; // Compressed.
                        if (value_offset + 8 > field + 4 + size) return error.InternalException;
                        wide = value_offset;
                        found = true;
                        break;
                    }
                    field += 4 + size;
                }
                if (!found) return error.InternalException;
                break :blk std.math.cast(usize, readU64(output, wide)) orelse return error.ResourceException;
            };
            // Locate the disk holding the local header and convert.
            var disk: usize = 0;
            for (boundaries[0..boundary_count], 0..) |boundary, i| {
                if (absolute >= 4 + boundary) disk = i + 1 else break;
            }
            const disk_start: usize = if (disk == 0) 0 else 4 + boundaries[disk - 1];
            const relative = absolute - disk_start;
            if (disk > std.math.maxInt(u16)) return error.UnsupportedException;
            std.mem.writeInt(u16, output[cursor + 34 ..][0..2], @intCast(disk), .little);
            if (rel != std.math.maxInt(u32)) {
                if (relative >= std.math.maxInt(u32)) return error.ResourceException;
                std.mem.writeInt(u32, output[cursor + 42 ..][0..4], @intCast(relative), .little);
            } else {
                // The spilled zip64 offset keeps its slot; only the value narrows.
                var field: usize = cursor + 46 + name_length;
                const extra_end = field + extra_length;
                var patched = false;
                while (field + 4 <= extra_end) {
                    const tag = readU16(output, field);
                    const size = readU16(output, field + 2);
                    if (field + 4 + size > extra_end) break;
                    if (tag == 0x0001) {
                        var value_offset = field + 4;
                        if (readU32(output, cursor + 20) == std.math.maxInt(u32)) value_offset += 8; // Uncompressed.
                        if (readU32(output, cursor + 24) == std.math.maxInt(u32)) value_offset += 8; // Compressed.
                        if (value_offset + 8 > field + 4 + size) return error.InternalException;
                        std.mem.writeInt(u64, output[value_offset..][0..8], relative, .little);
                        patched = true;
                        break;
                    }
                    field += 4 + size;
                }
                if (!patched) return error.InternalException;
            }
            cursor += 46 + name_length + extra_length + comment_length;
        }
    }

    // Patch the EOCD (and zip64 EOCD when present) disk fields.
    const disks: u64 = boundary_count + 1;
    const eocd_pos = total - 22 - archive_comment.len;
    const end_pos = eocd_pos - eocd_len + 22; // Start of EOCD (zip64 records precede).
    if (readU32(output, eocd_pos) != end_signature) return error.InternalException;
    const needs_zip64 = eocd_len != 22;
    if (entries.len >= std.math.maxInt(u16) or disks > std.math.maxInt(u16)) return error.UnsupportedException;
    const central_logical = 4 + pos;
    const central_offset_value = central_logical - (4 + central_disk_start);
    if (!needs_zip64) {
        std.mem.writeInt(u16, output[eocd_pos + 4 ..][0..2], @intCast(disks - 1), .little);
        std.mem.writeInt(u16, output[eocd_pos + 6 ..][0..2], @intCast(disks - 1), .little);
        std.mem.writeInt(u16, output[eocd_pos + 8 ..][0..2], @intCast(entries.len), .little);
        std.mem.writeInt(u32, output[eocd_pos + 16 ..][0..4], std.math.cast(u32, central_offset_value) orelse return error.ResourceException, .little);
    } else {
        if (readU32(output, end_pos) != zip64_end_signature) return error.InternalException;
        std.mem.writeInt(u32, output[end_pos + 16 ..][0..4], @intCast(disks - 1), .little);
        std.mem.writeInt(u32, output[end_pos + 20 ..][0..4], @intCast(disks - 1), .little);
        std.mem.writeInt(u64, output[end_pos + 24 ..][0..8], entries.len, .little);
        std.mem.writeInt(u64, output[end_pos + 32 ..][0..8], entries.len, .little);
        std.mem.writeInt(u64, output[end_pos + 48 ..][0..8], central_offset_value, .little);
        const locator = end_pos + 56;
        if (readU32(output, locator) != zip64_locator_signature) return error.InternalException;
        std.mem.writeInt(u32, output[locator + 4 ..][0..4], @intCast(disks - 1), .little);
        std.mem.writeInt(u16, output[eocd_pos + 4 ..][0..2], std.math.maxInt(u16), .little);
        std.mem.writeInt(u16, output[eocd_pos + 6 ..][0..2], std.math.maxInt(u16), .little);
        std.mem.writeInt(u16, output[eocd_pos + 8 ..][0..2], std.math.maxInt(u16), .little);
    }
    return .{ .total_len = total, .volumes = disks };
}

// Splits a spanned archive into its disk extents (all but the last are
// exactly volume_size bytes).
pub fn spannedVolumeExtents(total_len: usize, volume_size: u64) Exception!VolumePlan {
    if (volume_size == 0) return error.CallException;
    const vs: usize = std.math.cast(usize, volume_size) orelse return error.ResourceException;
    if (total_len <= vs) return .{ .volumes = 1 };
    return .{ .volumes = (total_len + vs - 1) / vs };
}

pub const VolumePlan = struct { volumes: u64 };

// Offsets resolve relative to the disk named in each field, per the
// Info-ZIP convention verified against system zip and 7zz.
pub fn zipDecodeOrdinalSpanned(volumes: []const []const u8, ordinal: usize, output: []u8, join: []u8, disk_starts_scratch: []usize, options: ZipDecodeOptions) Exception!usize {
    options.failure_cause.* = .none;
    if (volumes.len == 0) return error.DataException;
    var total: usize = 0;
    for (volumes) |v| total = try bounds.addUsize(total, v.len);
    if (join.len < total) return error.CapacityException;
    if (disk_starts_scratch.len < volumes.len) return error.CapacityException;
    const disk_starts = disk_starts_scratch[0..volumes.len];
    var at: usize = 0;
    for (volumes, 0..) |v, i| {
        disk_starts[i] = at;
        @memcpy(join[at..][0..v.len], v);
        at += v.len;
    }
    const archive = join[0..total];
    if (readU32(archive, 0) != spanning_signature) return error.DataException;

    // EOCD scan over the tail (same walk as the single-volume reader).
    if (archive.len < 22) return error.DataException;
    const earliest = if (archive.len > 22 + std.math.maxInt(u16)) archive.len - (22 + std.math.maxInt(u16)) else 0;
    var position = archive.len - 22;
    var eocd_pos: ?usize = null;
    while (true) {
        if (readU32(archive, position) == end_signature) {
            const comment = readU16(archive, position + 20);
            if (position + 22 + comment == archive.len) {
                eocd_pos = position;
                break;
            }
        }
        if (position == earliest) break;
        position -= 1;
    }
    const eocd = eocd_pos orelse return error.DataException;
    const disk_count_total = readU16(archive, eocd + 4);
    const central_disk = readU16(archive, eocd + 6);
    const size: usize = std.math.cast(usize, readU32(archive, eocd + 12)) orelse return error.ResourceException;
    const offset: usize = std.math.cast(usize, readU32(archive, eocd + 16)) orelse return error.ResourceException;
    var central_abs: usize = undefined;
    var count: usize = std.math.cast(usize, readU16(archive, eocd + 10)) orelse return error.ResourceException;
    if (disk_count_total == std.math.maxInt(u16)) {
        // zip64 spanned: disk numbers and 64-bit extents live in the records.
        if (eocd < 20 or readU32(archive, eocd - 20) != zip64_locator_signature) return error.DataException;
        const locator = eocd - 20;
        const record_rel = std.math.cast(usize, readU64(archive, locator + 8)) orelse return error.ResourceException;
        const record = locator - 12 - record_rel;
        if (readU32(archive, record) != zip64_end_signature) return error.DataException;
        const cd64 = std.math.cast(usize, readU32(archive, record + 20)) orelse return error.ResourceException;
        const size64 = std.math.cast(usize, readU64(archive, record + 40)) orelse return error.ResourceException;
        const off64 = std.math.cast(usize, readU64(archive, record + 48)) orelse return error.ResourceException;
        if (cd64 >= disk_starts.len) return error.DataException;
        central_abs = disk_starts[cd64] + off64;
        count = std.math.cast(usize, readU64(archive, record + 32)) orelse return error.ResourceException;
        _ = size64;
    } else {
        if (central_disk >= disk_starts.len) return error.DataException;
        central_abs = try bounds.addUsize(disk_starts[central_disk], offset);
        _ = size;
    }
    if (central_abs > eocd) return error.DataException;
    const directory: ZipDirectory = .{ .offset = central_abs, .size = eocd - central_abs, .count = count, .base = 0 };
    if (ordinal >= directory.count) return error.DataException;
    var cursor = directory.offset;
    var index: usize = 0;
    var entry: Info = undefined;
    while (index < directory.count) : (index += 1) {
        entry = try zipNext(archive, directory, &cursor, index);
        if (index == ordinal) break;
    }
    // The records may declare a smaller size than the scan; re-derive the
    // walk like the single-volume decoder.
    var spanned_options = options;
    spanned_options.disk_starts = disk_starts;
    return try zipDecodeEntry(archive, entry, output, spanned_options);
}

fn validateEntry(entry: Entry) Exception!void {
    if (entry.name.len == 0 or entry.name.len > std.math.maxInt(u16) or entry.extra.len > std.math.maxInt(u16) or entry.comment.len > std.math.maxInt(u16)) return error.CallException;
    // Only UTF-8 names (0x0800), the descriptor marker (0x0008), and the
    // level hint (0x0002, advisory) are writable; all else stays rejected.
    if (entry.flags & ~@as(u16, 0x0800 | 0x0008 | 0x0002) != 0 or (entry.flags & 0x0800 != 0 and !std.unicode.utf8ValidateSlice(entry.name))) return error.UnsupportedException;
    try validatePath(entry.name, entry.flags);
    switch (entry.method) {
        0, 8, 9, 12, 14, 93, 95, 98 => {},
        else => return error.UnsupportedException,
    }
    if (entry.name[entry.name.len - 1] == '/' and entry.data.len != 0) return error.CallException;
    try zipValidateExtra(entry.extra);
    if (entry.encrypted) {
        if (entry.password.len == 0) return error.CallException;
        if (entry.zipcrypto) {
            if (entry.salt_length != 0) return error.CallException;
        } else {
            if (entry.aes_strength < 1 or entry.aes_strength > 3) return error.UnsupportedException;
            if (entry.salt_length > 16) return error.CallException;
        }
    }
}

// WinZip AES reuses the CRC field, so bit 3 must clear; ZipCrypto keeps
// the descriptor and checks the time byte.
fn effectiveFlags(entry: Entry) u16 {
    var flags = entry.flags;
    if (entry.method == 14) flags |= 0x0002;
    if (entry.encrypted) flags |= 0x0001;
    if (entry.encrypted and !entry.zipcrypto) flags &= ~@as(u16, 0x0008);
    return flags;
}

const data_descriptor_signature: u32 = 0x08074b50;

// The trailing descriptor per flagged entry: signature, CRC, and the two
// sizes in the same width the headers use.
fn dataDescriptorLength(stored_size: usize, data_len: usize, descriptor: bool) usize {
    if (!descriptor) return 0;
    const zip64 = stored_size >= std.math.maxInt(u32) or data_len >= std.math.maxInt(u32);
    return if (zip64) 4 + 4 + 8 + 8 else 4 + 4 + 4 + 4;
}

fn writeDataDescriptor(sink: *io.Sink, entry: Entry, stored_size: usize, crc: u32, provider: crypto.Provider) Exception!void {
    _ = provider;
    const zip64 = stored_size >= std.math.maxInt(u32) or entry.data.len >= std.math.maxInt(u32);
    try putU32(sink, data_descriptor_signature);
    try putU32(sink, crc);
    if (zip64) {
        try putU64(sink, stored_size);
        try putU64(sink, entry.data.len);
    } else {
        try putU32(sink, std.math.cast(u32, stored_size) orelse return error.ResourceException);
        try putU32(sink, std.math.cast(u32, entry.data.len) orelse return error.ResourceException);
    }
}

fn zipVersionNeeded(method: u16) u16 {
    return switch (method) {
        9 => 21,
        12 => 46,
        14, 93, 95, 98 => 63,
        else => 20,
    };
}

pub fn encodeScratchSize(entry: Entry) usize {
    return switch (entry.method) {
        0, 8, 9 => 0,
        12 => bzip2.encodeWorkspaceSize(bzip2_block_default),
        14 => lzma.encodeWorkspaceSizeBt(lzma_props_default),
        93 => zstd_history_default + zstd.encoder_workspace_size,
        95 => xz.encodeWorkspaceSizeBt(xz_dictionary_default),
        98 => ppmd_zip.encodeWorkspaceSize(ppmd_mem_default),
        else => 0,
    };
}

fn aesOverhead(entry: Entry) Exception!usize {
    if (!entry.encrypted) return 0;
    if (entry.zipcrypto) return 12;
    const salt_length = try crypto.winzipSaltLength(entry.aes_strength);
    return try bounds.addUsize(try bounds.addUsize(salt_length, winzip_aes_verify_length), winzip_aes_hmac_length);
}

fn writeAesExtra(sink: *io.Sink, entry: Entry) Exception!void {
    try putU16(sink, winzip_aes_extra_id);
    try putU16(sink, winzip_aes_extra_data_length);
    try putU16(sink, winzip_aes_version);
    try sink.write(winzip_aes_vendor);
    try sink.write(&[_]u8{entry.aes_strength});
    try putU16(sink, entry.method);
}

fn entrySalt(entry: Entry, salt_length: usize) Exception![16]u8 {
    if (entry.salt_length != 0) {
        if (entry.salt_length != salt_length) return error.CallException;
        return entry.salt;
    }
    var salt: [16]u8 = undefined;
    try crypto.fillRandom(salt[0..salt_length]);
    return salt;
}

fn zipValidateExtra(extra: []const u8) Exception!void {
    var offset: usize = 0;
    while (offset < extra.len) {
        if (extra.len - offset < 4) return error.CallException;
        const id = readU16(extra, offset);
        const length = readU16(extra, offset + 2);
        offset = try bounds.addUsize(offset, 4);
        if (length > extra.len - offset or id == zip64_extra_id) return error.CallException;
        offset = try bounds.addUsize(offset, length);
    }
}

fn localZip64Length(compressed: usize, uncompressed: usize, descriptor: bool) usize {
    // With bit 3 set the local header carries no sizes, so no local zip64
    // extra; the central directory is authoritative.
    if (descriptor) return 0;
    return if (compressed >= std.math.maxInt(u32) or uncompressed >= std.math.maxInt(u32)) 20 else 0;
}

fn centralZip64Length(compressed: usize, uncompressed: usize, local_offset: usize) usize {
    var length: usize = 0;
    if (uncompressed >= std.math.maxInt(u32)) length += 8;
    if (compressed >= std.math.maxInt(u32)) length += 8;
    if (local_offset >= std.math.maxInt(u32)) length += 8;
    return if (length == 0) 0 else length + 4;
}

fn putU16(sink: *io.Sink, value: u16) Exception!void {
    try sink.writeInt(u16, value, .little);
}

fn putU32(sink: *io.Sink, value: u32) Exception!void {
    try sink.writeInt(u32, value, .little);
}

fn putU64(sink: *io.Sink, value: u64) Exception!void {
    try sink.writeInt(u64, value, .little);
}

fn writeLocalZip64(sink: *io.Sink, compressed: usize, uncompressed: usize, descriptor: bool) Exception!void {
    if (localZip64Length(compressed, uncompressed, descriptor) == 0) return;
    try putU16(sink, zip64_extra_id);
    try putU16(sink, 16);
    try putU64(sink, uncompressed);
    try putU64(sink, compressed);
}

fn writeCentralZip64(sink: *io.Sink, compressed: usize, uncompressed: usize, local_offset: usize) Exception!void {
    const length = centralZip64Length(compressed, uncompressed, local_offset);
    if (length == 0) return;
    try putU16(sink, zip64_extra_id);
    try putU16(sink, @intCast(length - 4));
    if (uncompressed >= std.math.maxInt(u32)) try putU64(sink, uncompressed);
    if (compressed >= std.math.maxInt(u32)) try putU64(sink, compressed);
    if (local_offset >= std.math.maxInt(u32)) try putU64(sink, local_offset);
}

fn validatePath(name: []const u8, flags: u16) Exception!void {
    if (bounds.isAbsoluteOrTraversal(name) or (name.len >= 2 and std.ascii.isAlphabetic(name[0]) and name[1] == ':')) return error.DataException;
    // An embedded NUL would truncate the name for any C-string consumer.
    if (std.mem.findScalar(u8, name, 0) != null) return error.DataException;
    if (flags & 0x0800 != 0 and !std.unicode.utf8ValidateSlice(name)) return error.DataException;
}

pub fn compressedSize(entry: Entry, history: []u8, measurement_buffer: []u8, scratch: []u8) Exception!usize {
    switch (entry.method) {
        0 => return entry.data.len,
        8 => {
            if (history.len < deflate_history_size or measurement_buffer.len < deflate_measurement_buffer_size) return error.CapacityException;
            var counter = measurement.Counter.init(null);
            var compressor = try deflate.Compress.init(&counter.writer, history[0..deflate_history_size], deflate_options);
            compressor.writer.writeAll(entry.data) catch return error.InternalException;
            compressor.finish() catch return error.InternalException;
            return measurement.measuredLength(&counter);
        },
        9 => {
            if (history.len < deflate64_history_size or measurement_buffer.len < deflate_measurement_buffer_size) return error.CapacityException;
            var counter = measurement.Counter.init(null);
            var compressor = try deflate.Compress64.init(&counter.writer, history[0..deflate64_history_size], deflate_options);
            compressor.writer.writeAll(entry.data) catch return error.InternalException;
            compressor.finish() catch return error.InternalException;
            return measurement.measuredLength(&counter);
        },
        12 => {
            const required = bzip2.encodeWorkspaceSize(bzip2_block_default);
            if (scratch.len < required) return error.CapacityException;
            return bzip2.requiredSize(entry.data, scratch[0..required], .{ .block_size = bzip2_block_default });
        },
        14 => {
            const required = lzma.encodeWorkspaceSizeBt(lzma_props_default);
            if (scratch.len < required) return error.CapacityException;
            const stream = try lzma.requiredSize(entry.data, scratch[0..required], .{ .properties = lzma_props_default, .marker_required = true });
            return try bounds.addUsize(stream, 9);
        },
        93 => {
            const needed = try zipZstdEncodeSize(entry.data, scratch);
            return needed;
        },
        95 => {
            const required = xz.encodeWorkspaceSizeBt(xz_dictionary_default);
            if (scratch.len < required) return error.CapacityException;
            return xz.requiredSize(entry.data, scratch[0..required], .{ .dictionary_size = xz_dictionary_default, .check = .crc32 });
        },
        98 => {
            const required = ppmd_zip.encodeWorkspaceSize(ppmd_mem_default);
            if (scratch.len < required) return error.CapacityException;
            const stream = try ppmd_zip.requiredSize(entry.data, scratch[0..required], .{ .order = ppmd_order_default, .mem_size = ppmd_mem_default, .restore_method = ppmd_restore_default });
            return try bounds.addUsize(stream, 2);
        },
        else => return error.UnsupportedException,
    }
}

fn zipZstdEncodeSize(input: []const u8, scratch: []u8) Exception!usize {
    const window = zstd_window_default;
    if (scratch.len < zstd_history_default + zstd.encoder_workspace_size) return error.CapacityException;
    const zhistory = scratch[0..zstd_history_default];
    const workspace: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[zstd_history_default..][0..zstd.encoder_workspace_size]));
    var counter = measurement.Counter.init(null);
    var source = std.Io.Reader.fixed(input);
    _ = zstd.encodeStream(&source, &counter.writer, zhistory, workspace, .{ .window_size = window }) catch |err| return encodeMap(err);
    return measurement.measuredLength(&counter);
}

fn writeData(sink: *io.Sink, entry: Entry, provider: crypto.Provider, history: []u8, staging: []u8, scratch: []u8) Exception!void {
    if (!entry.encrypted) {
        if (entry.method == 0) return sink.write(entry.data);
        const compressed = try zipCompressEntry(entry, provider, history, sink.bytes[sink.offset..], scratch);
        sink.offset = try bounds.addUsize(sink.offset, compressed.len);
        return;
    }
    if (entry.zipcrypto) {
        var keys = crypto.ZipCryptoKeys.init(entry.password);
        var header: [12]u8 = undefined;
        try crypto.fillRandom(header[0..11]);
        // With bit 3 set the CRC is unknown, so the check byte is the
        // high time byte.
        header[11] = if (entry.flags & 0x0008 != 0) @truncate(entry.dos_time >> 8) else @truncate(checksum.crc32With(provider, entry.data) >> 24);
        keys.encrypt(&header, &header);
        try sink.write(&header);
        if (entry.password_lifetime != 0 and entry.data.len > entry.password_lifetime) return error.ResourceException;
        if (entry.method == 0) {
            if (sink.bytes.len - sink.offset < entry.data.len) return error.CapacityException;
            keys.encrypt(sink.bytes[sink.offset..][0..entry.data.len], entry.data);
            sink.offset = try bounds.addUsize(sink.offset, entry.data.len);
            return;
        }
        const compressed = try zipCompressEntry(entry, provider, history, staging, scratch);
        if (entry.password_lifetime != 0 and compressed.len > entry.password_lifetime) return error.ResourceException;
        if (sink.bytes.len - sink.offset < compressed.len) return error.CapacityException;
        keys.encrypt(sink.bytes[sink.offset..][0..compressed.len], compressed);
        sink.offset = try bounds.addUsize(sink.offset, compressed.len);
        return;
    }
    const salt_length = try crypto.winzipSaltLength(entry.aes_strength);
    const key_length = try crypto.winzipKeyLength(entry.aes_strength);
    const salt = try entrySalt(entry, salt_length);
    var derived: [66]u8 = undefined;
    try crypto.winzipDeriveKey(provider, entry.password, salt[0..salt_length], key_length, derived[0 .. 2 * key_length + winzip_aes_verify_length]);
    const data_offset = sink.offset;
    try sink.write(salt[0..salt_length]);
    try sink.write(derived[2 * key_length ..][0..winzip_aes_verify_length]);
    if (entry.method == 0) {
        if (entry.password_lifetime != 0 and entry.data.len > entry.password_lifetime) return error.ResourceException;
        try crypto.winzipCtr(provider, derived[0..key_length], sink.bytes[sink.offset..][0..entry.data.len], entry.data);
        sink.offset = try bounds.addUsize(sink.offset, entry.data.len);
    } else {
        const compressed = try zipCompressEntry(entry, provider, history, staging, scratch);
        if (entry.password_lifetime != 0 and compressed.len > entry.password_lifetime) return error.ResourceException;
        try crypto.winzipCtr(provider, derived[0..key_length], sink.bytes[sink.offset..][0..compressed.len], compressed);
        sink.offset = try bounds.addUsize(sink.offset, compressed.len);
    }
    const ciphertext = sink.bytes[data_offset + salt_length + winzip_aes_verify_length .. sink.offset];
    var mac: [crypto.hmac_sha1_length]u8 = undefined;
    crypto.hmacSha1(provider, &mac, ciphertext, derived[key_length .. 2 * key_length]);
    try sink.write(mac[0..winzip_aes_hmac_length]);
}

fn zipCompressEntry(entry: Entry, provider: crypto.Provider, history: []u8, output: []u8, scratch: []u8) Exception![]const u8 {
    switch (entry.method) {
        8 => {
            if (history.len < deflate_history_size or output.len < deflate_measurement_buffer_size) return error.CapacityException;
            var writer = std.Io.Writer.fixed(output);
            var compressor = try deflate.Compress.init(&writer, history[0..deflate_history_size], deflate_options);
            compressor.writer.writeAll(entry.data) catch return error.InternalException;
            compressor.finish() catch return error.InternalException;
            return output[0..writer.end];
        },
        9 => {
            if (history.len < deflate64_history_size or output.len < deflate_measurement_buffer_size) return error.CapacityException;
            var writer = std.Io.Writer.fixed(output);
            var compressor = try deflate.Compress64.init(&writer, history[0..deflate64_history_size], deflate_options);
            compressor.writer.writeAll(entry.data) catch return error.InternalException;
            compressor.finish() catch return error.InternalException;
            return output[0..writer.end];
        },
        12 => {
            const required = bzip2.encodeWorkspaceSize(bzip2_block_default);
            if (scratch.len < required or output.len < deflate_measurement_buffer_size) return error.CapacityException;
            const written = try bzip2.encode(entry.data, output, scratch[0..required], .{ .block_size = bzip2_block_default });
            return output[0..written];
        },
        14 => {
            const required = lzma.encodeWorkspaceSizeBt(lzma_props_default);
            if (scratch.len < required) return error.CapacityException;
            var payload: [9]u8 = undefined;
            std.mem.writeInt(u16, payload[0..2], 0x0306, .little);
            std.mem.writeInt(u16, payload[2..4], 5, .little);
            payload[4] = lzma_props_default.encode();
            std.mem.writeInt(u32, payload[5..9], lzma_props_default.dictionary_size, .little);
            if (output.len < 9) return error.CapacityException;
            @memcpy(output[0..9], &payload);
            const written = try lzma.encode(entry.data, output[9..], scratch[0..required], .{ .properties = lzma_props_default, .marker_required = true });
            return output[0 .. 9 + written];
        },
        93 => {
            const window = zstd_window_default;
            if (scratch.len < zstd_history_default + zstd.encoder_workspace_size) return error.CapacityException;
            const zhistory = scratch[0..zstd_history_default];
            const workspace: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[zstd_history_default..][0..zstd.encoder_workspace_size]));
            var source = std.Io.Reader.fixed(entry.data);
            var writer = std.Io.Writer.fixed(output);
            _ = zstd.encodeStream(&source, &writer, zhistory, workspace, .{ .window_size = window }) catch |err| return encodeMap(err);
            return output[0..writer.end];
        },
        95 => {
            const required = xz.encodeWorkspaceSizeBt(xz_dictionary_default);
            if (scratch.len < required) return error.CapacityException;
            const written = try xz.encode(entry.data, output, scratch[0..required], .{ .dictionary_size = xz_dictionary_default, .check = .crc32, .provider = provider });
            return output[0..written];
        },
        98 => {
            const required = ppmd_zip.encodeWorkspaceSize(ppmd_mem_default);
            if (scratch.len < required) return error.CapacityException;
            var props: [2]u8 = undefined;
            const prop_value: u16 = @intCast((ppmd_order_default - 1) | ((ppmd_mem_default >> 20) - 1) << 4 | ppmd_restore_default << 12);
            std.mem.writeInt(u16, &props, prop_value, .little);
            if (output.len < 2) return error.CapacityException;
            @memcpy(output[0..2], &props);
            const written = try ppmd_zip.encode(entry.data, output[2..], scratch[0..required], .{ .order = ppmd_order_default, .mem_size = ppmd_mem_default, .restore_method = ppmd_restore_default });
            return output[0 .. 2 + written];
        },
        else => return error.UnsupportedException,
    }
}

fn encodeMap(err: zstd.EncodeError) Exception {
    return switch (err) {
        error.DataException => error.DataException,
        error.ResourceException => error.ResourceException,
        error.IoException => error.IoException,
    };
}

pub const Info = struct {
    name: []const u8,
    method: u16,
    flags: u16,
    dos_time: u16,
    crc: u32,
    compressed_size: usize,
    uncompressed_size: usize,
    local_offset: usize,
    local_relative: usize = 0,
    disk_number: u32 = 0,
    ordinal: usize,
    version_made_by: u16,
    internal_attributes: u16,
    external_attributes: u32,
    encrypted: bool = false,
    aes_strength: u8 = 0,
    aes_version: u16 = 0,
    actual_method: u16 = 0,
    extra: []const u8 = &.{},
};

pub const ZipDecodeOptions = struct {
    password: ?[]const u8 = null,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
    failure_cause: *crypto.FailureCause,
    staging: []u8 = &.{},
    scratch: []u8 = &.{},
    history: []u8 = &.{},
    provider: crypto.Provider = crypto.default_provider,
    // Spanned reads: absolute offset of each disk's first byte; empty
    // means single-volume (every disk number is 0).
    disk_starts: []const usize = &.{},
};

pub fn zipInspectCount(archive: []const u8) Exception!usize {
    return zipInspectCountEx(archive, .{});
}

pub fn zipInspectCountEx(archive: []const u8, limits: Limits) Exception!usize {
    const directory = try zipDirectory(archive);
    if (directory.count > limits.entries) return error.ResourceException;
    var cursor = directory.offset;
    var index: usize = 0;
    while (index < directory.count) : (index += 1) _ = try zipNext(archive, directory, &cursor, index);
    if (cursor != try bounds.addUsize(directory.offset, directory.size)) return error.DataException;
    return directory.count;
}

pub fn zipInspectOrdinal(archive: []const u8, ordinal: usize) Exception!Info {
    return zipInspectOrdinalEx(archive, ordinal, .{});
}

pub fn zipInspectOrdinalEx(archive: []const u8, ordinal: usize, limits: Limits) Exception!Info {
    const directory = try zipDirectory(archive);
    if (directory.count > limits.entries) return error.ResourceException;
    if (ordinal >= directory.count) return error.DataException;
    var cursor = directory.offset;
    var index: usize = 0;
    while (index < directory.count) : (index += 1) {
        const entry = try zipNext(archive, directory, &cursor, index);
        if (index == ordinal) return entry;
    }
    return error.DataException;
}

pub fn zipDecodeOrdinal(archive: []const u8, ordinal: usize, output: []u8, options: ZipDecodeOptions) Exception!usize {
    options.failure_cause.* = .none;
    const entry = try zipInspectOrdinal(archive, ordinal);
    return try zipDecodeEntry(archive, entry, output, options);
}

fn zipDecodeEntry(archive: []const u8, entry: Info, output: []u8, options: ZipDecodeOptions) Exception!usize {
    if (output.len < entry.uncompressed_size) return error.CapacityException;
    if (entry.flags & 0x40 != 0) return error.UnsupportedException;
    if (entry.flags & 0x20 != 0) return error.UnsupportedException;
    const encrypted = entry.flags & 1 != 0;
    if (encrypted and entry.method != winzip_aes_method and !zipMethodSupported(entry.method)) return error.UnsupportedException;
    if (!encrypted and entry.method == winzip_aes_method) return error.DataException;
    // The local offset is relative to the disk holding the local header;
    // single-volume archives start at 0.
    const local_offset = if (options.disk_starts.len > 0) blk: {
        if (entry.disk_number >= options.disk_starts.len) return error.DataException;
        break :blk try bounds.addUsize(options.disk_starts[entry.disk_number], entry.local_relative);
    } else blk: {
        if (entry.disk_number != 0) return error.UnsupportedException;
        break :blk entry.local_offset;
    };
    const header = try bounds.slice(archive, local_offset, 30);
    if (readU32(header, 0) != local_signature) return error.DataException;
    const local_method = readU16(header, 8);
    const local_flags = readU16(header, 6);
    const local_crc = readU32(header, 14);
    const local_compressed = readU32(header, 18);
    const local_uncompressed = readU32(header, 22);
    const name_length = readU16(header, 26);
    const extra_length = readU16(header, 28);
    if (local_flags != entry.flags or local_method != entry.method) return error.DataException;
    const local_name = try bounds.slice(archive, local_offset + 30, name_length);
    if (!std.mem.eql(u8, local_name, entry.name)) return error.DataException;
    if (entry.flags & 8 == 0) {
        if (local_crc != entry.crc or (local_compressed != std.math.maxInt(u32) and local_compressed != entry.compressed_size) or (local_uncompressed != std.math.maxInt(u32) and local_uncompressed != entry.uncompressed_size)) return error.DataException;
    }
    const data_offset = try bounds.addUsize(local_offset, 30 + name_length + extra_length);
    const compressed = try bounds.slice(archive, data_offset, entry.compressed_size);
    if (entry.flags & 8 != 0) try zipValidateDataDescriptor(archive, data_offset, entry);
    if (encrypted) {
        const password = options.password orelse return error.UnsupportedException;
        if (entry.method == winzip_aes_method) {
            const key_length = try crypto.winzipKeyLength(entry.aes_strength);
            const salt_length = try crypto.winzipSaltLength(entry.aes_strength);
            const header_length = try bounds.addUsize(try bounds.addUsize(salt_length, winzip_aes_verify_length), winzip_aes_hmac_length);
            if (entry.compressed_size < header_length) return error.DataException;
            const ciphertext_size = entry.compressed_size - header_length;
            if (options.kdf_rounds_limit != 0 and options.kdf_rounds_limit < crypto.winzip_pbkdf2_rounds) {
                options.failure_cause.* = .kdf_limit;
                return error.ResourceException;
            }
            if (options.password_lifetime != 0 and ciphertext_size > options.password_lifetime) {
                options.failure_cause.* = .password_lifetime;
                return error.ResourceException;
            }
            const derived_length = try bounds.addUsize(2 * key_length, winzip_aes_verify_length);
            var derived: [66]u8 = undefined;
            try crypto.winzipDeriveKey(options.provider, password, compressed[0..salt_length], key_length, derived[0..derived_length]);
            const stored_verify = compressed[salt_length..][0..winzip_aes_verify_length];
            if (!crypto.constantTimeEql(derived[2 * key_length .. derived_length], stored_verify)) {
                options.failure_cause.* = .wrong_password;
                return error.DataException;
            }
            const ciphertext = compressed[header_length - winzip_aes_hmac_length ..][0..ciphertext_size];
            const stored_hmac = compressed[entry.compressed_size - winzip_aes_hmac_length ..];
            var mac: [crypto.hmac_sha1_length]u8 = undefined;
            crypto.hmacSha1(options.provider, &mac, ciphertext, derived[key_length..][0..key_length]);
            if (!crypto.constantTimeEql(mac[0..winzip_aes_hmac_length], stored_hmac)) return error.IntegrityException;
            if (options.staging.len < ciphertext_size) return error.CapacityException;
            try crypto.winzipCtr(options.provider, derived[0..key_length], options.staging[0..ciphertext_size], ciphertext);
            _ = try zipDecompress(entry, options.staging[0..ciphertext_size], output, options);
            if (entry.aes_version == 1) {
                if (checksum.crc32With(options.provider, output[0..entry.uncompressed_size]) != entry.crc) return error.IntegrityException;
            }
            return entry.uncompressed_size;
        }
        if (entry.compressed_size < 12) return error.DataException;
        const ciphertext_size = entry.compressed_size - 12;
        if (options.password_lifetime != 0 and ciphertext_size > options.password_lifetime) {
            options.failure_cause.* = .password_lifetime;
            return error.ResourceException;
        }
        if (options.staging.len < ciphertext_size) return error.CapacityException;
        var keys = crypto.ZipCryptoKeys.init(password);
        var crypto_header: [12]u8 = undefined;
        @memcpy(&crypto_header, compressed[0..12]);
        keys.decrypt(&crypto_header, &crypto_header);
        const check_byte: u8 = if (entry.flags & 8 != 0) @truncate(entry.dos_time >> 8) else @truncate(entry.crc >> 24);
        if (crypto_header[11] != check_byte) {
            options.failure_cause.* = .wrong_password;
            return error.DataException;
        }
        keys.decrypt(options.staging[0..ciphertext_size], compressed[12..]);
        _ = try zipDecompress(entry, options.staging[0..ciphertext_size], output, options);
        if (checksum.crc32With(options.provider, output[0..entry.uncompressed_size]) != entry.crc) return error.IntegrityException;
        return entry.uncompressed_size;
    }
    const decoded = try zipDecompress(entry, compressed, output, options);
    if (decoded != entry.uncompressed_size) return error.DataException;
    if (checksum.crc32With(options.provider, output[0..entry.uncompressed_size]) != entry.crc) return error.IntegrityException;
    return decoded;
}

fn zipMethodSupported(method: u16) bool {
    return switch (method) {
        0, 8, 9, 12, 14, 93, 95, 98 => true,
        else => false,
    };
}

fn zipDecompress(entry: Info, compressed: []const u8, output: []u8, options: ZipDecodeOptions) Exception!usize {
    switch (entry.actual_method) {
        0 => {
            if (compressed.len != entry.uncompressed_size) return error.DataException;
            @memcpy(output[0..entry.uncompressed_size], compressed);
            return entry.uncompressed_size;
        },
        8 => {
            if (options.history.len < deflate_history_size) return error.CapacityException;
            var source = std.Io.Reader.fixed(compressed);
            var writer = std.Io.Writer.fixed(output[0..entry.uncompressed_size]);
            var inflater = deflate_seam.Decode.initBound(options.provider, &source, options.history[0..deflate_history_size]) catch return error.UnsupportedException;
            inflater.readerPtr().streamExact64(&writer, entry.uncompressed_size) catch return error.DataException;
            if (writer.end != entry.uncompressed_size or source.seek != compressed.len) return error.DataException;
            return entry.uncompressed_size;
        },
        9 => {
            if (options.history.len < deflate64_decode_history_size) return error.CapacityException;
            var source = std.Io.Reader.fixed(compressed);
            var writer = std.Io.Writer.fixed(output[0..entry.uncompressed_size]);
            var inflater = deflate.Decompress64.init(&source, options.history[0..deflate64_decode_history_size]);
            inflater.reader.streamExact64(&writer, entry.uncompressed_size) catch return error.DataException;
            if (writer.end != entry.uncompressed_size or source.seek != compressed.len) return error.DataException;
            return entry.uncompressed_size;
        },
        12 => {
            const scratch_size = try bzip2.decodeWorkspaceSizeFor(compressed);
            if (scratch_size > options.scratch.len) return error.CapacityException;
            const decoded = try bzip2.decode(compressed, output[0..entry.uncompressed_size], options.scratch[0..scratch_size], options.provider);
            if (decoded != entry.uncompressed_size) return error.DataException;
            return decoded;
        },
        14 => {
            if (compressed.len < 9) return error.DataException;
            const properties_size = readU16(compressed, 2);
            if (properties_size != 5 or compressed.len < 9 + properties_size) return error.DataException;
            const dictionary = readU32(compressed, 5);
            const properties = try lzma.Properties.decode(compressed[4], dictionary);
            const scratch_size = lzma.decodeWorkspaceSize(properties);
            if (scratch_size > options.scratch.len) return error.CapacityException;
            const lzma_options: lzma.Options = .{
                .properties = properties,
                .unpack_size = entry.uncompressed_size,
                .marker_required = entry.flags & 2 != 0,
            };
            const decoded = try lzma_seam.decode(options.provider, compressed[9..], output[0..entry.uncompressed_size], options.scratch[0..scratch_size], lzma_options);
            if (decoded != entry.uncompressed_size) return error.DataException;
            return decoded;
        },
        93 => {
            const window = try zipZstdWindow(compressed);
            const needed = try bounds.addUsize(window, zstd.block_size_max);
            if (needed > options.scratch.len) return error.CapacityException;
            var source = std.Io.Reader.fixed(compressed);
            var writer = std.Io.Writer.fixed(output[0..entry.uncompressed_size]);
            const decoded = zstd.decodeStream(&source, &writer, options.scratch[0..needed], .{
                .window_size = window,
                .max_decoded_bytes = entry.uncompressed_size,
            }) catch |err| {
                return switch (err) {
                    error.UnsupportedException => error.UnsupportedException,
                    error.ResourceException => error.ResourceException,
                    error.IoException => error.IoException,
                    error.IntegrityException => error.IntegrityException,
                    else => error.DataException,
                };
            };
            if (decoded != entry.uncompressed_size or source.seek != compressed.len) return error.DataException;
            return decoded;
        },
        95 => {
            if (options.scratch.len == 0) return error.CapacityException;
            const decoded = try xz.decode(compressed, output[0..entry.uncompressed_size], options.scratch, options.provider);
            if (decoded != entry.uncompressed_size) return error.DataException;
            return decoded;
        },
        98 => {
            if (compressed.len < 6) return error.DataException;
            const props = readU16(compressed, 0);
            const order = (props & 0xF) + 1;
            const mem_mb = ((props >> 4) & 0xFF) + 1;
            const restore = props >> 12;
            if (order < ppmd_zip.order_min or order > ppmd_zip.order_max) return error.UnsupportedException;
            if (restore > ppmd_zip.restore_cut_off) return error.UnsupportedException;
            const mem_size: u32 = @as(u32, mem_mb) << 20;
            const scratch_size = ppmd_zip.decodeWorkspaceSize(mem_size);
            if (scratch_size > options.scratch.len) return error.CapacityException;
            const result = try ppmd_zip.decode(compressed[2..], output[0..entry.uncompressed_size], options.scratch[0..scratch_size], .{
                .order = order,
                .mem_size = mem_size,
                .restore_method = restore,
            });
            if (result.decoded != entry.uncompressed_size) return error.DataException;
            if (result.consumed + 2 != compressed.len) return error.DataException;
            return result.decoded;
        },
        else => return error.UnsupportedException,
    }
}

fn zipZstdWindow(compressed: []const u8) Exception!u32 {
    if (compressed.len < 6) return error.DataException;
    const magic = readU32(compressed, 0);
    if (magic == 0xFD2F_B528) {
        const descriptor = compressed[4];
        if (descriptor & 0x20 == 0) {
            if (compressed.len < 6) return error.DataException;
            const window_descriptor = compressed[5];
            const window_log: u32 = 10 + (window_descriptor >> 3);
            // RFC 8878 caps windowLog at 31; larger values also exceed the u5
            // shift range, which is UB in release-fast.
            if (window_log > 31) return error.DataException;
            const window_base: u32 = @as(u32, 1) << @intCast(window_log);
            const window_add = (window_base / 8) * (window_descriptor & 0x07);
            return window_base + window_add;
        }
        const content_size = zstd.frameContentSize(compressed, zstd.window_size_max) catch return error.DataException;
        return @intCast(@max(content_size, 1024));
    }
    if (magic >= 0x184D_2A50 and magic <= 0x184D_2A5F) return 1024;
    return error.DataException;
}

fn zipValidateDataDescriptor(archive: []const u8, data_offset: usize, entry: Info) Exception!void {
    var offset = try bounds.addUsize(data_offset, entry.compressed_size);
    const marker = try bounds.slice(archive, offset, 4);
    if (readU32(marker, 0) == 0x0807_4b50) offset = try bounds.addUsize(offset, 4);
    const zip64 = entry.compressed_size >= std.math.maxInt(u32) or entry.uncompressed_size >= std.math.maxInt(u32);
    const descriptor = try bounds.slice(archive, offset, if (zip64) 20 else 12);
    if (readU32(descriptor, 0) != entry.crc) return error.DataException;
    if (zip64) {
        if (readU64(descriptor, 4) != entry.compressed_size or readU64(descriptor, 12) != entry.uncompressed_size) return error.DataException;
    } else if (readU32(descriptor, 4) != entry.compressed_size or readU32(descriptor, 8) != entry.uncompressed_size) return error.DataException;
}

const ZipDirectory = struct { offset: usize, size: usize, count: usize, base: usize };

fn zipDirectory(archive: []const u8) Exception!ZipDirectory {
    if (archive.len < 22) return error.DataException;
    const earliest = if (archive.len > 22 + std.math.maxInt(u16)) archive.len - (22 + std.math.maxInt(u16)) else 0;
    var position = archive.len - 22;
    while (true) {
        if (readU32(archive, position) == end_signature) {
            const comment = readU16(archive, position + 20);
            if (position + 22 + comment == archive.len) {
                const disk = readU16(archive, position + 4);
                const central_disk = readU16(archive, position + 6);
                const disk_count = readU16(archive, position + 8);
                const count: u64 = readU16(archive, position + 10);
                const size: u64 = readU32(archive, position + 12);
                const offset: u64 = readU32(archive, position + 16);
                const zip64 = disk == std.math.maxInt(u16) or central_disk == std.math.maxInt(u16) or disk_count == std.math.maxInt(u16) or count == std.math.maxInt(u16) or size == std.math.maxInt(u32) or offset == std.math.maxInt(u32);
                if (!zip64 and (disk != 0 or central_disk != 0 or disk_count != count)) return error.UnsupportedException;
                if (zip64) {
                    if (position < 20 or readU32(archive, position - 20) != zip64_locator_signature) return error.DataException;
                    if (readU32(archive, position - 16) != 0 or readU32(archive, position - 4) != 1) return error.UnsupportedException;
                    return zip64Directory(archive, position - 20, readU64(archive, position - 12));
                }
                const size_usize = std.math.cast(usize, size) orelse return error.ResourceException;
                const offset_usize = std.math.cast(usize, offset) orelse return error.ResourceException;
                const count_usize = std.math.cast(usize, count) orelse return error.ResourceException;
                if (size_usize > position) return error.DataException;
                const physical = position - size_usize;
                if (offset_usize > physical) return error.DataException;
                return .{ .offset = physical, .size = size_usize, .count = count_usize, .base = physical - offset_usize };
            }
        }
        if (position == earliest) break;
        position -= 1;
    }
    return error.DataException;
}

fn zip64Directory(archive: []const u8, locator: usize, record_relative: u64) Exception!ZipDirectory {
    const relative = std.math.cast(usize, record_relative) orelse return error.ResourceException;
    if (locator < 12 or relative > locator - 12) return error.DataException;
    var candidate = locator - 12;
    while (true) {
        if (readU32(archive, candidate) == zip64_end_signature) {
            const record_size = readU64(archive, candidate + 4);
            const record_end = std.math.add(u64, candidate, std.math.add(u64, 12, record_size) catch return error.DataException) catch return error.DataException;
            if (record_end == locator) {
                const record = try bounds.slice(archive, candidate, 56);
                if (record_size < 44 or readU32(record, 16) != 0 or readU32(record, 20) != 0) return error.UnsupportedException;
                const count = readU64(record, 32);
                if (readU64(record, 24) != count) return error.UnsupportedException;
                const size = std.math.cast(usize, readU64(record, 40)) orelse return error.ResourceException;
                const offset = std.math.cast(usize, readU64(record, 48)) orelse return error.ResourceException;
                if (candidate < relative) return error.DataException;
                const base = candidate - relative;
                const central = try bounds.addUsize(base, offset);
                if (central > candidate or size != candidate - central) return error.DataException;
                return .{ .offset = central, .size = size, .count = std.math.cast(usize, count) orelse return error.ResourceException, .base = base };
            }
        }
        if (candidate == relative) break;
        candidate -= 1;
    }
    return error.DataException;
}

fn zipNext(archive: []const u8, directory: ZipDirectory, cursor: *usize, ordinal: usize) Exception!Info {
    const end = try bounds.addUsize(directory.offset, directory.size);
    const record = try bounds.slice(archive, cursor.*, 46);
    if (cursor.* >= end or readU32(record, 0) != central_signature) return error.DataException;
    const method = readU16(record, 10);
    const flags = readU16(record, 8);
    const name_length = readU16(record, 28);
    const extra_length = readU16(record, 30);
    const comment_length = readU16(record, 32);
    const record_length = try bounds.addUsize(46 + name_length, extra_length + comment_length);
    if (record_length > end - cursor.*) return error.DataException;
    const name = try bounds.slice(archive, cursor.* + 46, name_length);
    try validatePath(name, readU16(record, 8));
    const extra = try bounds.slice(archive, cursor.* + 46 + name_length, extra_length);
    var compressed: u64 = readU32(record, 20);
    var uncompressed: u64 = readU32(record, 24);
    var local_relative: u64 = readU32(record, 42);
    var disk: u64 = readU16(record, 34);
    try zip64Extents(extra, &compressed, &uncompressed, &local_relative, &disk);
    cursor.* = try bounds.addUsize(cursor.*, record_length);
    var aes_strength: u8 = 0;
    var aes_version: u16 = 0;
    var actual_method: u16 = 0;
    if (method == winzip_aes_method) {
        try parseWinzipAesExtra(extra, &aes_strength, &aes_version, &actual_method);
    } else {
        actual_method = method;
    }
    return .{ .name = name, .method = method, .flags = flags, .dos_time = readU16(record, 12), .crc = readU32(record, 16), .compressed_size = std.math.cast(usize, compressed) orelse return error.ResourceException, .uncompressed_size = std.math.cast(usize, uncompressed) orelse return error.ResourceException, .local_offset = try bounds.addUsize(directory.base, std.math.cast(usize, local_relative) orelse return error.ResourceException), .local_relative = std.math.cast(usize, local_relative) orelse return error.ResourceException, .disk_number = std.math.cast(u32, disk) orelse return error.ResourceException, .ordinal = ordinal, .version_made_by = readU16(record, 4), .internal_attributes = readU16(record, 36), .external_attributes = readU32(record, 38), .encrypted = flags & 1 != 0, .aes_strength = aes_strength, .aes_version = aes_version, .actual_method = actual_method, .extra = extra };
}

fn parseWinzipAesExtra(extra: []const u8, strength: *u8, version: *u16, actual_method: *u16) Exception!void {
    var offset: usize = 0;
    while (offset < extra.len) {
        if (extra.len - offset < 4) return error.DataException;
        const id = readU16(extra, offset);
        const length = readU16(extra, offset + 2);
        offset = try bounds.addUsize(offset, 4);
        if (length > extra.len - offset) return error.DataException;
        if (id == winzip_aes_extra_id) {
            if (length != winzip_aes_extra_data_length) return error.DataException;
            const payload = extra[offset..][0..length];
            const vendor = payload[2..4];
            if (!std.mem.eql(u8, vendor, winzip_aes_vendor)) return error.UnsupportedException;
            const parsed_strength = payload[4];
            if (parsed_strength < 1 or parsed_strength > 3) return error.UnsupportedException;
            const parsed_method = readU16(payload, 5);
            // The stream inside AES is any supported method; WinZip pairs
            // AES with bzip2, LZMA, and PPMd.
            if (!zipMethodSupported(parsed_method)) return error.UnsupportedException;
            strength.* = parsed_strength;
            version.* = readU16(payload, 0);
            actual_method.* = parsed_method;
            return;
        }
        offset = try bounds.addUsize(offset, length);
    }
    return error.DataException;
}

fn zip64Extents(extra: []const u8, compressed: *u64, uncompressed: *u64, local_offset: *u64, disk: *u64) Exception!void {
    var offset: usize = 0;
    while (offset < extra.len) {
        if (extra.len - offset < 4) return error.DataException;
        const id = readU16(extra, offset);
        const length = readU16(extra, offset + 2);
        offset = try bounds.addUsize(offset, 4);
        if (length > extra.len - offset) return error.DataException;
        if (id == zip64_extra_id) {
            var value_offset: usize = 0;
            if (uncompressed.* == std.math.maxInt(u32)) {
                if (length - value_offset < 8) return error.DataException;
                uncompressed.* = readU64(extra, offset + value_offset);
                value_offset += 8;
            }
            if (compressed.* == std.math.maxInt(u32)) {
                if (length - value_offset < 8) return error.DataException;
                compressed.* = readU64(extra, offset + value_offset);
                value_offset += 8;
            }
            if (local_offset.* == std.math.maxInt(u32)) {
                if (length - value_offset < 8) return error.DataException;
                local_offset.* = readU64(extra, offset + value_offset);
                value_offset += 8;
            }
            if (disk.* == std.math.maxInt(u16)) {
                if (length - value_offset < 4) return error.DataException;
                disk.* = readU32(extra, offset + value_offset);
            }
            return;
        }
        offset = try bounds.addUsize(offset, length);
    }
    if (compressed.* == std.math.maxInt(u32) or uncompressed.* == std.math.maxInt(u32) or local_offset.* == std.math.maxInt(u32) or disk.* == std.math.maxInt(u16)) return error.DataException;
}

fn readU16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .little);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn readU64(data: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, data[offset..][0..8], .little);
}

test "zip encryption roundtrips zipcrypto and winzip aes strengths" {
    const testing = std.testing;
    const data = "the quick brown fox jumps over the lazy dog. the quick brown fox!";
    const password = "correct horse battery staple";
    const entries = [_]Entry{
        .{ .name = "plain.txt", .data = data, .method = 0 },
        .{ .name = "zipcrypto.txt", .data = data, .method = 0, .encrypted = true, .zipcrypto = true, .password = password },
        .{ .name = "aes128.bin", .data = data, .method = 0, .encrypted = true, .password = password, .aes_strength = 1 },
        .{ .name = "aes192.bin", .data = data, .method = 0, .encrypted = true, .password = password, .aes_strength = 2 },
        .{ .name = "aes256.bin", .data = data, .method = 0, .encrypted = true, .password = password, .aes_strength = 3 },
    };
    var cause: crypto.FailureCause = .none;
    var archive: [8192]u8 = undefined;
    const written = try encode(&entries, "", &archive, crypto.default_provider, &.{}, &.{}, &.{}, &.{}, &cause);
    var staging: [4096]u8 = undefined;
    for (entries, 0..) |entry, ordinal| {
        var output: [128]u8 = undefined;
        const decoded = try zipDecodeOrdinal(archive[0..written], ordinal, &output, .{
            .password = if (entry.encrypted) password else null,
            .failure_cause = &cause,
            .staging = &staging,
        });
        try testing.expectEqual(data.len, decoded);
        try testing.expectEqualSlices(u8, data, output[0..decoded]);
    }
}

test "zip wrong password reports wrong_password cause" {
    const testing = std.testing;
    const data = "secret payload bytes, secret payload bytes, secret!";
    const entries = [_]Entry{
        .{ .name = "aes256.bin", .data = data, .method = 0, .encrypted = true, .password = "right", .aes_strength = 3 },
        .{ .name = "zipcrypto.txt", .data = data, .method = 0, .encrypted = true, .zipcrypto = true, .password = "right" },
    };
    var cause: crypto.FailureCause = .none;
    var archive: [4096]u8 = undefined;
    const written = try encode(&entries, "", &archive, crypto.default_provider, &.{}, &.{}, &.{}, &.{}, &cause);
    var staging: [4096]u8 = undefined;
    var output: [128]u8 = undefined;
    for (0..entries.len) |ordinal| {
        cause = .none;
        if (zipDecodeOrdinal(archive[0..written], ordinal, &output, .{
            .password = "wrong",
            .failure_cause = &cause,
            .staging = &staging,
        })) |_| {
            try testing.expect(false);
        } else |err| {
            // A wrong password clears the one-byte PKWARE check once in 256
            // attempts; only the CRC rejects the rest.
            try testing.expect(err == error.DataException or err == error.IntegrityException);
            if (err == error.DataException) try testing.expectEqual(crypto.FailureCause.wrong_password, cause);
        }
    }
}

test "zip kdf_rounds_limit gates winzip aes" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a.bin", .data = "secret", .method = 0, .encrypted = true, .password = "pw", .kdf_rounds_limit = crypto.winzip_pbkdf2_rounds - 1 },
    };
    var cause: crypto.FailureCause = .none;
    try testing.expectError(error.ResourceException, requiredSize(&entries, "", &.{}, &.{}, &.{}, &cause));
    try testing.expectEqual(crypto.FailureCause.kdf_limit, cause);
}

test "zip aes128 single entry fits a 512-byte buffer" {
    // A mixed provider build serves no single tag for both arms; an
    // offprem tag has no encoder.
    if (!deflate_seam.encodeServed(checksum.default_provider) or !deflate_seam.decodeServed(checksum.default_provider)) return;

    const testing = std.testing;
    const data = "0123456789abcdef0123456789abcdef";
    const entries = [_]Entry{
        .{ .name = "a.txt", .data = data, .method = 8, .encrypted = true, .password = "pw", .aes_strength = 1 },
    };
    var cause: crypto.FailureCause = .none;
    var history: [deflate_history_size]u8 = undefined;
    var measure_buf: [deflate_measurement_buffer_size]u8 = undefined;
    var small: [512]u8 = undefined;
    var staging: [deflate_measurement_buffer_size]u8 = undefined;
    const required = try requiredSize(&entries, "", &history, &measure_buf, &.{}, &cause);
    try testing.expect(required < 512);
    const written = try encode(&entries, "", &small, crypto.default_provider, &history, &measure_buf, &staging, &.{}, &cause);
    var decode_history: [deflate_history_size]u8 = undefined;
    var output: [64]u8 = undefined;
    const decoded = try zipDecodeOrdinal(small[0..written], 0, &output, .{ .password = "pw", .failure_cause = &cause, .staging = &staging, .history = &decode_history });
    try testing.expectEqualSlices(u8, data, output[0..decoded]);
}

test "zip winzip aes clears the data descriptor flag" {
    // A descriptor cannot follow WinZip AES data, so bit 3 drops from both
    // headers regardless of the caller's request.
    //
    // A mixed provider build serves no single tag for both arms; run
    // only where the default tag serves them.
    if (!deflate_seam.encodeServed(checksum.default_provider) or !deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const data = "aes entry that requested the streaming shape";
    const entries = [_]Entry{
        .{ .name = "a.bin", .data = data, .method = 8, .encrypted = true, .password = "pw", .aes_strength = 3, .flags = 0x0008 },
    };
    var cause: crypto.FailureCause = .none;
    var history: [deflate_history_size]u8 = undefined;
    var measure_buf: [deflate_measurement_buffer_size]u8 = undefined;
    var staging: [256]u8 = undefined;
    var archive: [512]u8 = undefined;
    const written = try encode(&entries, "", &archive, crypto.default_provider, &history, &measure_buf, &staging, &.{}, &cause);
    try testing.expectEqual(@as(u16, 0x0001), readU16(&archive, 6));
    var offset: usize = 0;
    while (offset + 4 <= written) : (offset += 1) {
        if (readU32(&archive, offset) == central_signature) break;
    }
    try testing.expect(offset + 4 <= written);
    try testing.expectEqual(@as(u16, 0x0001), readU16(&archive, offset + 8));
    var decode_history: [deflate_history_size]u8 = undefined;
    var output: [128]u8 = undefined;
    const decoded = try zipDecodeOrdinal(archive[0..written], 0, &output, .{ .password = "pw", .failure_cause = &cause, .staging = &staging, .history = &decode_history });
    try testing.expectEqualSlices(u8, data, output[0..decoded]);
}

test "zip zipcrypto data descriptor uses the time check byte" {
    // With bit 3 set the zipcrypto check byte is the high time byte; the
    // CRC only arrives in the descriptor.
    const testing = std.testing;
    const data = "streamed zipcrypto payload for the time check byte";
    const crc = checksum.crc32With(crypto.default_provider, data);
    var dos_time: u16 = 0xab00;
    if (dos_time >> 8 == @as(u8, @truncate(crc >> 24))) dos_time = 0xcd00;
    try testing.expect(dos_time >> 8 != @as(u8, @truncate(crc >> 24)));
    const entries = [_]Entry{
        .{ .name = "s.txt", .data = data, .method = 0, .encrypted = true, .zipcrypto = true, .password = "pw", .flags = 0x0008, .dos_time = dos_time },
    };
    var cause: crypto.FailureCause = .none;
    var archive: [512]u8 = undefined;
    const written = try encode(&entries, "", &archive, crypto.default_provider, &.{}, &.{}, &.{}, &.{}, &cause);
    try testing.expectEqual(@as(u16, 0x0009), readU16(&archive, 6));
    try testing.expectEqual(@as(u32, 0), readU32(&archive, 14));
    try testing.expectEqual(@as(u32, 0), readU32(&archive, 18));
    try testing.expectEqual(@as(u32, 0), readU32(&archive, 22));
    var output: [128]u8 = undefined;
    var staging: [128]u8 = undefined;
    const decoded = try zipDecodeOrdinal(archive[0..written], 0, &output, .{ .password = "pw", .failure_cause = &cause, .staging = &staging });
    try testing.expectEqualSlices(u8, data, output[0..decoded]);
}

test "zip winzip aes accepts every supported compression method" {
    // The AES extra field names the real method; the decoder must accept
    // the full supported set the encoder emits.
    const testing = std.testing;
    const chunk = "actual compression method inside the aes envelope ";
    const data = chunk ++ chunk ++ chunk ++ chunk ++ chunk ++ chunk ++ chunk ++ chunk;
    const password = "pw";
    var cause: crypto.FailureCause = .none;

    {
        const entries = [_]Entry{
            .{ .name = "d64.bin", .data = data, .method = 9, .encrypted = true, .password = password, .aes_strength = 2 },
        };
        var history: [deflate64_history_size]u8 = undefined;
        var measure_buf: [deflate_measurement_buffer_size]u8 = undefined;
        var staging: [256]u8 = undefined;
        var archive: [1024]u8 = undefined;
        const written = try encode(&entries, "", &archive, crypto.default_provider, &history, &measure_buf, &staging, &.{}, &cause);
        var decode_history: [deflate64_decode_history_size]u8 = undefined;
        var output: [data.len]u8 = undefined;
        const decoded = try zipDecodeOrdinal(archive[0..written], 0, &output, .{ .password = password, .failure_cause = &cause, .staging = &staging, .history = &decode_history });
        try testing.expectEqualSlices(u8, data, output[0..decoded]);
    }
    {
        const entries = [_]Entry{
            .{ .name = "bz2.bin", .data = data, .method = 12, .encrypted = true, .password = password, .aes_strength = 3 },
        };
        const scratch_size = bzip2.encodeWorkspaceSize(bzip2_block_default);
        const scratch = try testing.allocator.alloc(u8, scratch_size);
        defer testing.allocator.free(scratch);
        const decode_scratch_size = bzip2.decodeWorkspaceSize(bzip2_block_default);
        const decode_scratch = try testing.allocator.alloc(u8, decode_scratch_size);
        defer testing.allocator.free(decode_scratch);
        var archive: [1024]u8 = undefined;
        var crypto_staging: [512]u8 = undefined;
        const written = try encode(&entries, "", &archive, crypto.default_provider, &.{}, &.{}, &crypto_staging, scratch, &cause);
        var output: [data.len]u8 = undefined;
        var decrypt_staging: [512]u8 = undefined;
        const decoded = try zipDecodeOrdinal(archive[0..written], 0, &output, .{ .password = password, .failure_cause = &cause, .staging = &decrypt_staging, .scratch = decode_scratch });
        try testing.expectEqualSlices(u8, data, output[0..decoded]);
    }
}

test "zip spanned write and read roundtrip" {
    const allocator = std.testing.allocator;

    var payload_a: [400000]u8 = undefined;
    var rng: u64 = 0x243F6A8885A308D3;
    for (&payload_a) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @as(u8, @truncate(rng)) & 15;
    }
    for (1..48) |i| @memcpy(payload_a[i * 4096 ..][0..2048], payload_a[0..2048]);
    const payload_b = "tail entry payload";

    const entries = [_]Entry{
        .{ .name = "a.bin", .data = &payload_a, .flags = 0x0008 },
        .{ .name = "b.bin", .data = payload_b },
    };
    var failure_cause: crypto.FailureCause = .none;
    const history = try allocator.alloc(u8, deflate_history_size);
    defer allocator.free(history);
    const measurement_buffer = try allocator.alloc(u8, deflate_measurement_buffer_size);
    defer allocator.free(measurement_buffer);
    const staging = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(staging);
    const scratch = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(scratch);

    const required = try requiredSize(&entries, "", history, measurement_buffer, scratch, &failure_cause);
    const volume_size: u64 = 4096;
    const disks = try allocator.alloc(usize, required / @as(usize, @intCast(volume_size)) + 2);
    defer allocator.free(disks);
    const plan_bounds = try allocator.alloc(usize, required / @as(usize, @intCast(volume_size)) + entries.len + 4);
    defer allocator.free(plan_bounds);
    const output = try allocator.alloc(u8, required + 4);
    defer allocator.free(output);
    const result = try encodeSpanned(&entries, "", output, volume_size, crypto.default_provider, history, measurement_buffer, staging, scratch, &failure_cause, plan_bounds);
    try std.testing.expect(result.volumes > 1);
    try std.testing.expect(std.mem.readInt(u32, output[0..4], .little) == 0x0807_4b50);

    // Slice the disks back out and decode through the spanned entry.
    const volumes_count = (result.total_len + volume_size - 1) / volume_size;
    const volumes = try allocator.alloc([]const u8, volumes_count);
    defer allocator.free(volumes);
    var at: usize = 0;
    for (0..volumes_count) |i| {
        const take = @min(@as(usize, @intCast(volume_size)), result.total_len - at);
        volumes[i] = output[at..][0..take];
        at += take;
    }
    const join = try allocator.alloc(u8, result.total_len);
    defer allocator.free(join);
    const options: ZipDecodeOptions = .{ .failure_cause = &failure_cause, .staging = staging, .scratch = scratch, .history = history, .provider = crypto.default_provider };
    var out_a: [payload_a.len]u8 = undefined;
    const n_a = try zipDecodeOrdinalSpanned(volumes, 0, &out_a, join, disks, options);
    try std.testing.expectEqual(payload_a.len, n_a);
    try std.testing.expectEqualSlices(u8, &payload_a, out_a[0..n_a]);
    var out_b: [payload_b.len]u8 = undefined;
    const n_b = try zipDecodeOrdinalSpanned(volumes, 1, &out_b, join, disks, options);
    try std.testing.expectEqualSlices(u8, payload_b, out_b[0..n_b]);
}
