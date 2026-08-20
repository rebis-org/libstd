const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const crypto = @import("../common/primitive/crypto.zig");
const winzip_aes_verify_length = crypto.winzip_verify_length;
const winzip_aes_hmac_length = crypto.winzip_hmac_length;
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");
const xz = @import("../grammar/xz.zig");
const bzip2 = @import("../leaf/bzip2.zig");
const deflate = @import("../leaf/deflate.zig");
pub const deflate_history_size = deflate.history_size;
pub const deflate64_history_size = deflate.deflate64_history_size;
pub const deflate64_decode_history_size = deflate.deflate64_decode_history_size;
pub const deflate_measurement_buffer_size = deflate.measurement_buffer_size;
const lzma = @import("../leaf/lzma.zig");
const ppmd_zip = @import("../leaf/ppmd/zip.zig");
const zip_ppmd_restore_default = ppmd_zip.restore_restart;
const zstd = @import("../leaf/zstd.zig");

const zip_deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 128 };
const zip_bzip2_block_default = 100_000;
const zip_lzma_props_default: lzma.Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = 1 << 20 };
const zip_zstd_window_default = 1 << 20;
const zip_zstd_history_default = std.mem.alignForward(usize, zip_zstd_window_default + zstd.block_size_max, 4);
const zip_xz_dictionary_default = 1 << 20;
const zip_ppmd_order_default = 8;
const zip_ppmd_mem_default = 4 << 20;
const zip_local_signature: u32 = 0x0403_4b50;
const zip_central_signature: u32 = 0x0201_4b50;
const zip_end_signature: u32 = 0x0605_4b50;
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
pub const ZipEntry = struct {
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
    salt: [16]u8 = .{0} ** 16,
    salt_length: u8 = 0,
    aes_strength: u8 = 3,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
};

pub fn zipRequiredSize(entries: []const ZipEntry, archive_comment: []const u8, history: []u8, measurement_buffer: []u8, scratch: []u8, failure_cause: *crypto.FailureCause) Failure!usize {
    failure_cause.* = .none;
    if (archive_comment.len > std.math.maxInt(u16)) return error.ResourceLimit;
    var local_total: usize = 0;
    var central_total: usize = 0;
    for (entries) |entry| {
        try validateZipEntry(entry);
        if (entry.encrypted and entry.kdf_rounds_limit != 0 and entry.kdf_rounds_limit < crypto.winzip_pbkdf2_rounds) {
            failure_cause.* = .kdf_limit;
            return error.ResourceLimit;
        }
        const compressed = try zipCompressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try zipAesOverhead(entry);
        if (entry.encrypted and entry.password_lifetime != 0 and compressed > entry.password_lifetime) {
            failure_cause.* = .password_lifetime;
            return error.ResourceLimit;
        }
        const local_offset = local_total;
        central_total = try bounds.add(central_total, 46 + entry.name.len + entry.extra.len + zipCentralZip64Length(try bounds.add(compressed, overhead), entry.data.len, local_offset) + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0) + entry.comment.len);
        local_total = try bounds.add(local_total, try bounds.add(30 + entry.name.len + entry.extra.len + zipLocalZip64Length(try bounds.add(compressed, overhead), entry.data.len) + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0), try bounds.add(compressed, overhead)));
    }
    const needs_zip64 = entries.len >= std.math.maxInt(u16) or central_total >= std.math.maxInt(u32) or local_total >= std.math.maxInt(u32);
    return try bounds.add(try bounds.add(local_total, central_total), try bounds.add(22 + archive_comment.len, if (needs_zip64) 76 else 0));
}

pub fn zipEncode(entries: []const ZipEntry, archive_comment: []const u8, output: []u8, history: []u8, measurement_buffer: []u8, staging: []u8, scratch: []u8, failure_cause: *crypto.FailureCause) Failure!usize {
    const required = try zipRequiredSize(entries, archive_comment, history, measurement_buffer, scratch, failure_cause);
    if (output.len < required) return error.InsufficientCapacity;
    var sink = io.Sink{ .bytes = output[0..required] };
    var offsets: usize = 0;
    for (entries) |entry| {
        const compressed = try zipCompressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try zipAesOverhead(entry);
        const stored_size = try bounds.add(compressed, overhead);
        const zip64 = stored_size >= std.math.maxInt(u32) or entry.data.len >= std.math.maxInt(u32);
        const extra_length = try bounds.add(try bounds.add(entry.extra.len, if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0), zipLocalZip64Length(stored_size, entry.data.len));
        try zipU32(&sink, zip_local_signature);
        try zipU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_version_needed else if (zip64) 45 else zipVersionNeeded(entry.method));
        try zipU16(&sink, if (entry.encrypted and !entry.zipcrypto) entry.flags | 1 else effectiveFlags(entry));
        try zipU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_method else entry.method);
        try zipU16(&sink, entry.dos_time);
        try zipU16(&sink, entry.dos_date);
        try zipU32(&sink, if (entry.encrypted and !entry.zipcrypto) 0 else checksum.crc32(entry.data));
        try zipU32(&sink, if (zip64) std.math.maxInt(u32) else std.math.cast(u32, stored_size) orelse return error.ResourceLimit);
        try zipU32(&sink, if (zip64) std.math.maxInt(u32) else std.math.cast(u32, entry.data.len) orelse return error.ResourceLimit);
        try zipU16(&sink, @intCast(entry.name.len));
        try zipU16(&sink, std.math.cast(u16, extra_length) orelse return error.ResourceLimit);
        try sink.write(entry.name);
        try zipWriteLocalZip64(&sink, stored_size, entry.data.len);
        try sink.write(entry.extra);
        if (entry.encrypted and !entry.zipcrypto) try zipWriteAesExtra(&sink, entry);
        try zipWriteData(&sink, entry, history, staging, scratch);
        offsets = try bounds.add(offsets, 30 + entry.name.len + extra_length + stored_size);
    }
    const central_offset = offsets;
    var local_offset: usize = 0;
    for (entries) |entry| {
        const compressed = try zipCompressedSize(entry, history, measurement_buffer, scratch);
        const overhead = try zipAesOverhead(entry);
        const stored_size = try bounds.add(compressed, overhead);
        const zip64 = stored_size >= std.math.maxInt(u32) or entry.data.len >= std.math.maxInt(u32) or local_offset >= std.math.maxInt(u32);
        const local_extra = zipLocalZip64Length(stored_size, entry.data.len);
        const central_extra = zipCentralZip64Length(stored_size, entry.data.len, local_offset);
        const extra_length = try bounds.add(try bounds.add(entry.extra.len, if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0), central_extra);
        try zipU32(&sink, zip_central_signature);
        try zipU16(&sink, entry.version_made_by);
        try zipU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_version_needed else if (zip64) 45 else zipVersionNeeded(entry.method));
        try zipU16(&sink, if (entry.encrypted and !entry.zipcrypto) entry.flags | 1 else effectiveFlags(entry));
        try zipU16(&sink, if (entry.encrypted and !entry.zipcrypto) winzip_aes_method else entry.method);
        try zipU16(&sink, entry.dos_time);
        try zipU16(&sink, entry.dos_date);
        try zipU32(&sink, if (entry.encrypted and !entry.zipcrypto) 0 else checksum.crc32(entry.data));
        try zipU32(&sink, if (stored_size >= std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(stored_size));
        try zipU32(&sink, if (entry.data.len >= std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(entry.data.len));
        try zipU16(&sink, @intCast(entry.name.len));
        try zipU16(&sink, std.math.cast(u16, extra_length) orelse return error.ResourceLimit);
        try zipU16(&sink, @intCast(entry.comment.len));
        try zipU16(&sink, 0);
        try zipU16(&sink, entry.internal_attributes);
        try zipU32(&sink, entry.external_attributes);
        try zipU32(&sink, if (local_offset >= std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(local_offset));
        try sink.write(entry.name);
        try zipWriteCentralZip64(&sink, stored_size, entry.data.len, local_offset);
        try sink.write(entry.extra);
        if (entry.encrypted and !entry.zipcrypto) try zipWriteAesExtra(&sink, entry);
        try sink.write(entry.comment);
        local_offset = try bounds.add(local_offset, 30 + entry.name.len + entry.extra.len + (if (entry.encrypted and !entry.zipcrypto) winzip_aes_extra_record_length else 0) + local_extra + stored_size);
    }
    const central_size = sink.offset - central_offset;
    const needs_zip64 = entries.len >= std.math.maxInt(u16) or central_size >= std.math.maxInt(u32) or central_offset >= std.math.maxInt(u32);
    if (needs_zip64) {
        const record_offset = sink.offset;
        try zipU32(&sink, zip64_end_signature);
        try zipU64(&sink, 44);
        try zipU16(&sink, 45);
        try zipU16(&sink, 45);
        try zipU32(&sink, 0);
        try zipU32(&sink, 0);
        try zipU64(&sink, entries.len);
        try zipU64(&sink, entries.len);
        try zipU64(&sink, central_size);
        try zipU64(&sink, central_offset);
        try zipU32(&sink, zip64_locator_signature);
        try zipU32(&sink, 0);
        try zipU64(&sink, record_offset);
        try zipU32(&sink, 1);
    }
    try zipU32(&sink, zip_end_signature);
    try zipU16(&sink, 0);
    try zipU16(&sink, 0);
    try zipU16(&sink, if (needs_zip64) std.math.maxInt(u16) else @intCast(entries.len));
    try zipU16(&sink, if (needs_zip64) std.math.maxInt(u16) else @intCast(entries.len));
    try zipU32(&sink, if (needs_zip64) std.math.maxInt(u32) else @intCast(central_size));
    try zipU32(&sink, if (needs_zip64) std.math.maxInt(u32) else @intCast(central_offset));
    try zipU16(&sink, @intCast(archive_comment.len));
    try sink.write(archive_comment);
    return sink.offset;
}

fn validateZipEntry(entry: ZipEntry) Failure!void {
    if (entry.name.len == 0 or entry.name.len > std.math.maxInt(u16) or entry.extra.len > std.math.maxInt(u16) or entry.comment.len > std.math.maxInt(u16)) return error.InvalidCall;
    if (entry.flags & ~@as(u16, 0x0800) != 0 or (entry.flags & 0x0800 != 0 and !std.unicode.utf8ValidateSlice(entry.name))) return error.Unsupported;
    try validateZipPath(entry.name, entry.flags);
    switch (entry.method) {
        0, 8, 9, 12, 14, 93, 95, 98 => {},
        else => return error.Unsupported,
    }
    if (entry.name[entry.name.len - 1] == '/' and entry.data.len != 0) return error.InvalidCall;
    try zipValidateExtra(entry.extra);
    if (entry.encrypted) {
        if (entry.password.len == 0) return error.InvalidCall;
        if (entry.zipcrypto) {
            if (entry.salt_length != 0) return error.InvalidCall;
        } else {
            if (entry.aes_strength != 3) return error.Unsupported;
            if (entry.salt_length > 16) return error.InvalidCall;
        }
    }
}

fn effectiveFlags(entry: ZipEntry) u16 {
    var flags = entry.flags;
    if (entry.method == 14) flags |= 0x0002;
    if (entry.encrypted) flags |= 0x0001;
    return flags;
}

fn zipVersionNeeded(method: u16) u16 {
    return switch (method) {
        9 => 21,
        12 => 46,
        14, 93, 95, 98 => 63,
        else => 20,
    };
}

pub fn zipEncodeScratchSize(entry: ZipEntry) usize {
    return switch (entry.method) {
        0, 8, 9 => 0,
        12 => bzip2.encodeWorkspaceSize(zip_bzip2_block_default),
        14 => lzma.encodeWorkspaceSizeBt(zip_lzma_props_default),
        93 => zip_zstd_history_default + zstd.encoder_workspace_size,
        95 => xz.encodeWorkspaceSizeBt(zip_xz_dictionary_default),
        98 => ppmd_zip.encodeWorkspaceSize(zip_ppmd_mem_default),
        else => 0,
    };
}

fn zipAesOverhead(entry: ZipEntry) Failure!usize {
    if (!entry.encrypted) return 0;
    if (entry.zipcrypto) return 12;
    const salt_length = try crypto.winzipSaltLength(entry.aes_strength);
    return try bounds.add(try bounds.add(salt_length, winzip_aes_verify_length), winzip_aes_hmac_length);
}

fn zipWriteAesExtra(sink: *io.Sink, entry: ZipEntry) Failure!void {
    try zipU16(sink, winzip_aes_extra_id);
    try zipU16(sink, winzip_aes_extra_data_length);
    try zipU16(sink, winzip_aes_version);
    try sink.write(winzip_aes_vendor);
    try sink.write(&[_]u8{entry.aes_strength});
    try zipU16(sink, entry.method);
}

fn entrySalt(entry: ZipEntry) Failure![16]u8 {
    if (entry.salt_length != 0) {
        if (entry.salt_length != 16) return error.InvalidCall;
        return entry.salt;
    }
    var salt: [16]u8 = undefined;
    if (!crypto.fillRandom(&salt)) {
        try crypto.deriveDeterministicSalt(entry.password, entry.name, entry.data, &salt);
    }
    return salt;
}

fn zipValidateExtra(extra: []const u8) Failure!void {
    var offset: usize = 0;
    while (offset < extra.len) {
        if (extra.len - offset < 4) return error.InvalidCall;
        const id = readU16(extra, offset);
        const length = readU16(extra, offset + 2);
        offset = try bounds.add(offset, 4);
        if (length > extra.len - offset or id == zip64_extra_id) return error.InvalidCall;
        offset = try bounds.add(offset, length);
    }
}

fn zipLocalZip64Length(compressed: usize, uncompressed: usize) usize {
    return if (compressed >= std.math.maxInt(u32) or uncompressed >= std.math.maxInt(u32)) 20 else 0;
}

fn zipCentralZip64Length(compressed: usize, uncompressed: usize, local_offset: usize) usize {
    var length: usize = 0;
    if (uncompressed >= std.math.maxInt(u32)) length += 8;
    if (compressed >= std.math.maxInt(u32)) length += 8;
    if (local_offset >= std.math.maxInt(u32)) length += 8;
    return if (length == 0) 0 else length + 4;
}

fn zipU16(sink: *io.Sink, value: u16) Failure!void {
    try sink.writeInt(u16, value, .little);
}

fn zipU32(sink: *io.Sink, value: u32) Failure!void {
    try sink.writeInt(u32, value, .little);
}

fn zipU64(sink: *io.Sink, value: u64) Failure!void {
    try sink.writeInt(u64, value, .little);
}

fn zipWriteLocalZip64(sink: *io.Sink, compressed: usize, uncompressed: usize) Failure!void {
    if (zipLocalZip64Length(compressed, uncompressed) == 0) return;
    try zipU16(sink, zip64_extra_id);
    try zipU16(sink, 16);
    try zipU64(sink, uncompressed);
    try zipU64(sink, compressed);
}

fn zipWriteCentralZip64(sink: *io.Sink, compressed: usize, uncompressed: usize, local_offset: usize) Failure!void {
    const length = zipCentralZip64Length(compressed, uncompressed, local_offset);
    if (length == 0) return;
    try zipU16(sink, zip64_extra_id);
    try zipU16(sink, @intCast(length - 4));
    if (uncompressed >= std.math.maxInt(u32)) try zipU64(sink, uncompressed);
    if (compressed >= std.math.maxInt(u32)) try zipU64(sink, compressed);
    if (local_offset >= std.math.maxInt(u32)) try zipU64(sink, local_offset);
}

fn validateZipPath(name: []const u8, flags: u16) Failure!void {
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, '\\') != null or name[0] == '/' or (name.len >= 2 and std.ascii.isAlphabetic(name[0]) and name[1] == ':')) return error.InvalidData;
    if (flags & 0x0800 != 0 and !std.unicode.utf8ValidateSlice(name)) return error.InvalidData;
    var segments = std.mem.splitScalar(u8, name, '/');
    while (segments.next()) |segment| {
        if (std.mem.eql(u8, segment, "..")) return error.InvalidData;
    }
}

pub fn zipCompressedSize(entry: ZipEntry, history: []u8, measurement_buffer: []u8, scratch: []u8) Failure!usize {
    switch (entry.method) {
        0 => return entry.data.len,
        8 => {
            if (history.len < deflate_history_size or measurement_buffer.len < deflate_measurement_buffer_size) return error.InsufficientCapacity;
            var counter = measurement.Counter.init(null);
            var compressor = deflate.Compress.init(&counter.writer, history[0..deflate_history_size], zip_deflate_options) catch |err| return err;
            compressor.writer.writeAll(entry.data) catch return error.InternalFailure;
            compressor.finish() catch return error.InternalFailure;
            return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
        },
        9 => {
            if (history.len < deflate64_history_size or measurement_buffer.len < deflate_measurement_buffer_size) return error.InsufficientCapacity;
            var counter = measurement.Counter.init(null);
            var compressor = deflate.Compress64.init(&counter.writer, history[0..deflate64_history_size], zip_deflate_options) catch |err| return err;
            compressor.writer.writeAll(entry.data) catch return error.InternalFailure;
            compressor.finish() catch return error.InternalFailure;
            return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
        },
        12 => {
            const required = bzip2.encodeWorkspaceSize(zip_bzip2_block_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            return bzip2.requiredSize(entry.data, scratch[0..required], .{ .block_size = zip_bzip2_block_default });
        },
        14 => {
            const required = lzma.encodeWorkspaceSizeBt(zip_lzma_props_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            const stream = try lzma.requiredSize(entry.data, scratch[0..required], .{ .properties = zip_lzma_props_default, .marker_required = true });
            return try bounds.add(stream, 9);
        },
        93 => {
            const needed = try zipZstdEncodeSize(entry.data, scratch);
            return needed;
        },
        95 => {
            const required = xz.encodeWorkspaceSizeBt(zip_xz_dictionary_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            return xz.requiredSize(entry.data, scratch[0..required], .{ .dictionary_size = zip_xz_dictionary_default, .check = .crc32 });
        },
        98 => {
            const required = ppmd_zip.encodeWorkspaceSize(zip_ppmd_mem_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            const stream = try ppmd_zip.requiredSize(entry.data, scratch[0..required], .{ .order = zip_ppmd_order_default, .mem_size = zip_ppmd_mem_default, .restore_method = zip_ppmd_restore_default });
            return try bounds.add(stream, 2);
        },
        else => return error.Unsupported,
    }
}

fn zipZstdEncodeSize(input: []const u8, scratch: []u8) Failure!usize {
    const window = zip_zstd_window_default;
    if (scratch.len < zip_zstd_history_default + zstd.encoder_workspace_size) return error.InsufficientCapacity;
    const zhistory = scratch[0..zip_zstd_history_default];
    const workspace: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[zip_zstd_history_default..][0..zstd.encoder_workspace_size]));
    var counter = measurement.Counter.init(null);
    var source = std.Io.Reader.fixed(input);
    _ = zstd.encodeStream(&source, &counter.writer, zhistory, workspace, .{ .window_size = window }) catch |err| return encodeMap(err);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

fn zipWriteData(sink: *io.Sink, entry: ZipEntry, history: []u8, staging: []u8, scratch: []u8) Failure!void {
    if (!entry.encrypted) {
        if (entry.method == 0) return sink.write(entry.data);
        const compressed = try zipCompressEntry(entry, history, sink.bytes[sink.offset..], scratch);
        sink.offset = try bounds.add(sink.offset, compressed.len);
        return;
    }
    if (entry.zipcrypto) {
        var keys = crypto.ZipCryptoKeys.init(entry.password);
        var header: [12]u8 = undefined;
        if (!crypto.fillRandom(header[0..11])) {
            var seed_bytes: [16]u8 = undefined;
            try crypto.deriveDeterministicSalt(entry.password, entry.name, entry.data, &seed_bytes);
            @memcpy(header[0..11], seed_bytes[0..11]);
        }
        header[11] = @truncate(checksum.crc32(entry.data) >> 24);
        keys.encrypt(&header, &header);
        try sink.write(&header);
        if (entry.password_lifetime != 0 and entry.data.len > entry.password_lifetime) return error.ResourceLimit;
        if (entry.method == 0) {
            if (sink.bytes.len - sink.offset < entry.data.len) return error.InsufficientCapacity;
            keys.encrypt(sink.bytes[sink.offset..][0..entry.data.len], entry.data);
            sink.offset = try bounds.add(sink.offset, entry.data.len);
            return;
        }
        const compressed = try zipCompressEntry(entry, history, staging, scratch);
        if (entry.password_lifetime != 0 and compressed.len > entry.password_lifetime) return error.ResourceLimit;
        if (sink.bytes.len - sink.offset < compressed.len) return error.InsufficientCapacity;
        keys.encrypt(sink.bytes[sink.offset..][0..compressed.len], compressed);
        sink.offset = try bounds.add(sink.offset, compressed.len);
        return;
    }
    const salt = try entrySalt(entry);
    var derived: [66]u8 = undefined;
    try crypto.winzipDeriveKey(entry.password, salt[0..16], 32, &derived);
    const data_offset = sink.offset;
    try sink.write(salt[0..16]);
    try sink.write(derived[64..66]);
    if (entry.method == 0) {
        if (entry.password_lifetime != 0 and entry.data.len > entry.password_lifetime) return error.ResourceLimit;
        try crypto.winzipCtr(derived[0..32], sink.bytes[sink.offset..][0..entry.data.len], entry.data);
        sink.offset = try bounds.add(sink.offset, entry.data.len);
    } else {
        const compressed = try zipCompressEntry(entry, history, staging, scratch);
        if (entry.password_lifetime != 0 and compressed.len > entry.password_lifetime) return error.ResourceLimit;
        try crypto.winzipCtr(derived[0..32], sink.bytes[sink.offset..][0..compressed.len], compressed);
        sink.offset = try bounds.add(sink.offset, compressed.len);
    }
    const ciphertext = sink.bytes[data_offset + 16 + winzip_aes_verify_length .. sink.offset];
    var mac: [crypto.hmac_sha1_length]u8 = undefined;
    crypto.hmacSha1(&mac, ciphertext, derived[32..64]);
    try sink.write(mac[0..winzip_aes_hmac_length]);
}

fn zipCompressEntry(entry: ZipEntry, history: []u8, output: []u8, scratch: []u8) Failure![]const u8 {
    switch (entry.method) {
        8 => {
            if (history.len < deflate_history_size or output.len < deflate_measurement_buffer_size) return error.InsufficientCapacity;
            var writer = std.Io.Writer.fixed(output);
            var compressor = deflate.Compress.init(&writer, history[0..deflate_history_size], zip_deflate_options) catch |err| return err;
            compressor.writer.writeAll(entry.data) catch return error.InternalFailure;
            compressor.finish() catch return error.InternalFailure;
            return output[0..writer.end];
        },
        9 => {
            if (history.len < deflate64_history_size or output.len < deflate_measurement_buffer_size) return error.InsufficientCapacity;
            var writer = std.Io.Writer.fixed(output);
            var compressor = deflate.Compress64.init(&writer, history[0..deflate64_history_size], zip_deflate_options) catch |err| return err;
            compressor.writer.writeAll(entry.data) catch return error.InternalFailure;
            compressor.finish() catch return error.InternalFailure;
            return output[0..writer.end];
        },
        12 => {
            const required = bzip2.encodeWorkspaceSize(zip_bzip2_block_default);
            if (scratch.len < required or output.len < deflate_measurement_buffer_size) return error.InsufficientCapacity;
            const written = try bzip2.encode(entry.data, output, scratch[0..required], .{ .block_size = zip_bzip2_block_default });
            return output[0..written];
        },
        14 => {
            const required = lzma.encodeWorkspaceSizeBt(zip_lzma_props_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            var payload: [9]u8 = undefined;
            std.mem.writeInt(u16, payload[0..2], 0x0306, .little);
            std.mem.writeInt(u16, payload[2..4], 5, .little);
            payload[4] = zip_lzma_props_default.encode();
            std.mem.writeInt(u32, payload[5..9], zip_lzma_props_default.dictionary_size, .little);
            if (output.len < 9) return error.InsufficientCapacity;
            @memcpy(output[0..9], &payload);
            const written = try lzma.encode(entry.data, output[9..], scratch[0..required], .{ .properties = zip_lzma_props_default, .marker_required = true });
            return output[0 .. 9 + written];
        },
        93 => {
            const window = zip_zstd_window_default;
            if (scratch.len < zip_zstd_history_default + zstd.encoder_workspace_size) return error.InsufficientCapacity;
            const zhistory = scratch[0..zip_zstd_history_default];
            const workspace: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[zip_zstd_history_default..][0..zstd.encoder_workspace_size]));
            var source = std.Io.Reader.fixed(entry.data);
            var writer = std.Io.Writer.fixed(output);
            _ = zstd.encodeStream(&source, &writer, zhistory, workspace, .{ .window_size = window }) catch |err| return encodeMap(err);
            return output[0..writer.end];
        },
        95 => {
            const required = xz.encodeWorkspaceSizeBt(zip_xz_dictionary_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            const written = try xz.encode(entry.data, output, scratch[0..required], .{ .dictionary_size = zip_xz_dictionary_default, .check = .crc32 });
            return output[0..written];
        },
        98 => {
            const required = ppmd_zip.encodeWorkspaceSize(zip_ppmd_mem_default);
            if (scratch.len < required) return error.InsufficientCapacity;
            var props: [2]u8 = undefined;
            const prop_value: u16 = @intCast((zip_ppmd_order_default - 1) | ((zip_ppmd_mem_default >> 20) - 1) << 4 | zip_ppmd_restore_default << 12);
            std.mem.writeInt(u16, &props, prop_value, .little);
            if (output.len < 2) return error.InsufficientCapacity;
            @memcpy(output[0..2], &props);
            const written = try ppmd_zip.encode(entry.data, output[2..], scratch[0..required], .{ .order = zip_ppmd_order_default, .mem_size = zip_ppmd_mem_default, .restore_method = zip_ppmd_restore_default });
            return output[0 .. 2 + written];
        },
        else => return error.Unsupported,
    }
}

fn encodeMap(err: zstd.EncodeError) Failure {
    return switch (err) {
        error.InvalidData => error.InvalidData,
        error.ResourceLimit => error.ResourceLimit,
        error.IoFailure => error.IoFailure,
    };
}

pub const ZipInfo = struct {
    name: []const u8,
    method: u16,
    flags: u16,
    dos_time: u16,
    crc: u32,
    compressed_size: usize,
    uncompressed_size: usize,
    local_offset: usize,
    ordinal: usize,
    version_made_by: u16,
    internal_attributes: u16,
    external_attributes: u32,
    encrypted: bool = false,
    aes_strength: u8 = 0,
    aes_version: u16 = 0,
    actual_method: u16 = 0,
};

pub const ZipDecodeOptions = struct {
    password: ?[]const u8 = null,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
    failure_cause: *crypto.FailureCause,
    staging: []u8 = &.{},
    scratch: []u8 = &.{},
    history: []u8 = &.{},
};

pub fn zipInspectCount(archive: []const u8) Failure!usize {
    const directory = try zipDirectory(archive);
    var cursor = directory.offset;
    var index: usize = 0;
    while (index < directory.count) : (index += 1) _ = try zipNext(archive, directory, &cursor, index);
    if (cursor != try bounds.add(directory.offset, directory.size)) return error.InvalidData;
    return directory.count;
}

pub fn zipInspectOrdinal(archive: []const u8, ordinal: usize) Failure!ZipInfo {
    const directory = try zipDirectory(archive);
    if (ordinal >= directory.count) return error.InvalidData;
    var cursor = directory.offset;
    var index: usize = 0;
    while (index < directory.count) : (index += 1) {
        const entry = try zipNext(archive, directory, &cursor, index);
        if (index == ordinal) return entry;
    }
    return error.InvalidData;
}

pub fn zipDecodeOrdinal(archive: []const u8, ordinal: usize, output: []u8, options: ZipDecodeOptions) Failure!usize {
    options.failure_cause.* = .none;
    const entry = try zipInspectOrdinal(archive, ordinal);
    if (output.len < entry.uncompressed_size) return error.InsufficientCapacity;
    if (entry.flags & 0x40 != 0) return error.Unsupported;
    if (entry.flags & 0x20 != 0) return error.Unsupported;
    const encrypted = entry.flags & 1 != 0;
    if (encrypted and entry.method != winzip_aes_method and !zipMethodSupported(entry.method)) return error.Unsupported;
    if (!encrypted and entry.method == winzip_aes_method) return error.InvalidData;
    const header = try bounds.slice(archive, entry.local_offset, 30);
    if (readU32(header, 0) != zip_local_signature) return error.InvalidData;
    const local_method = readU16(header, 8);
    const local_flags = readU16(header, 6);
    const local_crc = readU32(header, 14);
    const local_compressed = readU32(header, 18);
    const local_uncompressed = readU32(header, 22);
    const name_length = readU16(header, 26);
    const extra_length = readU16(header, 28);
    if (local_flags != entry.flags or local_method != entry.method) return error.InvalidData;
    const local_name = try bounds.slice(archive, entry.local_offset + 30, name_length);
    if (!std.mem.eql(u8, local_name, entry.name)) return error.InvalidData;
    if (entry.flags & 8 == 0) {
        if (local_crc != entry.crc or (local_compressed != std.math.maxInt(u32) and local_compressed != entry.compressed_size) or (local_uncompressed != std.math.maxInt(u32) and local_uncompressed != entry.uncompressed_size)) return error.InvalidData;
    }
    const data_offset = try bounds.add(entry.local_offset, 30 + name_length + extra_length);
    const compressed = try bounds.slice(archive, data_offset, entry.compressed_size);
    if (entry.flags & 8 != 0) try zipValidateDataDescriptor(archive, data_offset, entry);
    if (encrypted) {
        const password = options.password orelse return error.Unsupported;
        if (entry.method == winzip_aes_method) {
            const key_length = try crypto.winzipKeyLength(entry.aes_strength);
            const salt_length = try crypto.winzipSaltLength(entry.aes_strength);
            const header_length = try bounds.add(try bounds.add(salt_length, winzip_aes_verify_length), winzip_aes_hmac_length);
            if (entry.compressed_size < header_length) return error.InvalidData;
            const ciphertext_size = entry.compressed_size - header_length;
            if (options.kdf_rounds_limit != 0 and options.kdf_rounds_limit < crypto.winzip_pbkdf2_rounds) {
                options.failure_cause.* = .kdf_limit;
                return error.ResourceLimit;
            }
            if (options.password_lifetime != 0 and ciphertext_size > options.password_lifetime) {
                options.failure_cause.* = .password_lifetime;
                return error.ResourceLimit;
            }
            const derived_length = try bounds.add(2 * key_length, winzip_aes_verify_length);
            var derived: [66]u8 = undefined;
            try crypto.winzipDeriveKey(password, compressed[0..salt_length], key_length, derived[0..derived_length]);
            const stored_verify = compressed[salt_length..][0..winzip_aes_verify_length];
            if (!crypto.constantTimeEqual(derived[2 * key_length .. derived_length], stored_verify)) {
                options.failure_cause.* = .wrong_password;
                return error.InvalidData;
            }
            const ciphertext = compressed[header_length - winzip_aes_hmac_length ..][0..ciphertext_size];
            const stored_hmac = compressed[entry.compressed_size - winzip_aes_hmac_length ..];
            var mac: [crypto.hmac_sha1_length]u8 = undefined;
            crypto.hmacSha1(&mac, ciphertext, derived[key_length..][0..key_length]);
            if (!crypto.constantTimeEqual(mac[0..winzip_aes_hmac_length], stored_hmac)) return error.IntegrityFailure;
            if (options.staging.len < ciphertext_size) return error.InsufficientCapacity;
            try crypto.winzipCtr(derived[0..key_length], options.staging[0..ciphertext_size], ciphertext);
            _ = try zipDecompress(entry, options.staging[0..ciphertext_size], output, options);
            if (entry.aes_version == 1) {
                if (checksum.crc32(output[0..entry.uncompressed_size]) != entry.crc) return error.IntegrityFailure;
            }
            return entry.uncompressed_size;
        }
        if (entry.compressed_size < 12) return error.InvalidData;
        const ciphertext_size = entry.compressed_size - 12;
        if (options.password_lifetime != 0 and ciphertext_size > options.password_lifetime) {
            options.failure_cause.* = .password_lifetime;
            return error.ResourceLimit;
        }
        if (options.staging.len < ciphertext_size) return error.InsufficientCapacity;
        var keys = crypto.ZipCryptoKeys.init(password);
        var crypto_header: [12]u8 = undefined;
        @memcpy(&crypto_header, compressed[0..12]);
        keys.decrypt(&crypto_header, &crypto_header);
        const check_byte: u8 = if (entry.flags & 8 != 0) @truncate(entry.dos_time >> 8) else @truncate(entry.crc >> 24);
        if (crypto_header[11] != check_byte) {
            options.failure_cause.* = .wrong_password;
            return error.InvalidData;
        }
        keys.decrypt(options.staging[0..ciphertext_size], compressed[12..]);
        _ = try zipDecompress(entry, options.staging[0..ciphertext_size], output, options);
        if (checksum.crc32(output[0..entry.uncompressed_size]) != entry.crc) return error.IntegrityFailure;
        return entry.uncompressed_size;
    }
    const decoded = try zipDecompress(entry, compressed, output, options);
    if (decoded != entry.uncompressed_size) return error.InvalidData;
    if (checksum.crc32(output[0..entry.uncompressed_size]) != entry.crc) return error.IntegrityFailure;
    return decoded;
}

fn zipMethodSupported(method: u16) bool {
    return switch (method) {
        0, 8, 9, 12, 14, 93, 95, 98 => true,
        else => false,
    };
}

fn zipDecompress(entry: ZipInfo, compressed: []const u8, output: []u8, options: ZipDecodeOptions) Failure!usize {
    switch (entry.actual_method) {
        0 => {
            if (compressed.len != entry.uncompressed_size) return error.InvalidData;
            @memcpy(output[0..entry.uncompressed_size], compressed);
            return entry.uncompressed_size;
        },
        8 => {
            if (options.history.len < deflate_history_size) return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(compressed);
            var writer = std.Io.Writer.fixed(output[0..entry.uncompressed_size]);
            var inflater = deflate.Decompress.init(&source, options.history[0..deflate_history_size]);
            inflater.reader.streamExact64(&writer, entry.uncompressed_size) catch return error.InvalidData;
            if (writer.end != entry.uncompressed_size or source.seek != compressed.len) return error.InvalidData;
            return entry.uncompressed_size;
        },
        9 => {
            if (options.history.len < deflate64_decode_history_size) return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(compressed);
            var writer = std.Io.Writer.fixed(output[0..entry.uncompressed_size]);
            var inflater = deflate.Decompress64.init(&source, options.history[0..deflate64_decode_history_size]);
            inflater.reader.streamExact64(&writer, entry.uncompressed_size) catch return error.InvalidData;
            if (writer.end != entry.uncompressed_size or source.seek != compressed.len) return error.InvalidData;
            return entry.uncompressed_size;
        },
        12 => {
            const scratch_size = try bzip2.decodeWorkspaceSizeFor(compressed);
            if (scratch_size > options.scratch.len) return error.InsufficientCapacity;
            const decoded = try bzip2.decode(compressed, output[0..entry.uncompressed_size], options.scratch[0..scratch_size]);
            if (decoded != entry.uncompressed_size) return error.InvalidData;
            return decoded;
        },
        14 => {
            if (compressed.len < 9) return error.InvalidData;
            const properties_size = readU16(compressed, 2);
            if (properties_size != 5 or compressed.len < 9 + properties_size) return error.InvalidData;
            const dictionary = readU32(compressed, 5);
            const properties = try lzma.Properties.decode(compressed[4], dictionary);
            const scratch_size = lzma.decodeWorkspaceSize(properties);
            if (scratch_size > options.scratch.len) return error.InsufficientCapacity;
            const lzma_options: lzma.Options = .{
                .properties = properties,
                .unpack_size = entry.uncompressed_size,
                .marker_required = entry.flags & 2 != 0,
            };
            const decoded = try lzma.decode(compressed[9..], output[0..entry.uncompressed_size], options.scratch[0..scratch_size], lzma_options);
            if (decoded != entry.uncompressed_size) return error.InvalidData;
            return decoded;
        },
        93 => {
            const window = try zipZstdWindow(compressed);
            const needed = try bounds.add(window, zstd.block_size_max);
            if (needed > options.scratch.len) return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(compressed);
            var writer = std.Io.Writer.fixed(output[0..entry.uncompressed_size]);
            const decoded = zstd.decodeStream(&source, &writer, options.scratch[0..needed], .{
                .window_size = window,
                .max_decoded_bytes = entry.uncompressed_size,
            }) catch |err| {
                return switch (err) {
                    error.Unsupported => error.Unsupported,
                    error.ResourceLimit => error.ResourceLimit,
                    error.IoFailure => error.IoFailure,
                    error.IntegrityFailure => error.IntegrityFailure,
                    else => error.InvalidData,
                };
            };
            if (decoded != entry.uncompressed_size or source.seek != compressed.len) return error.InvalidData;
            return decoded;
        },
        95 => {
            if (options.scratch.len == 0) return error.InsufficientCapacity;
            const decoded = try xz.decode(compressed, output[0..entry.uncompressed_size], options.scratch);
            if (decoded != entry.uncompressed_size) return error.InvalidData;
            return decoded;
        },
        98 => {
            if (compressed.len < 6) return error.InvalidData;
            const props = readU16(compressed, 0);
            const order = (props & 0xF) + 1;
            const mem_mb = ((props >> 4) & 0xFF) + 1;
            const restore = props >> 12;
            if (order < ppmd_zip.order_min or order > ppmd_zip.order_max) return error.Unsupported;
            if (restore > ppmd_zip.restore_cut_off) return error.Unsupported;
            const mem_size: u32 = @as(u32, mem_mb) << 20;
            const scratch_size = ppmd_zip.decodeWorkspaceSize(mem_size);
            if (scratch_size > options.scratch.len) return error.InsufficientCapacity;
            const result = try ppmd_zip.decode(compressed[2..], output[0..entry.uncompressed_size], options.scratch[0..scratch_size], .{
                .order = order,
                .mem_size = mem_size,
                .restore_method = restore,
            });
            if (result.decoded != entry.uncompressed_size) return error.InvalidData;
            if (result.consumed + 2 != compressed.len) return error.InvalidData;
            return result.decoded;
        },
        else => return error.Unsupported,
    }
}

fn zipZstdWindow(compressed: []const u8) Failure!u32 {
    if (compressed.len < 6) return error.InvalidData;
    const magic = readU32(compressed, 0);
    if (magic == 0xFD2F_B528) {
        const descriptor = compressed[4];
        if (descriptor & 0x20 == 0) {
            if (compressed.len < 6) return error.InvalidData;
            const window_descriptor = compressed[5];
            const window_log: u32 = 10 + (window_descriptor >> 3);
            const window_base: u32 = @as(u32, 1) << @intCast(window_log);
            const window_add = (window_base / 8) * (window_descriptor & 0x07);
            return window_base + window_add;
        }
        const content_size = zstd.frameContentSize(compressed, zstd.window_size_max) catch return error.InvalidData;
        return @intCast(@max(content_size, 1024));
    }
    if (magic >= 0x184D_2A50 and magic <= 0x184D_2A5F) return 1024;
    return error.InvalidData;
}

fn zipValidateDataDescriptor(archive: []const u8, data_offset: usize, entry: ZipInfo) Failure!void {
    var offset = try bounds.add(data_offset, entry.compressed_size);
    const marker = try bounds.slice(archive, offset, 4);
    if (readU32(marker, 0) == 0x0807_4b50) offset = try bounds.add(offset, 4);
    const zip64 = entry.compressed_size >= std.math.maxInt(u32) or entry.uncompressed_size >= std.math.maxInt(u32);
    const descriptor = try bounds.slice(archive, offset, if (zip64) 20 else 12);
    if (readU32(descriptor, 0) != entry.crc) return error.InvalidData;
    if (zip64) {
        if (readU64(descriptor, 4) != entry.compressed_size or readU64(descriptor, 12) != entry.uncompressed_size) return error.InvalidData;
    } else if (readU32(descriptor, 4) != entry.compressed_size or readU32(descriptor, 8) != entry.uncompressed_size) return error.InvalidData;
}

const ZipDirectory = struct { offset: usize, size: usize, count: usize, base: usize };

fn zipDirectory(archive: []const u8) Failure!ZipDirectory {
    if (archive.len < 22) return error.InvalidData;
    const earliest = if (archive.len > 22 + std.math.maxInt(u16)) archive.len - (22 + std.math.maxInt(u16)) else 0;
    var position = archive.len - 22;
    while (true) {
        if (readU32(archive, position) == zip_end_signature) {
            const comment = readU16(archive, position + 20);
            if (position + 22 + comment == archive.len) {
                const disk = readU16(archive, position + 4);
                const central_disk = readU16(archive, position + 6);
                const disk_count = readU16(archive, position + 8);
                const count: u64 = readU16(archive, position + 10);
                const size: u64 = readU32(archive, position + 12);
                const offset: u64 = readU32(archive, position + 16);
                const zip64 = disk == std.math.maxInt(u16) or central_disk == std.math.maxInt(u16) or disk_count == std.math.maxInt(u16) or count == std.math.maxInt(u16) or size == std.math.maxInt(u32) or offset == std.math.maxInt(u32);
                if (!zip64 and (disk != 0 or central_disk != 0 or disk_count != count)) return error.Unsupported;
                if (zip64) {
                    if (position < 20 or readU32(archive, position - 20) != zip64_locator_signature) return error.InvalidData;
                    if (readU32(archive, position - 16) != 0 or readU32(archive, position - 4) != 1) return error.Unsupported;
                    return zip64Directory(archive, position - 20, readU64(archive, position - 12));
                }
                const size_usize = std.math.cast(usize, size) orelse return error.ResourceLimit;
                const offset_usize = std.math.cast(usize, offset) orelse return error.ResourceLimit;
                const count_usize = std.math.cast(usize, count) orelse return error.ResourceLimit;
                if (size_usize > position) return error.InvalidData;
                const physical = position - size_usize;
                if (offset_usize > physical) return error.InvalidData;
                return .{ .offset = physical, .size = size_usize, .count = count_usize, .base = physical - offset_usize };
            }
        }
        if (position == earliest) break;
        position -= 1;
    }
    return error.InvalidData;
}

fn zip64Directory(archive: []const u8, locator: usize, record_relative: u64) Failure!ZipDirectory {
    const relative = std.math.cast(usize, record_relative) orelse return error.ResourceLimit;
    if (locator < 12 or relative > locator - 12) return error.InvalidData;
    var candidate = locator - 12;
    while (true) {
        if (readU32(archive, candidate) == zip64_end_signature) {
            const record_size = readU64(archive, candidate + 4);
            const record_end = std.math.add(u64, candidate, std.math.add(u64, 12, record_size) catch return error.InvalidData) catch return error.InvalidData;
            if (record_end == locator) {
                const record = try bounds.slice(archive, candidate, 56);
                if (record_size < 44 or readU32(record, 16) != 0 or readU32(record, 20) != 0) return error.Unsupported;
                const count = readU64(record, 32);
                if (readU64(record, 24) != count) return error.Unsupported;
                const size = std.math.cast(usize, readU64(record, 40)) orelse return error.ResourceLimit;
                const offset = std.math.cast(usize, readU64(record, 48)) orelse return error.ResourceLimit;
                if (candidate < relative) return error.InvalidData;
                const base = candidate - relative;
                const central = try bounds.add(base, offset);
                if (central > candidate or size != candidate - central) return error.InvalidData;
                return .{ .offset = central, .size = size, .count = std.math.cast(usize, count) orelse return error.ResourceLimit, .base = base };
            }
        }
        if (candidate == relative) break;
        candidate -= 1;
    }
    return error.InvalidData;
}

fn zipNext(archive: []const u8, directory: ZipDirectory, cursor: *usize, ordinal: usize) Failure!ZipInfo {
    const end = try bounds.add(directory.offset, directory.size);
    const record = try bounds.slice(archive, cursor.*, 46);
    if (cursor.* >= end or readU32(record, 0) != zip_central_signature) return error.InvalidData;
    const method = readU16(record, 10);
    const flags = readU16(record, 8);
    const name_length = readU16(record, 28);
    const extra_length = readU16(record, 30);
    const comment_length = readU16(record, 32);
    const record_length = try bounds.add(46 + name_length, extra_length + comment_length);
    if (record_length > end - cursor.*) return error.InvalidData;
    const name = try bounds.slice(archive, cursor.* + 46, name_length);
    try validateZipPath(name, readU16(record, 8));
    const extra = try bounds.slice(archive, cursor.* + 46 + name_length, extra_length);
    var compressed: u64 = readU32(record, 20);
    var uncompressed: u64 = readU32(record, 24);
    var local_relative: u64 = readU32(record, 42);
    try zip64Extents(extra, &compressed, &uncompressed, &local_relative);
    cursor.* = try bounds.add(cursor.*, record_length);
    var aes_strength: u8 = 0;
    var aes_version: u16 = 0;
    var actual_method: u16 = 0;
    if (method == winzip_aes_method) {
        try parseWinzipAesExtra(extra, &aes_strength, &aes_version, &actual_method);
    } else {
        actual_method = method;
    }
    return .{ .name = name, .method = method, .flags = flags, .dos_time = readU16(record, 12), .crc = readU32(record, 16), .compressed_size = std.math.cast(usize, compressed) orelse return error.ResourceLimit, .uncompressed_size = std.math.cast(usize, uncompressed) orelse return error.ResourceLimit, .local_offset = try bounds.add(directory.base, std.math.cast(usize, local_relative) orelse return error.ResourceLimit), .ordinal = ordinal, .version_made_by = readU16(record, 4), .internal_attributes = readU16(record, 36), .external_attributes = readU32(record, 38), .encrypted = flags & 1 != 0, .aes_strength = aes_strength, .aes_version = aes_version, .actual_method = actual_method };
}

fn parseWinzipAesExtra(extra: []const u8, strength: *u8, version: *u16, actual_method: *u16) Failure!void {
    var offset: usize = 0;
    while (offset < extra.len) {
        if (extra.len - offset < 4) return error.InvalidData;
        const id = readU16(extra, offset);
        const length = readU16(extra, offset + 2);
        offset = try bounds.add(offset, 4);
        if (length > extra.len - offset) return error.InvalidData;
        if (id == winzip_aes_extra_id) {
            if (length != winzip_aes_extra_data_length) return error.InvalidData;
            const payload = extra[offset..][0..length];
            const vendor = payload[2..4];
            if (!std.mem.eql(u8, vendor, winzip_aes_vendor)) return error.Unsupported;
            const parsed_strength = payload[4];
            if (parsed_strength < 1 or parsed_strength > 3) return error.Unsupported;
            const parsed_method = readU16(payload, 5);
            if (parsed_method != 0 and parsed_method != 8) return error.Unsupported;
            strength.* = parsed_strength;
            version.* = readU16(payload, 0);
            actual_method.* = parsed_method;
            return;
        }
        offset = try bounds.add(offset, length);
    }
    return error.InvalidData;
}

fn zip64Extents(extra: []const u8, compressed: *u64, uncompressed: *u64, local_offset: *u64) Failure!void {
    var offset: usize = 0;
    while (offset < extra.len) {
        if (extra.len - offset < 4) return error.InvalidData;
        const id = readU16(extra, offset);
        const length = readU16(extra, offset + 2);
        offset = try bounds.add(offset, 4);
        if (length > extra.len - offset) return error.InvalidData;
        if (id == zip64_extra_id) {
            var value_offset: usize = 0;
            if (uncompressed.* == std.math.maxInt(u32)) {
                if (length - value_offset < 8) return error.InvalidData;
                uncompressed.* = readU64(extra, offset + value_offset);
                value_offset += 8;
            }
            if (compressed.* == std.math.maxInt(u32)) {
                if (length - value_offset < 8) return error.InvalidData;
                compressed.* = readU64(extra, offset + value_offset);
                value_offset += 8;
            }
            if (local_offset.* == std.math.maxInt(u32)) {
                if (length - value_offset < 8) return error.InvalidData;
                local_offset.* = readU64(extra, offset + value_offset);
            }
            return;
        }
        offset = try bounds.add(offset, length);
    }
    if (compressed.* == std.math.maxInt(u32) or uncompressed.* == std.math.maxInt(u32) or local_offset.* == std.math.maxInt(u32)) return error.InvalidData;
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
