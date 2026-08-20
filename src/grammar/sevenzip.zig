const std = @import("std");

const binary = @import("../common/primitive/binary.zig");
const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const crypto = @import("../common/primitive/crypto.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const Workspace = io.Workspace;
const limits_prim = @import("../common/primitive/limits.zig");
const Limits = limits_prim.Limits;
const measurement = @import("../common/primitive/measurement.zig");
const bcj = @import("../leaf/bcj.zig");
const bzip2 = @import("../leaf/bzip2.zig");
const deflate = @import("../leaf/deflate.zig");
const delta = @import("../leaf/delta.zig");
const lzma = @import("../leaf/lzma.zig");
const lzma2 = @import("../leaf/lzma2.zig");
const ppmd = @import("../leaf/ppmd.zig");

const signature = [6]u8{ '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };
const version = [2]u8{ 0, 4 };
const start_header_size = 32;

pub const CoderMethod = enum {
    copy,
    deflate,
    bzip2,
    lzma,
    lzma2,
    delta,
    x86,
    ppc,
    ia64,
    arm,
    armt,
    sparc,
    arm64,
    riscv,
    ppmd,
};

pub const SevenZipEntry = struct {
    name: []const u8,
    data: []const u8,
    method: CoderMethod = .copy,
    encrypted: bool = false,
    password: []const u8 = &.{},
    iv: [16]u8 = .{0} ** 16,
    iv_set: bool = false,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
};

pub const SevenZipInfo = struct {
    name: []const u8,
    size: u64,
    is_directory: bool,
    data_offset: u64,
    pack_size: u64,
    crc: ?u32,
    method: CoderMethod,
    attributes: []const u8,
    encrypted: bool = false,
    aes_num_cycles: u8 = 0,
    aes_salt: []const u8 = &.{},
    aes_iv: [16]u8 = .{0} ** 16,
    aes_iv_size: u8 = 0,
    folder: ?*const Folder = null,
    substream_offset: u64 = 0,
};

pub const SevenZipDecodeOptions = struct {
    password: ?[]const u8 = null,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
    failure_cause: *crypto.FailureCause,
};

const method_copy_id = [1]u8{0x00};
const method_lzma_id = [3]u8{ 0x03, 0x01, 0x01 };
const method_lzma2_id = [1]u8{0x21};
const method_deflate_id = [3]u8{ 0x04, 0x01, 0x08 };
const method_bzip2_id = [3]u8{ 0x04, 0x02, 0x02 };
const method_7z_aes_id = [4]u8{ 0x06, 0xF1, 0x07, 0x01 };
const method_delta_id = [1]u8{0x03};
const method_x86_id = [1]u8{0x04};
const method_ppc_id = [1]u8{0x05};
const method_ia64_id = [1]u8{0x06};
const method_arm_id = [1]u8{0x07};
const method_armt_id = [1]u8{0x08};
const method_sparc_id = [1]u8{0x09};
const method_arm64_id = [1]u8{0x0A};
const method_riscv_id = [1]u8{0x0B};
const method_ppmd_id = [3]u8{ 0x03, 0x04, 0x01 };
const method_7z_bcj_x86_id = [4]u8{ 0x03, 0x03, 0x01, 0x03 };
const method_7z_bcj_ppc_id = [4]u8{ 0x03, 0x03, 0x02, 0x05 };
const method_7z_bcj_ia64_id = [4]u8{ 0x03, 0x03, 0x04, 0x01 };
const method_7z_bcj_arm_id = [4]u8{ 0x03, 0x03, 0x05, 0x01 };
const method_7z_bcj_armt_id = [4]u8{ 0x03, 0x03, 0x07, 0x01 };
const method_7z_bcj_sparc_id = [4]u8{ 0x03, 0x03, 0x08, 0x05 };
const method_7z_bcj_arm64_id = [4]u8{ 0x03, 0x03, 0x0A, 0x01 };
const method_7z_bcj_riscv_id = [4]u8{ 0x03, 0x03, 0x0B, 0x01 };
const default_dictionary: u32 = 1 << 20;
const default_bzip2_block: u32 = 100_000;
const default_deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 128 };
const default_ppmd_order: u32 = 8;
const default_ppmd_mem: u32 = 4 << 20;
const default_ppmd_restore: u32 = 0;

fn methodId(method: CoderMethod) []const u8 {
    return switch (method) {
        .copy => &method_copy_id,
        .lzma => &method_lzma_id,
        .lzma2 => &method_lzma2_id,
        .deflate => &method_deflate_id,
        .bzip2 => &method_bzip2_id,
        .delta => &method_delta_id,
        .x86 => &method_7z_bcj_x86_id,
        .ppc => &method_7z_bcj_ppc_id,
        .ia64 => &method_7z_bcj_ia64_id,
        .arm => &method_7z_bcj_arm_id,
        .armt => &method_7z_bcj_armt_id,
        .sparc => &method_7z_bcj_sparc_id,
        .arm64 => &method_7z_bcj_arm64_id,
        .riscv => &method_7z_bcj_riscv_id,
        .ppmd => &method_ppmd_id,
    };
}

fn methodFromId(id: []const u8) Failure!CoderMethod {
    if (std.mem.eql(u8, id, &method_copy_id)) return .copy;
    if (std.mem.eql(u8, id, &method_lzma_id)) return .lzma;
    if (std.mem.eql(u8, id, &method_lzma2_id)) return .lzma2;
    if (std.mem.eql(u8, id, &method_deflate_id)) return .deflate;
    if (std.mem.eql(u8, id, &method_bzip2_id)) return .bzip2;
    if (std.mem.eql(u8, id, &method_delta_id)) return .delta;
    if (std.mem.eql(u8, id, &method_x86_id)) return .x86;
    if (std.mem.eql(u8, id, &method_ppc_id)) return .ppc;
    if (std.mem.eql(u8, id, &method_ia64_id)) return .ia64;
    if (std.mem.eql(u8, id, &method_arm_id)) return .arm;
    if (std.mem.eql(u8, id, &method_armt_id)) return .armt;
    if (std.mem.eql(u8, id, &method_sparc_id)) return .sparc;
    if (std.mem.eql(u8, id, &method_arm64_id)) return .arm64;
    if (std.mem.eql(u8, id, &method_riscv_id)) return .riscv;
    if (std.mem.eql(u8, id, &method_ppmd_id)) return .ppmd;
    if (std.mem.eql(u8, id, &method_7z_bcj_x86_id)) return .x86;
    if (std.mem.eql(u8, id, &method_7z_bcj_ppc_id)) return .ppc;
    if (std.mem.eql(u8, id, &method_7z_bcj_ia64_id)) return .ia64;
    if (std.mem.eql(u8, id, &method_7z_bcj_arm_id)) return .arm;
    if (std.mem.eql(u8, id, &method_7z_bcj_armt_id)) return .armt;
    if (std.mem.eql(u8, id, &method_7z_bcj_sparc_id)) return .sparc;
    if (std.mem.eql(u8, id, &method_7z_bcj_arm64_id)) return .arm64;
    if (std.mem.eql(u8, id, &method_7z_bcj_riscv_id)) return .riscv;
    return error.Unsupported;
}

fn coderAttributeSize(method: CoderMethod) usize {
    return switch (method) {
        .copy, .deflate, .bzip2 => 0,
        .lzma => 5,
        .lzma2 => 1,
        .delta => 1,
        .ppmd => 5,
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => 0,
    };
}

const PackedEntry = struct {
    method: CoderMethod,
    data: []const u8,
    crc: u32,
    encrypted: bool = false,
    filter: ?CoderMethod = null,
    iv: [16]u8 = .{0} ** 16,
    codec_size: usize = 0,
    decoded_size: usize = 0,
};

fn packBuffer(comptime codec: type, method: CoderMethod, input: []const u8, crc: u32, workspace: *Workspace, limits: Limits, scratch_size: usize, options: codec.Options) Failure!PackedEntry {
    const scratch = try workspace.take(u8, scratch_size);
    const packed_size = try codec.requiredSize(input, scratch, options);
    if (packed_size > limits.encoded_bytes) return error.ResourceLimit;
    if (try bounds.add(input.len, packed_size) > limits.codec_work) return error.ResourceLimit;
    const packed_data = try workspace.take(u8, packed_size);
    _ = try codec.encode(input, packed_data, scratch, options);
    return .{ .method = method, .data = packed_data, .crc = crc, .codec_size = packed_size, .decoded_size = input.len };
}

fn packEntry(entry: SevenZipEntry, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Failure!PackedEntry {
    if (entry.encrypted) {
        if (entry.password.len == 0) return error.InvalidCall;
        if (entry.kdf_rounds_limit != 0 and entry.kdf_rounds_limit < crypto.seven_zip_default_rounds) {
            failure_cause.* = .kdf_limit;
            return error.ResourceLimit;
        }
    }
    const unpacked_crc = checksum.crc32(entry.data);
    const compressed_entry = switch (entry.method) {
        .copy => blk: {
            if (entry.data.len > limits.encoded_bytes) return error.ResourceLimit;
            if (entry.data.len > limits.codec_work) return error.ResourceLimit;
            break :blk PackedEntry{ .method = .copy, .data = entry.data, .crc = unpacked_crc, .codec_size = entry.data.len, .decoded_size = entry.data.len };
        },
        .deflate => blk: {
            const history = try workspace.take(u8, deflate.history_size);
            var counter = measurement.Counter.init(null);
            var compressor = deflate.Compress.init(&counter.writer, history, default_deflate_options) catch return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(entry.data);
            _ = std.Io.Reader.streamRemaining(&source, &compressor.writer) catch return error.IoFailure;
            compressor.finish() catch return error.IoFailure;
            const packed_size = counter.written();
            if (packed_size > limits.encoded_bytes) return error.ResourceLimit;
            if (entry.data.len + packed_size > limits.codec_work) return error.ResourceLimit;
            const packed_data = try workspace.take(u8, packed_size);
            const history2 = try workspace.take(u8, deflate.history_size);
            var fixed_writer = std.Io.Writer.fixed(packed_data);
            var compressor2 = deflate.Compress.init(&fixed_writer, history2, default_deflate_options) catch return error.InsufficientCapacity;
            var source2 = std.Io.Reader.fixed(entry.data);
            _ = std.Io.Reader.streamRemaining(&source2, &compressor2.writer) catch return error.IoFailure;
            compressor2.finish() catch return error.IoFailure;
            break :blk PackedEntry{ .method = .deflate, .data = packed_data, .crc = unpacked_crc, .codec_size = packed_size, .decoded_size = entry.data.len };
        },
        .bzip2 => try packBuffer(bzip2, .bzip2, entry.data, unpacked_crc, workspace, limits, bzip2.encodeWorkspaceSize(default_bzip2_block), .{ .block_size = default_bzip2_block }),
        .lzma => blk: {
            const properties = lzma2.properties(default_dictionary);
            const options: lzma.Options = .{ .properties = properties, .unpack_size = entry.data.len, .marker_required = false, .max_work = limits.codec_work };
            break :blk try packBuffer(lzma, .lzma, entry.data, unpacked_crc, workspace, limits, lzma.encodeWorkspaceSizeBt(properties), options);
        },
        .lzma2 => blk: {
            const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.properties(default_dictionary), .max_work = limits.codec_work };
            break :blk try packBuffer(lzma2, .lzma2, entry.data, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
        },
        .ppmd => blk: {
            const options: ppmd.Options = .{ .order = default_ppmd_order, .mem_size = default_ppmd_mem, .unpack_size = entry.data.len, .max_work = limits.codec_work };
            break :blk try packBuffer(ppmd, .ppmd, entry.data, unpacked_crc, workspace, limits, ppmd.encodeWorkspaceSize(default_ppmd_mem), options);
        },
        .delta, .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => blk: {
            const filtered = try workspace.take(u8, entry.data.len);
            @memcpy(filtered, entry.data);
            try applyEncodeFilter(entry.method, filtered);
            const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.properties(default_dictionary), .max_work = limits.codec_work };
            var packed_entry = try packBuffer(lzma2, .lzma2, filtered, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
            packed_entry.filter = entry.method;
            break :blk packed_entry;
        },
    };
    if (!entry.encrypted) return compressed_entry;
    const password_utf16 = try passwordToUtf16(entry.password, workspace);
    var key: [crypto.seven_zip_key_length]u8 = undefined;
    crypto.sevenZipKdf(password_utf16, &.{}, crypto.seven_zip_default_cycles, &key);
    const padded_size = std.mem.alignForward(usize, compressed_entry.data.len, crypto.block_length);
    if (entry.password_lifetime != 0 and padded_size > entry.password_lifetime) {
        failure_cause.* = .password_lifetime;
        return error.ResourceLimit;
    }
    const encrypted_data = try workspace.take(u8, padded_size);
    @memset(encrypted_data[compressed_entry.data.len..], 0);
    @memcpy(encrypted_data[0..compressed_entry.data.len], compressed_entry.data);
    var iv: [16]u8 = entry.iv;
    if (!entry.iv_set) {
        if (!crypto.fillRandom(&iv)) try crypto.deriveDeterministicSalt(entry.password, entry.name, entry.data, &iv);
    }
    try crypto.aesCbcEncrypt(&key, iv, encrypted_data, encrypted_data);
    return .{ .method = compressed_entry.method, .data = encrypted_data, .crc = compressed_entry.crc, .encrypted = true, .filter = compressed_entry.filter, .iv = iv, .codec_size = compressed_entry.codec_size, .decoded_size = compressed_entry.decoded_size };
}

fn applyEncodeFilter(method: CoderMethod, data: []u8) Failure!void {
    switch (method) {
        .delta => delta.encode(data, 0),
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => bcj.encode(bcjKindFromMethod(method), 0, data),
        else => return error.InternalFailure,
    }
}

fn packAllEntries(entries: []const SevenZipEntry, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Failure![]const PackedEntry {
    const packed_entries = try workspace.take(PackedEntry, nonEmptyCount(entries));
    var index: usize = 0;
    var i: usize = 0;
    while (i < entries.len) {
        if (isEmptyEntry(entries[i])) {
            i += 1;
            continue;
        }
        if (entries[i].method == .lzma2 and !entries[i].encrypted) {
            var j = i + 1;
            while (j < entries.len and !isEmptyEntry(entries[j]) and entries[j].method == .lzma2 and !entries[j].encrypted) j += 1;
            if (j - i >= 2) {
                var total: usize = 0;
                for (entries[i..j]) |entry| total = try bounds.add(total, entry.data.len);
                if (total > limits.codec_work) return error.ResourceLimit;
                const concat = try workspace.take(u8, total);
                var offset: usize = 0;
                for (entries[i..j]) |entry| {
                    @memcpy(concat[offset..][0..entry.data.len], entry.data);
                    offset += entry.data.len;
                }
                const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.properties(default_dictionary), .max_work = limits.codec_work };
                const scratch = try workspace.take(u8, lzma2.encodeWorkspaceSizeBt(default_dictionary));
                const packed_size = try lzma2.requiredSize(concat, scratch, options);
                if (packed_size > limits.encoded_bytes) return error.ResourceLimit;
                if (try bounds.add(total, packed_size) > limits.codec_work) return error.ResourceLimit;
                const packed_data = try workspace.take(u8, packed_size);
                _ = try lzma2.encode(concat, packed_data, scratch, options);
                for (entries[i..j], 0..) |entry, k| {
                    packed_entries[index] = .{ .method = .lzma2, .data = if (k == 0) packed_data else &.{}, .crc = checksum.crc32(entry.data), .codec_size = packed_size, .decoded_size = entry.data.len };
                    index += 1;
                }
                i = j;
                continue;
            }
        }
        packed_entries[index] = try packEntry(entries[i], workspace, limits, failure_cause);
        index += 1;
        i += 1;
    }
    return packed_entries[0..index];
}

pub fn sevenZipPack(entries: []const SevenZipEntry, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Failure![]const PackedEntry {
    failure_cause.* = .none;
    return try packAllEntries(entries, workspace, limits, failure_cause);
}

fn requiredSizeFromPacked(entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!usize {
    var total_pack: usize = 0;
    const plan = try buildFolderPlan(packed_entries, workspace);
    for (plan) |folder| total_pack = try bounds.add(total_pack, packed_entries[folder.first].data.len);
    var counter = measurement.Counter.init(null);
    try writeHeader(&counter.writer, entries, packed_entries, workspace);
    const header_size = counter.written();
    const total = try bounds.add(try bounds.add(start_header_size, total_pack), std.math.cast(usize, header_size) orelse return error.ResourceLimit);
    return std.math.cast(usize, total) orelse error.ResourceLimit;
}

pub fn sevenZipPackedSize(entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!usize {
    return try requiredSizeFromPacked(entries, packed_entries, workspace);
}

fn writeArchive(output: []u8, entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!usize {
    const required = try requiredSizeFromPacked(entries, packed_entries, workspace);
    if (output.len < required) return error.InsufficientCapacity;
    var total_pack: usize = 0;
    const plan = try buildFolderPlan(packed_entries, workspace);
    for (plan) |folder| total_pack = try bounds.add(total_pack, packed_entries[folder.first].data.len);
    const header_offset = start_header_size + total_pack;
    var header_writer = std.Io.Writer.fixed(output[header_offset..]);
    try writeHeader(&header_writer, entries, packed_entries, workspace);
    const header_size = header_writer.end;
    const header_crc = checksum.crc32(output[header_offset..][0..header_size]);
    var start_header: [20]u8 = undefined;
    std.mem.writeInt(u64, start_header[0..8], total_pack, .little);
    std.mem.writeInt(u64, start_header[8..16], header_size, .little);
    std.mem.writeInt(u32, start_header[16..20], header_crc, .little);
    const start_header_crc = checksum.crc32(&start_header);
    var sink = io.Sink{ .bytes = output[0..required] };
    try sink.write(&signature);
    try sink.write(&version);
    try sink.writeInt(u32, start_header_crc, .little);
    try sink.write(&start_header);
    for (plan) |folder| {
        try sink.write(packed_entries[folder.first].data);
    }
    return required;
}

pub fn sevenZipWritePacked(entries: []const SevenZipEntry, packed_entries: []const PackedEntry, output: []u8, workspace: *Workspace) Failure!usize {
    return try writeArchive(output, entries, packed_entries, workspace);
}

pub fn sevenZipInspectCount(archive_bytes: []const u8, workspace: *Workspace, limits: Limits) Failure!u64 {
    const archive = try loadArchive(archive_bytes, workspace, limits);
    return archive.count;
}

pub fn sevenZipInspectOrdinal(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64) Failure!SevenZipInfo {
    const archive = try loadArchive(archive_bytes, workspace, limits);
    if (ordinal >= archive.count) return error.InvalidData;
    return archive.entries[ordinal];
}

pub fn sevenZipDecodeOrdinal(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, output: []u8, decode_options: SevenZipDecodeOptions) Failure!usize {
    decode_options.failure_cause.* = .none;
    const archive = try loadArchive(archive_bytes, workspace, limits);
    if (ordinal >= archive.count) return error.InvalidData;
    const entry = archive.entries[ordinal];
    const size = std.math.cast(usize, entry.size) orelse return error.ResourceLimit;
    if (output.len < size) return error.InsufficientCapacity;
    if (size == 0) return 0;
    var decode_output = output;
    var decode_target_len = size;
    if (entry.folder) |folder| {
        if (folder.num_substreams > 1) {
            const total_size = try folderOutputSize(folder);
            if (total_size > limits.decoded_bytes) return error.ResourceLimit;
            decode_output = try workspace.take(u8, total_size);
            decode_target_len = total_size;
        }
    }
    const pack_size = std.math.cast(usize, entry.pack_size) orelse return error.ResourceLimit;
    const decrypted_packed = blk: {
        if (!entry.encrypted) {
            const packed_data = try workspace.take(u8, pack_size);
            try readAt(archive.data, entry.data_offset, packed_data);
            break :blk packed_data;
        }
        const password = decode_options.password orelse return error.Unsupported;
        const rounds: u64 = if (entry.aes_num_cycles == 0x3F) 0 else @as(u64, 1) << @intCast(entry.aes_num_cycles);
        if (decode_options.kdf_rounds_limit != 0 and rounds > decode_options.kdf_rounds_limit) {
            decode_options.failure_cause.* = .kdf_limit;
            return error.ResourceLimit;
        }
        if (decode_options.password_lifetime != 0 and pack_size > decode_options.password_lifetime) {
            decode_options.failure_cause.* = .password_lifetime;
            return error.ResourceLimit;
        }
        const packed_data = try workspace.take(u8, pack_size);
        try readAt(archive.data, entry.data_offset, packed_data);
        const password_utf16 = try passwordToUtf16(password, workspace);
        var key: [crypto.seven_zip_key_length]u8 = undefined;
        if (entry.aes_num_cycles == 0x3F) {
            var direct: [64]u8 = .{0} ** 64;
            @memcpy(direct[0..entry.aes_salt.len], entry.aes_salt);
            @memcpy(direct[entry.aes_salt.len..][0..password_utf16.len], password_utf16);
            @memcpy(&key, direct[0..32]);
        } else {
            crypto.sevenZipKdf(password_utf16, entry.aes_salt, entry.aes_num_cycles, &key);
        }
        const decrypted = try workspace.take(u8, pack_size);
        try crypto.aesCbcDecrypt(&key, entry.aes_iv, decrypted, packed_data);
        break :blk decrypted;
    };
    switch (entry.method) {
        .copy => {
            if (decrypted_packed.len != decode_target_len and !entry.encrypted) return error.InvalidData;
            if (decrypted_packed.len < decode_target_len) return error.InvalidData;
            @memcpy(decode_output[0..decode_target_len], decrypted_packed[0..decode_target_len]);
        },
        .deflate => {
            const history = try workspace.take(u8, deflate.history_size);
            var source_reader = std.Io.Reader.fixed(decrypted_packed);
            var dest_writer = std.Io.Writer.fixed(decode_output);
            var inflater = deflate.Decompress.init(&source_reader, history);
            _ = inflater.reader.streamRemaining(&dest_writer) catch return error.InvalidData;
            if (dest_writer.end != decode_target_len) return error.InvalidData;
        },
        .bzip2 => {
            const scratch_size = try bzip2.decodeWorkspaceSizeFor(decrypted_packed);
            const scratch = try workspace.take(u8, scratch_size);
            const decoded = try bzip2.decode(decrypted_packed, decode_output, scratch);
            if (decoded != decode_target_len) return error.InvalidData;
        },
        .lzma => {
            const properties = try parseLzmaProperties(entry.attributes);
            const options: lzma.Options = .{ .properties = properties, .unpack_size = decode_target_len, .marker_required = false, .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(properties));
            const decoded = try lzma.decode(decrypted_packed, decode_output, scratch, options);
            if (decoded != decode_target_len) return error.InvalidData;
        },
        .lzma2 => {
            const dictionary = lzma2.dictionaryFromProp(try readLzma2Prop(entry.attributes));
            if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.Unsupported;
            const options: lzma2.Options = .{ .dictionary_size = dictionary, .properties = lzma2.properties(dictionary), .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma2.decodeWorkspaceSize(dictionary));
            const decoded = try lzma2.decode(decrypted_packed, decode_output, scratch, options);
            if (decoded != decode_target_len) return error.InvalidData;
        },
        .ppmd => {
            const options = try parsePpmdOptions(entry.attributes, decode_target_len, limits.codec_work);
            const scratch = try workspace.take(u8, ppmd.decodeWorkspaceSize(options.mem_size));
            const decoded = try ppmd.decode(decrypted_packed, decode_output, scratch, options);
            if (decoded != decode_target_len) return error.InvalidData;
        },
        else => return error.Unsupported,
    }
    if (entry.folder) |folder| {
        try applyFolderFilters(folder.coders, decode_output[0..decode_target_len]);
        if (folder.num_substreams > 1) {
            const offset = std.math.cast(usize, entry.substream_offset) orelse return error.ResourceLimit;
            if (offset + size > decode_target_len) return error.InvalidData;
            @memcpy(output[0..size], decode_output[offset..][0..size]);
        }
    }
    if (entry.crc) |expected| {
        if (checksum.crc32(output[0..size]) != expected) return error.IntegrityFailure;
    }
    return size;
}

fn readLzma2Prop(attributes: []const u8) Failure!u8 {
    if (attributes.len != 1) return error.InvalidData;
    return attributes[0];
}

fn parsePpmdOptions(attributes: []const u8, unpack_size: usize, codec_work: u64) Failure!ppmd.Options {
    if (attributes.len != 5) return error.InvalidData;
    const mem_field = std.mem.readInt(u32, attributes[1..5], .little);
    const mem_size = mem_field << 8;
    return .{
        .order = attributes[0],
        .mem_size = mem_size,
        .unpack_size = unpack_size,
        .max_work = codec_work,
    };
}

fn parseLzmaProperties(attributes: []const u8) Failure!lzma.Properties {
    if (attributes.len != 5) return error.InvalidData;
    const props_byte = attributes[0];
    var dictionary: u32 = 0;
    for (0..4) |i| dictionary |= @as(u32, attributes[1 + i]) << @intCast(8 * i);
    if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.Unsupported;
    return try lzma.Properties.decode(props_byte, dictionary);
}

fn applyFolderFilters(coders: []const ParsedCoder, data: []u8) Failure!void {
    var filters: [4]ParsedCoder = undefined;
    var filter_count: usize = 0;
    for (coders) |coder| {
        if (isFilterMethod(coder.method)) {
            if (filter_count >= filters.len) return error.Unsupported;
            filters[filter_count] = coder;
            filter_count += 1;
        }
    }
    for (filters[0..filter_count]) |coder| {
        switch (coder.method) {
            .delta => {
                if (coder.attributes.len != 1) return error.InvalidData;
                delta.decode(data, coder.attributes[0]);
            },
            .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => {
                const start_offset: u32 = if (coder.attributes.len == 0) 0 else if (coder.attributes.len == 4)
                    std.mem.readInt(u32, coder.attributes[0..4], .little)
                else
                    return error.InvalidData;
                const kind = bcjKindFromMethod(coder.method);
                if (start_offset % bcj.alignment(kind) != 0) return error.InvalidData;
                bcj.decode(kind, start_offset, data);
            },
            else => return error.InternalFailure,
        }
    }
}

fn isFilterMethod(method: CoderMethod) bool {
    return switch (method) {
        .delta, .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => true,
        else => false,
    };
}

fn bcjKindFromMethod(method: CoderMethod) bcj.Kind {
    return switch (method) {
        .x86 => .x86,
        .ppc => .ppc,
        .ia64 => .ia64,
        .arm => .arm,
        .armt => .armt,
        .sparc => .sparc,
        .arm64 => .arm64,
        .riscv => .riscv,
        else => unreachable,
    };
}

const LoadedArchive = struct {
    data: []const u8,
    count: u64,
    entries: []const SevenZipInfo,
};

fn readAt(data: []const u8, offset: u64, buffer: []u8) Failure!void {
    const start = std.math.cast(usize, offset) orelse return error.InvalidData;
    const end = try bounds.add(start, buffer.len);
    if (end > data.len) return error.InvalidData;
    @memcpy(buffer, data[start..end]);
}

fn loadArchive(data: []const u8, workspace: *Workspace, limits: Limits) Failure!LoadedArchive {
    if (data.len > limits.encoded_bytes) return error.ResourceLimit;
    var archive: LoadedArchive = .{
        .data = data,
        .count = 0,
        .entries = &.{},
    };
    var start_buffer: [start_header_size]u8 = undefined;
    try readAt(data, 0, &start_buffer);
    if (!std.mem.eql(u8, start_buffer[0..6], &signature)) return error.InvalidData;
    if (!std.mem.eql(u8, start_buffer[6..8], &version)) return error.Unsupported;
    const recorded_start_crc = std.mem.readInt(u32, start_buffer[8..12], .little);
    const start_header_crc = checksum.crc32(start_buffer[12..32]);
    if (recorded_start_crc != start_header_crc) return error.IntegrityFailure;
    const next_header_offset = std.mem.readInt(u64, start_buffer[12..20], .little);
    const next_header_size = std.mem.readInt(u64, start_buffer[20..28], .little);
    const recorded_header_crc = std.mem.readInt(u32, start_buffer[28..32], .little);
    if (next_header_size > limits.metadata_records) return error.ResourceLimit;
    const header_start = try bounds.add64(start_header_size, next_header_offset);
    const header_size_usize = std.math.cast(usize, next_header_size) orelse return error.ResourceLimit;
    const header_buffer = try workspace.take(u8, header_size_usize);
    try readAt(archive.data, header_start, header_buffer);
    if (checksum.crc32(header_buffer) != recorded_header_crc) return error.IntegrityFailure;
    var cursor = binary.ReadCursor.init(header_buffer);
    const header_id = try cursor.readU8();
    if (header_id != 0x01) return error.Unsupported;
    var streams: ?StreamsInfo = null;
    var files: ?FilesInfo = null;
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        switch (id) {
            0x04 => streams = try parseStreamsInfo(&cursor, workspace),
            0x05 => files = try parseFilesInfo(&cursor, workspace),
            0x02 => try skipArchiveProperties(&cursor),
            else => return error.Unsupported,
        }
    }
    const si = streams orelse return error.InvalidData;
    const fi = files orelse return error.InvalidData;
    archive.entries = try buildEntries(&si, &fi, workspace, limits);
    archive.count = archive.entries.len;
    return archive;
}

const StreamsInfo = struct {
    pack_pos: u64,
    pack_sizes: []const u64,
    pack_crcs: []const u32,
    folders: []const Folder,
};

const ParsedCoder = struct {
    method_id: []const u8,
    method: CoderMethod,
    attributes: []const u8,
    num_in_streams: u64,
    num_out_streams: u64,
};

const Folder = struct {
    num_substreams: u64,
    substream_sizes: []u64,
    substream_crcs: []const u32,
    pack_index: usize,
    method: CoderMethod,
    attributes: []const u8,
    num_in_streams: u64,
    num_out_streams: u64,
    total_out_streams: u64 = 1,
    encrypted: bool = false,
    aes_num_cycles: u8 = 0,
    aes_salt: []const u8 = &.{},
    aes_iv: [16]u8 = .{0} ** 16,
    aes_iv_size: u8 = 0,
    coders: []const ParsedCoder = &.{},
    unpack_size: u64 = 0,
};

const AesCoderProps = struct {
    num_cycles: u8,
    salt: []const u8,
    iv: [16]u8,
    iv_size: u8,
};

const FilesInfo = struct {
    num_files: u64,
    empty_streams: []const bool,
    empty_files: []const bool,
    names: []const []const u8,
};

fn parseStreamsInfo(cursor: *binary.ReadCursor, workspace: *Workspace) Failure!StreamsInfo {
    var pack_pos: u64 = 0;
    var pack_sizes: []const u64 = &.{};
    var pack_crcs: []const u32 = &.{};
    var folders: []Folder = &.{};
    var has_pack = false;
    var has_unpack = false;
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        switch (id) {
            0x06 => {
                has_pack = true;
                pack_pos = try readUint64(cursor);
                const num_pack_streams = try readUint64(cursor);
                if (num_pack_streams == 0) return error.InvalidData;
                const sizes = try workspace.take(u64, std.math.cast(usize, num_pack_streams) orelse return error.ResourceLimit);
                while (true) {
                    const pid = try cursor.readU8();
                    if (pid == 0x00) break;
                    if (pid == 0x09) {
                        for (sizes) |*s| s.* = try readUint64(cursor);
                    } else if (pid == 0x0A) {
                        pack_crcs = try readDigests(cursor, num_pack_streams, workspace);
                    } else {
                        return error.Unsupported;
                    }
                }
                pack_sizes = sizes;
            },
            0x07 => {
                has_unpack = true;
                folders = try parseFolders(cursor, workspace);
            },
            0x08 => {
                try parseSubStreamsInfo(cursor, workspace, folders);
            },
            else => return error.Unsupported,
        }
    }
    if (!has_pack or !has_unpack) return error.InvalidData;
    if (pack_sizes.len != folders.len) return error.InvalidData;
    for (folders, 0..) |folder, i| {
        if (folder.pack_index != i) return error.InvalidData;
    }
    return .{
        .pack_pos = pack_pos,
        .pack_sizes = pack_sizes,
        .pack_crcs = pack_crcs,
        .folders = folders,
    };
}

fn parseFolders(cursor: *binary.ReadCursor, workspace: *Workspace) Failure![]Folder {
    const folder_id = try cursor.readU8();
    if (folder_id != 0x0B) {
        return error.InvalidData;
    }
    const num_folders = try readUint64(cursor);
    const folder_count = std.math.cast(usize, num_folders) orelse return error.ResourceLimit;
    const external = try cursor.readU8();
    if (external != 0) {
        return error.Unsupported;
    }
    const folders = try workspace.take(Folder, folder_count);
    for (folders) |*folder| {
        const num_coders = try readUint64(cursor);
        if (num_coders < 1 or num_coders > 4) return error.Unsupported;
        const coder_count = std.math.cast(usize, num_coders) orelse return error.ResourceLimit;
        const coders = try workspace.take(ParsedCoder, coder_count);
        for (coders) |*coder| {
            coder.* = try parseCoder(cursor, workspace);
        }
        var encrypted = false;
        var aes: AesCoderProps = .{ .num_cycles = 0, .salt = &.{}, .iv = .{0} ** 16, .iv_size = 0 };
        var data_coder_count: usize = 0;
        var last_data: ?ParsedCoder = null;
        var folder_in_streams: u64 = 0;
        var folder_out_streams: u64 = 0;
        for (coders) |coder| {
            folder_in_streams = try bounds.add(folder_in_streams, coder.num_in_streams);
            folder_out_streams = try bounds.add(folder_out_streams, coder.num_out_streams);
            if (std.mem.eql(u8, coder.method_id, &method_7z_aes_id)) {
                if (encrypted) return error.Unsupported;
                encrypted = true;
                aes = try parse7zAesProps(coder.attributes);
            } else {
                if (!isFilterMethod(coder.method)) {
                    data_coder_count += 1;
                    last_data = coder;
                }
            }
        }
        if (data_coder_count == 0 or (encrypted and data_coder_count != 1)) return error.Unsupported;
        const data_coder = last_data.?;
        const method = data_coder.method;
        const attributes = data_coder.attributes;
        const num_in_streams = data_coder.num_in_streams;
        const num_out_streams = data_coder.num_out_streams;
        if (num_coders > 1) {
            const num_bonds = num_coders - 1;
            var bond: u64 = 0;
            while (bond < num_bonds) : (bond += 1) {
                const in_index = try readUint64(cursor);
                const coder_index = try readUint64(cursor);
                if (in_index >= folder_in_streams or coder_index >= num_coders) return error.InvalidData;
            }
            const num_packed_streams = folder_in_streams - num_bonds;
            if (num_packed_streams != 1) {
                var packed_index: u64 = 0;
                while (packed_index < num_packed_streams) : (packed_index += 1) {
                    const index = try readUint64(cursor);
                    if (index >= folder_in_streams) return error.InvalidData;
                }
            }
        }
        folder.* = .{
            .num_substreams = 1,
            .substream_sizes = &.{},
            .substream_crcs = &.{},
            .pack_index = 0,
            .method = method,
            .attributes = attributes,
            .num_in_streams = num_in_streams,
            .num_out_streams = num_out_streams,
            .total_out_streams = folder_out_streams,
            .encrypted = encrypted,
            .aes_num_cycles = aes.num_cycles,
            .aes_salt = aes.salt,
            .aes_iv = aes.iv,
            .aes_iv_size = aes.iv_size,
            .coders = coders,
        };
    }
    const unpack_id = try cursor.readU8();
    if (unpack_id != 0x0C) return error.InvalidData;
    for (folders) |*folder| {
        const stream_count = std.math.cast(usize, folder.total_out_streams) orelse return error.ResourceLimit;
        const arr = try workspace.take(u64, stream_count);
        for (0..stream_count) |index| {
            arr[index] = try readUint64(cursor);
        }
        folder.unpack_size = arr[stream_count - 1];
        folder.substream_sizes = arr[stream_count - 1 ..][0..1];
    }
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        if (id == 0x0A) {
            const digests = try readDigests(cursor, num_folders, workspace);
            for (folders, 0..) |*folder, i| {
                if (i < digests.len) folder.substream_crcs = digests[i .. i + 1];
            }
        } else return error.Unsupported;
    }
    for (folders, 0..) |*folder, i| folder.pack_index = i;
    return folders;
}

fn parseCoder(cursor: *binary.ReadCursor, workspace: *Workspace) Failure!ParsedCoder {
    const flags = try cursor.readU8();
    const id_size = flags & 0x0F;
    const is_complex = (flags & 0x10) != 0;
    const has_attributes = (flags & 0x20) != 0;
    if ((flags & 0x40) != 0 or (flags & 0x80) != 0) return error.Unsupported;
    if (id_size == 0 or id_size > 8) return error.Unsupported;
    const method_id = try cursor.readSlice(id_size);
    const method: CoderMethod = if (std.mem.eql(u8, method_id, &method_7z_aes_id)) .copy else try methodFromId(method_id);
    var num_in_streams: u64 = 1;
    var num_out_streams: u64 = 1;
    if (is_complex) {
        num_in_streams = try readUint64(cursor);
        num_out_streams = try readUint64(cursor);
    }
    if (num_in_streams != 1 or num_out_streams != 1) return error.Unsupported;
    const attributes = blk: {
        if (has_attributes) {
            const prop_size = try readUint64(cursor);
            const prop_count = std.math.cast(usize, prop_size) orelse return error.ResourceLimit;
            if (prop_size > cursor.remaining()) return error.InvalidData;
            const bytes = try workspace.take(u8, prop_count);
            const start = cursor.pos;
            try cursor.advance(prop_size);
            @memcpy(bytes, cursor.buffer[start..cursor.pos]);
            break :blk bytes;
        } else {
            if (method == .lzma or method == .lzma2) return error.InvalidData;
            break :blk &[_]u8{};
        }
    };
    return .{
        .method_id = method_id,
        .method = method,
        .attributes = attributes,
        .num_in_streams = num_in_streams,
        .num_out_streams = num_out_streams,
    };
}

fn parse7zAesProps(attributes: []const u8) Failure!AesCoderProps {
    if (attributes.len == 0) return error.InvalidData;
    const b0 = attributes[0];
    const num_cycles = b0 & 0x3F;
    if ((b0 & 0xC0) == 0) {
        if (attributes.len != 1) return error.InvalidData;
        return .{ .num_cycles = num_cycles, .salt = &.{}, .iv = .{0} ** 16, .iv_size = 0 };
    }
    if (attributes.len <= 1) return error.InvalidData;
    const b1 = attributes[1];
    const salt_size = @as(usize, (b0 >> 7) & 1) + (b1 >> 4);
    const iv_size = @as(usize, (b0 >> 6) & 1) + (b1 & 0x0F);
    if (attributes.len != 2 + salt_size + iv_size) return error.InvalidData;
    if (num_cycles > crypto.seven_zip_cycles_max and num_cycles != 0x3F) return error.Unsupported;
    var iv: [16]u8 = .{0} ** 16;
    @memcpy(iv[0..iv_size], attributes[2 + salt_size ..][0..iv_size]);
    return .{
        .num_cycles = num_cycles,
        .salt = attributes[2..][0..salt_size],
        .iv = iv,
        .iv_size = @intCast(iv_size),
    };
}

fn parseSubStreamsInfo(cursor: *binary.ReadCursor, workspace: *Workspace, folders: []Folder) Failure!void {
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        switch (id) {
            0x0D => {
                for (folders) |*folder| {
                    const count = try readUint64(cursor);
                    if (count == 0) return error.InvalidData;
                    folder.num_substreams = count;
                }
            },
            0x09 => {
                const total = try totalSubstreams(folders);
                const size_count = try substreamSizeCount(folders);
                const arr = try workspace.take(u64, total);
                for (0..size_count) |index| {
                    arr[index] = try readUint64(cursor);
                }
                var index: usize = 0;
                for (folders) |*folder| {
                    const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
                    folder.substream_sizes = arr[index .. index + count];
                    index += count;
                }
            },
            0x0A => {
                const total = try totalSubstreams(folders);
                const digests = try readDigests(cursor, total, workspace);
                var index: usize = 0;
                for (folders) |*folder| {
                    const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
                    if (index + count <= digests.len) {
                        folder.substream_crcs = digests[index .. index + count];
                    }
                    index += count;
                }
            },
            else => return error.Unsupported,
        }
    }
    try finalizeSubstreamSizes(folders);
}

fn totalSubstreams(folders: []const Folder) Failure!usize {
    var total: usize = 0;
    for (folders) |folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
        total = try bounds.add(total, count);
    }
    return total;
}

fn substreamSizeCount(folders: []const Folder) Failure!usize {
    var total: usize = 0;
    for (folders) |folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
        if (count > 0) total = try bounds.add(total, count - 1);
    }
    return total;
}

fn finalizeSubstreamSizes(folders: []Folder) Failure!void {
    for (folders) |*folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
        if (folder.substream_sizes.len != count) return error.InvalidData;
        if (count == 1) {
            if (folder.substream_sizes[0] != folder.unpack_size) return error.InvalidData;
            continue;
        }
        var sum: u64 = 0;
        for (folder.substream_sizes[0 .. count - 1]) |size| {
            sum = try bounds.add64(sum, size);
        }
        if (sum > folder.unpack_size) return error.InvalidData;
        folder.substream_sizes[count - 1] = folder.unpack_size - sum;
    }
}

fn parseFilesInfo(cursor: *binary.ReadCursor, workspace: *Workspace) Failure!FilesInfo {
    const num_files = try readUint64(cursor);
    const count = std.math.cast(usize, num_files) orelse return error.ResourceLimit;
    const empty_streams = try workspace.take(bool, count);
    const empty_files = try workspace.take(bool, count);
    const names = try workspace.take([]const u8, count);
    @memset(empty_streams, false);
    @memset(empty_files, false);
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        const prop_size = try readUint64(cursor);
        if (prop_size > cursor.remaining()) return error.InvalidData;
        const prop_start = cursor.pos;
        try cursor.advance(prop_size);
        var sub = binary.ReadCursor.init(cursor.buffer[prop_start..cursor.pos]);
        switch (id) {
            0x0E => {
                const bits = try readBitVectorRaw(&sub, count, workspace);
                for (0..count) |i| empty_streams[i] = bits[i];
            },
            0x0F => {
                const empty_count = countEmpty(empty_streams);
                const bits = try readBitVectorRaw(&sub, empty_count, workspace);
                for (0..empty_count) |i| empty_files[try emptyIndex(empty_streams, i)] = bits[i];
            },
            0x10 => {
                const empty_count = countEmpty(empty_streams);
                const bits = try readBitVectorRaw(&sub, empty_count, workspace);
                for (bits) |b| {
                    if (b) return error.Unsupported;
                }
            },
            0x11 => {
                const external = try sub.readU8();
                if (external != 0) return error.Unsupported;
                for (0..count) |i| {
                    names[i] = try readUtf16Name(&sub, workspace);
                }
            },
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 => {},
            else => return error.Unsupported,
        }
        if (id >= 0x0E and id <= 0x11 and sub.remaining() != 0) return error.InvalidData;
    }
    return .{
        .num_files = num_files,
        .empty_streams = empty_streams,
        .empty_files = empty_files,
        .names = names,
    };
}

fn skipArchiveProperties(cursor: *binary.ReadCursor) Failure!void {
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        const size = try readUint64(cursor);
        if (size > cursor.remaining()) return error.InvalidData;
        try cursor.advance(size);
    }
}

fn buildEntries(si: *const StreamsInfo, fi: *const FilesInfo, workspace: *Workspace, limits: Limits) Failure![]const SevenZipInfo {
    const count = fi.names.len;
    const entries = try workspace.take(SevenZipInfo, count);
    var folder_index: usize = 0;
    var substream_index: usize = 0;
    var substream_offset: u64 = 0;
    for (0..count) |i| {
        const is_empty = fi.empty_streams[i];
        const is_dir = is_empty and !fi.empty_files[i];
        var size: u64 = 0;
        var data_offset: u64 = 0;
        var pack_size: u64 = 0;
        var crc: ?u32 = null;
        var method: CoderMethod = .copy;
        var attributes: []const u8 = &[_]u8{};
        var encrypted = false;
        var aes_num_cycles: u8 = 0;
        var aes_salt: []const u8 = &.{};
        var aes_iv: [16]u8 = .{0} ** 16;
        var aes_iv_size: u8 = 0;
        var entry_folder: ?*const Folder = null;
        var file_substream_offset: u64 = 0;
        if (!is_empty) {
            while (folder_index < si.folders.len) {
                const folder_substream_count = std.math.cast(usize, si.folders[folder_index].num_substreams) orelse return error.ResourceLimit;
                if (substream_index < folder_substream_count) break;
                folder_index += 1;
                substream_index = 0;
                substream_offset = 0;
            }
            if (folder_index >= si.folders.len) return error.InvalidData;
            const folder = &si.folders[folder_index];
            entry_folder = folder;
            if (substream_index >= folder.substream_sizes.len) return error.InvalidData;
            size = folder.substream_sizes[substream_index];
            if (size > limits.decoded_bytes) return error.ResourceLimit;
            pack_size = si.pack_sizes[folder_index];
            if (pack_size > limits.encoded_bytes) return error.ResourceLimit;
            data_offset = try bounds.add64(start_header_size, try folderPackOffset(si, folder_index));
            method = folder.method;
            attributes = folder.attributes;
            encrypted = folder.encrypted;
            aes_num_cycles = folder.aes_num_cycles;
            aes_salt = folder.aes_salt;
            aes_iv = folder.aes_iv;
            aes_iv_size = folder.aes_iv_size;
            file_substream_offset = substream_offset;
            if (folder.substream_crcs.len > substream_index) {
                crc = folder.substream_crcs[substream_index];
            }
            substream_index += 1;
            substream_offset = try bounds.add64(substream_offset, size);
            const folder_substream_count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
            if (substream_index >= folder_substream_count) {
                folder_index += 1;
                substream_index = 0;
                substream_offset = 0;
            }
        }
        const name = try utf16LeToUtf8(fi.names[i], workspace);
        entries[i] = .{
            .name = name,
            .size = size,
            .is_directory = is_dir,
            .data_offset = data_offset,
            .pack_size = pack_size,
            .crc = crc,
            .method = method,
            .attributes = attributes,
            .encrypted = encrypted,
            .aes_num_cycles = aes_num_cycles,
            .aes_salt = aes_salt,
            .aes_iv = aes_iv,
            .aes_iv_size = aes_iv_size,
            .folder = entry_folder,
            .substream_offset = file_substream_offset,
        };
    }
    if (folder_index != si.folders.len) return error.InvalidData;
    return entries;
}

fn folderPackOffset(si: *const StreamsInfo, folder_index: usize) Failure!u64 {
    var offset = si.pack_pos;
    for (0..folder_index) |index| {
        offset = try bounds.add64(offset, si.pack_sizes[index]);
    }
    return offset;
}

fn folderOutputSize(folder: *const Folder) Failure!usize {
    var total: usize = 0;
    for (folder.substream_sizes) |size| {
        const part = std.math.cast(usize, size) orelse return error.ResourceLimit;
        total = try bounds.add(total, part);
    }
    return total;
}

fn writeHeader(writer: *std.Io.Writer, entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!void {
    try io.writeBytes(writer, &.{0x01});
    try io.writeBytes(writer, &.{0x04});
    try writeStreamsInfo(writer, entries, packed_entries, workspace);
    try writeFilesInfo(writer, entries, workspace);
    try io.writeBytes(writer, &.{0x00});
}

const FolderPlan = struct {
    filter: ?CoderMethod,
    method: CoderMethod,
    encrypted: bool,
    first: usize,
    count: usize,
};

fn buildFolderPlan(packed_entries: []const PackedEntry, workspace: *Workspace) Failure![]const FolderPlan {
    const plan = try workspace.take(FolderPlan, packed_entries.len);
    var plan_count: usize = 0;
    var i: usize = 0;
    while (i < packed_entries.len) {
        const p = packed_entries[i];
        var j = i + 1;
        if (p.method == .lzma2) {
            while (j < packed_entries.len and packed_entries[j].method == .lzma2 and
                packed_entries[j].filter == p.filter and packed_entries[j].encrypted == p.encrypted)
            {
                j += 1;
            }
        }
        plan[plan_count] = .{ .filter = p.filter, .method = p.method, .encrypted = p.encrypted, .first = i, .count = j - i };
        plan_count += 1;
        i = j;
    }
    return plan[0..plan_count];
}

fn folderUnpackSize(entries: []const SevenZipEntry, folder: FolderPlan) Failure!usize {
    var total: usize = 0;
    var index: usize = 0;
    for (entries) |entry| {
        if (isEmptyEntry(entry)) continue;
        if (index < folder.first) {
            index += 1;
            continue;
        }
        if (index >= folder.first + folder.count) break;
        total = try bounds.add(total, entry.data.len);
        index += 1;
    }
    return total;
}

fn writeStreamsInfo(writer: *std.Io.Writer, entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!void {
    const plan = try buildFolderPlan(packed_entries, workspace);
    try io.writeBytes(writer, &.{0x06});
    try writeUint64(writer, 0);
    try writeUint64(writer, plan.len);
    if (plan.len > 0) {
        try io.writeBytes(writer, &.{0x09});
        for (plan) |folder| {
            try writeUint64(writer, packed_entries[folder.first].data.len);
        }
    }
    try io.writeBytes(writer, &.{0x00});
    try io.writeBytes(writer, &.{0x07});
    try io.writeBytes(writer, &.{0x0B});
    try writeUint64(writer, plan.len);
    try io.writeBytes(writer, &.{0x00});
    for (plan) |folder| {
        const p = packed_entries[folder.first];
        const num_coders = @as(usize, if (p.encrypted) 1 else 0) + @as(usize, if (p.filter != null) 1 else 0) + 1;
        try writeUint64(writer, num_coders);
        if (p.encrypted) {
            const aes_flags: u8 = @as(u8, @intCast(method_7z_aes_id.len)) | 0x20;
            try io.writeBytes(writer, &.{aes_flags});
            try io.writeBytes(writer, &method_7z_aes_id);
            try writeUint64(writer, 18);
            var props: [18]u8 = undefined;
            props[0] = crypto.seven_zip_default_cycles | 0x40;
            props[1] = 0x0F;
            @memcpy(props[2..18], &p.iv);
            try io.writeBytes(writer, &props);
        }
        const method = p.method;
        try writeFolderCoder(writer, method, p.crc);
        if (p.filter) |filter| try writeFolderCoder(writer, filter, p.crc);
        var bond_index: usize = 0;
        while (bond_index + 1 < num_coders) : (bond_index += 1) {
            try writeUint64(writer, bond_index + 1);
            try writeUint64(writer, bond_index);
        }
    }
    try io.writeBytes(writer, &.{0x0C});
    for (plan) |folder| {
        const p = packed_entries[folder.first];
        const unpack_size = try folderUnpackSize(entries, folder);
        if (p.encrypted) try writeUint64(writer, p.codec_size);
        try writeUint64(writer, unpack_size);
        if (p.filter != null) try writeUint64(writer, unpack_size);
    }
    try io.writeBytes(writer, &.{0x00});
    if (plan.len > 0) {
        try io.writeBytes(writer, &.{0x08});
        var has_solid = false;
        for (plan) |folder| {
            if (folder.count > 1) has_solid = true;
        }
        if (has_solid) {
            try io.writeBytes(writer, &.{0x0D});
            for (plan) |folder| try writeUint64(writer, folder.count);
        }
        if (has_solid) {
            try io.writeBytes(writer, &.{0x09});
            for (plan) |folder| {
                var index: usize = 0;
                while (index + 1 < folder.count) : (index += 1) {
                    const p = packed_entries[folder.first + index];
                    try writeUint64(writer, p.decoded_size);
                }
            }
        }
        try io.writeBytes(writer, &.{0x0A});
        try io.writeBytes(writer, &.{0x01});
        for (packed_entries) |p| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, p.crc, .little);
            try io.writeBytes(writer, &bytes);
        }
        try io.writeBytes(writer, &.{0x00});
    }
    try io.writeBytes(writer, &.{0x00});
}

fn writeFolderCoder(writer: *std.Io.Writer, method: CoderMethod, unpacked_crc: u32) Failure!void {
    const id = methodId(method);
    const attr_size = coderAttributeSize(method);
    const flags: u8 = @as(u8, @intCast(id.len)) | (if (attr_size != 0) @as(u8, 0x20) else @as(u8, 0));
    try io.writeBytes(writer, &.{flags});
    try io.writeBytes(writer, id);
    if (attr_size != 0) {
        try writeUint64(writer, attr_size);
        try writeCoderAttributes(writer, method, unpacked_crc);
    }
}

fn writeCoderAttributes(writer: *std.Io.Writer, method: CoderMethod, unpacked_crc: u32) Failure!void {
    _ = unpacked_crc;
    switch (method) {
        .lzma => {
            const properties = lzma2.properties(default_dictionary);
            try io.writeBytes(writer, &.{properties.encode()});
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, default_dictionary, .little);
            try io.writeBytes(writer, &bytes);
        },
        .lzma2 => {
            try io.writeBytes(writer, &.{lzma2.propFromDictionary(default_dictionary)});
        },
        .ppmd => {
            try io.writeBytes(writer, &.{@intCast(default_ppmd_order)});
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, default_ppmd_mem >> 8, .little);
            try io.writeBytes(writer, &bytes);
        },
        .delta => {
            try io.writeBytes(writer, &.{0});
        },
        else => {},
    }
}

fn writeFilesInfo(writer: *std.Io.Writer, entries: []const SevenZipEntry, workspace: *Workspace) Failure!void {
    try io.writeBytes(writer, &.{0x05});
    try writeUint64(writer, entries.len);
    const empty_count = emptyCount(entries);
    if (empty_count > 0) {
        try writeSizedProperty(writer, workspace, 0x0E, struct {
            entries: []const SevenZipEntry,

            fn write(self: @This(), w: *std.Io.Writer) Failure!void {
                try writeBitVector(w, self.entries.len, struct {
                    entries: []const SevenZipEntry,

                    fn get(c: @This(), i: usize) bool {
                        return isEmptyEntry(c.entries[i]);
                    }
                }{ .entries = self.entries });
            }
        }{ .entries = entries });
        try writeSizedProperty(writer, workspace, 0x0F, struct {
            entries: []const SevenZipEntry,

            fn write(self: @This(), w: *std.Io.Writer) Failure!void {
                const empty_count2 = emptyCount(self.entries);
                try writeBitVector(w, empty_count2, struct {
                    entries: []const SevenZipEntry,

                    fn get(c: @This(), i: usize) bool {
                        return emptyFileAt(c.entries, i);
                    }
                }{ .entries = self.entries });
            }
        }{ .entries = entries });
    }
    try writeSizedProperty(writer, workspace, 0x11, struct {
        entries: []const SevenZipEntry,

        fn write(self: @This(), w: *std.Io.Writer) Failure!void {
            try io.writeBytes(w, &.{0x00});
            for (self.entries) |entry| {
                try writeUtf16Name(w, entry.name);
            }
        }
    }{ .entries = entries });
    try writeSizedProperty(writer, workspace, 0x14, struct {
        entries: []const SevenZipEntry,

        fn write(self: @This(), w: *std.Io.Writer) Failure!void {
            try io.writeBytes(w, &.{ 0x01, 0x00 });
            for (self.entries) |_| {
                var bytes: [8]u8 = .{0} ** 8;
                try io.writeBytes(w, &bytes);
            }
        }
    }{ .entries = entries });
    try writeSizedProperty(writer, workspace, 0x15, struct {
        entries: []const SevenZipEntry,

        fn write(self: @This(), w: *std.Io.Writer) Failure!void {
            try io.writeBytes(w, &.{ 0x01, 0x00 });
            for (self.entries) |entry| {
                const attr: u32 = if (isDirectoryEntry(entry)) 0x10 else 0x20;
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, attr, .little);
                try io.writeBytes(w, &bytes);
            }
        }
    }{ .entries = entries });
    try io.writeBytes(writer, &.{0x00});
}

fn writeSizedProperty(writer: *std.Io.Writer, workspace: *Workspace, id: u8, ctx: anytype) Failure!void {
    var counter = measurement.Counter.init(null);
    try ctx.write(&counter.writer);
    const size = counter.written();
    if (size == 0) {
        try io.writeBytes(writer, &.{id});
        try writeUint64(writer, 0);
        return;
    }
    if (writer.vtable == &measurement.Counter.vtable) {
        try io.writeBytes(writer, &.{id});
        try writeUint64(writer, size);
        try ctx.write(writer);
        return;
    }
    const buffer = try workspace.take(u8, std.math.cast(usize, size) orelse return error.ResourceLimit);
    var fixed_writer = std.Io.Writer.fixed(buffer);
    try ctx.write(&fixed_writer);
    try io.writeBytes(writer, &.{id});
    try writeUint64(writer, size);
    try io.writeBytes(writer, buffer);
}

fn isEmptyEntry(entry: SevenZipEntry) bool {
    return entry.data.len == 0 or (entry.name.len > 0 and entry.name[entry.name.len - 1] == '/');
}

fn isDirectoryEntry(entry: SevenZipEntry) bool {
    return entry.name.len > 0 and entry.name[entry.name.len - 1] == '/';
}

fn nonEmptyCount(entries: []const SevenZipEntry) usize {
    var count: usize = 0;
    for (entries) |entry| {
        if (!isEmptyEntry(entry)) count += 1;
    }
    return count;
}

fn emptyCount(entries: []const SevenZipEntry) usize {
    var count: usize = 0;
    for (entries) |entry| {
        if (isEmptyEntry(entry)) count += 1;
    }
    return count;
}

fn emptyFileAt(entries: []const SevenZipEntry, index: usize) bool {
    var seen: usize = 0;
    for (entries) |entry| {
        if (isEmptyEntry(entry)) {
            if (seen == index) return !isDirectoryEntry(entry);
            seen += 1;
        }
    }
    return false;
}

fn readDigests(cursor: *binary.ReadCursor, count: u64, workspace: *Workspace) Failure![]const u32 {
    const n = std.math.cast(usize, count) orelse return error.ResourceLimit;
    const all_defined = try cursor.readU8();
    if (all_defined == 1) {
        const crcs = try workspace.take(u32, n);
        for (crcs) |*c| {
            var bytes = try cursor.readBytes(4);
            c.* = std.mem.readInt(u32, &bytes, .little);
        }
        return crcs;
    }
    if (all_defined == 0) {
        const defined = try readBoolVectorRaw(cursor, n, workspace);
        const crcs = try workspace.take(u32, n);
        for (crcs) |*c| c.* = 0;
        for (0..n) |i| {
            if (defined[i]) {
                var bytes = try cursor.readBytes(4);
                crcs[i] = std.mem.readInt(u32, &bytes, .little);
            }
        }
        return crcs;
    }
    return error.Unsupported;
}

fn readBoolVectorRaw(cursor: *binary.ReadCursor, count: usize, workspace: *Workspace) Failure![]const bool {
    if (count == 0) return &.{};
    const all = try cursor.readU8();
    const result = try workspace.take(bool, count);
    if (all == 0) {
        @memset(result, false);
        return result;
    }
    if (all == 2) {
        @memset(result, true);
        return result;
    }
    if (all != 1) return error.InvalidData;
    const bytes_count = (count + 7) / 8;
    const bytes = try cursor.readSlice(bytes_count);
    for (0..count) |i| {
        const shift: u3 = @intCast(7 - (i % 8));
        result[i] = (bytes[i / 8] >> shift) & 1 != 0;
    }
    return result;
}

fn readBitVectorRaw(cursor: *binary.ReadCursor, count: usize, workspace: *Workspace) Failure![]const bool {
    if (count == 0) return &.{};
    const bytes_count = (count + 7) / 8;
    if (cursor.remaining() < bytes_count) return error.InvalidData;
    const bytes = try cursor.readSlice(bytes_count);
    const result = try workspace.take(bool, count);
    for (0..count) |i| {
        const shift: u3 = @intCast(7 - (i % 8));
        result[i] = (bytes[i / 8] >> shift) & 1 != 0;
    }
    return result;
}

fn countEmpty(bits: []const bool) usize {
    var count: usize = 0;
    for (bits) |b| {
        if (b) count += 1;
    }
    return count;
}

fn emptyIndex(bits: []const bool, target: usize) Failure!usize {
    var seen: usize = 0;
    for (bits, 0..) |b, i| {
        if (b) {
            if (seen == target) return i;
            seen += 1;
        }
    }
    return error.InvalidData;
}

fn readUtf16Name(cursor: *binary.ReadCursor, workspace: *Workspace) Failure![]const u8 {
    const start = cursor.pos;
    var byte_len: usize = 0;
    while (true) {
        if (cursor.remaining() < 2) return error.InvalidData;
        const unit = std.mem.readInt(u16, &(try cursor.readBytes(2)), .little);
        byte_len += 2;
        if (unit == 0) break;
    }
    const bytes = try workspace.take(u8, byte_len);
    @memcpy(bytes, cursor.buffer[start..cursor.pos]);
    return bytes;
}

fn utf16LeToUtf8(name_utf16: []const u8, workspace: *Workspace) Failure![]const u8 {
    if (name_utf16.len < 2 or name_utf16.len % 2 != 0) return error.InvalidData;
    var utf8_len: usize = 0;
    var i: usize = 0;
    while (i + 2 <= name_utf16.len) : (i += 2) {
        const unit = std.mem.readInt(u16, name_utf16[i..][0..2], .little);
        if (unit == 0) break;
        var cp: u21 = unit;
        if (unit >= 0xD800 and unit <= 0xDBFF) {
            if (i + 4 > name_utf16.len) return error.InvalidData;
            const low = std.mem.readInt(u16, name_utf16[i + 2 ..][0..2], .little);
            if (low < 0xDC00 or low > 0xDFFF) return error.InvalidData;
            cp = 0x10000 + ((@as(u21, unit - 0xD800) << 10) | @as(u21, low - 0xDC00));
            i += 2;
        } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
            return error.InvalidData;
        }
        utf8_len += std.unicode.utf8CodepointSequenceLength(cp) catch return error.InvalidData;
    }
    const result = try workspace.take(u8, utf8_len);
    i = 0;
    var offset: usize = 0;
    while (i + 2 <= name_utf16.len) : (i += 2) {
        const unit = std.mem.readInt(u16, name_utf16[i..][0..2], .little);
        if (unit == 0) break;
        var cp: u21 = unit;
        if (unit >= 0xD800 and unit <= 0xDBFF) {
            const low = std.mem.readInt(u16, name_utf16[i + 2 ..][0..2], .little);
            cp = 0x10000 + ((@as(u21, unit - 0xD800) << 10) | @as(u21, low - 0xDC00));
            i += 2;
        }
        offset += std.unicode.utf8Encode(cp, result[offset..]) catch return error.InvalidData;
    }
    return result;
}

fn writeUtf16Name(writer: *std.Io.Writer, name: []const u8) Failure!void {
    const stripped = if (name.len > 0 and name[name.len - 1] == '/') name[0 .. name.len - 1] else name;
    const view = std.unicode.Utf8View.init(stripped) catch return error.InvalidData;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x10000) {
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, @intCast(cp), .little);
            try io.writeBytes(writer, &bytes);
        } else {
            const high: u16 = @intCast(0xD800 + ((cp - 0x10000) >> 10));
            const low: u16 = @intCast(0xDC00 + ((cp - 0x10000) & 0x3FF));
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u16, bytes[0..2], high, .little);
            std.mem.writeInt(u16, bytes[2..4], low, .little);
            try io.writeBytes(writer, &bytes);
        }
    }
    var zero: [2]u8 = .{0} ** 2;
    try io.writeBytes(writer, &zero);
}

fn passwordToUtf16(password: []const u8, workspace: *Workspace) Failure![]const u8 {
    const view = std.unicode.Utf8View.init(password) catch return error.InvalidData;
    var byte_len: usize = 0;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| byte_len = try bounds.add(byte_len, if (cp < 0x10000) 2 else 4);
    const bytes = try workspace.take(u8, byte_len);
    var offset: usize = 0;
    var encode_it = view.iterator();
    while (encode_it.nextCodepoint()) |cp| {
        if (cp < 0x10000) {
            std.mem.writeInt(u16, bytes[offset..][0..2], @intCast(cp), .little);
            offset += 2;
        } else {
            const high: u16 = @intCast(0xD800 + ((cp - 0x10000) >> 10));
            const low: u16 = @intCast(0xDC00 + ((cp - 0x10000) & 0x3FF));
            std.mem.writeInt(u16, bytes[offset..][0..2], high, .little);
            std.mem.writeInt(u16, bytes[offset + 2 ..][0..2], low, .little);
            offset += 4;
        }
    }
    return bytes;
}

fn writeBoolVector(writer: *std.Io.Writer, count: usize, ctx: anytype) Failure!void {
    if (count == 0) return;
    const all_false = blk: {
        var all = true;
        for (0..count) |i| if (ctx.get(i)) {
            all = false;
            break;
        };
        break :blk all;
    };
    if (all_false) {
        try io.writeBytes(writer, &.{0x00});
        return;
    }
    try io.writeBytes(writer, &.{0x01});
    var byte: u8 = 0;
    for (0..count) |i| {
        if (ctx.get(i)) byte |= @as(u8, 0x80) >> @intCast(i % 8);
        if ((i + 1) % 8 == 0 or i + 1 == count) {
            try io.writeBytes(writer, &.{byte});
            byte = 0;
        }
    }
}

fn writeBitVector(writer: *std.Io.Writer, count: usize, ctx: anytype) Failure!void {
    if (count == 0) return;
    var byte: u8 = 0;
    for (0..count) |i| {
        if (ctx.get(i)) byte |= @as(u8, 0x80) >> @intCast(i % 8);
        if ((i + 1) % 8 == 0 or i + 1 == count) {
            try io.writeBytes(writer, &.{byte});
            byte = 0;
        }
    }
}

fn readUint64(cursor: *binary.ReadCursor) Failure!u64 {
    const first = try cursor.readU8();
    if (first < 0x80) return first;
    if (first == 0xFF) {
        const bytes = try cursor.readBytes(8);
        return std.mem.readInt(u64, &bytes, .big);
    }
    if (first == 0xFE) {
        const bytes = try cursor.readBytes(7);
        var value: u64 = 0;
        for (bytes) |b| value = (value << 8) | b;
        return value;
    }
    var extra: usize = 1;
    var mask: u8 = 0x40;
    while ((first & mask) != 0 and extra < 7) : (extra += 1) mask >>= 1;
    const shift: u6 = @intCast(8 - extra);
    const payload: u64 = first & ((@as(u64, 1) << shift) - 1);
    const bytes = try cursor.readSlice(extra);
    var value: u64 = payload;
    for (bytes) |b| value = (value << 8) | b;
    return value;
}

fn writeUint64(writer: *std.Io.Writer, value: u64) Failure!void {
    if (value < 0x80) {
        try io.writeBytes(writer, &.{@intCast(value)});
        return;
    }
    var extra: usize = 1;
    while (extra < 8) : (extra += 1) {
        const payload_bits: u6 = @intCast(8 - extra);
        const max = ((@as(u64, 1) << payload_bits) - 1) << @intCast(8 * extra) | ((@as(u64, 1) << @intCast(8 * extra)) - 1);
        if (value <= max) break;
    }
    if (extra == 8) {
        try io.writeBytes(writer, &.{0xFF});
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        try io.writeBytes(writer, &bytes);
        return;
    }
    const pattern: u8 = @as(u8, 0xFF) << @intCast(8 - extra);
    const payload: u8 = @intCast(value >> @intCast(8 * extra));
    try io.writeBytes(writer, &.{pattern | payload});
    const remainder = value & ((@as(u64, 1) << @intCast(8 * extra)) - 1);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, remainder, .big);
    try io.writeBytes(writer, bytes[8 - extra .. 8]);
}
