const std = @import("std");

const binary = @import("../../../common/primitive/binary.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const crypto = @import("../../../common/primitive/crypto.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const limits_prim = @import("../../../common/primitive/limits.zig");
const measurement = @import("../../../common/primitive/measurement.zig");
const bcj = @import("../../leaf/bcj/onprem.zig");
const bcj2 = @import("../../leaf/bcj2/onprem.zig");
const bzip2 = @import("../../leaf/bzip2/onprem.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const deflate_seam = @import("../../leaf/deflate/seam.zig");
const delta = @import("../../leaf/delta/onprem.zig");
const lzma = @import("../../leaf/lzma/onprem.zig");
const lzma_seam = @import("../../leaf/lzma/seam.zig");
const lzma2 = @import("../../leaf/lzma2/onprem.zig");
const lzma2_seam = @import("../../leaf/lzma2/seam.zig");
const ppmd = @import("../../leaf/ppmd/onprem.zig");

const Exception = exception_prim.Exception;
const Workspace = io.Workspace;
const Limits = limits_prim.Limits;

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
    bcj2,
};

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
    method: CoderMethod = .copy,
    filters: []const CoderMethod = &.{},
    encrypted: bool = false,
    password: []const u8 = &.{},
    iv: [16]u8 = @splat(0),
    iv_set: bool = false,
    // KDF cost knob: 0 selects the default 2^19 rounds; 1..24 is written
    // verbatim. 0x3F direct-key mode is decode-only.
    num_cycles_power: u8 = 0,
    salt: [16]u8 = @splat(0),
    salt_length: u8 = 0,
    // KDF bomb defense: the default ceiling equals the format maximum
    // (seven_zip_cycles_max); std.math.maxInt(u64) opts into unbounded rounds.
    kdf_rounds_limit: u64 = 1 << 24,
    password_lifetime: u64 = 0,
};

pub const Info = struct {
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
    aes_iv: [16]u8 = @splat(0),
    aes_iv_size: u8 = 0,
    folder: ?*const Folder = null,
    substream_offset: u64 = 0,
    // The entry folder's packed-stream sizes (one, or four for BCJ2), indexing
    // the streams-info workspace slice.
    pack_stream_sizes: []const u64 = &.{},
};

pub const SevenZipDecodeOptions = struct {
    password: ?[]const u8 = null,
    // KDF bomb defense: the default ceiling equals the format maximum
    // (seven_zip_cycles_max); std.math.maxInt(u64) opts into unbounded rounds.
    kdf_rounds_limit: u64 = 1 << 24,
    password_lifetime: u64 = 0,
    failure_cause: *crypto.FailureCause,
    provider: crypto.Provider = crypto.default_provider,
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
const method_7z_bcj2_id = [4]u8{ 0x03, 0x03, 0x01, 0x1B };
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

// Every known method id, primaries first: methodId takes the first row;
// decode also accepts single-byte and 7z-bcj aliases.
const method_ids = [_]struct { method: CoderMethod, id: []const u8 }{
    .{ .method = .copy, .id = &method_copy_id },
    .{ .method = .lzma, .id = &method_lzma_id },
    .{ .method = .lzma2, .id = &method_lzma2_id },
    .{ .method = .deflate, .id = &method_deflate_id },
    .{ .method = .bzip2, .id = &method_bzip2_id },
    .{ .method = .delta, .id = &method_delta_id },
    .{ .method = .x86, .id = &method_7z_bcj_x86_id },
    .{ .method = .ppc, .id = &method_7z_bcj_ppc_id },
    .{ .method = .ia64, .id = &method_7z_bcj_ia64_id },
    .{ .method = .arm, .id = &method_7z_bcj_arm_id },
    .{ .method = .armt, .id = &method_7z_bcj_armt_id },
    .{ .method = .sparc, .id = &method_7z_bcj_sparc_id },
    .{ .method = .arm64, .id = &method_7z_bcj_arm64_id },
    .{ .method = .riscv, .id = &method_7z_bcj_riscv_id },
    .{ .method = .ppmd, .id = &method_ppmd_id },
    .{ .method = .bcj2, .id = &method_7z_bcj2_id },
    .{ .method = .x86, .id = &method_x86_id },
    .{ .method = .ppc, .id = &method_ppc_id },
    .{ .method = .ia64, .id = &method_ia64_id },
    .{ .method = .arm, .id = &method_arm_id },
    .{ .method = .armt, .id = &method_armt_id },
    .{ .method = .sparc, .id = &method_sparc_id },
    .{ .method = .arm64, .id = &method_arm64_id },
    .{ .method = .riscv, .id = &method_riscv_id },
};

fn methodId(method: CoderMethod) []const u8 {
    inline for (method_ids) |row| if (row.method == method) return row.id;
    unreachable;
}

fn methodFromId(id: []const u8) Exception!CoderMethod {
    inline for (method_ids) |row| if (std.mem.eql(u8, id, row.id)) return row.method;
    return error.UnsupportedException;
}

fn coderAttributeSize(method: CoderMethod) usize {
    return switch (method) {
        .copy, .deflate, .bzip2 => 0,
        .lzma => 5,
        .lzma2 => 1,
        .delta => 1,
        .ppmd => 5,
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv, .bcj2 => 0,
    };
}

const PackedEntry = struct {
    method: CoderMethod,
    data: []const u8,
    crc: u32,
    encrypted: bool = false,
    filters: []const CoderMethod = &.{},
    iv: [16]u8 = @splat(0),
    salt: [16]u8 = @splat(0),
    salt_length: u8 = 0,
    num_cycles_power: u8 = 0,
    // True when the entry rides a prior entry's solid-run stream;
    // buildFolderPlan keys on this to match the packed bytes.
    solid_continuation: bool = false,
    pack_size: usize = 0,
    unpack_size: usize = 0,
};

fn packBuffer(comptime codec: type, method: CoderMethod, input: []const u8, unpacked_crc: u32, workspace: *Workspace, limits: Limits, scratch_size: usize, options: codec.Options) Exception!PackedEntry {
    const scratch = try workspace.take(u8, scratch_size);
    const packed_size = try codec.requiredSize(input, scratch, options);
    if (packed_size > limits.encoded_bytes) return error.ResourceException;
    if (try bounds.addUsize(input.len, packed_size) > limits.codec_work) return error.ResourceException;
    const packed_data = try workspace.take(u8, packed_size);
    _ = try codec.encode(input, packed_data, scratch, options);
    return .{ .method = method, .data = packed_data, .crc = unpacked_crc, .pack_size = packed_size, .unpack_size = input.len };
}

fn packEntry(entry: Entry, provider: crypto.Provider, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Exception!PackedEntry {
    if (entry.encrypted) {
        if (entry.password.len == 0) return error.CallException;
        if (entry.num_cycles_power > crypto.seven_zip_cycles_max) return error.CallException;
        if (entry.salt_length > 16) return error.CallException;
        const cycles = if (entry.num_cycles_power == 0) crypto.seven_zip_default_cycles else entry.num_cycles_power;
        const rounds: u64 = @as(u64, 1) << @intCast(cycles);
        if (entry.kdf_rounds_limit != 0 and entry.kdf_rounds_limit < rounds) {
            failure_cause.* = .kdf_limit;
            return error.ResourceException;
        }
    }
    const unpacked_crc = checksum.crc32With(provider, entry.data);
    // Filter chains ride LZMA1/LZMA2 coders only; any other codec with an
    // explicit filter is a caller error.
    const source: []const u8 = if (entry.filters.len != 0) blk: {
        if (entry.method != .lzma and entry.method != .lzma2) return error.CallException;
        const filtered = try workspace.take(u8, entry.data.len);
        @memcpy(filtered, entry.data);
        for (entry.filters) |filter| try applyEncodeFilter(filter, filtered);
        break :blk filtered;
    } else entry.data;
    var compressed_entry = switch (entry.method) {
        .bcj2 => return error.CallException, // Decode-only; creation never emits BCJ2.
        .copy => blk: {
            if (source.len > limits.encoded_bytes) return error.ResourceException;
            if (source.len > limits.codec_work) return error.ResourceException;
            break :blk PackedEntry{ .method = .copy, .data = source, .crc = unpacked_crc, .pack_size = source.len, .unpack_size = source.len };
        },
        .deflate => blk: {
            const measure_history = try workspace.take(u8, deflate.history_size);
            var counter = measurement.Counter.init(null);
            var measure_compressor = deflate.Compress.init(&counter.writer, measure_history, default_deflate_options) catch return error.CapacityException;
            var measure_source = std.Io.Reader.fixed(source);
            _ = std.Io.Reader.streamRemaining(&measure_source, &measure_compressor.writer) catch return error.IoException;
            measure_compressor.finish() catch return error.IoException;
            const packed_size = std.math.cast(usize, counter.written()) orelse return error.ResourceException;
            if (packed_size > limits.encoded_bytes) return error.ResourceException;
            if (source.len + packed_size > limits.codec_work) return error.ResourceException;
            const packed_data = try workspace.take(u8, packed_size);
            const history = try workspace.take(u8, deflate.history_size);
            var fixed_writer = std.Io.Writer.fixed(packed_data);
            var compressor = deflate.Compress.init(&fixed_writer, history, default_deflate_options) catch return error.CapacityException;
            var entry_source = std.Io.Reader.fixed(source);
            _ = std.Io.Reader.streamRemaining(&entry_source, &compressor.writer) catch return error.IoException;
            compressor.finish() catch return error.IoException;
            break :blk PackedEntry{ .method = .deflate, .data = packed_data, .crc = unpacked_crc, .pack_size = packed_size, .unpack_size = source.len };
        },
        .bzip2 => try packBuffer(bzip2, .bzip2, source, unpacked_crc, workspace, limits, bzip2.encodeWorkspaceSize(default_bzip2_block), .{ .block_size = default_bzip2_block }),
        .lzma => blk: {
            const properties = lzma2.defaultProperties(default_dictionary);
            const options: lzma.Options = .{ .properties = properties, .unpack_size = source.len, .marker_required = false, .max_work = limits.codec_work };
            break :blk try packBuffer(lzma, .lzma, source, unpacked_crc, workspace, limits, lzma.encodeWorkspaceSizeBt(properties), options);
        },
        .lzma2 => blk: {
            const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
            break :blk try packBuffer(lzma2, .lzma2, source, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
        },
        .ppmd => blk: {
            const options: ppmd.Options = .{ .order = default_ppmd_order, .mem_size = default_ppmd_mem, .unpack_size = source.len, .max_work = limits.codec_work };
            break :blk try packBuffer(ppmd, .ppmd, source, unpacked_crc, workspace, limits, ppmd.encodeWorkspaceSize(default_ppmd_mem), options);
        },
        .delta, .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => blk: {
            const filtered = try workspace.take(u8, entry.data.len);
            @memcpy(filtered, entry.data);
            try applyEncodeFilter(entry.method, filtered);
            const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
            var packed_entry = try packBuffer(lzma2, .lzma2, filtered, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
            // The primary filter rides as a one-element chain so the folder
            // plan emits its coder; explicit chains require .lzma/.lzma2.
            const chain = try workspace.take(CoderMethod, 1);
            chain[0] = entry.method;
            packed_entry.filters = chain;
            break :blk packed_entry;
        },
    };
    if (entry.filters.len != 0) compressed_entry.filters = entry.filters;
    if (!entry.encrypted) return compressed_entry;
    const password_utf16 = try passwordToUtf16(entry.password, workspace);
    const cycles = if (entry.num_cycles_power == 0) crypto.seven_zip_default_cycles else entry.num_cycles_power;
    var key: [crypto.seven_zip_key_length]u8 = undefined;
    crypto.sevenZipKdf(provider, password_utf16, entry.salt[0..entry.salt_length], cycles, &key);
    const padded_size = std.mem.alignForward(usize, compressed_entry.data.len, crypto.block_length);
    if (entry.password_lifetime != 0 and padded_size > entry.password_lifetime) {
        failure_cause.* = .password_lifetime;
        return error.ResourceException;
    }
    const encrypted_data = try workspace.take(u8, padded_size);
    @memset(encrypted_data[compressed_entry.data.len..], 0);
    @memcpy(encrypted_data[0..compressed_entry.data.len], compressed_entry.data);
    var iv: [16]u8 = entry.iv;
    if (!entry.iv_set) {
        try crypto.fillRandom(&iv);
    }
    try crypto.aesCbcEncrypt(provider, &key, iv, encrypted_data, encrypted_data);
    return .{ .method = compressed_entry.method, .data = encrypted_data, .crc = compressed_entry.crc, .encrypted = true, .filters = compressed_entry.filters, .iv = iv, .salt = entry.salt, .salt_length = entry.salt_length, .num_cycles_power = cycles, .pack_size = compressed_entry.pack_size, .unpack_size = compressed_entry.unpack_size };
}

fn applyEncodeFilter(method: CoderMethod, data: []u8) Exception!void {
    switch (method) {
        .delta => delta.encode(data, 0),
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => bcj.encode(bcjKindFromMethod(method), 0, data),
        else => return error.CallException,
    }
}

fn packAllEntries(entries: []const Entry, provider: crypto.Provider, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Exception![]const PackedEntry {
    const packed_entries = try workspace.take(PackedEntry, nonEmptyCount(entries));
    var index: usize = 0;
    var i: usize = 0;
    while (i < entries.len) {
        if (isEmptyEntry(entries[i])) {
            i += 1;
            continue;
        }
        // Coder state carries across the run's substreams, as in 7-Zip's solid
        // folders. Filtered entries need their own pre-filter pass.
        if ((entries[i].method == .lzma2 or entries[i].method == .ppmd) and !entries[i].encrypted and entries[i].filters.len == 0) {
            var j = i + 1;
            while (j < entries.len and !isEmptyEntry(entries[j]) and entries[j].method == entries[i].method and !entries[j].encrypted and entries[j].filters.len == 0) j += 1;
            if (j - i >= 2) {
                var total: usize = 0;
                for (entries[i..j]) |entry| total = try bounds.addUsize(total, entry.data.len);
                if (total > limits.codec_work) return error.ResourceException;
                const concat = try workspace.take(u8, total);
                var offset: usize = 0;
                for (entries[i..j]) |entry| {
                    @memcpy(concat[offset..][0..entry.data.len], entry.data);
                    offset += entry.data.len;
                }
                const scratch_size: usize = switch (entries[i].method) {
                    .lzma2 => lzma2.encodeWorkspaceSizeBt(default_dictionary),
                    .ppmd => ppmd.encodeWorkspaceSize(default_ppmd_mem),
                    else => unreachable,
                };
                const scratch = try workspace.take(u8, scratch_size);
                const packed_size = switch (entries[i].method) {
                    .lzma2 => blk: {
                        const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
                        break :blk try lzma2.requiredSize(concat, scratch, options);
                    },
                    .ppmd => blk: {
                        const options: ppmd.Options = .{ .order = default_ppmd_order, .mem_size = default_ppmd_mem, .unpack_size = total, .max_work = limits.codec_work };
                        break :blk try ppmd.requiredSize(concat, scratch, options);
                    },
                    else => unreachable,
                };
                if (packed_size > limits.encoded_bytes) return error.ResourceException;
                if (try bounds.addUsize(total, packed_size) > limits.codec_work) return error.ResourceException;
                const packed_data = try workspace.take(u8, packed_size);
                switch (entries[i].method) {
                    .lzma2 => {
                        const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
                        _ = try lzma2.encode(concat, packed_data, scratch, options);
                    },
                    .ppmd => {
                        const options: ppmd.Options = .{ .order = default_ppmd_order, .mem_size = default_ppmd_mem, .unpack_size = total, .max_work = limits.codec_work };
                        _ = try ppmd.encode(concat, packed_data, scratch, options);
                    },
                    else => unreachable,
                }
                for (entries[i..j], 0..) |entry, run_index| {
                    packed_entries[index] = .{ .method = entries[i].method, .data = if (run_index == 0) packed_data else &.{}, .crc = checksum.crc32With(provider, entry.data), .solid_continuation = run_index != 0, .pack_size = packed_size, .unpack_size = entry.data.len };
                    index += 1;
                }
                i = j;
                continue;
            }
        }
        packed_entries[index] = try packEntry(entries[i], provider, workspace, limits, failure_cause);
        index += 1;
        i += 1;
    }
    return packed_entries[0..index];
}

pub fn sevenZipPack(entries: []const Entry, provider: crypto.Provider, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Exception![]const PackedEntry {
    failure_cause.* = .none;
    return try packAllEntries(entries, provider, workspace, limits, failure_cause);
}

fn requiredSizeFromPacked(entries: []const Entry, packed_entries: []const PackedEntry, workspace: *Workspace, provider: crypto.Provider, limits: Limits, header_options: SevenZipHeaderOptions) Exception!usize {
    var total_pack_size: usize = 0;
    const plan = try buildFolderPlan(packed_entries, workspace);
    for (plan) |folder| total_pack_size = try bounds.addUsize(total_pack_size, packed_entries[folder.first].data.len);
    const header = try encodeHeaderBytes(entries, packed_entries, workspace, provider, limits, header_options);
    var counter = measurement.Counter.init(null);
    try writeNextHeader(&counter.writer, &header, total_pack_size);
    const header_struct_size = try measurement.measuredLength(&counter);
    const packs_and_header = try bounds.addUsize(total_pack_size, header.pack_size);
    const total = try bounds.addUsize(start_header_size, try bounds.addUsize(packs_and_header, header_struct_size));
    return std.math.cast(usize, total) orelse error.ResourceException;
}

pub fn sevenZipPackedSize(entries: []const Entry, packed_entries: []const PackedEntry, workspace: *Workspace, provider: crypto.Provider, limits: Limits, header_options: SevenZipHeaderOptions) Exception!usize {
    return try requiredSizeFromPacked(entries, packed_entries, workspace, provider, limits, header_options);
}

// The reference reader rejects an encrypted compressed header (AES+LZMA),
// so composition never emits it even though it is spec-legal.
pub const SevenZipHeaderOptions = struct {
    compress: bool = false,
    encrypt: bool = false,
    password: []const u8 = &.{},
    // 0 selects the default 2^19 rounds, otherwise the power is written
    // verbatim (1..24), matching the file-data knob.
    num_cycles_power: u8 = 0,
    // KDF bomb defense: the default ceiling equals the format maximum
    // (seven_zip_cycles_max); std.math.maxInt(u64) opts into unbounded rounds.
    kdf_rounds_limit: u64 = 1 << 24,
    password_lifetime: u64 = 0,
    failure_cause: ?*crypto.FailureCause = null,
};

// The prepared next-header: `stored` is what the start header addresses;
// `pack` is the compressed/encrypted stream placed just before it.
const HeaderEncode = struct {
    stored: []const u8 = &.{},
    pack: []const u8 = &.{},
    pack_size: usize = 0,
    unpack_size: usize = 0,
    encrypted: bool = false,
    compressed: bool = false,
    cycles: u8 = 0,
    iv: [16]u8 = @splat(0),
    pack_crc: u32 = 0,
    unpack_crc: u32 = 0,
    encoded: bool = false,
};

fn encryptHeaderBytes(cleartext: []const u8, workspace: *Workspace, provider: crypto.Provider, header_options: SevenZipHeaderOptions) Exception!struct { data: []const u8, cycles: u8, iv: [16]u8 } {
    if (header_options.password.len == 0) return error.CallException;
    if (header_options.num_cycles_power > crypto.seven_zip_cycles_max) return error.CallException;
    const cycles = if (header_options.num_cycles_power == 0) crypto.seven_zip_default_cycles else header_options.num_cycles_power;
    const rounds: u64 = @as(u64, 1) << @intCast(cycles);
    if (header_options.kdf_rounds_limit != 0 and header_options.kdf_rounds_limit < rounds) {
        if (header_options.failure_cause) |cause| cause.* = .kdf_limit;
        return error.ResourceException;
    }
    const password_utf16 = try passwordToUtf16(header_options.password, workspace);
    var key: [crypto.seven_zip_key_length]u8 = undefined;
    crypto.sevenZipKdf(provider, password_utf16, &.{}, cycles, &key);
    const padded_size = std.mem.alignForward(usize, cleartext.len, crypto.block_length);
    if (header_options.password_lifetime != 0 and padded_size > header_options.password_lifetime) {
        if (header_options.failure_cause) |cause| cause.* = .password_lifetime;
        return error.ResourceException;
    }
    const encrypted_data = try workspace.take(u8, padded_size);
    @memset(encrypted_data[cleartext.len..], 0);
    @memcpy(encrypted_data[0..cleartext.len], cleartext);
    var iv: [16]u8 = undefined;
    try crypto.fillRandom(&iv);
    try crypto.aesCbcEncrypt(provider, &key, iv, encrypted_data, encrypted_data);
    return .{ .data = encrypted_data, .cycles = cycles, .iv = iv };
}

fn encodeHeaderBytes(entries: []const Entry, packed_entries: []const PackedEntry, workspace: *Workspace, provider: crypto.Provider, limits: Limits, header_options: SevenZipHeaderOptions) Exception!HeaderEncode {
    var counter = measurement.Counter.init(null);
    try writeHeader(&counter.writer, entries, packed_entries, workspace);
    const header_size = try measurement.measuredLength(&counter);
    const header_bytes = try workspace.take(u8, header_size);
    var fixed = std.Io.Writer.fixed(header_bytes);
    try writeHeader(&fixed, entries, packed_entries, workspace);
    const unpack_crc = checksum.crc32With(provider, header_bytes);
    if (!header_options.compress and !header_options.encrypt) {
        return .{ .stored = header_bytes, .unpack_size = header_size, .unpack_crc = unpack_crc };
    }
    if (header_options.encrypt and !header_options.compress) {
        // The -mhe shape: one AES coder over the stored header; the recorded
        // unpack size is the unpadded header size.
        const encrypted = try encryptHeaderBytes(header_bytes, workspace, provider, header_options);
        return .{
            .pack = encrypted.data,
            .pack_size = encrypted.data.len,
            .unpack_size = header_size,
            .encrypted = true,
            .cycles = encrypted.cycles,
            .iv = encrypted.iv,
            .pack_crc = checksum.crc32With(provider, encrypted.data),
            .unpack_crc = unpack_crc,
            .encoded = true,
        };
    }
    const properties = lzma2.defaultProperties(default_dictionary);
    const lzma_options: lzma.Options = .{ .properties = properties, .unpack_size = header_size, .marker_required = false, .max_work = limits.codec_work };
    const scratch = try workspace.take(u8, lzma.encodeWorkspaceSizeBt(properties));
    const packed_size = try lzma.requiredSize(header_bytes, scratch, lzma_options);
    const compressed = try workspace.take(u8, packed_size);
    _ = try lzma.encode(header_bytes, compressed, scratch, lzma_options);
    if (!header_options.encrypt) {
        return .{
            .pack = compressed,
            .pack_size = compressed.len,
            .unpack_size = header_size,
            .compressed = true,
            .pack_crc = checksum.crc32With(provider, compressed),
            .unpack_crc = unpack_crc,
            .encoded = true,
        };
    }
    const encrypted = try encryptHeaderBytes(compressed, workspace, provider, header_options);
    return .{
        .pack = encrypted.data,
        .pack_size = encrypted.data.len,
        .unpack_size = header_size,
        .encrypted = true,
        .compressed = true,
        .cycles = encrypted.cycles,
        .iv = encrypted.iv,
        .pack_crc = checksum.crc32With(provider, encrypted.data),
        .unpack_crc = unpack_crc,
        .encoded = true,
    };
}

// Writes the raw next-header, or the kEncodedHeader structure naming the
// header stream's offset past the data pack streams.
fn writeNextHeader(writer: *std.Io.Writer, header: *const HeaderEncode, pack_offset: u64) Exception!void {
    if (!header.encoded) {
        try io.writeBytes(writer, header.stored);
        return;
    }
    try io.writeBytes(writer, &.{k_encoded_header});
    try io.writeBytes(writer, &.{0x06});
    try writeUint64(writer, pack_offset);
    try writeUint64(writer, 1);
    try io.writeBytes(writer, &.{0x09});
    try writeUint64(writer, header.pack_size);
    try io.writeBytes(writer, &.{0x00});
    try io.writeBytes(writer, &.{0x07});
    try io.writeBytes(writer, &.{0x0B});
    try writeUint64(writer, 1);
    try io.writeBytes(writer, &.{0x00});
    const num_coders: usize = @as(usize, if (header.encrypted) 1 else 0) + @as(usize, if (header.compressed) 1 else 0);
    try writeUint64(writer, num_coders);
    if (header.encrypted) {
        const aes_flags: u8 = @as(u8, @intCast(method_7z_aes_id.len)) | 0x20;
        try io.writeBytes(writer, &.{aes_flags});
        try io.writeBytes(writer, &method_7z_aes_id);
        const iv_size: usize = 16;
        // The size halves are 1-bit high plus 4-bit low summing to the size:
        // 16 is high=1 low=15 (see parse7zAesProps).
        const iv_high: u8 = @intCast(iv_size >> 4);
        var props: [2 + 16]u8 = undefined;
        props[0] = header.cycles | (iv_high << 6);
        props[1] = @as(u8, @intCast(iv_size - iv_high));
        @memcpy(props[2..][0..iv_size], &header.iv);
        try writeUint64(writer, 2 + iv_size);
        try io.writeBytes(writer, props[0 .. 2 + iv_size]);
    }
    if (header.compressed) try writeFolderCoder(writer, .lzma, header.unpack_crc);
    if (header.encrypted and header.compressed) {
        try writeUint64(writer, 1);
        try writeUint64(writer, 0);
    }
    try io.writeBytes(writer, &.{0x0C});
    // A lone AES coder records the real header size; the reader strips
    // the padding.
    //
    // An AES coder feeding a compressor records its padded output, as in
    // file-data folders.
    if (header.encrypted and header.compressed) try writeUint64(writer, header.pack_size);
    try writeUint64(writer, header.unpack_size);
    try io.writeBytes(writer, &.{0x0A});
    try io.writeBytes(writer, &.{0x01});
    var unpack_digest: [4]u8 = undefined;
    std.mem.writeInt(u32, &unpack_digest, header.unpack_crc, .little);
    try io.writeBytes(writer, &unpack_digest);
    try io.writeBytes(writer, &.{0x00});
    try io.writeBytes(writer, &.{0x00});
}

fn writeArchive(output: []u8, entries: []const Entry, packed_entries: []const PackedEntry, workspace: *Workspace, provider: crypto.Provider, limits: Limits, header_options: SevenZipHeaderOptions) Exception!usize {
    const required = try requiredSizeFromPacked(entries, packed_entries, workspace, provider, limits, header_options);
    if (output.len < required) return error.CapacityException;
    var total_pack_size: usize = 0;
    const plan = try buildFolderPlan(packed_entries, workspace);
    for (plan) |folder| total_pack_size = try bounds.addUsize(total_pack_size, packed_entries[folder.first].data.len);
    const header = try encodeHeaderBytes(entries, packed_entries, workspace, provider, limits, header_options);
    const header_offset = start_header_size + total_pack_size + header.pack_size;
    var header_writer = std.Io.Writer.fixed(output[header_offset..]);
    try writeNextHeader(&header_writer, &header, total_pack_size);
    const header_size = header_writer.end;
    const header_crc = checksum.crc32With(provider, output[header_offset..][0..header_size]);
    var start_header: [20]u8 = undefined;
    std.mem.writeInt(u64, start_header[0..8], total_pack_size + header.pack_size, .little);
    std.mem.writeInt(u64, start_header[8..16], header_size, .little);
    std.mem.writeInt(u32, start_header[16..20], header_crc, .little);
    const start_header_crc = checksum.crc32With(provider, &start_header);
    var sink = io.Sink{ .bytes = output[0..required] };
    try sink.write(&signature);
    try sink.write(&version);
    try sink.writeInt(u32, start_header_crc, .little);
    try sink.write(&start_header);
    for (plan) |folder| {
        try sink.write(packed_entries[folder.first].data);
    }
    try sink.write(header.pack);
    return required;
}

pub const VolumeLayout = struct {
    total_len: usize,
    volumes: u64,
};

// Volume 1 carries the signature header; splitting at volume_size boundaries
// matches 7zz -v, so volumes need no extra encoding.
pub fn sevenZipVolumeExtents(total_len: usize, volume_size: u64) Exception!VolumeLayout {
    if (volume_size <= start_header_size) return error.CallException;
    if (total_len == 0) return error.DataException;
    const first_data = volume_size - start_header_size;
    if (total_len <= start_header_size + first_data) {
        return .{ .total_len = total_len, .volumes = 1 };
    }
    const rest = total_len - start_header_size - first_data;
    const later = (rest + volume_size - 1) / volume_size;
    return .{ .total_len = total_len, .volumes = 1 + later };
}

pub fn sevenZipWritePackedVolumes(entries: []const Entry, packed_entries: []const PackedEntry, output: []u8, volume_size: u64, workspace: *Workspace, provider: crypto.Provider, limits: Limits, header_options: SevenZipHeaderOptions) Exception!VolumeLayout {
    const total = try writeArchive(output, entries, packed_entries, workspace, provider, limits, header_options);
    return try sevenZipVolumeExtents(total, volume_size);
}

// Concatenates the volume payloads behind volume 1's start header, then runs
// the single-volume loader over the result.
pub fn sevenZipDecodeVolumes(volumes: []const []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, output: []u8, decode_options: SevenZipDecodeOptions) Exception!usize {
    if (volumes.len == 0) return error.DataException;
    decode_options.failure_cause.* = .none;
    var total: usize = 0;
    for (volumes, 0..) |volume, i| {
        if (volume.len < start_header_size and i == 0) return error.DataException;
        const payload = if (i == 0) volume[start_header_size..] else volume;
        total = try bounds.addUsize(total, payload.len);
        if (total > limits.encoded_bytes) return error.ResourceException;
    }
    // The joined payload follows volume 1's start header; materialize one
    // contiguous stream so the loader's offsets line up.
    const first = volumes[0];
    const full = try workspace.take(u8, start_header_size + total);
    @memcpy(full[0..start_header_size], first[0..start_header_size]);
    var at: usize = start_header_size;
    for (volumes, 0..) |volume, i| {
        const payload = if (i == 0) volume[start_header_size..] else volume;
        @memcpy(full[at..][0..payload.len], payload);
        at += payload.len;
    }
    return try sevenZipDecodeOrdinal(full, workspace, limits, ordinal, output, decode_options);
}

pub fn sevenZipWritePacked(entries: []const Entry, packed_entries: []const PackedEntry, output: []u8, workspace: *Workspace, provider: crypto.Provider, limits: Limits, header_options: SevenZipHeaderOptions) Exception!usize {
    return try writeArchive(output, entries, packed_entries, workspace, provider, limits, header_options);
}

pub fn sevenZipInspectCountEx(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, options: *const SevenZipLoadOptions) Exception!u64 {
    const loaded = try loadArchive(archive_bytes, workspace, limits, options);
    return loaded.count;
}

pub fn sevenZipInspectOrdinal(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, provider: crypto.Provider) Exception!Info {
    var cause: crypto.FailureCause = .none;
    const options: SevenZipLoadOptions = .{ .failure_cause = &cause, .provider = provider };
    return try sevenZipInspectOrdinalEx(archive_bytes, workspace, limits, ordinal, &options);
}

pub fn sevenZipInspectOrdinalEx(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, options: *const SevenZipLoadOptions) Exception!Info {
    const loaded = try loadArchive(archive_bytes, workspace, limits, options);
    if (ordinal >= loaded.count) return error.DataException;
    return loaded.entries[std.math.cast(usize, ordinal) orelse return error.DataException];
}

pub fn sevenZipDecodeOrdinal(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, output: []u8, decode_options: SevenZipDecodeOptions) Exception!usize {
    decode_options.failure_cause.* = .none;
    const load_options: SevenZipLoadOptions = .{
        .password = decode_options.password,
        .kdf_rounds_limit = decode_options.kdf_rounds_limit,
        .password_lifetime = decode_options.password_lifetime,
        .failure_cause = decode_options.failure_cause,
        .provider = decode_options.provider,
    };
    const loaded = try loadArchive(archive_bytes, workspace, limits, &load_options);
    if (ordinal >= loaded.count) return error.DataException;
    const entry = loaded.entries[std.math.cast(usize, ordinal) orelse return error.DataException];
    const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;
    if (size == 0) return 0;
    var decode_output = output;
    var decode_target_len = size;
    if (entry.folder) |folder| {
        if (folder.num_substreams > 1) {
            const total_size = try folderOutputSize(folder);
            if (total_size > limits.decoded_bytes) return error.ResourceException;
            decode_output = try workspace.take(u8, total_size);
            decode_target_len = total_size;
        }
    }
    const pack_size = std.math.cast(usize, entry.pack_size) orelse return error.ResourceException;
    const packed_data = try workspace.take(u8, pack_size);
    try readAt(loaded.data, entry.data_offset, packed_data);
    const decrypted_packed = try aesDecryptStream(entry.encrypted, entry.aes_num_cycles, entry.aes_salt, entry.aes_iv, packed_data, workspace, &load_options);
    switch (entry.method) {
        .copy => {
            if (decrypted_packed.len != decode_target_len and !entry.encrypted) return error.DataException;
            if (decrypted_packed.len < decode_target_len) return error.DataException;
            @memcpy(decode_output[0..decode_target_len], decrypted_packed[0..decode_target_len]);
        },
        .deflate => {
            const history = try workspace.take(u8, deflate.history_size);
            var source_reader = std.Io.Reader.fixed(decrypted_packed);
            var dest_writer = std.Io.Writer.fixed(decode_output);
            var inflater = deflate_seam.Decode.initBound(decode_options.provider, &source_reader, history) catch return error.UnsupportedException;
            _ = inflater.readerPtr().streamRemaining(&dest_writer) catch return error.DataException;
            if (dest_writer.end != decode_target_len) return error.DataException;
        },
        .bzip2 => {
            const scratch_size = try bzip2.decodeWorkspaceSizeFor(decrypted_packed);
            const scratch = try workspace.take(u8, scratch_size);
            const decoded = try bzip2.decode(decrypted_packed, decode_output, scratch, decode_options.provider);
            if (decoded != decode_target_len) return error.DataException;
        },
        .lzma => {
            const properties = try parseLzmaProperties(entry.attributes);
            const options: lzma.Options = .{ .properties = properties, .unpack_size = decode_target_len, .marker_required = false, .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(properties));
            const decoded = try lzma_seam.decode(decode_options.provider, decrypted_packed, decode_output, scratch, options);
            if (decoded != decode_target_len) return error.DataException;
        },
        .lzma2 => {
            const dictionary = lzma2.dictionarySizeFromProperties(try readLzma2Prop(entry.attributes));
            if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.UnsupportedException;
            const options: lzma2.Options = .{ .dictionary_size = dictionary, .properties = lzma2.defaultProperties(dictionary), .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma2.decodeWorkspaceSize(dictionary));
            const decoded = try lzma2_seam.decode(decode_options.provider, decrypted_packed, decode_output, scratch, options);
            if (decoded != decode_target_len) return error.DataException;
        },
        .ppmd => {
            const options = try parsePpmdOptions(entry.attributes, decode_target_len, limits.codec_work);
            const scratch = try workspace.take(u8, ppmd.decodeWorkspaceSize(options.mem_size));
            const decoded = try ppmd.decode(decrypted_packed, decode_output, scratch, options);
            if (decoded != decode_target_len) return error.DataException;
        },
        .bcj2 => {
            const folder = entry.folder orelse return error.DataException;
            const written = try decodeBcj2Folder(folder, entry.pack_stream_sizes, decrypted_packed, decode_output[0..decode_target_len], workspace, limits, decode_options.provider);
            if (written != decode_target_len) return error.DataException;
        },
        else => return error.UnsupportedException,
    }
    if (entry.folder) |folder| {
        try applyFolderFilters(folder.coders, decode_output[0..decode_target_len]);
        if (folder.num_substreams > 1) {
            const offset = std.math.cast(usize, entry.substream_offset) orelse return error.ResourceException;
            if (offset + size > decode_target_len) return error.DataException;
            @memcpy(output[0..size], decode_output[offset..][0..size]);
        }
    }
    if (entry.crc) |expected| {
        if (checksum.crc32With(decode_options.provider, output[0..size]) != expected) return error.IntegrityException;
    }
    return size;
}

fn readLzma2Prop(attributes: []const u8) Exception!u8 {
    if (attributes.len != 1) return error.DataException;
    return attributes[0];
}

// Recombines a BCJ2 folder: each input is a raw packed stream or a decoded
// coder output, per `folder.bcj2_sources`.
fn decodeBcj2Folder(folder: *const Folder, pack_sizes: []const u64, packed_data: []const u8, output: []u8, workspace: *Workspace, limits: Limits, provider: lzma2_seam.Provider) Exception!usize {
    if (!folder.bcj2 or pack_sizes.len != 4) return error.DataException;
    var packed_offset: usize = 0;
    var packed_slices: [4][]const u8 = undefined;
    for (0..4) |k| {
        const size = std.math.cast(usize, pack_sizes[k]) orelse return error.ResourceException;
        packed_offset = try bounds.addUsize(packed_offset, size);
        if (packed_offset > packed_data.len) return error.DataException;
        packed_slices[k] = packed_data[packed_offset - size .. packed_offset];
    }
    var substreams: [4][]const u8 = undefined;
    for (0..4) |k| {
        const source = folder.bcj2_sources[k];
        const ordinal = std.math.cast(usize, source.pack_ordinal) orelse return error.ResourceException;
        if (ordinal >= 4) return error.DataException;
        const slice = packed_slices[ordinal];
        if (source.producer) |coder_index| {
            if (coder_index >= folder.coders.len) return error.DataException;
            substreams[k] = try decodeBcj2Substream(folder.coders[coder_index], slice, workspace, limits, provider);
        } else {
            substreams[k] = slice;
        }
    }
    return bcj2.decode(substreams[0], substreams[1], substreams[2], substreams[3], output);
}

fn decodeBcj2Substream(coder: ParsedCoder, packed_data: []const u8, workspace: *Workspace, limits: Limits, provider: lzma2_seam.Provider) Exception![]const u8 {
    switch (coder.method) {
        .copy => return packed_data,
        .lzma2 => {
            const dictionary = lzma2.dictionarySizeFromProperties(try readLzma2Prop(coder.attributes));
            if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.UnsupportedException;
            const options: lzma2.Options = .{ .dictionary_size = dictionary, .properties = lzma2.defaultProperties(dictionary), .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma2.decodeWorkspaceSize(dictionary));
            const decoded_size = try lzma2_seam.decodedSize(provider, packed_data, scratch, options);
            if (decoded_size > limits.decoded_bytes) return error.ResourceException;
            const buffer = try workspace.take(u8, decoded_size);
            const decoded = try lzma2_seam.decode(provider, packed_data, buffer, scratch, options);
            return buffer[0..decoded];
        },
        else => return error.UnsupportedException,
    }
}

fn parsePpmdOptions(attributes: []const u8, unpack_size: usize, codec_work: u64) Exception!ppmd.Options {
    if (attributes.len != 5) return error.DataException;
    const mem_size = std.mem.readInt(u32, attributes[1..5], .little);
    return .{
        .order = attributes[0],
        .mem_size = mem_size,
        .unpack_size = unpack_size,
        .max_work = codec_work,
    };
}

fn parseLzmaProperties(attributes: []const u8) Exception!lzma.Properties {
    if (attributes.len != 5) return error.DataException;
    const props_byte = attributes[0];
    var dictionary: u32 = 0;
    for (0..4) |i| dictionary |= @as(u32, attributes[1 + i]) << @intCast(8 * i);
    if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.UnsupportedException;
    return try lzma.Properties.decode(props_byte, dictionary);
}

fn applyFolderFilters(coders: []const ParsedCoder, data: []u8) Exception!void {
    var filters: [4]ParsedCoder = undefined;
    var filter_count: usize = 0;
    for (coders) |coder| {
        if (isFilterMethod(coder.method)) {
            if (filter_count >= filters.len) return error.UnsupportedException;
            filters[filter_count] = coder;
            filter_count += 1;
        }
    }
    for (filters[0..filter_count]) |coder| {
        switch (coder.method) {
            .delta => {
                if (coder.attributes.len != 1) return error.DataException;
                delta.decode(data, coder.attributes[0]);
            },
            .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => {
                const start_offset: u32 = if (coder.attributes.len == 0) 0 else if (coder.attributes.len == 4)
                    std.mem.readInt(u32, coder.attributes[0..4], .little)
                else
                    return error.DataException;
                const kind = bcjKindFromMethod(coder.method);
                if (start_offset % bcj.alignment(kind) != 0) return error.DataException;
                bcj.decode(kind, start_offset, data);
            },
            else => return error.InternalException,
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
    // Maps a 7z coder to the leaf kind that applies its filter.
    return switch (method) {
        .x86 => bcj.fromId(method_x86_id[0]).?,
        .ppc => bcj.fromId(method_ppc_id[0]).?,
        .ia64 => bcj.fromId(method_ia64_id[0]).?,
        .arm => bcj.fromId(method_arm_id[0]).?,
        .armt => bcj.fromId(method_armt_id[0]).?,
        .sparc => bcj.fromId(method_sparc_id[0]).?,
        .arm64 => bcj.fromId(method_arm64_id[0]).?,
        .riscv => bcj.fromId(method_riscv_id[0]).?,
        else => unreachable,
    };
}

const LoadedArchive = struct {
    data: []const u8,
    count: u64,
    entries: []const Info,
};

fn readAt(data: []const u8, offset: u64, buffer: []u8) Exception!void {
    const start = std.math.cast(usize, offset) orelse return error.DataException;
    const end = try bounds.addUsize(start, buffer.len);
    if (end > data.len) return error.DataException;
    @memcpy(buffer, data[start..end]);
}

// Options for the archive-level load (inspect and decode paths share it): the
// password channel serves both file-data and encoded-header decryption.
pub const SevenZipLoadOptions = struct {
    password: ?[]const u8 = null,
    // KDF bomb defense: the default ceiling equals the format maximum
    // (seven_zip_cycles_max); std.math.maxInt(u64) opts into unbounded rounds.
    kdf_rounds_limit: u64 = 1 << 24,
    password_lifetime: u64 = 0,
    failure_cause: *crypto.FailureCause,
    provider: crypto.Provider = crypto.default_provider,
};

const k_header: u8 = 0x01;
const k_encoded_header: u8 = 0x17;

fn loadArchive(data: []const u8, workspace: *Workspace, limits: Limits, options: *const SevenZipLoadOptions) Exception!LoadedArchive {
    if (data.len > limits.encoded_bytes) return error.ResourceException;
    var archive: LoadedArchive = .{
        .data = data,
        .count = 0,
        .entries = &.{},
    };
    var start_buffer: [start_header_size]u8 = undefined;
    try readAt(data, 0, &start_buffer);
    if (!std.mem.eql(u8, start_buffer[0..6], &signature)) return error.DataException;
    if (!std.mem.eql(u8, start_buffer[6..8], &version)) return error.UnsupportedException;
    const recorded_start_crc = std.mem.readInt(u32, start_buffer[8..12], .little);
    const start_header_crc = checksum.crc32With(options.provider, start_buffer[12..32]);
    if (recorded_start_crc != start_header_crc) return error.IntegrityException;
    const next_header_offset = std.mem.readInt(u64, start_buffer[12..20], .little);
    const next_header_size = std.mem.readInt(u64, start_buffer[20..28], .little);
    const recorded_header_crc = std.mem.readInt(u32, start_buffer[28..32], .little);
    if (next_header_size > limits.metadata_records) return error.ResourceException;
    const header_start = try bounds.addU64(start_header_size, next_header_offset);
    const header_size_usize = std.math.cast(usize, next_header_size) orelse return error.ResourceException;
    const header_buffer = try workspace.take(u8, header_size_usize);
    try readAt(archive.data, header_start, header_buffer);
    if (checksum.crc32With(options.provider, header_buffer) != recorded_header_crc) return error.IntegrityException;
    var header_bytes: []const u8 = header_buffer;
    var cursor = binary.ReadCursor.init(header_bytes);
    const header_id = try cursor.readU8();
    if (header_id == k_encoded_header) {
        header_bytes = try decodeEncodedHeader(data, &cursor, workspace, limits, options);
        cursor = binary.ReadCursor.init(header_bytes);
        if (try cursor.readU8() != k_header) return error.DataException;
    } else if (header_id != k_header) {
        return error.UnsupportedException;
    }
    var streams: ?StreamsInfo = null;
    var files: ?FilesInfo = null;
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        switch (id) {
            0x04 => streams = try parseStreamsInfo(&cursor, workspace, false),
            0x05 => files = try parseFilesInfo(&cursor, workspace),
            0x02 => try skipArchiveProperties(&cursor),
            else => return error.UnsupportedException,
        }
    }
    const si = streams orelse return error.DataException;
    const fi = files orelse return error.DataException;
    archive.entries = try buildEntries(&si, &fi, workspace, limits);
    archive.count = archive.entries.len;
    return archive;
}

// kEncodedHeader (0x17) wraps the header in a one-folder packed stream,
// optionally AES-encrypted; the decoded bytes parse as an ordinary kHeader.
fn decodeEncodedHeader(archive_data: []const u8, cursor: *binary.ReadCursor, workspace: *Workspace, limits: Limits, options: *const SevenZipLoadOptions) Exception![]const u8 {
    // The StreamsInfo, ending in kEnd per 7zOut.cpp's writer, is the whole
    // structure: nothing may follow.
    const si = try parseStreamsInfo(cursor, workspace, true);
    if (cursor.remaining() != 0) return error.DataException;
    if (si.folders.len != 1) return error.UnsupportedException;
    const folder = &si.folders[0];
    if (folder.bcj2) return error.UnsupportedException;
    if (folder.num_pack_streams != 1 or si.pack_sizes.len != 1) return error.UnsupportedException;
    for (folder.coders) |coder| {
        if (isFilterMethod(coder.method)) return error.UnsupportedException;
    }
    const unpack_size = std.math.cast(usize, folder.unpack_size) orelse return error.ResourceException;
    if (unpack_size == 0) return error.DataException;
    if (unpack_size > limits.metadata_records) return error.ResourceException;
    const pack_size = std.math.cast(usize, si.pack_sizes[0]) orelse return error.ResourceException;
    if (pack_size > limits.encoded_bytes) return error.ResourceException;
    const pack_pos = std.math.cast(usize, si.pack_pos) orelse return error.ResourceException;
    const packed_data = try workspace.take(u8, pack_size);
    try readAt(archive_data, try bounds.addUsize(start_header_size, pack_pos), packed_data);
    if (si.pack_crcs.len == 1) {
        if (si.pack_crcs[0]) |expected| {
            if (checksum.crc32With(options.provider, packed_data) != expected) return error.IntegrityException;
        }
    }
    const output = try workspace.take(u8, unpack_size);
    decodeFolderStream(folder, packed_data, output, workspace, limits, options) catch |err| {
        // An encrypted-folder failure usually means a wrong password; keep
        // causes already set; leave limit and data refusals unlabeled.
        if (folder.encrypted and options.failure_cause.* == .none) options.failure_cause.* = .wrong_password;
        return err;
    };
    // The UnpackInfo folder CRC and any SubStreamsInfo digest must each match
    // the decoded header bytes (vendor 7zIn.cpp).
    if (folder.folder_crc) |expected| {
        if (checksum.crc32With(options.provider, output) != expected) {
            if (folder.encrypted) options.failure_cause.* = .wrong_password;
            return error.IntegrityException;
        }
    }
    if (folder.substream_crcs.len == 1) {
        if (folder.substream_crcs[0]) |expected| {
            if (checksum.crc32With(options.provider, output) != expected) {
                if (folder.encrypted) options.failure_cause.* = .wrong_password;
                return error.IntegrityException;
            }
        }
    }
    return output;
}

// Decrypts and decodes one packed stream into caller-sized output; serves the
// encoded-header path and every header form through it.
fn decodeFolderStream(folder: *const Folder, packed_data: []const u8, output: []u8, workspace: *Workspace, limits: Limits, options: *const SevenZipLoadOptions) Exception!void {
    const decrypted = try aesDecryptFolder(folder, packed_data, workspace, options);
    switch (folder.method) {
        .copy => {
            if (decrypted.len < output.len) return error.DataException;
            @memcpy(output, decrypted[0..output.len]);
        },
        .deflate => {
            const history = try workspace.take(u8, deflate.history_size);
            var source_reader = std.Io.Reader.fixed(decrypted);
            var dest_writer = std.Io.Writer.fixed(output);
            var inflater = deflate_seam.Decode.initBound(options.provider, &source_reader, history) catch return error.UnsupportedException;
            _ = inflater.readerPtr().streamRemaining(&dest_writer) catch return error.DataException;
            if (dest_writer.end != output.len) return error.DataException;
        },
        .bzip2 => {
            const scratch = try workspace.take(u8, try bzip2.decodeWorkspaceSizeFor(decrypted));
            const decoded = try bzip2.decode(decrypted, output, scratch, options.provider);
            if (decoded != output.len) return error.DataException;
        },
        .lzma => {
            const properties = try parseLzmaProperties(folder.attributes);
            const lzma_options: lzma.Options = .{ .properties = properties, .unpack_size = output.len, .marker_required = false, .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(properties));
            const decoded = try lzma_seam.decode(options.provider, decrypted, output, scratch, lzma_options);
            if (decoded != output.len) return error.DataException;
        },
        .lzma2 => {
            const dictionary = lzma2.dictionarySizeFromProperties(try readLzma2Prop(folder.attributes));
            if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.UnsupportedException;
            const lzma2_options: lzma2.Options = .{ .dictionary_size = dictionary, .properties = lzma2.defaultProperties(dictionary), .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma2.decodeWorkspaceSize(dictionary));
            const decoded = try lzma2_seam.decode(options.provider, decrypted, output, scratch, lzma2_options);
            if (decoded != output.len) return error.DataException;
        },
        .ppmd => {
            const ppmd_options = try parsePpmdOptions(folder.attributes, output.len, limits.codec_work);
            const scratch = try workspace.take(u8, ppmd.decodeWorkspaceSize(ppmd_options.mem_size));
            const decoded = try ppmd.decode(decrypted, output, scratch, ppmd_options);
            if (decoded != output.len) return error.DataException;
        },
        else => return error.UnsupportedException,
    }
}

fn aesDecryptFolder(folder: *const Folder, packed_data: []const u8, workspace: *Workspace, options: *const SevenZipLoadOptions) Exception![]const u8 {
    return aesDecryptStream(folder.encrypted, folder.aes_num_cycles, folder.aes_salt, folder.aes_iv, packed_data, workspace, options);
}

fn aesDecryptStream(encrypted: bool, num_cycles: u8, salt: []const u8, iv: [16]u8, packed_data: []const u8, workspace: *Workspace, options: *const SevenZipLoadOptions) Exception![]const u8 {
    if (!encrypted) return packed_data;
    const password = options.password orelse return error.UnsupportedException;
    const rounds: u64 = if (num_cycles == 0x3F) 0 else @as(u64, 1) << @intCast(num_cycles);
    if (options.kdf_rounds_limit != 0 and rounds > options.kdf_rounds_limit) {
        options.failure_cause.* = .kdf_limit;
        return error.ResourceException;
    }
    if (options.password_lifetime != 0 and packed_data.len > options.password_lifetime) {
        options.failure_cause.* = .password_lifetime;
        return error.ResourceException;
    }
    const password_utf16 = try passwordToUtf16(password, workspace);
    var key: [crypto.seven_zip_key_length]u8 = undefined;
    if (num_cycles == 0x3F) {
        // Direct-key mode is bounded by the fixed key-material word; refuse
        // passwords that would overflow it instead of smashing the stack.
        if (salt.len + password_utf16.len > 64) return error.UnsupportedException;
        var key_material: [64]u8 = @splat(0);
        @memcpy(key_material[0..salt.len], salt);
        @memcpy(key_material[salt.len..][0..password_utf16.len], password_utf16);
        @memcpy(&key, key_material[0..32]);
    } else {
        crypto.sevenZipKdf(options.provider, password_utf16, salt, num_cycles, &key);
    }
    const decrypted = try workspace.take(u8, packed_data.len);
    try crypto.aesCbcDecrypt(options.provider, &key, iv, decrypted, packed_data);
    return decrypted;
}

const StreamsInfo = struct {
    pack_pos: u64,
    pack_sizes: []const u64,
    // Null entries are pack streams whose CRC the header leaves undefined.
    pack_crcs: []?u32,
    folders: []const Folder,
};

const ParsedCoder = struct {
    method_id: []const u8,
    method: CoderMethod,
    attributes: []const u8,
    num_in_streams: u64,
    num_out_streams: u64,
};

const Bond = struct {
    in_index: u64,
    coder_index: u64,
};

// A BCJ2 input source: a raw packed-stream ordinal, or a producer coder whose
// own input is at `pack_ordinal`.
const Bcj2Source = struct {
    pack_ordinal: u64,
    producer: ?usize = null,
};

const Folder = struct {
    num_substreams: u64,
    substream_sizes: []u64,
    // The UnpackInfo kCRC digest of the whole folder output; doubles as a
    // lone substream's digest.
    folder_crc: ?u32 = null,
    // Null entries are substreams whose digest the header leaves undefined.
    substream_crcs: []?u32,
    pack_index: usize,
    num_pack_streams: u64 = 1,
    method: CoderMethod,
    attributes: []const u8,
    num_in_streams: u64,
    num_out_streams: u64,
    total_out_streams: u64 = 1,
    encrypted: bool = false,
    aes_num_cycles: u8 = 0,
    aes_salt: []const u8 = &.{},
    aes_iv: [16]u8 = @splat(0),
    aes_iv_size: u8 = 0,
    coders: []const ParsedCoder = &.{},
    bonds: []const Bond = &.{},
    bcj2: bool = false,
    bcj2_sources: [4]Bcj2Source = undefined,
    unpack_size: u64 = 0,
};

const AesCoderProps = struct {
    num_cycles: u8,
    salt: []const u8,
    iv: [16]u8,
    iv_size: u8,
};

const FilesInfo = struct {
    empty_streams: []const bool,
    empty_files: []const bool,
    names: []const []const u8,
};

fn parseStreamsInfo(cursor: *binary.ReadCursor, workspace: *Workspace, comptime aes_only_folders: bool) Exception!StreamsInfo {
    var pack_pos: u64 = 0;
    var pack_sizes: []const u64 = &.{};
    var pack_crcs: []?u32 = &.{};
    var folders: []Folder = &.{};
    var has_pack = false;
    var has_unpack = false;
    // Vendor 7zIn.cpp reads PackInfo, then UnpackInfo, then at most one
    // SubStreamsInfo; anything else is a corrupt header.
    const Section = enum { start, pack, unpack, substreams };
    var section: Section = .start;
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        switch (id) {
            0x06 => {
                if (section != .start) return error.DataException;
                section = .pack;
                has_pack = true;
                pack_pos = try readUint64(cursor);
                const num_pack_streams = try readUint64(cursor);
                if (num_pack_streams == 0) return error.DataException;
                const sizes = try workspace.take(u64, std.math.cast(usize, num_pack_streams) orelse return error.ResourceException);
                var has_sizes = false;
                while (true) {
                    const pid = try cursor.readU8();
                    if (pid == 0x00) break;
                    if (pid == 0x09) {
                        has_sizes = true;
                        for (sizes) |*s| s.* = try readUint64(cursor);
                    } else if (pid == 0x0A) {
                        pack_crcs = try readDigests(cursor, std.math.cast(usize, num_pack_streams) orelse return error.ResourceException, workspace);
                    } else {
                        return error.UnsupportedException;
                    }
                }
                // kSize absence reads as zero-length streams, matching p7zip's
                // value-initialized PackSizes, never recycled workspace bytes.
                if (!has_sizes) @memset(sizes, 0);
                pack_sizes = sizes;
            },
            0x07 => {
                if (section != .pack) return error.DataException;
                section = .unpack;
                has_unpack = true;
                folders = try parseFolders(cursor, workspace, aes_only_folders);
            },
            0x08 => {
                if (section != .unpack) return error.DataException;
                section = .substreams;
                try parseSubStreamsInfo(cursor, workspace, folders);
            },
            else => return error.UnsupportedException,
        }
    }
    if (!has_pack or !has_unpack) return error.DataException;
    // Pack streams are per-folder runs, four for BCJ2, tiling the size array
    // in folder order.
    var next_pack_index: usize = 0;
    for (folders) |*folder| {
        folder.pack_index = next_pack_index;
        const run = std.math.cast(usize, folder.num_pack_streams) orelse return error.ResourceException;
        next_pack_index = try bounds.addUsize(next_pack_index, run);
    }
    if (next_pack_index != pack_sizes.len) return error.DataException;
    return .{
        .pack_pos = pack_pos,
        .pack_sizes = pack_sizes,
        .pack_crcs = pack_crcs,
        .folders = folders,
    };
}

fn parseFolders(cursor: *binary.ReadCursor, workspace: *Workspace, comptime aes_only_folders: bool) Exception![]Folder {
    const folder_id = try cursor.readU8();
    if (folder_id != 0x0B) {
        return error.DataException;
    }
    const num_folders = try readUint64(cursor);
    const folder_count = std.math.cast(usize, num_folders) orelse return error.ResourceException;
    const external = try cursor.readU8();
    if (external != 0) {
        return error.UnsupportedException;
    }
    const folders = try workspace.take(Folder, folder_count);
    for (folders) |*folder| {
        const num_coders = try readUint64(cursor);
        // A BCJ2 folder carries four compressor coders and the recombiner, so the bound leaves
        // headroom without going open-ended.
        if (num_coders < 1 or num_coders > 8) return error.UnsupportedException;
        const coder_count = std.math.cast(usize, num_coders) orelse return error.ResourceException;
        const coders = try workspace.take(ParsedCoder, coder_count);
        for (coders) |*coder| {
            coder.* = try parseCoder(cursor, workspace);
        }
        var encrypted = false;
        var aes: AesCoderProps = .{ .num_cycles = 0, .salt = &.{}, .iv = @splat(0), .iv_size = 0 };
        var data_coder_count: usize = 0;
        var last_data: ?ParsedCoder = null;
        var bcj2_idx: ?usize = null;
        var filter_present = false;
        var folder_in_streams: usize = 0;
        var folder_out_streams: usize = 0;
        const coder_in_base = try workspace.take(u64, coder_count);
        const coder_out_base = try workspace.take(u64, coder_count);
        for (coders, 0..) |coder, i| {
            coder_in_base[i] = folder_in_streams;
            coder_out_base[i] = folder_out_streams;
            folder_in_streams = try bounds.addUsize(folder_in_streams, std.math.cast(usize, coder.num_in_streams) orelse return error.DataException);
            folder_out_streams = try bounds.addUsize(folder_out_streams, std.math.cast(usize, coder.num_out_streams) orelse return error.DataException);
            if (std.mem.eql(u8, coder.method_id, &method_7z_aes_id)) {
                if (encrypted) return error.UnsupportedException;
                encrypted = true;
                aes = try parse7zAesProps(coder.attributes);
            } else if (coder.method == .bcj2) {
                if (bcj2_idx != null) return error.UnsupportedException;
                bcj2_idx = i;
            } else if (isFilterMethod(coder.method)) {
                filter_present = true;
            } else {
                data_coder_count += 1;
                last_data = coder;
            }
        }
        // An AES-only folder is the -mhe encoded-header shape; file-data
        // folders always carry a data coder.
        if (data_coder_count == 0) {
            if (!(aes_only_folders and encrypted)) return error.UnsupportedException;
        } else if (encrypted and data_coder_count != 1) return error.UnsupportedException;
        if (bcj2_idx != null and (encrypted or filter_present)) return error.UnsupportedException;
        var method: CoderMethod = .copy;
        var attributes: []const u8 = &.{};
        var num_in_streams: u64 = 1;
        var num_out_streams: u64 = 1;
        if (last_data) |data_coder| {
            method = data_coder.method;
            attributes = data_coder.attributes;
            num_in_streams = data_coder.num_in_streams;
            num_out_streams = data_coder.num_out_streams;
        }
        var bonds: []const Bond = &.{};
        var packed_inputs: []const u64 = &.{};
        var bcj2_sources: [4]Bcj2Source = undefined;
        const bcj2_in_base = if (bcj2_idx) |i| coder_in_base[i] else 0;
        if (num_coders > 1) {
            const num_bonds = num_coders - 1;
            const bond_count = std.math.cast(usize, num_bonds) orelse return error.ResourceException;
            const bond_list = try workspace.take(Bond, bond_count);
            var bond: u64 = 0;
            while (bond < num_bonds) : (bond += 1) {
                const in_index = try readUint64(cursor);
                const coder_index = try readUint64(cursor);
                if (in_index >= folder_in_streams or coder_index >= num_coders) return error.DataException;
                // An input stream feeds from exactly one place, so a repeat means a malformed folder.
                for (bond_list[0..@intCast(bond)]) |existing| {
                    if (existing.in_index == in_index) return error.DataException;
                }
                bond_list[@intCast(bond)] = .{ .in_index = in_index, .coder_index = coder_index };
            }
            bonds = bond_list;
            const num_packed_streams = folder_in_streams - num_bonds;
            if (num_packed_streams == 0) return error.DataException;
            if (num_packed_streams != 1) {
                const packed_count = std.math.cast(usize, num_packed_streams) orelse return error.ResourceException;
                const packed_list = try workspace.take(u64, packed_count);
                var packed_index: u64 = 0;
                while (packed_index < num_packed_streams) : (packed_index += 1) {
                    const index = try readUint64(cursor);
                    if (index >= folder_in_streams) return error.DataException;
                    packed_list[@intCast(packed_index)] = index;
                }
                packed_inputs = packed_list;
            }
        }
        if (bcj2_idx) |bi| {
            method = .bcj2;
            attributes = coders[bi].attributes;
            num_in_streams = coders[bi].num_in_streams;
            num_out_streams = coders[bi].num_out_streams;
            for (0..4) |k| {
                const global_in = bcj2_in_base + k;
                var producer: ?usize = null;
                for (bonds) |existing| {
                    if (existing.in_index == global_in) producer = @intCast(existing.coder_index);
                }
                if (producer) |ci| {
                    if (coders[ci].num_in_streams != 1 or coders[ci].method == .bcj2) return error.UnsupportedException;
                    bcj2_sources[k] = .{
                        .pack_ordinal = try packedOrdinal(packed_inputs, folder_in_streams - bonds.len, coder_in_base[ci]),
                        .producer = ci,
                    };
                } else {
                    bcj2_sources[k] = .{
                        .pack_ordinal = try packedOrdinal(packed_inputs, folder_in_streams - bonds.len, global_in),
                        .producer = null,
                    };
                }
            }
        }
        folder.* = .{
            .num_substreams = 1,
            .substream_sizes = &.{},
            .folder_crc = null,
            .substream_crcs = &.{},
            .pack_index = 0,
            .num_pack_streams = if (bcj2_idx != null) folder_in_streams - bonds.len else 1,
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
            .bonds = bonds,
            .bcj2 = bcj2_idx != null,
            .bcj2_sources = bcj2_sources,
        };
    }
    const unpack_id = try cursor.readU8();
    if (unpack_id != 0x0C) return error.DataException;
    for (folders) |*folder| {
        const stream_count = std.math.cast(usize, folder.total_out_streams) orelse return error.ResourceException;
        const arr = try workspace.take(u64, stream_count);
        for (0..stream_count) |index| {
            arr[index] = try readUint64(cursor);
        }
        // The folder's data is the one output no bond consumes; usually the
        // last (only) stream.
        const sink = folderSinkOutput(folder) orelse (stream_count - 1);
        folder.unpack_size = arr[sink];
        folder.substream_sizes = arr[sink .. sink + 1];
    }
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        if (id == 0x0A) {
            const digests = try readDigests(cursor, std.math.cast(usize, num_folders) orelse return error.ResourceException, workspace);
            for (folders, 0..) |*folder, i| {
                if (i < digests.len) folder.folder_crc = digests[i];
            }
        } else return error.UnsupportedException;
    }
    return folders;
}

// Maps a global input index to its packed-stream ordinal; bonded (coder-fed)
// inputs have none.
fn packedOrdinal(packed_inputs: []const u64, num_packed_streams: u64, global_in: u64) Exception!u64 {
    if (packed_inputs.len != 0) {
        for (packed_inputs, 0..) |input, ordinal| {
            if (input == global_in) return ordinal;
        }
        return error.UnsupportedException;
    }
    if (num_packed_streams == 1 and global_in == 0) return 0;
    return error.UnsupportedException;
}

// The global index of the folder output stream no bond consumes, if exactly one exists.
fn folderSinkOutput(folder: *const Folder) ?usize {
    var unbound: ?u64 = null;
    var out_index: u64 = 0;
    for (folder.coders) |coder| {
        var local: u64 = 0;
        while (local < coder.num_out_streams) : (local += 1) {
            const global_out = out_index + local;
            var consumed = false;
            for (folder.bonds) |bond| {
                // The parse bounds coder_index to the coder table, so the cast cannot fail.
                const bond_index: usize = @intCast(bond.coder_index);
                if (folder.coders[bond_index].num_out_streams == 1 and globalOutputBase(folder, bond_index) == global_out) consumed = true;
            }
            if (!consumed) {
                if (unbound != null) return null;
                unbound = global_out;
            }
        }
        out_index += coder.num_out_streams;
    }
    if (unbound) |sink| return std.math.cast(usize, sink);
    return null;
}

fn globalOutputBase(folder: *const Folder, coder_index: u64) u64 {
    var base: u64 = 0;
    for (folder.coders[0..@intCast(coder_index)]) |coder| {
        base += coder.num_out_streams;
    }
    return base;
}

fn parseCoder(cursor: *binary.ReadCursor, workspace: *Workspace) Exception!ParsedCoder {
    const flags = try cursor.readU8();
    const id_size = flags & 0x0F;
    const is_complex = (flags & 0x10) != 0;
    const has_attributes = (flags & 0x20) != 0;
    if ((flags & 0x40) != 0 or (flags & 0x80) != 0) return error.UnsupportedException;
    if (id_size == 0 or id_size > 8) return error.UnsupportedException;
    const method_id = try cursor.readSlice(id_size);
    const method: CoderMethod = if (std.mem.eql(u8, method_id, &method_7z_aes_id)) .copy else try methodFromId(method_id);
    var num_in_streams: u64 = 1;
    var num_out_streams: u64 = 1;
    if (is_complex) {
        num_in_streams = try readUint64(cursor);
        num_out_streams = try readUint64(cursor);
    }
    if (method == .bcj2) {
        // BCJ2 is the one many-to-one coder, with four sub-stream inputs and one output.
        if (num_in_streams != 4 or num_out_streams != 1) return error.UnsupportedException;
    } else if (num_in_streams != 1 or num_out_streams != 1) return error.UnsupportedException;
    const attributes = blk: {
        if (has_attributes) {
            const prop_size = try readUint64(cursor);
            const prop_count = std.math.cast(usize, prop_size) orelse return error.ResourceException;
            if (prop_size > cursor.remaining()) return error.DataException;
            const bytes = try workspace.take(u8, prop_count);
            const start = cursor.pos;
            try cursor.advance(prop_size);
            @memcpy(bytes, cursor.buffer[start..cursor.pos]);
            break :blk bytes;
        } else {
            if (method == .lzma or method == .lzma2) return error.DataException;
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

fn parse7zAesProps(attributes: []const u8) Exception!AesCoderProps {
    if (attributes.len == 0) return error.DataException;
    const b0 = attributes[0];
    const num_cycles = b0 & 0x3F;
    // Both wire shapes share the cost ceiling; single-byte 0x3E must not
    // reach the KDF as unchecked 2^62 rounds.
    if (num_cycles > crypto.seven_zip_cycles_max and num_cycles != 0x3F) return error.UnsupportedException;
    if ((b0 & 0xC0) == 0) {
        if (attributes.len != 1) return error.DataException;
        return .{ .num_cycles = num_cycles, .salt = &.{}, .iv = @splat(0), .iv_size = 0 };
    }
    if (attributes.len <= 1) return error.DataException;
    const b1 = attributes[1];
    const salt_size = @as(usize, (b0 >> 7) & 1) + (b1 >> 4);
    const iv_size = @as(usize, (b0 >> 6) & 1) + (b1 & 0x0F);
    if (attributes.len != 2 + salt_size + iv_size) return error.DataException;
    var iv: [16]u8 = @splat(0);
    @memcpy(iv[0..iv_size], attributes[2 + salt_size ..][0..iv_size]);
    return .{
        .num_cycles = num_cycles,
        .salt = attributes[2..][0..salt_size],
        .iv = iv,
        .iv_size = @intCast(iv_size),
    };
}

fn parseSubStreamsInfo(cursor: *binary.ReadCursor, workspace: *Workspace, folders: []Folder) Exception!void {
    var saw_counts = false;
    var saw_sizes = false;
    var saw_crcs = false;
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        switch (id) {
            0x0D => {
                // Vendor 7zIn.cpp reads kNumUnpackStream once, before kSize
                // and kCRC; a repeat or late occurrence is a corrupt header.
                if (saw_counts or saw_sizes or saw_crcs) return error.DataException;
                saw_counts = true;
                for (folders) |*folder| {
                    const count = try readUint64(cursor);
                    folder.num_substreams = count;
                    if (count != 1) {
                        // Drop the single-substream default inherited from
                        // kCodersUnpackSize; 0x09 or finalize rederives sizes.
                        folder.substream_sizes = &.{};
                    }
                }
            },
            0x09 => {
                if (saw_sizes or saw_crcs) return error.DataException;
                saw_sizes = true;
                // Sizes read in folder order; each folder's last substream is
                // the unpack total minus the listed sizes (vendor 7zIn.cpp).
                for (folders) |*folder| {
                    const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceException;
                    if (count == 0) continue;
                    const arr = try workspace.take(u64, count);
                    var known: u64 = 0;
                    for (arr[0 .. count - 1]) |*size| {
                        size.* = try readUint64(cursor);
                        known = try bounds.addU64(known, size.*);
                    }
                    if (known > folder.unpack_size) return error.DataException;
                    arr[count - 1] = folder.unpack_size - known;
                    folder.substream_sizes = arr;
                }
            },
            0x0A => {
                if (saw_crcs) return error.DataException;
                saw_crcs = true;
                const digests2 = try readDigests(cursor, try foldDigestCount(folders), workspace);
                try assignSubstreamDigests(folders, digests2, workspace);
            },
            else => return error.UnsupportedException,
        }
    }
    if (!saw_crcs) {
        // Vendor applies the same fold with an all-undefined digest list when
        // the SubStreamsInfo block carries no kCRC property.
        const undef = try workspace.take(?u32, try foldDigestCount(folders));
        @memset(undef, null);
        try assignSubstreamDigests(folders, undef, workspace);
    }
    try finalizeSubstreamSizes(folders);
}

fn totalSubstreams(folders: []const Folder) Exception!usize {
    var total: usize = 0;
    for (folders) |folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceException;
        total = try bounds.addUsize(total, count);
    }
    return total;
}

// Wire digest count: single-substream folders with a defined UnpackInfo kCRC
// fold out (vendor behavior).
fn foldDigestCount(folders: []const Folder) Exception!usize {
    var total: usize = 0;
    for (folders) |folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceException;
        if (count != 1 or folder.folder_crc == null) {
            total = try bounds.addUsize(total, count);
        }
    }
    return total;
}

// Spreads the kCRC list across folders: single-substream folders take their
// folder CRC; the wire list fills the rest.
fn assignSubstreamDigests(folders: []Folder, digests2: []?u32, workspace: *Workspace) Exception!void {
    const total = try totalSubstreams(folders);
    const arr = try workspace.take(?u32, total);
    var k2: usize = 0;
    var index: usize = 0;
    for (folders) |*folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceException;
        if (count == 1 and folder.folder_crc != null) {
            arr[index] = folder.folder_crc;
        } else {
            for (0..count) |j| {
                arr[index + j] = digests2[k2];
                k2 += 1;
            }
        }
        folder.substream_crcs = arr[index .. index + count];
        index += count;
    }
}

fn finalizeSubstreamSizes(folders: []Folder) Exception!void {
    for (folders) |*folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceException;
        if (folder.substream_sizes.len != count) return error.DataException;
        if (count == 0) continue;
        if (count == 1) {
            if (folder.substream_sizes[0] != folder.unpack_size) return error.DataException;
            continue;
        }
        var sum: u64 = 0;
        for (folder.substream_sizes[0 .. count - 1]) |size| {
            sum = try bounds.addU64(sum, size);
        }
        if (sum > folder.unpack_size) return error.DataException;
        folder.substream_sizes[count - 1] = folder.unpack_size - sum;
    }
}

fn parseFilesInfo(cursor: *binary.ReadCursor, workspace: *Workspace) Exception!FilesInfo {
    const num_files = try readUint64(cursor);
    const count = std.math.cast(usize, num_files) orelse return error.ResourceException;
    const empty_streams = try workspace.take(bool, count);
    const empty_files = try workspace.take(bool, count);
    const names = try workspace.take([]const u8, count);
    @memset(empty_streams, false);
    @memset(empty_files, false);
    // kNames absence must read as "no name", never as recycled workspace bytes.
    @memset(names, &.{});
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        const prop_size = try readUint64(cursor);
        if (prop_size > cursor.remaining()) return error.DataException;
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
                    if (b) return error.UnsupportedException;
                }
            },
            0x11 => {
                const external = try sub.readU8();
                if (external != 0) return error.UnsupportedException;
                for (0..count) |i| {
                    names[i] = try readUtf16Name(&sub, workspace);
                }
            },
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19 => {},
            // kStartPos shifts per-file data offsets; pack offsets here are
            // computed sequentially, so accepting it would mis-locate data.
            0x18 => return error.UnsupportedException,
            else => return error.UnsupportedException,
        }
        if (id >= 0x0E and id <= 0x11 and sub.remaining() != 0) return error.DataException;
    }
    return .{
        .empty_streams = empty_streams,
        .empty_files = empty_files,
        .names = names,
    };
}

fn skipArchiveProperties(cursor: *binary.ReadCursor) Exception!void {
    while (cursor.remaining() > 0) {
        const id = try cursor.readU8();
        if (id == 0x00) break;
        const size = try readUint64(cursor);
        if (size > cursor.remaining()) return error.DataException;
        try cursor.advance(size);
    }
}

fn buildEntries(si: *const StreamsInfo, fi: *const FilesInfo, workspace: *Workspace, limits: Limits) Exception![]const Info {
    const count = fi.names.len;
    if (@as(u64, count) > limits.entries) return error.ResourceException;
    const entries = try workspace.take(Info, count);
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
        var aes_iv: [16]u8 = @splat(0);
        var aes_iv_size: u8 = 0;
        var entry_folder: ?*const Folder = null;
        var file_substream_offset: u64 = 0;
        var entry_pack_stream_sizes: []const u64 = &.{};
        if (!is_empty) {
            while (folder_index < si.folders.len) {
                const folder_substream_count = std.math.cast(usize, si.folders[folder_index].num_substreams) orelse return error.ResourceException;
                if (substream_index < folder_substream_count) break;
                folder_index += 1;
                substream_index = 0;
                substream_offset = 0;
            }
            if (folder_index >= si.folders.len) return error.DataException;
            const folder = &si.folders[folder_index];
            entry_folder = folder;
            if (substream_index >= folder.substream_sizes.len) return error.DataException;
            size = folder.substream_sizes[substream_index];
            if (size > limits.decoded_bytes) return error.ResourceException;
            const pack_run = std.math.cast(usize, folder.num_pack_streams) orelse return error.ResourceException;
            if (folder.pack_index + pack_run > si.pack_sizes.len) return error.DataException;
            entry_pack_stream_sizes = si.pack_sizes[folder.pack_index..][0..pack_run];
            for (entry_pack_stream_sizes) |stream_size| {
                pack_size = try bounds.addU64(pack_size, stream_size);
            }
            if (pack_size > limits.encoded_bytes) return error.ResourceException;
            data_offset = try bounds.addU64(start_header_size, try folderPackOffset(si, folder_index));
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
            substream_offset = try bounds.addU64(substream_offset, size);
            const folder_substream_count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceException;
            if (substream_index >= folder_substream_count) {
                folder_index += 1;
                substream_index = 0;
                substream_offset = 0;
            }
        }
        const name = try utf16LeToUtf8(fi.names[i], workspace);
        // Decode-side parity with ZIP: refuse traversal, absolute, backslash,
        // and embedded-NUL names instead of delegating tar-slip checks to consumers.
        if (bounds.isAbsoluteOrTraversal(name) or std.mem.findScalar(u8, name, 0) != null) return error.DataException;
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
            .pack_stream_sizes = entry_pack_stream_sizes,
        };
    }
    // Vendor FillLinks skips folders that carry no substreams; tolerate them
    // at the tail instead of rejecting the archive.
    while (folder_index < si.folders.len and si.folders[folder_index].num_substreams == 0) {
        folder_index += 1;
    }
    if (folder_index != si.folders.len) return error.DataException;
    return entries;
}

fn folderPackOffset(si: *const StreamsInfo, folder_index: usize) Exception!u64 {
    var offset = si.pack_pos;
    for (0..folder_index) |index| {
        const run = std.math.cast(usize, si.folders[index].num_pack_streams) orelse return error.ResourceException;
        for (0..run) |sub| {
            offset = try bounds.addU64(offset, si.pack_sizes[si.folders[index].pack_index + sub]);
        }
    }
    return offset;
}

fn folderOutputSize(folder: *const Folder) Exception!usize {
    var total: usize = 0;
    for (folder.substream_sizes) |size| {
        const part = std.math.cast(usize, size) orelse return error.ResourceException;
        total = try bounds.addUsize(total, part);
    }
    return total;
}

fn writeHeader(writer: *std.Io.Writer, entries: []const Entry, packed_entries: []const PackedEntry, workspace: *Workspace) Exception!void {
    try io.writeBytes(writer, &.{0x01});
    try io.writeBytes(writer, &.{0x04});
    try writeStreamsInfo(writer, entries, packed_entries, workspace);
    try writeFilesInfo(writer, entries, workspace);
    try io.writeBytes(writer, &.{0x00});
}

const FolderPlan = struct {
    filters: []const CoderMethod,
    method: CoderMethod,
    encrypted: bool,
    first: usize,
    count: usize,
};

fn buildFolderPlan(packed_entries: []const PackedEntry, workspace: *Workspace) Exception![]const FolderPlan {
    const plan = try workspace.take(FolderPlan, packed_entries.len);
    var plan_count: usize = 0;
    var i: usize = 0;
    while (i < packed_entries.len) {
        const p = packed_entries[i];
        var j = i + 1;
        // Group by the recorded solid membership only; any other rule desyncs
        // the header from the packed bytes.
        while (j < packed_entries.len and packed_entries[j].solid_continuation) j += 1;
        plan[plan_count] = .{ .filters = p.filters, .method = p.method, .encrypted = p.encrypted, .first = i, .count = j - i };
        plan_count += 1;
        i = j;
    }
    return plan[0..plan_count];
}

fn folderUnpackSize(entries: []const Entry, folder: FolderPlan) Exception!usize {
    var total: usize = 0;
    var index: usize = 0;
    for (entries) |entry| {
        if (isEmptyEntry(entry)) continue;
        if (index < folder.first) {
            index += 1;
            continue;
        }
        if (index >= folder.first + folder.count) break;
        total = try bounds.addUsize(total, entry.data.len);
        index += 1;
    }
    return total;
}

fn writeStreamsInfo(writer: *std.Io.Writer, entries: []const Entry, packed_entries: []const PackedEntry, workspace: *Workspace) Exception!void {
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
        const num_coders = @as(usize, if (p.encrypted) 1 else 0) + p.filters.len + 1;
        try writeUint64(writer, num_coders);
        if (p.encrypted) {
            const aes_flags: u8 = @as(u8, @intCast(method_7z_aes_id.len)) | 0x20;
            try io.writeBytes(writer, &.{aes_flags});
            try io.writeBytes(writer, &method_7z_aes_id);
            const salt_size: usize = p.salt_length;
            const iv_size: usize = 16;
            // Sizes encode as 1-bit high plus 4-bit low halves summing to the
            // size: 16 is high=1 low=15 (see parse7zAesProps).
            const salt_high: u8 = @intCast(salt_size >> 4);
            const iv_high: u8 = @intCast(iv_size >> 4);
            var props: [2 + 16 + 16]u8 = undefined;
            props[0] = p.num_cycles_power | (salt_high << 7) | (iv_high << 6);
            props[1] = @as(u8, @intCast((salt_size - salt_high) << 4)) | @as(u8, @intCast(iv_size - iv_high));
            @memcpy(props[2 .. 2 + salt_size], p.salt[0..salt_size]);
            @memcpy(props[2 + salt_size ..][0..iv_size], &p.iv);
            try writeUint64(writer, 2 + salt_size + iv_size);
            try io.writeBytes(writer, props[0 .. 2 + salt_size + iv_size]);
        }
        const method = p.method;
        try writeFolderCoder(writer, method, p.crc);
        // Coders decode in written order, so the chain's last filter (nearest
        // the packed stream) is written first.
        var filter_index = p.filters.len;
        while (filter_index > 0) {
            filter_index -= 1;
            try writeFolderCoder(writer, p.filters[filter_index], p.crc);
        }
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
        if (p.encrypted) try writeUint64(writer, p.pack_size);
        // Every filter in the chain is size-preserving, so each coder's
        // unpack size is the entry's unpacked size.
        var size_count: usize = p.filters.len + 1;
        while (size_count > 0) : (size_count -= 1) {
            try writeUint64(writer, unpack_size);
        }
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
                    try writeUint64(writer, p.unpack_size);
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

fn writeFolderCoder(writer: *std.Io.Writer, method: CoderMethod, unpacked_crc: u32) Exception!void {
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

fn writeCoderAttributes(writer: *std.Io.Writer, method: CoderMethod, unpacked_crc: u32) Exception!void {
    _ = unpacked_crc;
    switch (method) {
        .lzma => {
            const properties = lzma2.defaultProperties(default_dictionary);
            try io.writeBytes(writer, &.{properties.encode()});
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, default_dictionary, .little);
            try io.writeBytes(writer, &bytes);
        },
        .lzma2 => {
            try io.writeBytes(writer, &.{lzma2.propertiesFromDictionarySize(default_dictionary)});
        },
        .ppmd => {
            try io.writeBytes(writer, &.{@intCast(default_ppmd_order)});
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, default_ppmd_mem, .little);
            try io.writeBytes(writer, &bytes);
        },
        .delta => {
            try io.writeBytes(writer, &.{0});
        },
        else => {},
    }
}

fn writeFilesInfo(writer: *std.Io.Writer, entries: []const Entry, workspace: *Workspace) Exception!void {
    try io.writeBytes(writer, &.{0x05});
    try writeUint64(writer, entries.len);
    const empty_count = emptyCount(entries);
    if (empty_count > 0) {
        try writeSizedProperty(writer, workspace, 0x0E, struct {
            entries: []const Entry,

            fn write(self: @This(), w: *std.Io.Writer) Exception!void {
                try writeBitVector(w, self.entries.len, struct {
                    entries: []const Entry,

                    fn get(c: @This(), i: usize) bool {
                        return isEmptyEntry(c.entries[i]);
                    }
                }{ .entries = self.entries });
            }
        }{ .entries = entries });
        try writeSizedProperty(writer, workspace, 0x0F, struct {
            entries: []const Entry,

            fn write(self: @This(), w: *std.Io.Writer) Exception!void {
                const empty_count2 = emptyCount(self.entries);
                try writeBitVector(w, empty_count2, struct {
                    entries: []const Entry,

                    fn get(c: @This(), i: usize) bool {
                        return emptyFileAt(c.entries, i);
                    }
                }{ .entries = self.entries });
            }
        }{ .entries = entries });
    }
    try writeSizedProperty(writer, workspace, 0x11, struct {
        entries: []const Entry,

        fn write(self: @This(), w: *std.Io.Writer) Exception!void {
            try io.writeBytes(w, &.{0x00});
            for (self.entries) |entry| {
                try writeUtf16Name(w, entry.name);
            }
        }
    }{ .entries = entries });
    try writeSizedProperty(writer, workspace, 0x14, struct {
        entries: []const Entry,

        fn write(self: @This(), w: *std.Io.Writer) Exception!void {
            try io.writeBytes(w, &.{ 0x01, 0x00 });
            for (self.entries) |_| {
                var bytes: [8]u8 = @splat(0);
                try io.writeBytes(w, &bytes);
            }
        }
    }{ .entries = entries });
    try writeSizedProperty(writer, workspace, 0x15, struct {
        entries: []const Entry,

        fn write(self: @This(), w: *std.Io.Writer) Exception!void {
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

fn writeSizedProperty(writer: *std.Io.Writer, workspace: *Workspace, id: u8, ctx: anytype) Exception!void {
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
    const buffer = try workspace.take(u8, std.math.cast(usize, size) orelse return error.ResourceException);
    var fixed_writer = std.Io.Writer.fixed(buffer);
    try ctx.write(&fixed_writer);
    try io.writeBytes(writer, &.{id});
    try writeUint64(writer, size);
    try io.writeBytes(writer, buffer);
}

fn isEmptyEntry(entry: Entry) bool {
    return entry.data.len == 0 or (entry.name.len > 0 and entry.name[entry.name.len - 1] == '/');
}

fn isDirectoryEntry(entry: Entry) bool {
    return entry.name.len > 0 and entry.name[entry.name.len - 1] == '/';
}

fn nonEmptyCount(entries: []const Entry) usize {
    var count: usize = 0;
    for (entries) |entry| {
        if (!isEmptyEntry(entry)) count += 1;
    }
    return count;
}

fn emptyCount(entries: []const Entry) usize {
    var count: usize = 0;
    for (entries) |entry| {
        if (isEmptyEntry(entry)) count += 1;
    }
    return count;
}

fn emptyFileAt(entries: []const Entry, index: usize) bool {
    var seen: usize = 0;
    for (entries) |entry| {
        if (isEmptyEntry(entry)) {
            if (seen == index) return !isDirectoryEntry(entry);
            seen += 1;
        }
    }
    return false;
}

fn readDigests(cursor: *binary.ReadCursor, count: usize, workspace: *Workspace) Exception![]?u32 {
    const all_defined = try cursor.readU8();
    if (all_defined == 1) {
        const crcs = try workspace.take(?u32, count);
        for (crcs) |*c| {
            var bytes = try cursor.readBytes(4);
            c.* = std.mem.readInt(u32, &bytes, .little);
        }
        return crcs;
    }
    if (all_defined == 0) {
        // The 0 selector means raw MSB-first defined-bits follow immediately
        // (vendor ReadBoolVector); no second selector byte precedes them.
        const defined = try readBitVectorRaw(cursor, count, workspace);
        const crcs = try workspace.take(?u32, count);
        for (crcs, 0..) |*c, i| {
            if (defined[i]) {
                var bytes = try cursor.readBytes(4);
                c.* = std.mem.readInt(u32, &bytes, .little);
            } else {
                c.* = null;
            }
        }
        return crcs;
    }
    return error.UnsupportedException;
}

fn readBitVectorRaw(cursor: *binary.ReadCursor, count: usize, workspace: *Workspace) Exception![]const bool {
    if (count == 0) return &.{};
    const bytes_count = (count + 7) / 8;
    if (cursor.remaining() < bytes_count) return error.DataException;
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

fn emptyIndex(bits: []const bool, target: usize) Exception!usize {
    var seen: usize = 0;
    for (bits, 0..) |b, i| {
        if (b) {
            if (seen == target) return i;
            seen += 1;
        }
    }
    return error.DataException;
}

fn readUtf16Name(cursor: *binary.ReadCursor, workspace: *Workspace) Exception![]const u8 {
    const start = cursor.pos;
    var byte_len: usize = 0;
    while (true) {
        if (cursor.remaining() < 2) return error.DataException;
        const unit = std.mem.readInt(u16, &(try cursor.readBytes(2)), .little);
        byte_len += 2;
        if (unit == 0) break;
    }
    const bytes = try workspace.take(u8, byte_len);
    @memcpy(bytes, cursor.buffer[start..cursor.pos]);
    return bytes;
}

fn utf16LeToUtf8(name_utf16: []const u8, workspace: *Workspace) Exception![]const u8 {
    if (name_utf16.len < 2 or name_utf16.len % 2 != 0) return error.DataException;
    var utf8_len: usize = 0;
    var i: usize = 0;
    while (i + 2 <= name_utf16.len) : (i += 2) {
        const unit = std.mem.readInt(u16, name_utf16[i..][0..2], .little);
        if (unit == 0) break;
        var cp: u21 = unit;
        if (unit >= 0xD800 and unit <= 0xDBFF) {
            if (i + 4 > name_utf16.len) return error.DataException;
            const low = std.mem.readInt(u16, name_utf16[i + 2 ..][0..2], .little);
            if (low < 0xDC00 or low > 0xDFFF) return error.DataException;
            cp = 0x10000 + ((@as(u21, unit - 0xD800) << 10) | @as(u21, low - 0xDC00));
            i += 2;
        } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
            return error.DataException;
        }
        utf8_len += std.unicode.utf8CodepointSequenceLength(cp) catch return error.DataException;
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
        offset += std.unicode.utf8Encode(cp, result[offset..]) catch return error.DataException;
    }
    return result;
}

fn writeUtf16Name(writer: *std.Io.Writer, name: []const u8) Exception!void {
    const stripped = if (name.len > 0 and name[name.len - 1] == '/') name[0 .. name.len - 1] else name;
    const view = std.unicode.Utf8View.init(stripped) catch return error.DataException;
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
    var zero: [2]u8 = @splat(0);
    try io.writeBytes(writer, &zero);
}

fn passwordToUtf16(password: []const u8, workspace: *Workspace) Exception![]const u8 {
    const view = std.unicode.Utf8View.init(password) catch return error.DataException;
    var byte_len: usize = 0;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| byte_len = try bounds.addUsize(byte_len, 2 * binary.utf16LeUnits(cp));
    const bytes = try workspace.take(u8, byte_len);
    var cursor = binary.WriteCursor.init(bytes);
    var encode_it = view.iterator();
    while (encode_it.nextCodepoint()) |cp| try cursor.writeUtf16Le(cp);
    return bytes;
}

fn writeBitVector(writer: *std.Io.Writer, count: usize, ctx: anytype) Exception!void {
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

fn readUint64(cursor: *binary.ReadCursor) Exception!u64 {
    // Mirrors vendor ReadNumberSpec: the first byte's leading one bits count
    // the continuation bytes, which follow little-endian, lowest byte first.
    const first = try cursor.readU8();
    var value: u64 = 0;
    var mask: u8 = 0x80;
    var extra: u6 = 0;
    while (extra < 8) : (extra += 1) {
        if ((first & mask) == 0) {
            const payload: u64 = first & (mask - 1);
            return value | (payload << (extra * 8));
        }
        value |= @as(u64, try cursor.readU8()) << (extra * 8);
        mask >>= 1;
    }
    return value;
}

fn writeUint64(writer: *std.Io.Writer, value: u64) Exception!void {
    if (value < 0x80) {
        try io.writeBytes(writer, &.{@intCast(value)});
        return;
    }
    // The `extra` count leaves the first byte `7 - extra` payload bits;
    // capacity is 1 << (7*extra + 7).
    var extra: u6 = 1;
    while (extra < 8 and value >= (@as(u64, 1) << @intCast(7 * @as(u32, extra) + 7))) extra += 1;
    if (extra == 8) {
        try io.writeBytes(writer, &.{0xFF});
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .little);
        try io.writeBytes(writer, &bytes);
        return;
    }
    const pattern: u8 = @as(u8, 0xFF) << @intCast(8 - extra);
    const payload: u8 = @intCast(value >> @intCast(8 * @as(u64, extra)));
    try io.writeBytes(writer, &.{pattern | payload});
    const remainder = value & ((@as(u64, 1) << @intCast(8 * @as(u64, extra))) - 1);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, remainder, .little);
    try io.writeBytes(writer, bytes[0..extra]);
}

test "sevenzip StreamsInfo enforces vendor section order" {
    var backing: [4096]u8 = undefined;
    var workspace = try Workspace.init(backing[0..].ptr, backing.len);
    // Vendor 7zIn.cpp reads PackInfo, then UnpackInfo, then at most one
    // SubStreamsInfo; a SubStreamsInfo before UnpackInfo must not parse.
    const misordered = [_]u8{ 0x06, 0x00, 0x01, 0x09, 0x00, 0x00, 0x08, 0x00, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00 };
    var bad = binary.ReadCursor.init(&misordered);
    try std.testing.expectError(error.DataException, parseStreamsInfo(&bad, &workspace, false));
    const ordered = [_]u8{ 0x06, 0x00, 0x01, 0x09, 0x00, 0x00, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00 };
    var good = binary.ReadCursor.init(&ordered);
    _ = try parseStreamsInfo(&good, &workspace, false);
}

test "sevenzip ppmd solid grouping roundtrip" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);

    var repetitive: [4096]u8 = undefined;
    for (&repetitive, 0..) |*byte, i| byte.* = @truncate(i / 97);
    const datas = [_][]const u8{ repetitive[0..1500], repetitive[500..2000], repetitive[1000..2500] };
    const entries = [_]Entry{
        .{ .name = "a.bin", .data = datas[0], .method = .ppmd },
        .{ .name = "b.bin", .data = datas[1], .method = .ppmd },
        .{ .name = "c.bin", .data = datas[2], .method = .ppmd },
    };

    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    // Grouping evidence: the folder's packed stream rides on the first entry;
    // independent packing gives every entry its own non-empty stream.
    try testing.expect(packed_entries[0].data.len > 0);
    for (packed_entries[1..]) |p| try testing.expectEqual(@as(usize, 0), p.data.len);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total, written);

    for (datas, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, i, out, .{ .failure_cause = &cause });
        try testing.expectEqual(data.len, produced);
        try testing.expectEqualSlices(u8, data, out);
    }
}

test "sevenzip filter chain roundtrips lzma and lzma2" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);

    var executable: [2048]u8 = undefined;
    // x86 call-flavored bytes so the BCJ filter has real instructions to
    // convert, not just data it passes through unchanged.
    for (&executable, 0..) |*byte, i| byte.* = if (i % 16 < 4) 0xE8 else @truncate(i / 29);
    const datas = [_][]const u8{ executable[0..2048], executable[512..1536] };
    const entries = [_]Entry{
        .{ .name = "code.bin", .data = datas[0], .method = .lzma2, .filters = &.{.x86} },
        .{ .name = "patch.bin", .data = datas[1], .method = .lzma, .filters = &.{.delta} },
    };

    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    try testing.expectEqual(@as(usize, 1), packed_entries[0].filters.len);
    try testing.expectEqual(CoderMethod.x86, packed_entries[0].filters[0]);
    try testing.expectEqual(@as(usize, 1), packed_entries[1].filters.len);
    try testing.expectEqual(CoderMethod.delta, packed_entries[1].filters[0]);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total, written);

    for (datas, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, i, out, .{ .failure_cause = &cause });
        try testing.expectEqual(data.len, produced);
        try testing.expectEqualSlices(u8, data, out);
    }
}

test "sevenzip primary filter methods encode the filter coder" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);

    var executable: [2048]u8 = undefined;
    // x86 call-flavored bytes so the BCJ filter has real instructions to
    // convert, not just data it passes through unchanged.
    for (&executable, 0..) |*byte, i| byte.* = if (i % 16 < 4) 0xE8 else @truncate(i / 29);
    const datas = [_][]const u8{ executable[0..2048], executable[256..1792] };
    const entries = [_]Entry{
        .{ .name = "x.bin", .data = datas[0], .method = .x86 },
        .{ .name = "d.bin", .data = datas[1], .method = .delta },
    };

    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    // The shorthand filter method is its own one-element chain; dropping it
    // fails the archive CRC on decode.
    try testing.expectEqual(@as(usize, 1), packed_entries[0].filters.len);
    try testing.expectEqual(CoderMethod.x86, packed_entries[0].filters[0]);
    try testing.expectEqual(@as(usize, 1), packed_entries[1].filters.len);
    try testing.expectEqual(CoderMethod.delta, packed_entries[1].filters[0]);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total, written);

    for (datas, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, i, out, .{ .failure_cause = &cause });
        try testing.expectEqual(data.len, produced);
        try testing.expectEqualSlices(u8, data, out);
    }
}

test "sevenzip rejects filters outside lzma coders" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 16 * 1024 * 1024);
    defer allocator.free(backing);
    var data: [64]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i *% 7);
    // Each row is a caller error: filters ride LZMA coders only, shorthand
    // cannot stack, and copy takes none.
    const bad = [_]Entry{
        .{ .name = "a", .data = data[0..], .method = .ppmd, .filters = &.{.x86} },
        .{ .name = "b", .data = data[0..], .method = .deflate, .filters = &.{.x86} },
        .{ .name = "c", .data = data[0..], .method = .x86, .filters = &.{.lzma} },
        .{ .name = "d", .data = data[0..], .method = .copy, .filters = &.{.delta} },
    };
    for (bad) |entry| {
        var workspace = try Workspace.init(backing.ptr, backing.len);
        var cause: crypto.FailureCause = .none;
        const single = [_]Entry{entry};
        try testing.expectError(error.CallException, sevenZipPack(&single, crypto.default_provider, &workspace, .{}, &cause));
    }
}

test "sevenzip filtered entries pack outside solid runs" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);

    var repetitive: [4096]u8 = undefined;
    for (&repetitive, 0..) |*byte, i| byte.* = if (i % 8 < 2) 0xE8 else @truncate(i / 97);
    const datas = [_][]const u8{ repetitive[0..1500], repetitive[500..2000], repetitive[1000..2500] };
    const entries = [_]Entry{
        .{ .name = "f.bin", .data = datas[0], .method = .lzma2, .filters = &.{.x86} },
        .{ .name = "s.bin", .data = datas[1], .method = .lzma2 },
        .{ .name = "t.bin", .data = datas[2], .method = .lzma2 },
    };

    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    // The filtered entry owns its packed stream; the two unfiltered entries
    // form a solid folder instead.
    try testing.expect(packed_entries[0].data.len > 0);
    try testing.expectEqual(@as(usize, 1), packed_entries[0].filters.len);
    try testing.expectEqual(CoderMethod.x86, packed_entries[0].filters[0]);
    try testing.expect(packed_entries[1].data.len > 0);
    try testing.expectEqual(@as(usize, 0), packed_entries[1].filters.len);
    try testing.expectEqual(@as(usize, 0), packed_entries[2].data.len);
    try testing.expect(packed_entries[2].solid_continuation);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total, written);

    for (datas, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, i, out, .{ .failure_cause = &cause });
        try testing.expectEqual(data.len, produced);
        try testing.expectEqualSlices(u8, data, out);
    }
}

test "sevenzip vendor number wire format" {
    // Pins the 7z varint to vendor 7zIn.cpp ReadNumberSpec; 152378 and 204800
    // came from 7zz 26.04 reading this writer's archive.
    const testing = std.testing;
    const cases = [_]struct { value: u64, wire: []const u8 }{
        .{ .value = 0, .wire = &.{0x00} },
        .{ .value = 0x7F, .wire = &.{0x7F} },
        .{ .value = 0x80, .wire = &.{ 0x80, 0x80 } },
        .{ .value = 16383, .wire = &.{ 0xBF, 0xFF } },
        .{ .value = 16384, .wire = &.{ 0xC0, 0x00, 0x40 } },
        .{ .value = 152378, .wire = &.{ 0xC2, 0x3A, 0x53 } },
        .{ .value = 204800, .wire = &.{ 0xC3, 0x00, 0x20 } },
        .{ .value = 1 << 24, .wire = &.{ 0xE1, 0x00, 0x00, 0x00 } },
        .{ .value = (1 << 56) - 1, .wire = &.{ 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
        .{ .value = 0xFFFFFFFFFFFFFFFF, .wire = &.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
    };
    for (cases) |case| {
        var buffer: [16]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try writeUint64(&writer, case.value);
        try testing.expectEqualSlices(u8, case.wire, writer.buffered());
        var cursor = binary.ReadCursor.init(case.wire);
        try testing.expectEqual(case.value, try readUint64(&cursor));
        try testing.expectEqual(@as(usize, 0), cursor.remaining());
    }
}

test "sevenzip digest list wire format" {
    // Pins the digest list to vendor 7zIn.cpp ReadHashDigests: 1 selects all,
    // 0 precedes MSB-first bits (ReadBoolVector), else refusal.
    const testing = std.testing;
    var backing: [4096]u8 = undefined;
    var workspace = try Workspace.init(&backing, backing.len);

    {
        const wire = [_]u8{ 0x01, 0x78, 0x56, 0x34, 0x12, 0xCD, 0xAB, 0x00, 0x00 };
        var cursor = binary.ReadCursor.init(&wire);
        const digests = try readDigests(&cursor, 2, &workspace);
        try testing.expectEqual(@as(?u32, 0x12345678), digests[0]);
        try testing.expectEqual(@as(?u32, 0x0000ABCD), digests[1]);
        try testing.expectEqual(@as(usize, 0), cursor.remaining());
    }
    {
        // Bits 0b10100000: entries 0 and 2 defined, 1 and 3 undefined.
        const wire = [_]u8{ 0x00, 0xA0, 0xEF, 0xBE, 0xAD, 0xDE, 0x11, 0x00, 0x00, 0x22 };
        var cursor = binary.ReadCursor.init(&wire);
        const digests = try readDigests(&cursor, 4, &workspace);
        try testing.expectEqual(@as(?u32, 0xDEADBEEF), digests[0]);
        try testing.expectEqual(@as(?u32, null), digests[1]);
        try testing.expectEqual(@as(?u32, 0x22000011), digests[2]);
        try testing.expectEqual(@as(?u32, null), digests[3]);
        try testing.expectEqual(@as(usize, 0), cursor.remaining());
    }
    {
        const wire = [_]u8{0x00};
        var cursor = binary.ReadCursor.init(&wire);
        const digests = try readDigests(&cursor, 0, &workspace);
        try testing.expectEqual(@as(usize, 0), digests.len);
    }
    {
        const wire = [_]u8{0x02};
        var cursor = binary.ReadCursor.init(&wire);
        try testing.expectError(error.UnsupportedException, readDigests(&cursor, 1, &workspace));
    }
}

test "sevenzip substream digest fold and zero-count folders" {
    // Pins SubStreamsInfo digests to vendor ReadSubStreamsInfo: single-substream
    // folders fold out; absent kCRC folds undefined; zero counts clear stale sizes.
    const testing = std.testing;
    var backing: [16 * 1024]u8 = undefined;
    var workspace = try Workspace.init(&backing, backing.len);
    var sizes_a = [_]u64{100};
    var sizes_c = [_]u64{ 10, 20, 30 };
    const Fixture = struct {
        sizes_a: []u64,
        sizes_c: []u64,
        fn make(self: @This()) [3]Folder {
            // Folder A: one substream, whole-folder CRC defined. Folder B:
            // zero substreams. Folder C: three substreams, no folder CRC.
            return .{
                .{ .num_substreams = 1, .substream_sizes = self.sizes_a, .substream_crcs = &.{}, .pack_index = 0, .method = .copy, .attributes = &.{}, .num_in_streams = 1, .num_out_streams = 1, .folder_crc = 0x11111111, .unpack_size = 100 },
                .{ .num_substreams = 0, .substream_sizes = &.{}, .substream_crcs = &.{}, .pack_index = 1, .method = .copy, .attributes = &.{}, .num_in_streams = 1, .num_out_streams = 1, .unpack_size = 0 },
                .{ .num_substreams = 3, .substream_sizes = self.sizes_c, .substream_crcs = &.{}, .pack_index = 2, .method = .copy, .attributes = &.{}, .num_in_streams = 1, .num_out_streams = 1, .unpack_size = 60 },
            };
        }
    };
    const fixture = Fixture{ .sizes_a = &sizes_a, .sizes_c = &sizes_c };

    // kCRC carries three digests: A folds to its folder CRC, B contributes
    // none, C takes all three.
    {
        var folders = fixture.make();
        const wire = [_]u8{
            0x0A, 0x01, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x00,
        };
        var cursor = binary.ReadCursor.init(&wire);
        try parseSubStreamsInfo(&cursor, &workspace, &folders);
        try testing.expectEqual(@as(usize, 1), folders[0].substream_crcs.len);
        try testing.expectEqual(@as(?u32, 0x11111111), folders[0].substream_crcs[0]);
        try testing.expectEqual(@as(usize, 0), folders[1].substream_crcs.len);
        try testing.expectEqual(@as(usize, 3), folders[2].substream_crcs.len);
        try testing.expectEqual(@as(?u32, 1), folders[2].substream_crcs[0]);
        try testing.expectEqual(@as(?u32, 2), folders[2].substream_crcs[1]);
        try testing.expectEqual(@as(?u32, 3), folders[2].substream_crcs[2]);
        try testing.expectEqual(@as(usize, 0), cursor.remaining());
    }

    // Without kCRC the same fold applies over all-undefined digests: A keeps
    // its folder CRC, C stays null.
    {
        var folders = fixture.make();
        const wire = [_]u8{0x00};
        var cursor = binary.ReadCursor.init(&wire);
        try parseSubStreamsInfo(&cursor, &workspace, &folders);
        try testing.expectEqual(@as(usize, 1), folders[0].substream_crcs.len);
        try testing.expectEqual(@as(?u32, 0x11111111), folders[0].substream_crcs[0]);
        try testing.expectEqual(@as(usize, 3), folders[2].substream_crcs.len);
        try testing.expectEqual(@as(?u32, null), folders[2].substream_crcs[0]);
        try testing.expectEqual(@as(?u32, null), folders[2].substream_crcs[1]);
        try testing.expectEqual(@as(?u32, null), folders[2].substream_crcs[2]);
    }

    // A zero count in kNumUnpackStream is legal and drops the stale
    // single-substream default sizes.
    {
        var folders = fixture.make();
        const wire = [_]u8{ 0x0D, 0x00, 0x00, 0x00, 0x00 };
        var cursor = binary.ReadCursor.init(&wire);
        try parseSubStreamsInfo(&cursor, &workspace, &folders);
        try testing.expectEqual(@as(u64, 0), folders[0].num_substreams);
        try testing.expectEqual(@as(usize, 0), folders[0].substream_sizes.len);
        try testing.expectEqual(@as(u64, 0), folders[2].num_substreams);
        try testing.expectEqual(@as(usize, 0), folders[2].substream_sizes.len);
    }

    // A multi-substream count without kSize sizes is corrupt (vendor
    // ThrowIncorrect): the stale default cannot satisfy it.
    {
        var folders = fixture.make();
        const wire = [_]u8{ 0x0D, 0x00, 0x00, 0x03, 0x00 };
        var cursor = binary.ReadCursor.init(&wire);
        try testing.expectError(error.DataException, parseSubStreamsInfo(&cursor, &workspace, &folders));
    }

    // Repeated kNumUnpackStream is a corrupt header.
    {
        var folders = fixture.make();
        const wire = [_]u8{ 0x0D, 0x01, 0x00, 0x00, 0x0D };
        var cursor = binary.ReadCursor.init(&wire);
        try testing.expectError(error.DataException, parseSubStreamsInfo(&cursor, &workspace, &folders));
    }

    // Repeated kCRC is a corrupt header.
    {
        var folders = fixture.make();
        const wire = [_]u8{ 0x0A, 0x00, 0x40, 0xEE, 0x00, 0x00, 0x00, 0x0A };
        var cursor = binary.ReadCursor.init(&wire);
        try testing.expectError(error.DataException, parseSubStreamsInfo(&cursor, &workspace, &folders));
    }
}

test "sevenzip buildEntries skips trailing zero-substream folders" {
    // Vendor FillLinks tolerates empty folders; an undefined digest must
    // surface crc = null, never a phantom zero.
    const testing = std.testing;
    var backing: [16 * 1024]u8 = undefined;
    var workspace = try Workspace.init(&backing, backing.len);
    var sizes_a = [_]u64{7};
    var crcs_a = [_]?u32{@as(?u32, null)};
    const pack_sizes = [_]u64{7};
    const folders = [_]Folder{
        .{ .num_substreams = 1, .substream_sizes = &sizes_a, .substream_crcs = &crcs_a, .pack_index = 0, .method = .copy, .attributes = &.{}, .num_in_streams = 1, .num_out_streams = 1, .unpack_size = 7 },
        .{ .num_substreams = 0, .substream_sizes = &.{}, .substream_crcs = &.{}, .pack_index = 1, .method = .copy, .attributes = &.{}, .num_in_streams = 1, .num_out_streams = 1, .unpack_size = 0 },
    };
    const si = StreamsInfo{ .pack_pos = 32, .pack_sizes = &pack_sizes, .pack_crcs = &.{}, .folders = &folders };
    const empty_streams = [_]bool{false};
    const empty_files = [_]bool{false};
    const name_a = [_]u8{ 0x61, 0x00 };
    const names = [_][]const u8{&name_a};
    const fi = FilesInfo{ .empty_streams = &empty_streams, .empty_files = &empty_files, .names = &names };
    const entries = try buildEntries(&si, &fi, &workspace, .{});
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("a", entries[0].name);
    try testing.expectEqual(@as(u64, 7), entries[0].size);
    try testing.expectEqual(@as(?u32, null), entries[0].crc);
}

test "sevenzip encrypted roundtrip with salt and custom cycles" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);
    const data = "seven zip secret seven zip secret seven zip secret";
    var salt: [16]u8 = undefined;
    for (&salt, 0..) |*byte, i| byte.* = @intCast(i + 1);
    const entries = [_]Entry{
        .{ .name = "enc.bin", .data = data, .method = .copy, .encrypted = true, .password = "pw", .num_cycles_power = 10, .salt = salt, .salt_length = 16 },
    };
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total, written);

    var decode_ws = try Workspace.init(backing.ptr, backing.len);
    const out = try allocator.alloc(u8, data.len);
    defer allocator.free(out);
    const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, 0, out, .{ .password = "pw", .failure_cause = &cause });
    try testing.expectEqual(data.len, produced);
    try testing.expectEqualSlices(u8, data, out);

    // A decode budget below the encoded 2^10 rounds is refused with kdf_limit.
    var refuse_ws = try Workspace.init(backing.ptr, backing.len);
    cause = .none;
    const refuse_out = try allocator.alloc(u8, data.len);
    defer allocator.free(refuse_out);
    try testing.expectError(error.ResourceException, sevenZipDecodeOrdinal(archive, &refuse_ws, .{}, 0, refuse_out, .{
        .password = "pw",
        .kdf_rounds_limit = (1 << 10) - 1,
        .failure_cause = &cause,
    }));
    try testing.expectEqual(crypto.FailureCause.kdf_limit, cause);
}

test "sevenzip folder plan stays consistent across directory and encryption breaks" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    var repetitive: [2048]u8 = undefined;
    for (&repetitive, 0..) |*byte, i| byte.* = @truncate(i / 31);
    const first = repetitive[0..1000];
    const second = repetitive[400..1400];

    // Case 1: the directory breaks the solid run; one folder used to lose the
    // second entry's bytes.
    const with_dir = [_]Entry{
        .{ .name = "a.bin", .data = first, .method = .lzma2 },
        .{ .name = "sub/", .data = &.{}, .method = .copy },
        .{ .name = "b.bin", .data = second, .method = .lzma2 },
    };
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_dir = try sevenZipPack(&with_dir, crypto.default_provider, &workspace, .{}, &cause);
    const total_dir = try sevenZipPackedSize(&with_dir, packed_dir, &workspace, crypto.default_provider, .{}, .{});
    const archive_dir = try allocator.alloc(u8, total_dir);
    defer allocator.free(archive_dir);
    const written_dir = try sevenZipWritePacked(&with_dir, packed_dir, archive_dir, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total_dir, written_dir);
    // Ordinals 0 and 2: ordinal 1 is the directory entry between them.
    for ([_][]const u8{ first, second }, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive_dir, &decode_ws, .{}, if (i == 0) 0 else 2, out, .{ .failure_cause = &cause });
        try testing.expectEqualSlices(u8, data, out[0..produced]);
    }

    // Case 2: encrypted entries never join solid runs; each is its own folder,
    // pack stream, and IV.
    const encrypted_pair = [_]Entry{
        .{ .name = "enc-a.bin", .data = first, .method = .lzma2, .encrypted = true, .password = "pw" },
        .{ .name = "enc-b.bin", .data = second, .method = .lzma2, .encrypted = true, .password = "pw" },
    };
    var enc_workspace = try Workspace.init(backing.ptr, backing.len);
    const packed_enc = try sevenZipPack(&encrypted_pair, crypto.default_provider, &enc_workspace, .{}, &cause);
    const total_enc = try sevenZipPackedSize(&encrypted_pair, packed_enc, &enc_workspace, crypto.default_provider, .{}, .{});
    const archive_enc = try allocator.alloc(u8, total_enc);
    defer allocator.free(archive_enc);
    const written_enc = try sevenZipWritePacked(&encrypted_pair, packed_enc, archive_enc, &enc_workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total_enc, written_enc);
    for ([_][]const u8{ first, second }, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive_enc, &decode_ws, .{}, i, out, .{ .password = "pw", .failure_cause = &cause });
        try testing.expectEqualSlices(u8, data, out[0..produced]);
    }
}

test "sevenzip encrypted lzma2 entry roundtrips" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    var repetitive: [97]u8 = undefined;
    const corpus_01 = "Squdgy fez, blank jimp crwth vox!";
    for (&repetitive, 0..) |*byte, i| byte.* = corpus_01[i % corpus_01.len];
    const data = repetitive[0..97];
    const entries = [_]Entry{
        .{ .name = "l2.txt", .data = data, .method = .lzma2, .encrypted = true, .password = "pw" },
    };
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});
    try testing.expectEqual(total, written);
    var decode_ws = try Workspace.init(backing.ptr, backing.len);
    const out = try allocator.alloc(u8, data.len);
    defer allocator.free(out);
    const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, 0, out, .{ .password = "pw", .failure_cause = &cause });
    try testing.expectEqualSlices(u8, data, out[0..produced]);
}

test "sevenzip encoded headers roundtrip in both modes" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    var repetitive: [600]u8 = undefined;
    const corpus_01 = "Squdgy fez, blank jimp crwth vox!";
    for (&repetitive, 0..) |*byte, i| byte.* = corpus_01[i % corpus_01.len];
    const data = repetitive[0..600];
    const entries = [_]Entry{
        .{ .name = "inner/a.txt", .data = data, .method = .lzma2 },
        .{ .name = "inner/b.txt", .data = data, .method = .lzma2 },
        .{ .name = "inner", .data = &.{} },
    };
    const modes = [_]SevenZipHeaderOptions{
        .{ .compress = true },
        .{ .encrypt = true, .password = "header-secret" },
    };
    for (modes) |mode| {
        var workspace = try Workspace.init(backing.ptr, backing.len);
        var cause: crypto.FailureCause = .none;
        const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
        const total = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, mode);
        const archive = try allocator.alloc(u8, total);
        defer allocator.free(archive);
        const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, mode);
        try testing.expectEqual(total, written);
        // The next header no longer starts with kHeader: it is the encoded
        // structure whose first byte is kEncodedHeader.
        const next_header_size = std.mem.readInt(u64, archive[20..28], .little);
        const next_header_offset = std.mem.readInt(u64, archive[12..20], .little);
        try testing.expectEqual(@as(u64, k_encoded_header), archive[start_header_size + next_header_offset]);
        try testing.expect(next_header_size < total);

        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const count = try sevenZipInspectCountEx(archive, &decode_ws, .{}, &.{
            .password = if (mode.encrypt) "header-secret" else null,
            .failure_cause = &cause,
        });
        try testing.expectEqual(@as(u64, 3), count);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, 0, out, .{
            .password = if (mode.encrypt) "header-secret" else null,
            .failure_cause = &cause,
        });
        try testing.expectEqualSlices(u8, data, out[0..produced]);
        if (mode.encrypt) {
            var fail_ws = try Workspace.init(backing.ptr, backing.len);
            try testing.expectError(error.UnsupportedException, sevenZipInspectCountEx(archive, &fail_ws, .{}, &.{ .failure_cause = &cause }));
            var wrong_ws = try Workspace.init(backing.ptr, backing.len);
            // The wrong password fails wherever the garbage stream first
            // breaks; the contract is the failure cause, not the stage.
            _ = sevenZipDecodeOrdinal(archive, &wrong_ws, .{}, 0, out, .{
                .password = "wrong",
                .failure_cause = &cause,
            }) catch {};
            try testing.expectEqual(crypto.FailureCause.wrong_password, cause);
        }
    }
}

test "sevenzip decode captured failing encrypted archive" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const testing = std.testing;
    const allocator = testing.allocator;
    const hex = "377abcaf271c0004b264b2a5300000000000000061000000000000008558bbbb2b72c63fac9cfd34eaca9f16e66742cea052cbb171699629473766c1fb2c5dbf512f7ea0868dbd6dbb3fc9357fc34c640104060001093000070b0100022406f1070112530fb5ab02e1850647c55791b562eef5860f2121011001000c306100080a011ccdcb5000000501110f006c0032002e007400780074000000140a0100000000000000000015060100200000000000";
    var archive: [177]u8 = undefined;
    for (&archive, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch unreachable;
    }
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    @memset(backing, 0xAA);
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    var corpus_data: [97]u8 = undefined;
    const corpus_01 = "Squdgy fez, blank jimp crwth vox!";
    for (&corpus_data, 0..) |*byte, i| byte.* = corpus_01[i % corpus_01.len];
    const out = try allocator.alloc(u8, corpus_data.len);
    defer allocator.free(out);
    const produced = try sevenZipDecodeOrdinal(&archive, &workspace, .{}, 0, out, .{ .password = "secret", .failure_cause = &cause });
    try testing.expectEqualSlices(u8, &corpus_data, out[0..produced]);
}

fn hexBytes(comptime len: usize, comptime hex: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    for (&out, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[2 * i ..][0..2], 16) catch unreachable;
    }
    return out;
}

// Captured from 7-Zip 26.x (`7zz a -m0=BCJ2 -m1=LZMA2 -mx=5`); hex keeps
// binary fixtures out of the tree.
const bcj2_lzma2_7z_hex =
    "377abcaf271c0004680dc853c101000000000000720000000000000003d82b46e0032b00285d00486bb62414e8bbc1f7" ++
    "862bf0e75602d709b27284cbf7dc450308b8467a9684be00466f3cf4843800000000004f0000007300000097000000bb" ++
    "000000df00000103000001270000014b0000016f00000193000001b7000001db000001ff00000223000002470000026b" ++
    "0000028f000002b3000002d7000002fb0000031f00000343000003670000038b000003af000003d3000003f70000041b" ++
    "0000043f0000046300000487000004ab000000300000001c000000540000003e00000078000000600000009c00000082" ++
    "000000c0000000a4000000e4000000c600000108000000e80000012c0000010a000001500000012c000001740000014e" ++
    "0000019800000170000001bc00000192000001e0000001b400000204000001d600000228000001f80000024c0000021a" ++
    "000002700000023c000002940000025e000002b800000280000002dc000002a200000300000002c400000324000002e6" ++
    "00000348000003080000036c0000032a000003900000034c000003b40000036e000003d800000390000003fc000003b2" ++
    "00000420000003d400000444000003f600000468000004180000048c0000043a0000045c00bffffbffffffff41934e10" ++
    "0001040600040930808081040d00070b01000221210100140303011b04010100000203040c832c84b000080a01f09180" ++
    "b3000005011907000000000000001117006200720061006e00630068002e00620069006e000000190400000000140a01" ++
    "0094d13ab09c57dd01150601002080a4810000" ++
    "";
const bcj2_branch_bin_hex =
    "90909090909090909090e840000000909090909090e9e0ffffff0f8510000000cccccc90909090909090909090e84100" ++
    "0000909090909090e9dfffffff0f8511000000cccccc90909090909090909090e842000000909090909090e9deffffff" ++
    "0f8512000000cccccc90909090909090909090e843000000909090909090e9ddffffff0f8513000000cccccc90909090" ++
    "909090909090e844000000909090909090e9dcffffff0f8514000000cccccc90909090909090909090e8450000009090" ++
    "90909090e9dbffffff0f8515000000cccccc90909090909090909090e846000000909090909090e9daffffff0f851600" ++
    "0000cccccc90909090909090909090e847000000909090909090e9d9ffffff0f8517000000cccccc9090909090909090" ++
    "9090e848000000909090909090e9d8ffffff0f8518000000cccccc90909090909090909090e849000000909090909090" ++
    "e9d7ffffff0f8519000000cccccc90909090909090909090e84a000000909090909090e9d6ffffff0f851a000000cccc" ++
    "cc90909090909090909090e84b000000909090909090e9d5ffffff0f851b000000cccccc90909090909090909090e84c" ++
    "000000909090909090e9d4ffffff0f851c000000cccccc90909090909090909090e84d000000909090909090e9d3ffff" ++
    "ff0f851d000000cccccc90909090909090909090e84e000000909090909090e9d2ffffff0f851e000000cccccc909090" ++
    "90909090909090e84f000000909090909090e9d1ffffff0f851f000000cccccc90909090909090909090e85000000090" ++
    "9090909090e9d0ffffff0f8520000000cccccc90909090909090909090e851000000909090909090e9cfffffff0f8521" ++
    "000000cccccc90909090909090909090e852000000909090909090e9ceffffff0f8522000000cccccc90909090909090" ++
    "909090e853000000909090909090e9cdffffff0f8523000000cccccc90909090909090909090e8540000009090909090" ++
    "90e9ccffffff0f8524000000cccccc90909090909090909090e855000000909090909090e9cbffffff0f8525000000cc" ++
    "cccc90909090909090909090e856000000909090909090e9caffffff0f8526000000cccccc90909090909090909090e8" ++
    "57000000909090909090e9c9ffffff0f8527000000cccccc90909090909090909090e858000000909090909090e9c8ff" ++
    "ffff0f8528000000cccccc90909090909090909090e859000000909090909090e9c7ffffff0f8529000000cccccc9090" ++
    "9090909090909090e85a000000909090909090e9c6ffffff0f852a000000cccccc90909090909090909090e85b000000" ++
    "909090909090e9c5ffffff0f852b000000cccccc90909090909090909090e85c000000909090909090e9c4ffffff0f85" ++
    "2c000000cccccc90909090909090909090e85d000000909090909090e9c3ffffff0f852d000000cccccc909090909090" ++
    "90909090e85e000000909090909090e9c2ffffff0f852e000000cccccc90909090909090909090e85f00000090909090" ++
    "9090e9c1ffffff0f852f000000cccccc90909090909090909090e860000000909090909090e9c0ffffff0f8530000000" ++
    "cccccc90909090909090909090e861000000909090909090e9bfffffff0f8531000000cccccc90909090909090909090" ++
    "";
const aes256_7z_hex =
    "377abcaf271c0004afccd57250000000000000006a00000000000000c7c6c908de6b8e456ffc7b5c50428e4e0b9f0a2c" ++
    "8f9a7e14097bd39f4128ed576f1e1691e32584058270b96f019801c20e2211feea95d048689d6085e76e54220e5fd111" ++
    "65e82a70ae0f01f6d058d99f8d8e336b0104060001095000070b0100022406f1070112530f65760b89ec46a2e4984b32" ++
    "4173d47a1e2121010001000c45870800080a01434d78ec00000501190011150070006c00610069006e002e0074007800" ++
    "74000000140a0100e6d43ab09c57dd01150601002080a4810000" ++
    "";
const aes_plain_txt_hex =
    "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a546865" ++
    "20717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a546865207175" ++
    "69636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b" ++
    "2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b206272" ++
    "6f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e" ++
    "20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f" ++
    "78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a" ++
    "756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d70" ++
    "73206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f" ++
    "76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f766572" ++
    "20746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f766572207468" ++
    "65206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c" ++
    "617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a79" ++
    "20646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f" ++
    "672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a" ++
    "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a546865" ++
    "20717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a546865207175" ++
    "69636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b" ++
    "2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b206272" ++
    "6f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e" ++
    "20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f" ++
    "78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a" ++
    "756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d70" ++
    "73206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f" ++
    "76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f766572" ++
    "20746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f766572207468" ++
    "65206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c" ++
    "617a7920646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a79" ++
    "20646f672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f" ++
    "672e0a54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a" ++
    "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a546865" ++
    "20717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a546865207175" ++
    "69636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b" ++
    "2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b206272" ++
    "6f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e" ++
    "20666f78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f" ++
    "78206a756d7073206f76657220746865206c617a7920646f672e0a54686520717569636b2062726f776e20666f78206a" ++
    "756d7073206f76657220746865206c617a7920646f672e0a" ++
    "";

test "sevenzip decodes 7zz BCJ2 + LZMA2 folder" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    // Four packed streams: LZMA2 main, call, and jump coders bonded into
    // BCJ2, plus the raw bitmap.
    const testing = std.testing;
    const allocator = testing.allocator;
    const archive_bytes = hexBytes(595, bcj2_lzma2_7z_hex);
    const expected = hexBytes(1200, bcj2_branch_bin_hex);
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);
    var cause: crypto.FailureCause = .none;

    var inspect_ws = try Workspace.init(backing.ptr, backing.len);
    const info = try sevenZipInspectOrdinal(&archive_bytes, &inspect_ws, .{}, 0, crypto.default_provider);
    try testing.expectEqual(CoderMethod.bcj2, info.method);
    try testing.expectEqual(expected.len, info.size);

    var workspace = try Workspace.init(backing.ptr, backing.len);
    const out = try allocator.alloc(u8, expected.len);
    defer allocator.free(out);
    const produced = try sevenZipDecodeOrdinal(&archive_bytes, &workspace, .{}, 0, out, .{ .failure_cause = &cause });
    try testing.expectEqual(expected.len, produced);
    try testing.expectEqualSlices(u8, &expected, out);
}

test "sevenzip decodes 7zz AES-256 encrypted archive" {
    // Mixed provider builds serve no single tag for both arms; run where
    // the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    // Captured from `7zz a -ppassword123` (7zAES, 2^19 KDF rounds, LZMA2).
    const testing = std.testing;
    const allocator = testing.allocator;
    const archive_bytes = hexBytes(218, aes256_7z_hex);
    const expected = hexBytes(1800, aes_plain_txt_hex);
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);
    var cause: crypto.FailureCause = .none;

    var workspace = try Workspace.init(backing.ptr, backing.len);
    const out = try allocator.alloc(u8, expected.len);
    defer allocator.free(out);
    const produced = try sevenZipDecodeOrdinal(&archive_bytes, &workspace, .{}, 0, out, .{ .password = "password123", .failure_cause = &cause });
    try testing.expectEqual(expected.len, produced);
    try testing.expectEqualSlices(u8, &expected, out);

    // A wrong password must fail instead of returning unauthenticated bytes.
    var bad_ws = try Workspace.init(backing.ptr, backing.len);
    if (sevenZipDecodeOrdinal(&archive_bytes, &bad_ws, .{}, 0, out, .{ .password = "wrong", .failure_cause = &cause })) |_| {
        try testing.expect(false);
    } else |_| {
        // The wrong password rejects the decode; that is the expected outcome.
    }
}

test "sevenzip compound filter chain roundtrips" {
    const allocator = std.testing.allocator;

    var executable: [8192]u8 = undefined;
    var rng: u64 = 0x243F6A8885A308D3;
    for (&executable) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @as(u8, @truncate(rng)) & 15;
    }
    const exe_seed: [256]u8 = executable[0..256].*;
    for (0..16) |i| @memcpy(executable[i * 512 ..][0..256], &exe_seed);
    for (0..8) |i| {
        executable[i * 1024] = 0xE8;
        std.mem.writeInt(u32, executable[i * 1024 + 1 ..][0..4], @intCast(4096 -% @as(u32, @intCast(i * 512))), .little);
    }

    const entries = [_]Entry{
        .{ .name = "chained.bin", .data = &executable, .method = .lzma2, .filters = &.{ .delta, .x86 } },
    };
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    const archive_size = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, archive_size);
    defer allocator.free(archive);
    _ = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider, .{}, .{});

    // Our decoder reverses the chain.
    var out: [executable.len]u8 = undefined;
    const n = try sevenZipDecodeOrdinal(archive, &workspace, .{}, 0, &out, .{ .failure_cause = &cause });
    try std.testing.expectEqual(executable.len, n);
    try std.testing.expectEqualSlices(u8, &executable, out[0..n]);
}

test "sevenzip multi-volume write and read" {
    const allocator = std.testing.allocator;

    var payload: [300000]u8 = undefined;
    var rng: u64 = 0x243F6A8885A308D3;
    for (&payload) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @as(u8, @truncate(rng)) & 15;
    }
    for (1..64) |i| @memcpy(payload[i * 4096 ..][0..2048], payload[0..2048]);

    const entries = [_]Entry{
        .{ .name = "big.bin", .data = &payload, .method = .lzma2 },
    };
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    const single_size = try sevenZipPackedSize(&entries, packed_entries, &workspace, crypto.default_provider, .{}, .{});
    const archive = try allocator.alloc(u8, single_size);
    defer allocator.free(archive);
    const volume_size: u64 = 64 * 1024;
    const layout = try sevenZipWritePackedVolumes(&entries, packed_entries, archive, volume_size, &workspace, crypto.default_provider, .{}, .{});
    try std.testing.expect(layout.total_len == single_size);
    try std.testing.expect(layout.volumes > 1);

    const volumes = try allocator.alloc([]const u8, layout.volumes);
    defer allocator.free(volumes);
    var at: usize = 0;
    for (0..layout.volumes) |i| {
        const take = @min(volume_size, single_size - at);
        volumes[i] = archive[at..][0..take];
        at += take;
    }
    const decode_ws_backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(decode_ws_backing);
    var decode_ws = try Workspace.init(decode_ws_backing.ptr, decode_ws_backing.len);
    var out: [payload.len]u8 = undefined;
    const n = try sevenZipDecodeVolumes(volumes, &decode_ws, .{}, 0, &out, .{ .failure_cause = &cause });
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualSlices(u8, &payload, out[0..n]);
}
