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
const bcj2 = @import("../leaf/bcj2.zig");
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
    bcj2,
};

pub const SevenZipEntry = struct {
    name: []const u8,
    data: []const u8,
    method: CoderMethod = .copy,
    filter: ?CoderMethod = null,
    encrypted: bool = false,
    password: []const u8 = &.{},
    iv: [16]u8 = @splat(0),
    iv_set: bool = false,
    // KDF cost knob: 0 selects the default 2^19 rounds, otherwise the power
    // is written verbatim (1..24). 0x3F direct-key mode is decode-only here.
    num_cycles_power: u8 = 0,
    salt: [16]u8 = @splat(0),
    salt_length: u8 = 0,
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
    aes_iv: [16]u8 = @splat(0),
    aes_iv_size: u8 = 0,
    folder: ?*const Folder = null,
    substream_offset: u64 = 0,
    // Per packed-stream sizes of the entry's folder (one stream for ordinary folders, four for
    // BCJ2), pointing into the streams-info workspace slice.
    pack_stream_sizes: []const u64 = &.{},
};

pub const SevenZipDecodeOptions = struct {
    password: ?[]const u8 = null,
    kdf_rounds_limit: u64 = 0,
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
        .bcj2 => &method_7z_bcj2_id,
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
    if (std.mem.eql(u8, id, &method_7z_bcj2_id)) return .bcj2;
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
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv, .bcj2 => 0,
    };
}

const PackedEntry = struct {
    method: CoderMethod,
    data: []const u8,
    crc: u32,
    encrypted: bool = false,
    filter: ?CoderMethod = null,
    iv: [16]u8 = @splat(0),
    salt: [16]u8 = @splat(0),
    salt_length: u8 = 0,
    num_cycles_power: u8 = 0,
    // True when this entry's bytes ride on the previous entry's packed stream
    // (a solid run merged by packAllEntries). buildFolderPlan keys on this so
    // the header's folder plan can never diverge from what was packed.
    solid_continuation: bool = false,
    pack_size: usize = 0,
    unpack_size: usize = 0,
};

fn packBuffer(comptime codec: type, method: CoderMethod, input: []const u8, unpacked_crc: u32, workspace: *Workspace, limits: Limits, scratch_size: usize, options: codec.Options) Failure!PackedEntry {
    const scratch = try workspace.take(u8, scratch_size);
    const packed_size = try codec.requiredSize(input, scratch, options);
    if (packed_size > limits.encoded_bytes) return error.ResourceLimit;
    if (try bounds.addUsize(input.len, packed_size) > limits.codec_work) return error.ResourceLimit;
    const packed_data = try workspace.take(u8, packed_size);
    _ = try codec.encode(input, packed_data, scratch, options);
    return .{ .method = method, .data = packed_data, .crc = unpacked_crc, .pack_size = packed_size, .unpack_size = input.len };
}

fn packEntry(entry: SevenZipEntry, provider: crypto.Provider, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Failure!PackedEntry {
    if (entry.encrypted) {
        if (entry.password.len == 0) return error.InvalidCall;
        if (entry.num_cycles_power > crypto.seven_zip_cycles_max) return error.InvalidCall;
        if (entry.salt_length > 16) return error.InvalidCall;
        const cycles = if (entry.num_cycles_power == 0) crypto.seven_zip_default_cycles else entry.num_cycles_power;
        const rounds: u64 = @as(u64, 1) << @intCast(cycles);
        if (entry.kdf_rounds_limit != 0 and entry.kdf_rounds_limit < rounds) {
            failure_cause.* = .kdf_limit;
            return error.ResourceLimit;
        }
    }
    const unpacked_crc = checksum.crc32With(provider, entry.data);
    const compressed_entry = switch (entry.method) {
        .bcj2 => return error.InvalidCall, // Decode-only; creation never emits BCJ2.
        .copy => blk: {
            if (entry.filter != null) return error.InvalidCall;
            if (entry.data.len > limits.encoded_bytes) return error.ResourceLimit;
            if (entry.data.len > limits.codec_work) return error.ResourceLimit;
            break :blk PackedEntry{ .method = .copy, .data = entry.data, .crc = unpacked_crc, .pack_size = entry.data.len, .unpack_size = entry.data.len };
        },
        .deflate => blk: {
            const measure_history = try workspace.take(u8, deflate.history_size);
            var counter = measurement.Counter.init(null);
            var measure_compressor = deflate.Compress.init(&counter.writer, measure_history, default_deflate_options) catch return error.InsufficientCapacity;
            var measure_source = std.Io.Reader.fixed(entry.data);
            _ = std.Io.Reader.streamRemaining(&measure_source, &measure_compressor.writer) catch return error.IoFailure;
            measure_compressor.finish() catch return error.IoFailure;
            const packed_size = counter.written();
            if (packed_size > limits.encoded_bytes) return error.ResourceLimit;
            if (entry.data.len + packed_size > limits.codec_work) return error.ResourceLimit;
            const packed_data = try workspace.take(u8, packed_size);
            const history = try workspace.take(u8, deflate.history_size);
            var fixed_writer = std.Io.Writer.fixed(packed_data);
            var compressor = deflate.Compress.init(&fixed_writer, history, default_deflate_options) catch return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(entry.data);
            _ = std.Io.Reader.streamRemaining(&source, &compressor.writer) catch return error.IoFailure;
            compressor.finish() catch return error.IoFailure;
            break :blk PackedEntry{ .method = .deflate, .data = packed_data, .crc = unpacked_crc, .pack_size = packed_size, .unpack_size = entry.data.len };
        },
        .bzip2 => try packBuffer(bzip2, .bzip2, entry.data, unpacked_crc, workspace, limits, bzip2.encodeWorkspaceSize(default_bzip2_block), .{ .block_size = default_bzip2_block }),
        .lzma => blk: {
            const properties = lzma2.defaultProperties(default_dictionary);
            const options: lzma.Options = .{ .properties = properties, .unpack_size = entry.data.len, .marker_required = false, .max_work = limits.codec_work };
            break :blk try packBuffer(lzma, .lzma, entry.data, unpacked_crc, workspace, limits, lzma.encodeWorkspaceSizeBt(properties), options);
        },
        .lzma2 => blk: {
            const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
            break :blk try packBuffer(lzma2, .lzma2, entry.data, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
        },
        .ppmd => blk: {
            const options: ppmd.Options = .{ .order = default_ppmd_order, .mem_size = default_ppmd_mem, .unpack_size = entry.data.len, .max_work = limits.codec_work };
            break :blk try packBuffer(ppmd, .ppmd, entry.data, unpacked_crc, workspace, limits, ppmd.encodeWorkspaceSize(default_ppmd_mem), options);
        },
        .delta, .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => blk: {
            if (entry.filter) |explicit| {
                // LZMA1 filter chains stay decodable by every 7z reader and
                // LZMA2 is the modern default, so accept either coder here.
                const filtered = try workspace.take(u8, entry.data.len);
                @memcpy(filtered, entry.data);
                try applyEncodeFilter(explicit, filtered);
                var packed_entry = switch (entry.method) {
                    .lzma => blk2: {
                        const properties = lzma2.defaultProperties(default_dictionary);
                        const options: lzma.Options = .{ .properties = properties, .unpack_size = filtered.len, .marker_required = false, .max_work = limits.codec_work };
                        break :blk2 try packBuffer(lzma, .lzma, filtered, unpacked_crc, workspace, limits, lzma.encodeWorkspaceSizeBt(properties), options);
                    },
                    .lzma2 => blk2: {
                        const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
                        break :blk2 try packBuffer(lzma2, .lzma2, filtered, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
                    },
                    else => return error.InvalidCall,
                };
                packed_entry.filter = explicit;
                break :blk packed_entry;
            }
            const filtered = try workspace.take(u8, entry.data.len);
            @memcpy(filtered, entry.data);
            try applyEncodeFilter(entry.method, filtered);
            const options: lzma2.Options = .{ .dictionary_size = default_dictionary, .properties = lzma2.defaultProperties(default_dictionary), .max_work = limits.codec_work };
            var packed_entry = try packBuffer(lzma2, .lzma2, filtered, unpacked_crc, workspace, limits, lzma2.encodeWorkspaceSizeBt(default_dictionary), options);
            packed_entry.filter = entry.method;
            break :blk packed_entry;
        },
    };
    if (!entry.encrypted) return compressed_entry;
    const password_utf16 = try passwordToUtf16(entry.password, workspace);
    const cycles = if (entry.num_cycles_power == 0) crypto.seven_zip_default_cycles else entry.num_cycles_power;
    var key: [crypto.seven_zip_key_length]u8 = undefined;
    crypto.sevenZipKdf(provider, password_utf16, entry.salt[0..entry.salt_length], cycles, &key);
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
        try crypto.fillRandom(&iv);
    }
    try crypto.aesCbcEncrypt(provider, &key, iv, encrypted_data, encrypted_data);
    return .{ .method = compressed_entry.method, .data = encrypted_data, .crc = compressed_entry.crc, .encrypted = true, .filter = compressed_entry.filter, .iv = iv, .salt = entry.salt, .salt_length = entry.salt_length, .num_cycles_power = cycles, .pack_size = compressed_entry.pack_size, .unpack_size = compressed_entry.unpack_size };
}

fn applyEncodeFilter(method: CoderMethod, data: []u8) Failure!void {
    switch (method) {
        .delta => delta.encode(data, 0),
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => bcj.encode(bcjKindFromMethod(method), 0, data),
        else => return error.InvalidCall,
    }
}

fn packAllEntries(entries: []const SevenZipEntry, provider: crypto.Provider, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Failure![]const PackedEntry {
    const packed_entries = try workspace.take(PackedEntry, nonEmptyCount(entries));
    var index: usize = 0;
    var i: usize = 0;
    while (i < entries.len) {
        if (isEmptyEntry(entries[i])) {
            i += 1;
            continue;
        }
        // One folder and one continuous codec stream per run, so coder state
        // carries across the substreams as in ip7z/7zip's solid folders.
        if ((entries[i].method == .lzma2 or entries[i].method == .ppmd) and !entries[i].encrypted) {
            var j = i + 1;
            while (j < entries.len and !isEmptyEntry(entries[j]) and entries[j].method == entries[i].method and !entries[j].encrypted and entries[j].filter == entries[i].filter) j += 1;
            if (j - i >= 2) {
                var total: usize = 0;
                for (entries[i..j]) |entry| total = try bounds.addUsize(total, entry.data.len);
                if (total > limits.codec_work) return error.ResourceLimit;
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
                if (packed_size > limits.encoded_bytes) return error.ResourceLimit;
                if (try bounds.addUsize(total, packed_size) > limits.codec_work) return error.ResourceLimit;
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

pub fn sevenZipPack(entries: []const SevenZipEntry, provider: crypto.Provider, workspace: *Workspace, limits: Limits, failure_cause: *crypto.FailureCause) Failure![]const PackedEntry {
    failure_cause.* = .none;
    return try packAllEntries(entries, provider, workspace, limits, failure_cause);
}

fn requiredSizeFromPacked(entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!usize {
    var total_pack_size: usize = 0;
    const plan = try buildFolderPlan(packed_entries, workspace);
    for (plan) |folder| total_pack_size = try bounds.addUsize(total_pack_size, packed_entries[folder.first].data.len);
    var counter = measurement.Counter.init(null);
    try writeHeader(&counter.writer, entries, packed_entries, workspace);
    const header_size = counter.written();
    const total = try bounds.addUsize(try bounds.addUsize(start_header_size, total_pack_size), std.math.cast(usize, header_size) orelse return error.ResourceLimit);
    return std.math.cast(usize, total) orelse error.ResourceLimit;
}

pub fn sevenZipPackedSize(entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace) Failure!usize {
    return try requiredSizeFromPacked(entries, packed_entries, workspace);
}

fn writeArchive(output: []u8, entries: []const SevenZipEntry, packed_entries: []const PackedEntry, workspace: *Workspace, provider: crypto.Provider) Failure!usize {
    const required = try requiredSizeFromPacked(entries, packed_entries, workspace);
    if (output.len < required) return error.InsufficientCapacity;
    var total_pack_size: usize = 0;
    const plan = try buildFolderPlan(packed_entries, workspace);
    for (plan) |folder| total_pack_size = try bounds.addUsize(total_pack_size, packed_entries[folder.first].data.len);
    const header_offset = start_header_size + total_pack_size;
    var header_writer = std.Io.Writer.fixed(output[header_offset..]);
    try writeHeader(&header_writer, entries, packed_entries, workspace);
    const header_size = header_writer.end;
    const header_crc = checksum.crc32With(provider, output[header_offset..][0..header_size]);
    var start_header: [20]u8 = undefined;
    std.mem.writeInt(u64, start_header[0..8], total_pack_size, .little);
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
    return required;
}

pub fn sevenZipWritePacked(entries: []const SevenZipEntry, packed_entries: []const PackedEntry, output: []u8, workspace: *Workspace, provider: crypto.Provider) Failure!usize {
    return try writeArchive(output, entries, packed_entries, workspace, provider);
}

pub fn sevenZipInspectCount(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, provider: crypto.Provider) Failure!u64 {
    const loaded = try loadArchive(archive_bytes, workspace, limits, provider);
    return loaded.count;
}

pub fn sevenZipInspectOrdinal(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, provider: crypto.Provider) Failure!SevenZipInfo {
    const loaded = try loadArchive(archive_bytes, workspace, limits, provider);
    if (ordinal >= loaded.count) return error.InvalidData;
    return loaded.entries[ordinal];
}

pub fn sevenZipDecodeOrdinal(archive_bytes: []const u8, workspace: *Workspace, limits: Limits, ordinal: u64, output: []u8, decode_options: SevenZipDecodeOptions) Failure!usize {
    decode_options.failure_cause.* = .none;
    const loaded = try loadArchive(archive_bytes, workspace, limits, decode_options.provider);
    if (ordinal >= loaded.count) return error.InvalidData;
    const entry = loaded.entries[ordinal];
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
            try readAt(loaded.data, entry.data_offset, packed_data);
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
        try readAt(loaded.data, entry.data_offset, packed_data);
        const password_utf16 = try passwordToUtf16(password, workspace);
        var key: [crypto.seven_zip_key_length]u8 = undefined;
        if (entry.aes_num_cycles == 0x3F) {
            var key_material: [64]u8 = @splat(0);
            @memcpy(key_material[0..entry.aes_salt.len], entry.aes_salt);
            @memcpy(key_material[entry.aes_salt.len..][0..password_utf16.len], password_utf16);
            @memcpy(&key, key_material[0..32]);
        } else {
            crypto.sevenZipKdf(decode_options.provider, password_utf16, entry.aes_salt, entry.aes_num_cycles, &key);
        }
        const decrypted = try workspace.take(u8, pack_size);
        try crypto.aesCbcDecrypt(decode_options.provider, &key, entry.aes_iv, decrypted, packed_data);
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
            const decoded = try bzip2.decode(decrypted_packed, decode_output, scratch, decode_options.provider);
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
            const dictionary = lzma2.dictionarySizeFromProperties(try readLzma2Prop(entry.attributes));
            if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.Unsupported;
            const options: lzma2.Options = .{ .dictionary_size = dictionary, .properties = lzma2.defaultProperties(dictionary), .max_work = limits.codec_work };
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
        .bcj2 => {
            const folder = entry.folder orelse return error.InvalidData;
            const written = try decodeBcj2Folder(folder, entry.pack_stream_sizes, decrypted_packed, decode_output[0..decode_target_len], workspace, limits);
            if (written != decode_target_len) return error.InvalidData;
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
        if (checksum.crc32With(decode_options.provider, output[0..size]) != expected) return error.IntegrityFailure;
    }
    return size;
}

fn readLzma2Prop(attributes: []const u8) Failure!u8 {
    if (attributes.len != 1) return error.InvalidData;
    return attributes[0];
}

// Recombines a BCJ2 folder. Each of the four inputs is a raw packed stream or the decoded
// output of one of the folder's compressor coders, per `folder.bcj2_sources`.
fn decodeBcj2Folder(folder: *const Folder, pack_sizes: []const u64, packed_data: []const u8, output: []u8, workspace: *Workspace, limits: Limits) Failure!usize {
    if (!folder.bcj2 or pack_sizes.len != 4) return error.InvalidData;
    var packed_offset: usize = 0;
    var packed_slices: [4][]const u8 = undefined;
    for (0..4) |k| {
        const size = std.math.cast(usize, pack_sizes[k]) orelse return error.ResourceLimit;
        packed_offset = try bounds.addUsize(packed_offset, size);
        if (packed_offset > packed_data.len) return error.InvalidData;
        packed_slices[k] = packed_data[packed_offset - size .. packed_offset];
    }
    var substreams: [4][]const u8 = undefined;
    for (0..4) |k| {
        const source = folder.bcj2_sources[k];
        const ordinal = std.math.cast(usize, source.pack_ordinal) orelse return error.ResourceLimit;
        if (ordinal >= 4) return error.InvalidData;
        const slice = packed_slices[ordinal];
        if (source.producer) |coder_index| {
            if (coder_index >= folder.coders.len) return error.InvalidData;
            substreams[k] = try decodeBcj2Substream(folder.coders[coder_index], slice, workspace, limits);
        } else {
            substreams[k] = slice;
        }
    }
    return bcj2.decode(substreams[0], substreams[1], substreams[2], substreams[3], output);
}

fn decodeBcj2Substream(coder: ParsedCoder, packed_data: []const u8, workspace: *Workspace, limits: Limits) Failure![]const u8 {
    switch (coder.method) {
        .copy => return packed_data,
        .lzma2 => {
            const dictionary = lzma2.dictionarySizeFromProperties(try readLzma2Prop(coder.attributes));
            if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.Unsupported;
            const options: lzma2.Options = .{ .dictionary_size = dictionary, .properties = lzma2.defaultProperties(dictionary), .max_work = limits.codec_work };
            const scratch = try workspace.take(u8, lzma2.decodeWorkspaceSize(dictionary));
            const decoded_size = try lzma2.decodedSize(packed_data, scratch, options);
            if (decoded_size > limits.decoded_bytes) return error.ResourceLimit;
            const buffer = try workspace.take(u8, decoded_size);
            const decoded = try lzma2.decode(packed_data, buffer, scratch, options);
            return buffer[0..decoded];
        },
        else => return error.Unsupported,
    }
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
    const end = try bounds.addUsize(start, buffer.len);
    if (end > data.len) return error.InvalidData;
    @memcpy(buffer, data[start..end]);
}

fn loadArchive(data: []const u8, workspace: *Workspace, limits: Limits, provider: crypto.Provider) Failure!LoadedArchive {
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
    const start_header_crc = checksum.crc32With(provider, start_buffer[12..32]);
    if (recorded_start_crc != start_header_crc) return error.IntegrityFailure;
    const next_header_offset = std.mem.readInt(u64, start_buffer[12..20], .little);
    const next_header_size = std.mem.readInt(u64, start_buffer[20..28], .little);
    const recorded_header_crc = std.mem.readInt(u32, start_buffer[28..32], .little);
    if (next_header_size > limits.metadata_records) return error.ResourceLimit;
    const header_start = try bounds.addU64(start_header_size, next_header_offset);
    const header_size_usize = std.math.cast(usize, next_header_size) orelse return error.ResourceLimit;
    const header_buffer = try workspace.take(u8, header_size_usize);
    try readAt(archive.data, header_start, header_buffer);
    if (checksum.crc32With(provider, header_buffer) != recorded_header_crc) return error.IntegrityFailure;
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

const Bond = struct {
    in_index: u64,
    coder_index: u64,
};

// Where one of a BCJ2 coder's four inputs comes from: a raw packed stream at the ordinal,
// or the decoded output of a compressor coder (whose own input is at `pack_ordinal`).
const Bcj2Source = struct {
    pack_ordinal: u64,
    producer: ?usize = null,
};

const Folder = struct {
    num_substreams: u64,
    substream_sizes: []u64,
    substream_crcs: []const u32,
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
    packed_inputs: []const u64 = &.{},
    bcj2: bool = false,
    // Where the BCJ2 coder's four inputs begin in the input stream index space.
    bcj2_in_base: u64 = 0,
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
    // Packed streams are per-folder runs, and a BCJ2 folder owns four, so the runs tile the
    // pack size array in folder order.
    var next_pack_index: usize = 0;
    for (folders) |*folder| {
        folder.pack_index = next_pack_index;
        const run = std.math.cast(usize, folder.num_pack_streams) orelse return error.ResourceLimit;
        next_pack_index = try bounds.addUsize(next_pack_index, run);
    }
    if (next_pack_index != pack_sizes.len) return error.InvalidData;
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
        // A BCJ2 folder carries four compressor coders and the recombiner, so the bound leaves
        // headroom without going open-ended.
        if (num_coders < 1 or num_coders > 8) return error.Unsupported;
        const coder_count = std.math.cast(usize, num_coders) orelse return error.ResourceLimit;
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
        var folder_in_streams: u64 = 0;
        var folder_out_streams: u64 = 0;
        const coder_in_base = try workspace.take(u64, coder_count);
        const coder_out_base = try workspace.take(u64, coder_count);
        for (coders, 0..) |coder, i| {
            coder_in_base[i] = folder_in_streams;
            coder_out_base[i] = folder_out_streams;
            folder_in_streams = try bounds.addUsize(folder_in_streams, coder.num_in_streams);
            folder_out_streams = try bounds.addUsize(folder_out_streams, coder.num_out_streams);
            if (std.mem.eql(u8, coder.method_id, &method_7z_aes_id)) {
                if (encrypted) return error.Unsupported;
                encrypted = true;
                aes = try parse7zAesProps(coder.attributes);
            } else if (coder.method == .bcj2) {
                if (bcj2_idx != null) return error.Unsupported;
                bcj2_idx = i;
            } else if (isFilterMethod(coder.method)) {
                filter_present = true;
            } else {
                data_coder_count += 1;
                last_data = coder;
            }
        }
        if (data_coder_count == 0 or (encrypted and data_coder_count != 1)) return error.Unsupported;
        if (bcj2_idx != null and (encrypted or filter_present)) return error.Unsupported;
        var method = last_data.?.method;
        var attributes = last_data.?.attributes;
        var num_in_streams = last_data.?.num_in_streams;
        var num_out_streams = last_data.?.num_out_streams;
        var bonds: []const Bond = &.{};
        var packed_inputs: []const u64 = &.{};
        var bcj2_sources: [4]Bcj2Source = undefined;
        const bcj2_in_base = if (bcj2_idx) |i| coder_in_base[i] else 0;
        if (num_coders > 1) {
            const num_bonds = num_coders - 1;
            const bond_count = std.math.cast(usize, num_bonds) orelse return error.ResourceLimit;
            const bond_list = try workspace.take(Bond, bond_count);
            var bond: u64 = 0;
            while (bond < num_bonds) : (bond += 1) {
                const in_index = try readUint64(cursor);
                const coder_index = try readUint64(cursor);
                if (in_index >= folder_in_streams or coder_index >= num_coders) return error.InvalidData;
                // An input stream feeds from exactly one place, so a repeat means a malformed folder.
                for (bond_list[0..@intCast(bond)]) |existing| {
                    if (existing.in_index == in_index) return error.InvalidData;
                }
                bond_list[@intCast(bond)] = .{ .in_index = in_index, .coder_index = coder_index };
            }
            bonds = bond_list;
            const num_packed_streams = folder_in_streams - num_bonds;
            if (num_packed_streams == 0) return error.InvalidData;
            if (num_packed_streams != 1) {
                const packed_count = std.math.cast(usize, num_packed_streams) orelse return error.ResourceLimit;
                const packed_list = try workspace.take(u64, packed_count);
                var packed_index: u64 = 0;
                while (packed_index < num_packed_streams) : (packed_index += 1) {
                    const index = try readUint64(cursor);
                    if (index >= folder_in_streams) return error.InvalidData;
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
                    if (coders[ci].num_in_streams != 1 or coders[ci].method == .bcj2) return error.Unsupported;
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
            .packed_inputs = packed_inputs,
            .bcj2 = bcj2_idx != null,
            .bcj2_in_base = bcj2_in_base,
            .bcj2_sources = bcj2_sources,
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
        // The folder's data is the one output no bond consumes. For the common single-coder
        // folder that is the last (only) stream.
        const sink = folderSinkOutput(folder) orelse (stream_count - 1);
        folder.unpack_size = arr[sink];
        folder.substream_sizes = arr[sink .. sink + 1];
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
    return folders;
}

// Maps a global input stream index to its ordinal among the folder's packed streams. A
// bonded (coder-fed) input has no packed ordinal.
fn packedOrdinal(packed_inputs: []const u64, num_packed_streams: u64, global_in: u64) Failure!u64 {
    if (packed_inputs.len != 0) {
        for (packed_inputs, 0..) |input, ordinal| {
            if (input == global_in) return ordinal;
        }
        return error.Unsupported;
    }
    if (num_packed_streams == 1 and global_in == 0) return 0;
    return error.Unsupported;
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
                if (folder.coders[bond.coder_index].num_out_streams == 1 and globalOutputBase(folder, bond.coder_index) == global_out) consumed = true;
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
    if (method == .bcj2) {
        // BCJ2 is the one many-to-one coder, with four sub-stream inputs and one output.
        if (num_in_streams != 4 or num_out_streams != 1) return error.Unsupported;
    } else if (num_in_streams != 1 or num_out_streams != 1) return error.Unsupported;
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
        return .{ .num_cycles = num_cycles, .salt = &.{}, .iv = @splat(0), .iv_size = 0 };
    }
    if (attributes.len <= 1) return error.InvalidData;
    const b1 = attributes[1];
    const salt_size = @as(usize, (b0 >> 7) & 1) + (b1 >> 4);
    const iv_size = @as(usize, (b0 >> 6) & 1) + (b1 & 0x0F);
    if (attributes.len != 2 + salt_size + iv_size) return error.InvalidData;
    if (num_cycles > crypto.seven_zip_cycles_max and num_cycles != 0x3F) return error.Unsupported;
    var iv: [16]u8 = @splat(0);
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
                    // The size list omits each folder's final substream: it is
                    // the folder's unpack total minus the listed sizes.
                    var known: u64 = 0;
                    for (arr[index .. index + count - 1]) |size| {
                        known = try bounds.addU64(known, size);
                    }
                    if (known > folder.unpack_size) return error.InvalidData;
                    arr[index + count - 1] = folder.unpack_size - known;
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
        total = try bounds.addUsize(total, count);
    }
    return total;
}

fn substreamSizeCount(folders: []const Folder) Failure!usize {
    var total: usize = 0;
    for (folders) |folder| {
        const count = std.math.cast(usize, folder.num_substreams) orelse return error.ResourceLimit;
        if (count > 0) total = try bounds.addUsize(total, count - 1);
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
            sum = try bounds.addU64(sum, size);
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
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19 => {},
            // kStartPos shifts per-file data offsets; pack offsets here are
            // computed sequentially, so accepting it would mis-locate data.
            0x18 => return error.Unsupported,
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
        var aes_iv: [16]u8 = @splat(0);
        var aes_iv_size: u8 = 0;
        var entry_folder: ?*const Folder = null;
        var file_substream_offset: u64 = 0;
        var entry_pack_stream_sizes: []const u64 = &.{};
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
            const pack_run = std.math.cast(usize, folder.num_pack_streams) orelse return error.ResourceLimit;
            if (folder.pack_index + pack_run > si.pack_sizes.len) return error.InvalidData;
            entry_pack_stream_sizes = si.pack_sizes[folder.pack_index..][0..pack_run];
            for (entry_pack_stream_sizes) |stream_size| {
                pack_size = try bounds.addU64(pack_size, stream_size);
            }
            if (pack_size > limits.encoded_bytes) return error.ResourceLimit;
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
            .pack_stream_sizes = entry_pack_stream_sizes,
        };
    }
    if (folder_index != si.folders.len) return error.InvalidData;
    return entries;
}

fn folderPackOffset(si: *const StreamsInfo, folder_index: usize) Failure!u64 {
    var offset = si.pack_pos;
    for (0..folder_index) |index| {
        const run = std.math.cast(usize, si.folders[index].num_pack_streams) orelse return error.ResourceLimit;
        for (0..run) |sub| {
            offset = try bounds.addU64(offset, si.pack_sizes[si.folders[index].pack_index + sub]);
        }
    }
    return offset;
}

fn folderOutputSize(folder: *const Folder) Failure!usize {
    var total: usize = 0;
    for (folder.substream_sizes) |size| {
        const part = std.math.cast(usize, size) orelse return error.ResourceLimit;
        total = try bounds.addUsize(total, part);
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
        // Solid membership was decided by packAllEntries and is recorded on
        // the entry; grouping by any other rule desyncs the header from the
        // packed bytes (directories and encrypted entries break runs there,
        // so they must break folders here too).
        while (j < packed_entries.len and packed_entries[j].solid_continuation) j += 1;
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
        total = try bounds.addUsize(total, entry.data.len);
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
            const salt_size: usize = p.salt_length;
            const iv_size: usize = 16;
            // Sizes encode as a 1-bit high half plus a 4-bit low half that
            // SUM to the size, so 16 is high=1 low=15 (see parseAesProps).
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
        if (p.encrypted) try writeUint64(writer, p.pack_size);
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
                var bytes: [8]u8 = @splat(0);
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
    var zero: [2]u8 = @splat(0);
    try io.writeBytes(writer, &zero);
}

fn passwordToUtf16(password: []const u8, workspace: *Workspace) Failure![]const u8 {
    const view = std.unicode.Utf8View.init(password) catch return error.InvalidData;
    var byte_len: usize = 0;
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| byte_len = try bounds.addUsize(byte_len, if (cp < 0x10000) 2 else 4);
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

test "sevenzip ppmd solid grouping roundtrip" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);

    var repetitive: [4096]u8 = undefined;
    for (&repetitive, 0..) |*byte, i| byte.* = @truncate(i / 97);
    const datas = [_][]const u8{ repetitive[0..1500], repetitive[500..2000], repetitive[1000..2500] };
    const entries = [_]SevenZipEntry{
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
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace);
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider);
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

test "sevenzip encrypted roundtrip with salt and custom cycles" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 64 * 1024 * 1024);
    defer allocator.free(backing);
    const data = "seven zip secret seven zip secret seven zip secret";
    var salt: [16]u8 = undefined;
    for (&salt, 0..) |*byte, i| byte.* = @intCast(i + 1);
    const entries = [_]SevenZipEntry{
        .{ .name = "enc.bin", .data = data, .method = .copy, .encrypted = true, .password = "pw", .num_cycles_power = 10, .salt = salt, .salt_length = 16 },
    };
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace);
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider);
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
    try testing.expectError(error.ResourceLimit, sevenZipDecodeOrdinal(archive, &refuse_ws, .{}, 0, refuse_out, .{
        .password = "pw",
        .kdf_rounds_limit = (1 << 10) - 1,
        .failure_cause = &cause,
    }));
    try testing.expectEqual(crypto.FailureCause.kdf_limit, cause);
}

test "sevenzip folder plan stays consistent across directory and encryption breaks" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    var repetitive: [2048]u8 = undefined;
    for (&repetitive, 0..) |*byte, i| byte.* = @truncate(i / 31);
    const first = repetitive[0..1000];
    const second = repetitive[400..1400];

    // Case 1: two lzma2 entries split by a directory entry. packAllEntries
    // breaks the solid run at the directory, so the header must declare two
    // folders / two pack streams — one folder here used to lose the second
    // entry's bytes entirely.
    const with_dir = [_]SevenZipEntry{
        .{ .name = "a.bin", .data = first, .method = .lzma2 },
        .{ .name = "sub/", .data = &.{}, .method = .copy },
        .{ .name = "b.bin", .data = second, .method = .lzma2 },
    };
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_dir = try sevenZipPack(&with_dir, crypto.default_provider, &workspace, .{}, &cause);
    const total_dir = try sevenZipPackedSize(&with_dir, packed_dir, &workspace);
    const archive_dir = try allocator.alloc(u8, total_dir);
    defer allocator.free(archive_dir);
    const written_dir = try sevenZipWritePacked(&with_dir, packed_dir, archive_dir, &workspace, crypto.default_provider);
    try testing.expectEqual(total_dir, written_dir);
    // Ordinals 0 and 2: ordinal 1 is the directory entry between them.
    for ([_][]const u8{ first, second }, 0..) |data, i| {
        var decode_ws = try Workspace.init(backing.ptr, backing.len);
        const out = try allocator.alloc(u8, data.len);
        defer allocator.free(out);
        const produced = try sevenZipDecodeOrdinal(archive_dir, &decode_ws, .{}, if (i == 0) 0 else 2, out, .{ .failure_cause = &cause });
        try testing.expectEqualSlices(u8, data, out[0..produced]);
    }

    // Case 2: two encrypted lzma2 entries. Encryption never joins solid runs,
    // so each entry is its own folder with its own pack stream and IV.
    const encrypted_pair = [_]SevenZipEntry{
        .{ .name = "enc-a.bin", .data = first, .method = .lzma2, .encrypted = true, .password = "pw" },
        .{ .name = "enc-b.bin", .data = second, .method = .lzma2, .encrypted = true, .password = "pw" },
    };
    var enc_workspace = try Workspace.init(backing.ptr, backing.len);
    const packed_enc = try sevenZipPack(&encrypted_pair, crypto.default_provider, &enc_workspace, .{}, &cause);
    const total_enc = try sevenZipPackedSize(&encrypted_pair, packed_enc, &enc_workspace);
    const archive_enc = try allocator.alloc(u8, total_enc);
    defer allocator.free(archive_enc);
    const written_enc = try sevenZipWritePacked(&encrypted_pair, packed_enc, archive_enc, &enc_workspace, crypto.default_provider);
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
    const testing = std.testing;
    const allocator = testing.allocator;
    const backing = try allocator.alloc(u8, 96 * 1024 * 1024);
    defer allocator.free(backing);
    var repetitive: [97]u8 = undefined;
    const corpus_01 = "Squdgy fez, blank jimp crwth vox!";
    for (&repetitive, 0..) |*byte, i| byte.* = corpus_01[i % corpus_01.len];
    const data = repetitive[0..97];
    const entries = [_]SevenZipEntry{
        .{ .name = "l2.txt", .data = data, .method = .lzma2, .encrypted = true, .password = "pw" },
    };
    var workspace = try Workspace.init(backing.ptr, backing.len);
    var cause: crypto.FailureCause = .none;
    const packed_entries = try sevenZipPack(&entries, crypto.default_provider, &workspace, .{}, &cause);
    const total = try sevenZipPackedSize(&entries, packed_entries, &workspace);
    const archive = try allocator.alloc(u8, total);
    defer allocator.free(archive);
    const written = try sevenZipWritePacked(&entries, packed_entries, archive, &workspace, crypto.default_provider);
    try testing.expectEqual(total, written);
    var decode_ws = try Workspace.init(backing.ptr, backing.len);
    const out = try allocator.alloc(u8, data.len);
    defer allocator.free(out);
    const produced = try sevenZipDecodeOrdinal(archive, &decode_ws, .{}, 0, out, .{ .password = "pw", .failure_cause = &cause });
    try testing.expectEqualSlices(u8, data, out[0..produced]);
}

test "sevenzip decode captured failing encrypted archive" {
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

// Captured from ip7z/7zip 26.x CLI output (`7zz a -m0=BCJ2 -m1=LZMA2 -mx=5`) and inlined
// as hex, so no binary fixture enters the tree.
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
    // The folder arrives as four packed streams: the LZMA2 main, call, and jump coders bonded
    // into the BCJ2 recombiner, plus the raw range-coded bitmap.
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
    } else |_| {}
}
