const std = @import("std");

const binary = @import("../common/primitive/binary.zig");
const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;

const sink = @import("rar/sink.zig");
const blake2sp = @import("rar/blake2sp.zig");
const filters50 = @import("rar/filters50.zig");
const unpack50 = @import("rar/unpack50.zig");
const unpack29 = @import("rar/unpack29.zig");
const unpack20 = @import("rar/unpack20.zig");
const pack50 = @import("rar/pack50.zig");
const finder = @import("rar/finder.zig");

// Family detection, archive walking, entry decode (store, RAR5 LZ, RAR3
// PPMd/LZ, RAR2 LZ/audio), and RAR5 creation, all on caller-provided storage
// carved by the hook from the call workspace.

pub const RarInfo = struct {
    name: []const u8,
    size: u64,
    data_offset: u64,
    packed_size: u64,
    crc: u32,
    // False when the producer recorded no CRC32 (RAR5 blake2-only entries):
    // 0 is a legitimate CRC32 value, so presence must be tracked separately.
    has_crc: bool = true,
    ordinal: usize,
    // Decode-side requirements, resolved during the walk so the caller can
    // size the engine buffers before decoding: which engine and how large a
    // window it must build. Zero for store entries.
    family: enum { rar4, rar5 } = .rar5,
    method: u8 = 0,
    unpack_version: u8 = 0,
    window_bytes: u64 = 0,
};

pub const Entry = struct {
    info: RarInfo,
    family: enum { rar4, rar5 },
    is_directory: bool,
    // Normalized method: 0 = store, 1-5 = LZ level. RAR4 stores the raw
    // 0x30-0x35 byte's low nibble; RAR5 the compression info's method field.
    method: u8,
    // RAR4: unpack version (15/20/26/29/36). RAR5: normalized algorithm
    // version (50 or 70).
    unpack_version: u8,
    solid: bool,
    file_flags: u16, // RAR4 raw flags (dictionary code lives here)
    dict_bits: u6, // RAR5 window exponent from the compression info
    blake2: ?[32]u8,
};

const Family = @TypeOf(@as(Entry, undefined).family);

pub const rar4_signature = [7]u8{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 };
const sfx_scan_limit: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Workspace plans
// ---------------------------------------------------------------------------

// Decode-side buffers, carved by the caller (the compose hook) from the call
// workspace. Only one engine state is live at a time; `state` holds whichever
// is in use. `ppm_heap` must be the LAST carve of the workspace so PPMd can
// grow to whatever the stream requests within what remains.
pub const DecodeBuffers = struct {
    state: []align(8) u8,
    window: []u8,
    table_pool: []u16,
    pending50: []filters50.Filter,
    pending29: []unpack29.PendingFilter,
    filter_scratch: []u8,
    ppm_heap: []u8,

    pub fn state50(self: *DecodeBuffers) Failure!*unpack50.State {
        if (self.state.len < @sizeOf(unpack50.State)) return error.InternalFailure;
        return @ptrCast(@alignCast(self.state.ptr));
    }

    pub fn state29(self: *DecodeBuffers) Failure!*unpack29.State {
        if (self.state.len < @sizeOf(unpack29.State)) return error.InternalFailure;
        return @ptrCast(@alignCast(self.state.ptr));
    }

    pub fn state20(self: *DecodeBuffers) Failure!*unpack20.State {
        if (self.state.len < @sizeOf(unpack20.State)) return error.InternalFailure;
        return @ptrCast(@alignCast(self.state.ptr));
    }
};

// Largest decode table pool across engines (unpack50 uses four tables of
// 446 words each; unpack29 four of 404; unpack20 1402 total).
pub const table_pool_words = unpack50.table_pool_words * 4;

// Window ceilings per family: RAR4 caps at 4 MB (dict code 6); RAR5 declares
// its own (base 0x20000 << dict_bits, 4-bit exponent for v50).
pub const max_rar4_window: usize = 4 * 1024 * 1024;
pub const max_rar5_window_bits: u6 = 31; // 0x20000 << 14 already is 2^31; refuse beyond
pub const max_pending50 = unpack50.max_pending_filters;
pub const max_pending29 = unpack29.max_pending_filters;
pub const PendingFilter50 = filters50.Filter;
pub const PendingFilter29 = unpack29.PendingFilter;
pub const LzToken = finder.LzToken;
pub const pack50Sizes = pack50.workspacesFor;
pub const filter_scratch_extra = filters50.max_filter_block;

// Write-side buffers for archive creation.
pub const WriteBuffers = struct {
    hash: []u32,
    hash2: []u32,
    hash3: []u32,
    bt_left: []u32,
    bt_right: []u32,
    tokens: []finder.LzToken,
    staging: []u8, // block compressor staging: 2x input + slack
    packed_buf: []u8, // all entries' packed data, laid out back to back
    packed_sizes: []usize,
};

pub const write_sizes = struct {
    pub const hash_words = finder.MatchFinder.hash_size;
    pub const hash2_words = finder.MatchFinder.hash2_size;
    pub const hash3_words = finder.MatchFinder.hash3_size;
};

// Per-entry packed-size bound used to lay out `packed`.
pub fn packedBound(entry: RarEntry) usize {
    if (entry.is_directory or entry.data.len == 0 or entry.method == 0) return entry.data.len;
    return entry.data.len * pack50.max_expansion + pack50.output_slack;
}

// ---------------------------------------------------------------------------
// Family detection
// ---------------------------------------------------------------------------

fn detectFamily(archive: []const u8) Failure!struct { family: Family, offset: usize } {
    if (archive.len >= rar4_signature.len and
        std.mem.eql(u8, archive[0..rar4_signature.len], &rar4_signature))
        return .{ .family = .rar4, .offset = 0 };

    // RAR5 with an SFX prefix: scan for the 8-byte signature, then confirm a
    // main block follows.
    const sig50 = rar5_signature;
    if (archive.len < sig50.len) return error.InvalidData;
    const limit = @min(archive.len, sfx_scan_limit);
    var offset: usize = 0;
    while (offset <= limit - sig50.len) : (offset += 1) {
        if (!std.mem.eql(u8, archive[offset..][0..sig50.len], &sig50)) continue;
        if (offset == 0) return .{ .family = .rar5, .offset = 0 };
        var cursor = offset + sig50.len;
        const header = parseRar5Block(archive, &cursor) catch continue;
        if (header.header_type == rar5_type_main) return .{ .family = .rar5, .offset = offset };
    }
    return error.InvalidData;
}

const rar5_signature = [8]u8{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };
const rar5_type_main: u64 = 1;
const rar5_type_file: u64 = 2;
const rar5_type_service: u64 = 3;
const rar5_type_encryption: u64 = 4;
const rar5_type_end: u64 = 5;
const rar5_flag_extra: u64 = 0x0001;
const rar5_flag_data: u64 = 0x0002;
const rar5_flag_split_before: u64 = 0x0008;
const rar5_flag_split_after: u64 = 0x0010;
const rar5_flag_solid_dep: u64 = 0x0020;
const rar5_flag_child: u64 = 0x0040;
const rar5_archive_volume: u64 = 0x0001;
const rar5_archive_volnum: u64 = 0x0002;
const rar5_file_directory: u64 = 0x0001;
const rar5_file_mtime: u64 = 0x0002;
const rar5_file_crc32: u64 = 0x0004;
const rar5_file_size_unknown: u64 = 0x0008;
const rar5_extra_crypt: u64 = 0x01;
const rar5_extra_hash: u64 = 0x02;
const rar5_extra_redir: u64 = 0x05;
const rar5_hash_blake2sp: u64 = 0x00;

// ---------------------------------------------------------------------------
// RAR5 block walking
// ---------------------------------------------------------------------------

const Rar5Block = struct {
    header_type: u64,
    header_flags: u64,
    data_offset: u64 = 0, // absolute offset of the data area
    data_size: u64 = 0,
    // file-block fields (valid when header_type == file/service)
    file_flags: u64 = 0,
    unpacked_size: u64 = 0,
    data_crc32: u32 = 0,
    compression: u64 = 0,
    name: []const u8 = &.{},
    blake2: ?[32]u8 = null,
    is_directory: bool = false,
    archive_flags: u64 = 0,
};

fn parseRar5Block(archive: []const u8, cursor: *usize) Failure!Rar5Block {
    const crc_offset = cursor.*;
    const crc_bytes = try bounds.slice(archive, crc_offset, 4);
    cursor.* = try bounds.add(cursor.*, 4);
    const header_start = cursor.*;
    var sub = binary.ReadCursor.init(archive[cursor.*..]);
    const size = try sub.readULEB128();
    if (size == 0 or size > 2 * 1024 * 1024) return error.InvalidData;
    const header_body_start = cursor.* + sub.pos;
    const header_body_end = try bounds.add(header_body_start, std.math.cast(usize, size) orelse return error.ResourceLimit);
    if (header_body_end > archive.len) return error.InvalidData;
    const recorded_crc = std.mem.readInt(u32, crc_bytes[0..4], .little);
    const computed_crc = checksum.crc32(archive[header_start..header_body_end]);
    if (computed_crc != recorded_crc) return error.IntegrityFailure;
    const htype = try sub.readULEB128();
    const flags = try sub.readULEB128();
    var extra_size: u64 = 0;
    if (flags & rar5_flag_extra != 0) extra_size = try sub.readULEB128();
    var data_size: u64 = 0;
    if (flags & rar5_flag_data != 0) data_size = try sub.readULEB128();

    var result: Rar5Block = .{
        .header_type = htype,
        .header_flags = flags,
        .data_size = data_size,
    };
    result.data_offset = header_body_end;

    switch (htype) {
        rar5_type_main => {
            result.archive_flags = try sub.readULEB128();
            if (result.archive_flags & rar5_archive_volnum != 0) {
                _ = try sub.readULEB128();
            }
        },
        rar5_type_file, rar5_type_service => {
            if (flags & (rar5_flag_split_before | rar5_flag_split_after | rar5_flag_solid_dep | rar5_flag_child) != 0)
                return error.Unsupported;
            result.file_flags = try sub.readULEB128();
            result.unpacked_size = try sub.readULEB128();
            _ = try sub.readULEB128(); // attributes
            if (result.file_flags & rar5_file_mtime != 0) {
                _ = try sub.readU32le();
            }
            if (result.file_flags & rar5_file_crc32 != 0) {
                result.data_crc32 = try sub.readU32le();
            }
            result.compression = try sub.readULEB128();
            _ = try sub.readULEB128(); // host_os
            const name_length = try sub.readULEB128();
            result.name = try sub.readSlice(std.math.cast(usize, name_length) orelse return error.ResourceLimit);
            result.is_directory = result.file_flags & rar5_file_directory != 0;
            if (flags & rar5_flag_extra != 0) {
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
                        rar5_extra_redir, rar5_extra_crypt => return error.Unsupported,
                        rar5_extra_hash => {
                            const record_data = try sub.readSlice(record_data_size);
                            var extra_sub = binary.ReadCursor.init(record_data);
                            const hash_type = try extra_sub.readULEB128();
                            if (hash_type == rar5_hash_blake2sp) {
                                const hash_bytes = try extra_sub.readSlice(32);
                                var hash: [32]u8 = undefined;
                                @memcpy(&hash, hash_bytes);
                                result.blake2 = hash;
                            }
                        },
                        else => _ = try sub.readSlice(record_data_size),
                    }
                    extra_remaining -= consumed;
                }
            }
        },
        rar5_type_encryption => {},
        rar5_type_end => {
            result.archive_flags = try sub.readULEB128();
        },
        // Unknown types are skipped by size below: the reference parses
        // HFL_SKIPIFUNKNOWN but never enforces it, so a block a future RAR
        // version added is walked past, not fatal.
        else => {},
    }
    const data_end = try bounds.add(header_body_end, std.math.cast(usize, data_size) orelse return error.ResourceLimit);
    if (data_end > archive.len) return error.InvalidData;
    cursor.* = data_end;
    return result;
}

// Walk the archive, invoking `visit` for every file entry in archive order
// (directories are walked but not visited; see the ordinal note below).
// Header CRCs are verified as blocks are crossed.
fn walkRar5(archive: []const u8, offset: usize, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
    var cursor = offset + rar5_signature.len;
    var seen_main = false;
    var ordinal: usize = 0;
    while (cursor < archive.len) {
        const header = try parseRar5Block(archive, &cursor);
        switch (header.header_type) {
            rar5_type_encryption => return error.Unsupported,
            rar5_type_main => {
                const flags = header.archive_flags;
                if (flags & (rar5_archive_volume | rar5_archive_volnum) != 0) return error.Unsupported;
                if (header.header_flags & (rar5_flag_data | rar5_flag_split_before | rar5_flag_split_after | rar5_flag_solid_dep | rar5_flag_child) != 0)
                    return error.Unsupported;
                seen_main = true;
            },
            rar5_type_end => {
                if (!seen_main) return error.InvalidData;
                if (header.archive_flags & rar5_archive_volume != 0) return error.Unsupported;
                return;
            },
            rar5_type_service => {
                if (!seen_main) return error.InvalidData;
                // Service blocks (QuickOpen, etc.) carry no file payload we
                // expose; skip their data.
                continue;
            },
            rar5_type_file => {
                if (!seen_main) return error.InvalidData;
                var entry: Entry = .{
                    .info = .{
                        .name = header.name,
                        .size = header.unpacked_size,
                        .data_offset = header.data_offset,
                        .packed_size = header.data_size,
                        .crc = header.data_crc32,
                        .has_crc = header.file_flags & rar5_file_crc32 != 0,
                        .ordinal = ordinal,
                    },
                    .family = .rar5,
                    .is_directory = header.is_directory,
                    .method = 0,
                    .unpack_version = 0,
                    .solid = false,
                    .file_flags = 0,
                    .dict_bits = 0,
                    .blake2 = header.blake2,
                };
                if (!header.is_directory) {
                    if (header.file_flags & rar5_file_size_unknown != 0) return error.Unsupported;
                    if (header.header_flags & rar5_flag_data == 0) return error.Unsupported;
                    const method = (header.compression >> 7) & 0x7;
                    const algo_raw: u8 = @intCast(header.compression & 0x3F);
                    const compat = (header.compression >> 20) & 1 != 0;
                    const version: u8 = if (algo_raw == 0) 50 else if (algo_raw == 1) (if (compat) @as(u8, 50) else 70) else algo_raw;
                    if (method == 0) {
                        if (header.data_size != header.unpacked_size) return error.Unsupported;
                        entry.method = 0;
                    } else {
                        if (method > 5) return error.Unsupported;
                        if (version != 50 and version != 70) return error.Unsupported;
                        const win_bits_field: u6 = @intCast((header.compression >> 10) & (if (version == 70) @as(u64, 0x1F) else 0x0F));
                        // The window the entry was encoded against; decoding
                        // with less would silently truncate history, so a
                        // window we cannot fit is refused, never clamped.
                        const win: u64 = (@as(u64, 0x20000) << win_bits_field);
                        if (win_bits_field > max_rar5_window_bits) return error.ResourceLimit;
                        entry.method = @intCast(method);
                        entry.unpack_version = version;
                        entry.dict_bits = winBitsCeil(win);
                        entry.solid = (header.compression >> 6) & 1 != 0;
                    }
                    // Integrity coverage is CRC32 or better: a file block
                    // that carries neither (some producers strip both) is
                    // refused rather than delivered unverifiable.
                    if (header.file_flags & rar5_file_crc32 == 0 and header.blake2 == null)
                        return error.Unsupported;
                }
                entry.info.family = .rar5;
                entry.info.method = entry.method;
                entry.info.unpack_version = entry.unpack_version;
                entry.info.window_bytes = if (entry.method == 0) 0 else @as(u64, 1) << entry.dict_bits;
                // Ordinals count the entries a caller can actually read:
                // directories are listed in the walk but never exposed, and
                // must not shift the file ordinals (the v20 fixture's two
                // directory entries once pushed every file ordinal by two).
                if (!entry.is_directory) {
                    ordinal = try bounds.add(ordinal, 1);
                    try visit(ctx, entry);
                }
            },
            else => {},
        }
    }
    // EOF exactly on a block boundary is a clean end, matching the reference
    // (UnexpEndArcMsg stays silent when the walk position equals the file
    // size): older producers omit the end-of-archive block, and a truncated
    // archive still fails above on whichever block runs past EOF.
    if (!seen_main) return error.InvalidData;
}

fn winBitsCeil(win: u64) u6 {
    const bits: u6 = @intCast(64 - @clz(win -| 1));
    return @max(bits, 17);
}

// RAR4 window exponent from the file flags' dictionary-size field, one
// formula for every legacy version (matching the reference): the field is
// (flags >> 5) & 7, code 7 is the directory marker and clamps to 6.
fn dictBitsRar4(file_flags: u16) u5 {
    const dict_code: u5 = @intCast((file_flags >> 5) & 7);
    return if (dict_code > 6) 22 else 16 + dict_code;
}

// ---------------------------------------------------------------------------
// RAR4 block walking
// ---------------------------------------------------------------------------

// Header CRC note (measured against production archives and the unrar
// reference): RAR legacy HEAD_CRC is the low 16 bits of CRC-32 — NOT
// CRC-16/ARC, despite the field's width. CRC-16/ARC of real header bytes
// gives values no producer stores.

const rar4_mark: u8 = 0x72;
const rar4_main: u8 = 0x73;
const rar4_file: u8 = 0x74;
const rar4_end: u8 = 0x7b;
const rar4_long_block: u16 = 0x8000;
const rar4_lhd_large: u16 = 0x0100;
const rar4_lhd_split_before: u16 = 0x0001;
const rar4_lhd_split_after: u16 = 0x0002;
const rar4_lhd_password: u16 = 0x0004;
const rar4_lhd_solid: u16 = 0x0010;
const rar4_mhd_volume: u16 = 0x0001;
const rar4_mhd_password: u16 = 0x0080;
const rar4_mhd_protect: u16 = 0x0040;
const rar4_window_mask: u16 = 0x00e0;
const rar4_window_directory: u16 = 0x00e0;

const Rar4Header = struct {
    header_type: u8,
    flags: u16,
    head_size: u16,
    data_size: u64,
    header_offset: usize,
};

fn parseRar4Header(archive: []const u8, offset: usize) Failure!Rar4Header {
    const head = try bounds.slice(archive, offset, 7);
    const head_size = std.mem.readInt(u16, head[5..7], .little);
    if (head_size < 7) return error.InvalidData;
    const header_end = try bounds.add(offset, head_size);
    if (header_end > archive.len) return error.InvalidData;
    const flags = std.mem.readInt(u16, head[3..5], .little);
    // CRC-32 low 16 bits over bytes [2..head_size] — except the marker block
    // (0x72), whose first two bytes ARE the 'Ra' signature and carry no CRC;
    // the reference exempts HEAD3_SIGN the same way.
    if (head[2] != rar4_mark) {
        const stored_crc = std.mem.readInt(u16, head[0..2], .little);
        const computed_crc: u16 = @truncate(checksum.crc32(archive[offset + 2 .. header_end]));
        if (stored_crc != computed_crc) return error.IntegrityFailure;
    }
    var data_size: u64 = 0;
    if (flags & rar4_long_block != 0) {
        const add = try bounds.slice(archive, offset + 7, 4);
        data_size = std.mem.readInt(u32, add[0..4], .little);
    }
    return .{
        .header_type = head[2],
        .flags = flags,
        .head_size = head_size,
        .data_size = data_size,
        .header_offset = offset,
    };
}

const Rar4File = struct {
    header: Rar4Header,
    packed_size: u64,
    unpacked_size: u64,
    file_crc: u32,
    unpack_version: u8,
    method: u8,
    name: []const u8,
    is_directory: bool,
};

fn parseRar4File(archive: []const u8, header: Rar4Header) Failure!Rar4File {
    // For a RAR4 file block the base header's ADD_SIZE field IS PACK_SIZE;
    // there is no second packed-size field. Reading one here would shift
    // every subsequent field by 4 bytes (the reference got this wrong once;
    // every entry then showed empty names, ~2^32 sizes, and one shared CRC).
    var packed_size: u64 = header.data_size;
    const fields_offset = try bounds.add(header.header_offset, 7 + @as(usize, if (header.flags & rar4_long_block != 0) 4 else 0));
    var sub = binary.ReadCursor.init(archive[fields_offset..]);
    const unpacked_size_low = try sub.readU32le();
    _ = try sub.readU8(); // host_os
    const file_crc = try sub.readU32le();
    _ = try sub.readU32le(); // mtime
    const unpack_version = try sub.readU8();
    const method_raw = try sub.readU8();
    const name_size = std.mem.readInt(u16, &(try sub.readBytes(2)), .little);
    _ = try sub.readU32le(); // attributes
    var unpacked_size: u64 = unpacked_size_low;
    if (header.flags & rar4_lhd_large != 0) {
        const packed_high = try sub.readU32le();
        const unpacked_high = try sub.readU32le();
        packed_size |= @as(u64, packed_high) << 32;
        unpacked_size |= @as(u64, unpacked_high) << 32;
    }
    const name = try sub.readSlice(name_size);

    // The dictionary-size field with every bit set is the DIRECTORY marker
    // (LHD_WINDOWMASK == LHD_DIRECTORY == 0x00e0); a directory has no data.
    const is_directory = (header.flags & rar4_window_mask) == rar4_window_directory;

    return .{
        .header = header,
        .packed_size = packed_size,
        .unpacked_size = unpacked_size,
        .file_crc = file_crc,
        .unpack_version = unpack_version,
        .method = method_raw -% 0x30,
        .name = name,
        .is_directory = is_directory,
    };
}

fn walkRar4(archive: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
    var cursor: usize = 0;
    var seen_main = false;
    var ordinal: usize = 0;
    while (cursor < archive.len) {
        if (archive.len - cursor < 7) return error.InvalidData;
        const header = try parseRar4Header(archive, cursor);
        switch (header.header_type) {
            rar4_mark => {},
            rar4_main => {
                // 0x0040 is MHD_PROTECT (recovery record) — NOT password;
                // conflating them reported every protected archive as
                // encrypted. Only 0x0080 (MHD_PASSWORD) and the volume flag
                // are unsupported here.
                if (header.flags & (rar4_mhd_volume | rar4_mhd_password) != 0) return error.Unsupported;
                seen_main = true;
            },
            rar4_file => {
                if (!seen_main) return error.InvalidData;
                if (header.flags & (rar4_lhd_split_before | rar4_lhd_split_after | rar4_lhd_password) != 0)
                    return error.Unsupported;
                const file = try parseRar4File(archive, header);
                var entry: Entry = .{
                    .info = .{
                        .name = file.name,
                        .size = file.unpacked_size,
                        .data_offset = @intCast(header.header_offset + header.head_size),
                        .packed_size = file.packed_size,
                        .crc = file.file_crc,
                        .ordinal = ordinal,
                    },
                    .family = .rar4,
                    .is_directory = file.is_directory,
                    .method = 0,
                    .unpack_version = file.unpack_version,
                    .solid = false,
                    .file_flags = header.flags,
                    .dict_bits = 0,
                    .blake2 = null,
                };
                if (!file.is_directory) {
                    if (file.method > 5) return error.Unsupported;
                    if (file.unpack_version != 20 and file.unpack_version != 26 and
                        file.unpack_version != 29 and file.unpack_version != 36)
                        return error.Unsupported; // v15 and unknown futures
                    entry.method = file.method;
                    entry.solid = header.flags & rar4_lhd_solid != 0;
                }
                entry.info.family = .rar4;
                entry.info.method = entry.method;
                entry.info.unpack_version = entry.unpack_version;
                entry.info.window_bytes = if (entry.method == 0) 0 else @as(u64, 1) << dictBitsRar4(entry.file_flags);
                // See the RAR5 walk: directories are never exposed and do not
                // consume ordinals.
                if (!entry.is_directory) {
                    ordinal = try bounds.add(ordinal, 1);
                    try visit(ctx, entry);
                }
                // Advance past the payload using the recomputed 64-bit packed
                // size (the base header only holds the low 32 bits).
                const payload_end = try bounds.add(cursor + header.head_size, std.math.cast(usize, file.packed_size) orelse return error.ResourceLimit);
                if (payload_end > archive.len) return error.InvalidData;
                cursor = payload_end;
                continue;
            },
            rar4_end => return,
            else => {
                // comment / av / protect / sign / service blocks: validate the
                // header CRC (done above) and skip their data. A recovery
                // record (PROTECT) is ordinary content, not encryption.
            },
        }
        const data_end = try bounds.add(cursor + header.head_size, std.math.cast(usize, header.data_size) orelse return error.ResourceLimit);
        if (data_end > archive.len) return error.InvalidData;
        cursor = data_end;
    }
    // Same EOF rule as the RAR5 walk: unrar's UnexpEndArcMsg stays silent at
    // a block boundary, and RAR 1.5 archives never wrote an end block.
    if (!seen_main) return error.InvalidData;
}

// ---------------------------------------------------------------------------
// Inspect verbs
// ---------------------------------------------------------------------------

const CountCtx = struct { count: usize = 0, max_entries: u64 };

fn countVisit(ctx: *CountCtx, entry: Entry) Failure!void {
    if (entry.is_directory) return;
    if (ctx.count >= ctx.max_entries) return error.ResourceLimit;
    ctx.count = try bounds.add(ctx.count, 1);
}

fn walkEntries(archive: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
    const located = try detectFamily(archive);
    switch (located.family) {
        .rar4 => try walkRar4(archive, ctx, visit),
        .rar5 => try walkRar5(archive, located.offset, ctx, visit),
    }
}

pub fn rarInspectCount(archive: []const u8, max_entries: u64) Failure!usize {
    var ctx: CountCtx = .{ .max_entries = max_entries };
    try walkEntries(archive, &ctx, countVisit);
    return ctx.count;
}

const FindCtx = struct {
    target: usize,
    ordinal: usize = 0,
    found: ?RarInfo = null,
    max_entries: u64,
};

fn findVisit(ctx: *FindCtx, entry: Entry) Failure!void {
    if (entry.is_directory) return;
    if (ctx.ordinal >= ctx.max_entries) return error.ResourceLimit;
    if (ctx.found == null and ctx.ordinal == ctx.target) {
        ctx.found = entry.info;
    }
    ctx.ordinal = try bounds.add(ctx.ordinal, 1);
}

pub fn rarInspectOrdinal(archive: []const u8, ordinal: usize, max_entries: u64) Failure!RarInfo {
    var ctx: FindCtx = .{ .target = ordinal, .max_entries = max_entries };
    try walkEntries(archive, &ctx, findVisit);
    if (ctx.found) |info| return info;
    return error.InvalidData;
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// Largest of the three engine states; the caller carves one buffer this big
// and the active engine is constructed in place.
pub const max_state_bytes = @max(@sizeOf(unpack50.State), @max(@sizeOf(unpack29.State), @sizeOf(unpack20.State)));

// Pass 1: locate the target entry and, for a solid target, the ordinal where
// its compression group started (the most recent non-solid file entry before
// it), plus the largest dictionary any group member declares — the shared
// session must be built for that window.
const LocateCtx = struct {
    target: usize,
    ordinal: usize = 0,
    last_group_start: usize = 0,
    group_max_window: u64 = 0,
    group_max_pool: usize = 0,
    target_entry: ?Entry = null,
    group_start: usize = 0,
};

fn locateVisit(ctx: *LocateCtx, entry: Entry) Failure!void {
    if (entry.is_directory) return;
    if (!entry.solid) {
        ctx.last_group_start = ctx.ordinal;
        ctx.group_max_window = 0;
        ctx.group_max_pool = 0;
    }
    if (ctx.ordinal == ctx.target) {
        ctx.target_entry = entry;
        ctx.group_start = if (entry.solid) ctx.last_group_start else ctx.ordinal;
    }
    if (ctx.ordinal >= ctx.last_group_start) {
        if (entry.info.window_bytes > ctx.group_max_window) ctx.group_max_window = entry.info.window_bytes;
        if (entry.method != 0) {
            const pool: usize = if (entry.family == .rar4 and (entry.unpack_version == 20 or entry.unpack_version == 26))
                unpack20.table_pool_words
            else if (entry.family == .rar4)
                unpack29.table_pool_words * 4
            else
                unpack50.table_pool_words * 4;
            if (pool > ctx.group_max_pool) ctx.group_max_pool = pool;
        }
    }
    ctx.ordinal = try bounds.add(ctx.ordinal, 1);
}

// Pass 2: replay the group's compressed entries through the session — a
// discard sink for predecessors, the caller's buffer for the target. Store
// entries never join a compressed stream and are skipped. Entries before the
// group start cost a header walk only.
fn replayVisit(
    session: anytype,
    archive: []const u8,
    ctx: *const LocateCtx,
    entry: Entry,
    output: []u8,
) Failure!void {
    if (entry.is_directory) return;
    if (entry.info.ordinal > ctx.target) return;
    if (entry.info.ordinal < ctx.group_start) return;
    if (entry.method == 0) return; // stores never join a compressed stream; the facade copies them
    const payload = try bounds.slice(archive, entry.info.data_offset, entry.info.packed_size);
    if (entry.info.ordinal == ctx.target) {
        const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceLimit;
        var bs = sink.BufferSink.init(output[0..size]);
        try session.decodeFile(payload, entry.info.size, entry.solid, bs.sink());
        if (bs.overflowed) return error.InvalidData;
    } else {
        var discard = sink.DiscardSink{};
        try session.decodeFile(payload, entry.info.size, entry.solid, discard.sink());
    }
}

pub fn rarDecodeOrdinal(
    archive: []const u8,
    ordinal: usize,
    output: []u8,
    bufs: *DecodeBuffers,
) Failure!usize {
    var locate: LocateCtx = .{ .target = ordinal };
    try walkEntries(archive, &locate, locateVisit);
    const entry = locate.target_entry orelse return error.InvalidData;
    if (entry.is_directory) return error.InvalidData;

    const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceLimit;
    if (output.len < size) return error.InsufficientCapacity;

    if (entry.method == 0) {
        const payload = try bounds.slice(archive, entry.info.data_offset, entry.info.packed_size);
        if (payload.len != size) return error.InvalidData;
        @memcpy(output[0..size], payload);
    } else {
        const window_len = std.math.cast(usize, locate.group_max_window) orelse return error.ResourceLimit;
        try replayCompressed(archive, &locate, entry, output[0..size], bufs, window_len);
    }

    // Integrity: CRC32 over the delivered bytes; RAR5 archives that carry a
    // BLAKE2sp hash extra record verify that too.
    if (entry.info.has_crc and checksum.crc32(output[0..size]) != entry.info.crc) return error.IntegrityFailure;
    if (entry.blake2) |expected| {
        var got: [32]u8 = undefined;
        blake2sp.blake2sp(output[0..size], &got);
        if (!std.mem.eql(u8, &expected, &got)) return error.IntegrityFailure;
    }
    return size;
}

fn replayCompressed(
    archive: []const u8,
    locate: *const LocateCtx,
    target: Entry,
    output: []u8,
    bufs: *DecodeBuffers,
    window_len: usize,
) Failure!void {
    if (bufs.window.len < window_len) return error.InternalFailure;
    if (bufs.filter_scratch.len < window_len + filter_scratch_extra) return error.InternalFailure;

    switch (target.family) {
        .rar5 => {
            if (bufs.table_pool.len < unpack50.table_pool_words * 4) return error.InternalFailure;
            if (bufs.pending50.len < unpack50.max_pending_filters) return error.InternalFailure;
            const st = try bufs.state50();
            var session = try unpack50.Session.init(
                st,
                bufs.window[0..window_len],
                bufs.table_pool[0 .. unpack50.table_pool_words * 4],
                bufs.pending50,
                bufs.filter_scratch,
                target.unpack_version == 70,
            );
            var replay: ReplayCtx50 = .{ .session = &session, .archive = archive, .locate = locate, .output = output };
            try walkEntries(archive, &replay, replayVisit50);
        },
        .rar4 => {
            switch (target.unpack_version) {
                29, 36 => {
                    if (bufs.table_pool.len < unpack29.table_pool_words * 4) return error.InternalFailure;
                    if (bufs.pending29.len < unpack29.max_pending_filters) return error.InternalFailure;
                    const st = try bufs.state29();
                    var session = try unpack29.Session.init(
                        st,
                        bufs.window[0..window_len],
                        bufs.table_pool[0 .. unpack29.table_pool_words * 4],
                        bufs.pending29,
                        bufs.filter_scratch,
                        bufs.ppm_heap,
                    );
                    var replay: ReplayCtx29 = .{ .session = &session, .archive = archive, .locate = locate, .output = output };
                    try walkEntries(archive, &replay, replayVisit29);
                },
                20, 26 => {
                    if (bufs.table_pool.len < unpack20.table_pool_words) return error.InternalFailure;
                    const st = try bufs.state20();
                    var session = try unpack20.Session.init(
                        st,
                        bufs.window[0..window_len],
                        bufs.table_pool[0..unpack20.table_pool_words],
                    );
                    var replay: ReplayCtx20 = .{ .session = &session, .archive = archive, .locate = locate, .output = output };
                    try walkEntries(archive, &replay, replayVisit20);
                },
                else => return error.Unsupported,
            }
        },
    }
}

const ReplayCtx50 = struct {
    session: *unpack50.Session,
    archive: []const u8,
    locate: *const LocateCtx,
    output: []u8,
};
const ReplayCtx29 = struct {
    session: *unpack29.Session,
    archive: []const u8,
    locate: *const LocateCtx,
    output: []u8,
};
const ReplayCtx20 = struct {
    session: *unpack20.Session,
    archive: []const u8,
    locate: *const LocateCtx,
    output: []u8,
};

fn replayVisit50(ctx: *ReplayCtx50, entry: Entry) Failure!void {
    try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output);
}
fn replayVisit29(ctx: *ReplayCtx29, entry: Entry) Failure!void {
    try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output);
}
fn replayVisit20(ctx: *ReplayCtx20, entry: Entry) Failure!void {
    try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output);
}

// ---------------------------------------------------------------------------
// RAR5 archive creation (store or LZ)
// ---------------------------------------------------------------------------

pub const RarEntry = struct {
    name: []const u8,
    data: []const u8 = &.{},
    mtime: u32 = 0,
    is_directory: bool = false,
    method: u8 = 0, // 0 = store, 1-5 = LZ level
};

fn writeVint(value: u64, out: []u8) usize {
    var v = value;
    var i: usize = 0;
    while (true) {
        out[i] = @intCast(v & 0x7F);
        v >>= 7;
        if (v != 0) {
            out[i] |= 0x80;
            i += 1;
        } else {
            return i + 1;
        }
    }
}

fn vintSize(value: u64) usize {
    var v = value;
    var size: usize = 1;
    while (v > 0x7F) {
        v >>= 7;
        size += 1;
    }
    return size;
}

// compression_info: algo 0, solid 0, method 1-5, dict_bits 3 (1 MiB window).
fn compressionInfoVint(method: u3) u64 {
    return (@as(u64, method) << 7) | (@as(u64, 3) << 10);
}

const block_writer = struct {
    // Serialize `contents` (already starting with the type vint) as one
    // header: CRC32 over [size_vint .. end], little-endian, then the bytes.
    fn emitHeader(out: []u8, pos: usize, contents: []const u8) Failure!usize {
        var size_buf: [10]u8 = undefined;
        const size_len = writeVint(contents.len, &size_buf);
        // The header CRC covers the size vint plus the contents, matching the
        // reader, which checksums from the size field through the body end.
        var crc_state = checksum.Crc32.init();
        crc_state.update(size_buf[0..size_len]);
        crc_state.update(contents);
        const total = 4 + size_len + contents.len;
        if (out.len < pos + total) return error.InsufficientCapacity;
        std.mem.writeInt(u32, out[pos..][0..4], crc_state.final(), .little);
        var cursor = pos + 4;
        @memcpy(out[cursor..][0..size_len], size_buf[0..size_len]);
        cursor += size_len;
        @memcpy(out[cursor..][0..contents.len], contents);
        return pos + total;
    }

    fn mainBlockSize() usize {
        // type(1) + flags(1) + archive_flags(1) = 3 contents bytes; one-byte
        // size vint; 4 CRC bytes.
        return 4 + 1 + 3;
    }

    fn writeMainBlock(out: []u8, pos: usize) Failure!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(1, contents[c..]); // main
        c += writeVint(0, contents[c..]); // header flags
        c += writeVint(0, contents[c..]); // archive flags
        return emitHeader(out, pos, contents[0..c]);
    }

    fn endBlockSize() usize {
        // type(1) + flags(1) + end_flags(1) = 3 contents bytes.
        return 4 + 1 + 3;
    }

    fn writeEndBlock(out: []u8, pos: usize) Failure!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(5, contents[c..]); // end_archive
        c += writeVint(0, contents[c..]); // header flags
        c += writeVint(0, contents[c..]); // end flags
        return emitHeader(out, pos, contents[0..c]);
    }

    // Header-only size for a file block carrying `packed_len` bytes of data.
    fn fileBlockSize(entry: RarEntry, packed_len: usize) usize {
        var file_flags: u64 = 0x02; // FHFL_UTIME
        if (entry.is_directory) {
            file_flags |= 0x01;
        } else {
            file_flags |= 0x04; // FHFL_CRC32
        }
        const attributes: u64 = if (entry.is_directory) 0x10 else 0x20;

        var body: usize = 0;
        body += vintSize(file_flags);
        body += vintSize(if (entry.is_directory) 0 else entry.data.len);
        body += vintSize(attributes);
        body += 4; // mtime
        if (!entry.is_directory) body += 4; // crc32
        body += vintSize(if (entry.method == 0) 0 else compressionInfoVint(@intCast(entry.method)));
        body += vintSize(3); // host_os unix
        body += vintSize(entry.name.len);
        body += entry.name.len;

        var contents: usize = 0;
        contents += vintSize(2); // file
        contents += vintSize(if (packed_len > 0) 0x02 else 0);
        if (packed_len > 0) contents += vintSize(packed_len);
        contents += body;

        return 4 + vintSize(contents) + contents + packed_len;
    }

    fn writeFileBlock(
        out: []u8,
        pos: usize,
        entry: RarEntry,
        packed_data: []const u8,
    ) Failure!usize {
        var file_flags: u64 = 0x02;
        if (entry.is_directory) {
            file_flags |= 0x01;
        } else {
            file_flags |= 0x04;
        }
        const attributes: u64 = if (entry.is_directory) 0x10 else 0x20;
        const data_crc = if (entry.is_directory) 0 else checksum.crc32(entry.data);

        var body: [4200]u8 = undefined;
        var b: usize = 0;
        b += writeVint(file_flags, body[b..]);
        b += writeVint(if (entry.is_directory) 0 else entry.data.len, body[b..]);
        b += writeVint(attributes, body[b..]);
        std.mem.writeInt(u32, body[b..][0..4], entry.mtime, .little);
        b += 4;
        if (!entry.is_directory) {
            std.mem.writeInt(u32, body[b..][0..4], data_crc, .little);
            b += 4;
        }
        b += writeVint(if (entry.method == 0) 0 else compressionInfoVint(@intCast(entry.method)), body[b..]);
        b += writeVint(3, body[b..]);
        b += writeVint(entry.name.len, body[b..]);
        @memcpy(body[b..][0..entry.name.len], entry.name);
        b += entry.name.len;

        const data_size: usize = if (entry.is_directory) 0 else packed_data.len;
        var contents: [4400]u8 = undefined;
        var c: usize = 0;
        c += writeVint(2, contents[c..]);
        c += writeVint(if (data_size > 0) 0x02 else 0, contents[c..]);
        if (data_size > 0) c += writeVint(data_size, contents[c..]);
        @memcpy(contents[c..][0..b], body[0..b]);
        c += b;

        var cursor = try emitHeader(out, pos, contents[0..c]);
        if (data_size > 0) {
            if (out.len < cursor + packed_data.len) return error.InsufficientCapacity;
            @memcpy(out[cursor..][0..packed_data.len], packed_data);
            cursor += packed_data.len;
        }
        return cursor;
    }
};

fn checkWriteEntries(entries: []const RarEntry) Failure!void {
    for (entries) |entry| {
        if (entry.name.len > 4096) return error.InvalidCall;
        if (entry.method > 5) return error.InvalidCall;
    }
    if (entries.len > 65535) return error.ResourceLimit;
}

// Compress every LZ entry into its slot of the packed region, returning the
// total archive size. Shared by the sizing query and the commit pass (each
// runs it afresh — the two-pass shape the zip writer established).
fn packEntries(entries: []const RarEntry, ws: *WriteBuffers) Failure!usize {
    var total: usize = rar5_signature.len + block_writer.mainBlockSize() + block_writer.endBlockSize();
    var packed_cursor: usize = 0;
    for (entries, 0..) |entry, i| {
        const packed_len: usize = if (entry.is_directory or entry.data.len == 0 or entry.method == 0) blk: {
            // Store entries' "packed" data is the raw bytes; lay them into
            // the packed region so the writer reads everything from there.
            if (ws.packed_buf.len - packed_cursor < entry.data.len) return error.InternalFailure;
            @memcpy(ws.packed_buf[packed_cursor .. packed_cursor + entry.data.len], entry.data);
            break :blk entry.data.len;
        } else blk: {
            const bound = packedBound(entry);
            if (ws.packed_buf.len - packed_cursor < bound) return error.InternalFailure;
            const slice = ws.packed_buf[packed_cursor .. packed_cursor + bound];
            const sizes = pack50.workspacesFor(entry.data.len);
            if (ws.hash.len < sizes.hash_words or ws.hash2.len < sizes.hash2_words or
                ws.hash3.len < sizes.hash3_words or ws.bt_left.len < sizes.bt_words or
                ws.bt_right.len < sizes.bt_words or ws.tokens.len < sizes.token_count or
                ws.staging.len < sizes.staging_bytes) return error.InternalFailure;
            const written = try pack50.compressBlock(entry.data, @intCast(entry.method), true, .{
                .hash = ws.hash,
                .hash2 = ws.hash2,
                .hash3 = ws.hash3,
                .bt_left = ws.bt_left,
                .bt_right = ws.bt_right,
                .tokens = ws.tokens,
                .staging = ws.staging,
            }, slice);
            break :blk written;
        };
        if (ws.packed_sizes.len < entries.len) return error.InternalFailure;
        ws.packed_sizes[i] = packed_len;
        packed_cursor = try bounds.add(packed_cursor, packed_len);
        total = try bounds.add(total, block_writer.fileBlockSize(entry, packed_len));
    }
    return total;
}

pub fn rarWriteSize(entries: []const RarEntry, ws: *WriteBuffers) Failure!usize {
    try checkWriteEntries(entries);
    return packEntries(entries, ws);
}

pub fn rarEncode(entries: []const RarEntry, output: []u8, ws: *WriteBuffers) Failure!usize {
    const required = try rarWriteSize(entries, ws);
    if (output.len < required) return error.InsufficientCapacity;

    var pos: usize = 0;
    @memcpy(output[pos..][0..rar5_signature.len], &rar5_signature);
    pos += rar5_signature.len;
    pos = try block_writer.writeMainBlock(output, pos);

    var i: usize = 0;
    var cursor: usize = 0;
    while (i < entries.len) : (i += 1) {
        const entry = entries[i];
        const packed_len = ws.packed_sizes[i];
        const packed_slice = ws.packed_buf[cursor .. cursor + packed_len];
        pos = try block_writer.writeFileBlock(output, pos, entry, packed_slice);
        cursor = try bounds.add(cursor, packed_len);
    }

    pos = try block_writer.writeEndBlock(output, pos);
    return pos;
}

test "vint encoding matches the rar5 wire form" {
    var buf: [10]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), writeVint(0x42, &buf));
    try std.testing.expectEqual(@as(u8, 0x42), buf[0]);
    try std.testing.expectEqual(@as(usize, 2), writeVint(0x2101, &buf));
    try std.testing.expectEqual(@as(u8, 0x81), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x42), buf[1]);
    try std.testing.expectEqual(vintSize(0x2101), 2);
}

test "created archive round-trips through our own reader (store and lz)" {
    const testing = std.testing;
    const data1 = "hello rar5 stored";
    const data2 = "The quick brown fox jumps over the lazy dog. " ** 8;
    const allocator = testing.allocator;

    const window = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(window);
    const state_store = try allocator.alloc(u64, (max_state_bytes + 7) / 8);
    defer allocator.free(state_store);
    const table_pool = try allocator.alloc(u16, table_pool_words);
    defer allocator.free(table_pool);
    const pending50 = try allocator.alloc(PendingFilter50, max_pending50);
    defer allocator.free(pending50);
    const pending29 = try allocator.alloc(PendingFilter29, max_pending29);
    defer allocator.free(pending29);
    const filter_scratch = try allocator.alloc(u8, window.len + filter_scratch_extra);
    defer allocator.free(filter_scratch);
    const ppm_heap = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(ppm_heap);

    for ([_]u8{ 0, 3 }) |method| {
        const entries = [_]RarEntry{
            .{ .name = "m1.txt", .data = data1, .method = method },
            .{ .name = "m2.txt", .data = data2, .method = method },
        };
        const sizes = pack50Sizes(@max(data1.len, data2.len));
        const hash = try allocator.alloc(u32, sizes.hash_words);
        defer allocator.free(hash);
        const hash2 = try allocator.alloc(u32, sizes.hash2_words);
        defer allocator.free(hash2);
        const hash3 = try allocator.alloc(u32, sizes.hash3_words);
        defer allocator.free(hash3);
        const bt_left = try allocator.alloc(u32, sizes.bt_words);
        defer allocator.free(bt_left);
        const bt_right = try allocator.alloc(u32, sizes.bt_words);
        defer allocator.free(bt_right);
        const tokens = try allocator.alloc(LzToken, sizes.token_count);
        defer allocator.free(tokens);
        const staging = try allocator.alloc(u8, sizes.staging_bytes);
        defer allocator.free(staging);
        var packed_total: usize = 0;
        for (entries) |e| packed_total += packedBound(e);
        const packed_buf = try allocator.alloc(u8, packed_total);
        defer allocator.free(packed_buf);
        const packed_sizes = try allocator.alloc(usize, entries.len);
        defer allocator.free(packed_sizes);
        var ws = WriteBuffers{
            .hash = hash,
            .hash2 = hash2,
            .hash3 = hash3,
            .bt_left = bt_left,
            .bt_right = bt_right,
            .tokens = tokens,
            .staging = staging,
            .packed_buf = packed_buf,
            .packed_sizes = packed_sizes,
        };
        const required = try rarWriteSize(&entries, &ws);
        const archive = try allocator.alloc(u8, required);
        defer allocator.free(archive);
        const written = try rarEncode(&entries, archive, &ws);
        try testing.expectEqual(required, written);

        try testing.expectEqual(@as(usize, 2), try rarInspectCount(archive, 128));
        const out1 = try allocator.alloc(u8, data1.len);
        defer allocator.free(out1);
        const out2 = try allocator.alloc(u8, data2.len);
        defer allocator.free(out2);
        const bufs = DecodeBuffers{
            .state = std.mem.sliceAsBytes(state_store),
            .window = window,
            .table_pool = table_pool,
            .pending50 = pending50,
            .pending29 = pending29,
            .filter_scratch = filter_scratch,
            .ppm_heap = ppm_heap,
        };
        try testing.expectEqual(@as(usize, data1.len), try rarDecodeOrdinal(archive, 0, out1, @constCast(&bufs)));
        try testing.expectEqualSlices(u8, data1, out1);
        try testing.expectEqual(@as(usize, data2.len), try rarDecodeOrdinal(archive, 1, out2, @constCast(&bufs)));
        try testing.expectEqualSlices(u8, data2, out2);
    }
}
