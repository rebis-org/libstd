const std = @import("std");

const binary = @import("../../../common/primitive/binary.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const crypto = @import("../../../common/primitive/crypto.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const sink = @import("../../../common/sink.zig");
const blake2sp = @import("blake2sp.zig");
const filters50 = @import("filters50.zig");
const unpack20 = @import("unpack20.zig");
const unpack29 = @import("unpack29.zig");
const unpack50 = @import("unpack50.zig");

const Exception = exception_prim.Exception;
pub const PendingFilter50 = filters50.Filter;
pub const filter_scratch_extra = filters50.max_filter_block;
pub const PendingFilter29 = unpack29.PendingFilter;
pub const max_pending29 = unpack29.max_pending_filters;
pub const max_pending50 = unpack50.max_pending_filters;

// Vendor unrar floors the v29/36 window at twice the max filter block so
// any unpacked size can stream (unpack.cpp MinAllocSize).

pub const unpack29_min_window = unpack29.max_filter_block * 2;

// Every buffer comes from the caller, so the decode path allocates nothing.

pub const Family = enum { rar4, rar5 };

// One data part of a split entry: its volume index, its offset inside that
// volume, and its packed size.
pub const SplitPart = struct {
    volume: usize,
    offset: usize,
    packed_size: usize,
};

pub const RarInfo = struct {
    name: []const u8,
    size: u64,
    data_offset: u64,
    packed_size: u64,
    crc: u32,
    // False when the producer recorded no CRC32, because 0 itself is a valid CRC32.
    has_crc: bool = true,
    ordinal: usize,
    // The walk resolves engine and window before buffer sizing; the window is 0 for store.
    family: Family = .rar5,
    method: u8 = 0,
    unpack_version: u8 = 0,
    window_bytes: u64 = 0,
    // Modification time in Unix seconds, 0 when absent. Solid entries decode by
    // replay from their group start.
    mtime: u64 = 0,
    solid: bool = false,
};

pub const Entry = struct {
    info: RarInfo,
    family: Family,
    is_directory: bool,
    // Normalized method: 0 is store, 1-5 are LZ levels, from the RAR4 low nibble
    // or the RAR5 method field.
    method: u8,
    // The unpack version in RAR4 (15/20/26/29/36), and the normalized
    // algorithm version in RAR5 (50 or 70).
    unpack_version: u8,
    solid: bool,
    file_flags: u16, // The raw RAR4 flags, which hold the dictionary code.
    dict_bits: u6, // The RAR5 window exponent from the compression info.
    blake2: ?[32]u8,
    // Entry-header encryption parameters for -p and -m data; -hp header
    // encryption stays with the walk.
    crypt: ?Crypt = null,
    // Split-entry data parts in volume order, valid only until the next entry
    // completes because the walk reuses the part scratch.
    parts: []const SplitPart = &.{},
};

pub const Crypt = union(enum) {
    // The RAR5 crypt extra: a PBKDF2-HMAC-SHA256 KDF, AES-256-CBC data, and an
    // HMAC-SHA256 hash conversion keyed by the second derived block.
    rar5: struct {
        lg2count: u8,
        salt: [16]u8,
        iv: [16]u8,
        pswcheck: ?[8]u8,
        hashmac: bool,
    },
    // The RAR4 LHD_PASSWORD: a SHA1-based KDF with the header salt, and AES-128-CBC.
    rar4: struct {
        salt: [8]u8,
    },
};

pub const DecodeOptions = struct {
    password: ?[]const u8 = null,
    // Header-decryption staging for -hp archives; it must cover the largest header.
    scratch: []u8 = &.{},
    // KDF budget in HMAC/SHA rounds; work above it fails with .kdf_limit.
    // 0 means no limit.
    kdf_rounds_limit: u64 = 0,
    // The caller-side cap on encrypted payload bytes per entry. 0 means no limit.
    password_lifetime: u64 = 0,
    // Set on a kdf_limit or password_lifetime refusal, like the ZIP/7z paths.
    failure_cause: ?*crypto.FailureCause = null,
    // Optional single-entry KDF memo shared across passes; see Rar5KdfMemo.
    kdf_memo: ?*Rar5KdfMemo = null,
    // The primitive provider for KDF and block decryption on this call.
    provider: crypto.Provider = crypto.default_provider,
};

const rar5_kdf_lg2_count_max = 24;

pub const rar4_signature = [7]u8{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 };
const sfx_scan_limit: usize = 1024 * 1024;

// Decode-side buffers carved from the call workspace. One engine state is
// live at a time.
pub const DecodeBuffers = struct {
    // Decrypted-payload staging: AES-CBC needs a mutable copy, and the
    // split-entry gather concatenates here.
    packed_stage: []u8 = &.{},
    state: []align(8) u8,
    window: []u8,
    table_pool: []u16,
    pending50: []filters50.Filter,
    pending29: []unpack29.PendingFilter,
    filter_scratch: []u8,
    ppm_heap: []u8,
    // Part scratch for the volume walk: one slot per part, bounded by the
    // volume count, reused per entry.
    split_parts: []SplitPart = &.{},

    pub fn state50(self: *DecodeBuffers) Exception!*unpack50.Unpacker {
        if (self.state.len < @sizeOf(unpack50.Unpacker)) return error.InternalException;
        return @ptrCast(@alignCast(self.state.ptr));
    }

    pub fn state29(self: *DecodeBuffers) Exception!*unpack29.Unpacker {
        if (self.state.len < @sizeOf(unpack29.Unpacker)) return error.InternalException;
        return @ptrCast(@alignCast(self.state.ptr));
    }

    pub fn state20(self: *DecodeBuffers) Exception!*unpack20.Decoder {
        if (self.state.len < @sizeOf(unpack20.Decoder)) return error.InternalException;
        return @ptrCast(@alignCast(self.state.ptr));
    }
};

// The largest table pool across engines, so one buffer serves every session.
pub const table_pool_words = unpack50.table_pool_words * 4;

// Window ceilings per family: RAR4 caps at 4 MB; RAR5/RAR7 declare their
// own inside the compression info.

fn detectFamily(archive: []const u8, provider: crypto.Provider) Exception!struct { family: Family, offset: usize } {
    if (archive.len >= rar4_signature.len and
        std.mem.eql(u8, archive[0..rar4_signature.len], &rar4_signature))
        return .{ .family = .rar4, .offset = 0 };

    // An SFX prefix moves the signature off offset 0; the scan confirms a
    // main block follows.
    const signature = rar5_signature;
    if (archive.len < signature.len) return error.DataException;
    const limit = @min(archive.len, sfx_scan_limit);
    var offset: usize = 0;
    while (offset <= limit - signature.len) : (offset += 1) {
        if (!std.mem.eql(u8, archive[offset..][0..signature.len], &signature)) continue;
        if (offset == 0) return .{ .family = .rar5, .offset = 0 };
        var cursor = offset + signature.len;
        const header = parseRar5Block(archive, &cursor, provider) catch continue;
        if (header.header_type == rar5_type_main) return .{ .family = .rar5, .offset = offset };
    }
    return error.DataException;
}

pub const rar5_signature = [8]u8{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00 };
pub const rar5_type_main: u64 = 1;
pub const rar5_type_file: u64 = 2;
pub const rar5_type_service: u64 = 3;
pub const rar5_type_encryption: u64 = 4;
pub const rar5_type_end: u64 = 5;
pub const rar5_flag_extra: u64 = 0x0001;
pub const rar5_flag_data: u64 = 0x0002;
pub const rar5_flag_skip_if_unknown: u64 = 0x0004;
pub const rar5_flag_split_before: u64 = 0x0008;
pub const rar5_flag_split_after: u64 = 0x0010;
// HFL_CHILD and HFL_INHERITED: the block refines its parent; listing counts
// a HEAD_FILE child only.
const rar5_flag_child: u64 = 0x0020;
const rar5_flag_inherited: u64 = 0x0040;
pub const rar5_archive_volume: u64 = 0x0001;
pub const rar5_archive_volnum: u64 = 0x0002;
// MHFL_PROTECT: a recovery record exists; unrar only reports it, and the RR
// service block is skipped.
pub const rar5_archive_protect: u64 = 0x0008;
// Main-header extra records live in their own namespace: MHEXTRA_LOCATOR is 1
// even though file-extra FHEXTRA_CRYPT is also 1.
pub const rar5_main_extra_locator: u64 = 0x01;
pub const rar5_locator_qlist: u64 = 0x01;
pub const rar5_locator_rr: u64 = 0x02;
pub const rar5_earc_next_volume: u64 = 0x0001;
pub const rar5_file_directory: u64 = 0x0001;
pub const rar5_file_mtime: u64 = 0x0002;
pub const rar5_file_crc32: u64 = 0x0004;
const rar5_file_size_unknown: u64 = 0x0008;
pub const rar5_extra_crypt: u64 = 0x01;
pub const rar5_extra_hash: u64 = 0x02;
const rar5_extra_redir: u64 = 0x05;
// FHEXTRA_SUBDATA: opaque per-file payload; the reader tolerates it and the
// RR service block uses it to carry the recovery-percent vint.
pub const rar5_extra_subdata: u64 = 0x07;
const rar5_hash_blake2sp: u64 = 0x00;

pub const Rar5Keys = struct { key: [32]u8, hash_key: [32]u8, pswcheck: [32]u8 };

// Single-entry rar5Kdf memo: replay passes would re-derive the same keys;
// keyed by password fingerprint.
pub const Rar5KdfMemo = struct {
    populated: bool = false,
    lg2count: u8 = 0,
    salt: [16]u8 = @splat(0),
    password_fp: [16]u8 = @splat(0),
    keys: Rar5Keys = undefined,
};

// RAR5 KDF: PBKDF2 covers the first block; the hash key and password check
// continue the chain.
pub fn rar5Kdf(password: []const u8, salt: *const [16]u8, lg2count: u8, opts: DecodeOptions) Exception!Rar5Keys {
    if (lg2count > rar5_kdf_lg2_count_max) return error.UnsupportedException;
    const rounds: u64 = @as(u64, 1) << @intCast(lg2count);
    if (opts.kdf_rounds_limit != 0 and rounds > opts.kdf_rounds_limit) {
        if (opts.failure_cause) |cause| cause.* = .kdf_limit;
        return error.ResourceException;
    }
    var password_fp: [16]u8 = @splat(0);
    if (opts.kdf_memo != null) {
        var fp_sha = crypto.Sha256.bind(opts.provider, .{});
        fp_sha.update(password);
        const fp_full = fp_sha.finalResult();
        @memcpy(&password_fp, fp_full[0..16]);
        if (opts.kdf_memo.?.populated and
            opts.kdf_memo.?.lg2count == lg2count and
            std.mem.eql(u8, &opts.kdf_memo.?.salt, salt) and
            std.mem.eql(u8, &opts.kdf_memo.?.password_fp, &password_fp))
        {
            return opts.kdf_memo.?.keys;
        }
    }
    var salt_block: [20]u8 = undefined;
    @memcpy(salt_block[0..16], salt);
    @memcpy(salt_block[16..20], &[_]u8{ 0, 0, 0, 1 });
    var u_value: [32]u8 = undefined;
    crypto.hmacSha256(opts.provider, &u_value, &salt_block, password);
    var accumulator: [32]u8 = u_value;
    const rounds32: u32 = @intCast(rounds);
    var keys: Rar5Keys = undefined;
    var iteration: u32 = 1;
    while (iteration < rounds32) : (iteration += 1) {
        crypto.hmacSha256(opts.provider, &u_value, &u_value, password);
        for (&accumulator, u_value) |*byte, other| byte.* ^= other;
    }
    keys.key = accumulator;
    for (0..16) |_| {
        crypto.hmacSha256(opts.provider, &u_value, &u_value, password);
        for (&accumulator, u_value) |*byte, other| byte.* ^= other;
    }
    keys.hash_key = accumulator;
    for (0..16) |_| {
        crypto.hmacSha256(opts.provider, &u_value, &u_value, password);
        for (&accumulator, u_value) |*byte, other| byte.* ^= other;
    }
    keys.pswcheck = accumulator;
    if (opts.kdf_memo) |memo| {
        memo.populated = true;
        memo.lg2count = lg2count;
        memo.salt = salt.*;
        memo.password_fp = password_fp;
        memo.keys = keys;
    }
    return keys;
}

pub fn rar5PswCheck(kdf_value: *const [32]u8) [8]u8 {
    var check: [8]u8 = @splat(0);
    for (kdf_value, 0..) |byte, i| check[i % 8] ^= byte;
    return check;
}

// A stored password check is valid only when its SHA-256 csum matches
// (arcread.cpp HEAD_CRYPT and FHEXTRA_CRYPT).
fn rar5PswCheckValid(provider: crypto.Provider, check: *const [8]u8, csum: *const [4]u8) bool {
    var sha = crypto.Sha256.bind(provider, .{});
    sha.update(check);
    const digest = sha.finalResult();
    return std.mem.eql(u8, digest[0..4], csum);
}

// Encrypted-entry CRC32 MAC: HMAC-SHA256 of the little-endian CRC, folded
// bytewise into 32 bits (unrar ConvertHashToMAC).
pub fn rar5CrcMac(provider: crypto.Provider, crc: u32, hash_key: *const [32]u8) u32 {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, crc, .little);
    var digest: [32]u8 = undefined;
    crypto.hmacSha256(provider, &digest, &raw, hash_key);
    var mac: u32 = 0;
    for (digest, 0..) |byte, i| mac ^= @as(u32, byte) << @intCast((i & 3) * 8);
    return mac;
}

fn rar5BlakeMac(provider: crypto.Provider, digest: *const [32]u8, hash_key: *const [32]u8) [32]u8 {
    var mac: [32]u8 = undefined;
    crypto.hmacSha256(provider, &mac, digest, hash_key);
    return mac;
}

const Rar4Keys = struct { key: [16]u8, iv: [16]u8 };

// SetKey30 hashes a self-modifying RawPsw (vendor sha1.cpp); a plain SHA-1
// KDF diverges past 127 buffered bytes.
const Rar29Sha1 = struct {
    state: [5]u32,
    count: u64,
    buffer: [64]u8,

    fn init() Rar29Sha1 {
        return .{
            .state = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },
            .count = 0,
            .buffer = @splat(0),
        };
    }

    fn transform(state: *[5]u32, block_bytes: *const [64]u8, workspace: *[16]u32) void {
        var w: [80]u32 = undefined;
        for (0..16) |i| w[i] = @byteSwap(std.mem.readInt(u32, block_bytes[i * 4 ..][0..4], .little));
        for (16..80) |i| w[i] = std.math.rotl(u32, w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        var a = state[0];
        var b = state[1];
        var c = state[2];
        var d = state[3];
        var e = state[4];
        for (0..80) |i| {
            const third = i / 20;
            const f: u32 = switch (third) {
                0 => (b & (c ^ d)) ^ d,
                1, 3 => b ^ c ^ d,
                else => (b & c) | (d & (b | c)),
            };
            const k: u32 = switch (third) {
                0 => 0x5A827999,
                1 => 0x6ED9EBA1,
                2 => 0x8F1BBCDC,
                else => 0xCA62C1D6,
            };
            const t = std.math.rotl(u32, a, 5) +% f +% e +% k +% w[i];
            e = d;
            d = c;
            c = std.math.rotl(u32, b, 30);
            b = a;
            a = t;
        }
        state[0] +%= a;
        state[1] +%= b;
        state[2] +%= c;
        state[3] +%= d;
        state[4] +%= e;
        // The vendor expands the schedule in place, so the workspace words
        // are W[64..79]; process_rar29 writes them back.
        for (0..16) |word| workspace[word] = w[64 + word];
    }

    fn process(self: *Rar29Sha1, data: []const u8) void {
        var workspace: [16]u32 = undefined;
        var i: usize = 0;
        var j: usize = @intCast(self.count & 63);
        self.count += data.len;
        if (j + data.len > 63) {
            i = 64 - j;
            @memcpy(self.buffer[j..], data[0..i]);
            transform(&self.state, &self.buffer, &workspace);
            while (i + 63 < data.len) : (i += 64) {
                transform(&self.state, data[i..][0..64], &workspace);
            }
            j = 0;
        }
        if (data.len > i) {
            @memcpy(self.buffer[j..][0 .. data.len - i], data[i..]);
        }
    }

    // The rar29 variant: transforms sourced from data write the final
    // schedule words back; buffered blocks and tails do not.
    fn processRar29(self: *Rar29Sha1, data: []u8) void {
        var workspace: [16]u32 = undefined;
        var i: usize = 0;
        var j: usize = @intCast(self.count & 63);
        self.count += data.len;
        if (j + data.len > 63) {
            i = 64 - j;
            @memcpy(self.buffer[j..], data[0..i]);
            transform(&self.state, &self.buffer, &workspace);
            while (i + 63 < data.len) : (i += 64) {
                transform(&self.state, data[i..][0..64], &workspace);
                for (0..16) |word| {
                    std.mem.writeInt(u32, data[i + word * 4 ..][0..4], workspace[word], .little);
                }
            }
            j = 0;
        }
        if (data.len > i) {
            @memcpy(self.buffer[j..][0 .. data.len - i], data[i..]);
        }
    }

    // Finalizes a copy, mirroring vendor sha1_done; the KDF forks the context
    // every 0x4000 rounds, so the source context keeps accumulating.
    fn done(self: *const Rar29Sha1) [5]u32 {
        var copy = self.*;
        var workspace: [16]u32 = undefined;
        const bit_length = copy.count * 8;
        var buf_pos: usize = @intCast(copy.count & 0x3f);
        copy.buffer[buf_pos] = 0x80;
        buf_pos += 1;
        if (buf_pos != 56) {
            if (buf_pos > 56) {
                @memset(copy.buffer[buf_pos..], 0);
                buf_pos = 0;
            }
            if (buf_pos == 0) transform(&copy.state, &copy.buffer, &workspace);
            @memset(copy.buffer[buf_pos..56], 0);
        }
        std.mem.writeInt(u64, copy.buffer[56..64], bit_length, .big);
        transform(&copy.state, &copy.buffer, &workspace);
        return copy.state;
    }
};

// SetKey30: 0x40000 rar29 rounds over RawPsw||round-le24, an IV byte per
// 0x4000th fork, UTF-16LE password with salt (vendor crypt3.cpp).
fn rar4Kdf(password_utf16le: []const u8, salt: ?[]const u8, opts: DecodeOptions) Exception!Rar4Keys {
    // Vendor truncates at MAXPASSWORD_RAR = 127 UTF-16 chars (crypt3.cpp);
    // hashing more would derive keys no vendor build reproduces.
    const password = if (password_utf16le.len > 254) password_utf16le[0..254] else password_utf16le;
    const hash_rounds: u32 = 0x40000;
    if (opts.kdf_rounds_limit != 0 and hash_rounds > opts.kdf_rounds_limit) {
        if (opts.failure_cause) |cause| cause.* = .kdf_limit;
        return error.ResourceException;
    }
    var raw: [2 * 512 + 8]u8 = undefined;
    if (password.len > raw.len - 8) return error.UnsupportedException;
    @memcpy(raw[0..password.len], password);
    var raw_len = password.len;
    if (salt) |salt_bytes| {
        @memcpy(raw[raw_len..][0..salt_bytes.len], salt_bytes);
        raw_len += salt_bytes.len;
    }
    var sha = Rar29Sha1.init();
    var keys: Rar4Keys = undefined;
    var round: u32 = 0;
    while (round < hash_rounds) : (round += 1) {
        sha.processRar29(raw[0..raw_len]);
        var round_le24: [3]u8 = .{ @truncate(round), @truncate(round >> 8), @truncate(round >> 16) };
        sha.process(&round_le24);
        if (round % (hash_rounds / 16) == 0) {
            const digest = sha.done();
            keys.iv[round / (hash_rounds / 16)] = @truncate(digest[4]);
        }
    }
    const digest = sha.done();
    // AESKey[I*4+J] = (byte)(state_word[I] >> J*8): each 4-byte digest word is
    // serialized little-endian (unrar SetKey30).
    for (0..4) |i| {
        for (0..4) |j| {
            keys.key[i * 4 + j] = @truncate(digest[i] >> @intCast(j * 8));
        }
    }
    return keys;
}

fn passwordToUtf16Le(password: []const u8, utf16le: []u8) Exception![]u8 {
    var cursor = binary.WriteCursor.init(utf16le);
    var i: usize = 0;
    while (i < password.len) {
        const len = std.unicode.utf8ByteSequenceLength(password[i]) catch return error.DataException;
        if (i + len > password.len) return error.DataException;
        const code_point: u21 = switch (len) {
            1 => password[i],
            2 => std.unicode.utf8Decode2(password[i..][0..2].*) catch return error.DataException,
            3 => std.unicode.utf8Decode3(password[i..][0..3].*) catch return error.DataException,
            4 => std.unicode.utf8Decode4(password[i..][0..4].*) catch return error.DataException,
            else => unreachable,
        };
        i += len;
        cursor.writeUtf16Le(code_point) catch return error.ResourceException;
    }
    return utf16le[0..cursor.pos];
}

const Rar5Block = struct {
    header_type: u64,
    flags: u64,
    data_offset: u64 = 0,
    data_size: u64 = 0,
    // The file block fields, which are valid only when header_type is file or service.
    file_flags: u64 = 0,
    unpacked_size: u64 = 0,
    data_crc32: u32 = 0,
    compression: u64 = 0,
    name: []const u8 = &.{},
    blake2: ?[32]u8 = null,
    is_directory: bool = false,
    archive_flags: u64 = 0,
    // The zero-based volume number from a MHFL_VOLNUMBER main header.
    archive_volnum: u64 = 0,
    mtime: u64 = 0,
    crypt: ?Crypt = null,
    // The HEAD_CRYPT fields, which are valid only when header_type is encryption.
    enc_lg2count: u8 = 0,
    enc_salt: [16]u8 = @splat(0),
    enc_pswcheck: ?[8]u8 = null,
};

fn parseRar5FileBody(provider: crypto.Provider, cursor: *binary.ReadCursor, flags: u64, extra_size: u64, result: *Rar5Block) Exception!void {
    result.file_flags = try cursor.readUleb128();
    result.unpacked_size = try cursor.readUleb128();
    _ = try cursor.readUleb128(); // Attributes.
    if (result.file_flags & rar5_file_mtime != 0) {
        // The RAR5 mtime is Unix time, stored directly.
        result.mtime = try cursor.readU32Le();
    }
    if (result.file_flags & rar5_file_crc32 != 0) {
        result.data_crc32 = try cursor.readU32Le();
    }
    result.compression = try cursor.readUleb128();
    _ = try cursor.readUleb128(); // Host OS.
    const name_length = try cursor.readUleb128();
    result.name = try cursor.readSlice(std.math.cast(usize, name_length) orelse return error.ResourceException);
    result.is_directory = result.file_flags & rar5_file_directory != 0;
    if (flags & rar5_flag_extra != 0) {
        const extra_size_usize = std.math.cast(usize, extra_size) orelse return error.ResourceException;
        var extra_remaining: usize = extra_size_usize;
        // The reference stops at a short record instead of failing
        // (ProcessExtra50): RAR 5.21 writes SUBDATA one byte short.
        while (extra_remaining >= 2) {
            const record_start = cursor.pos;
            const record_size = try cursor.readUleb128();
            if (record_size == 0) break;
            const after_size = extra_remaining - (cursor.pos - record_start);
            if (after_size == 0 or record_size > after_size) break;
            const type_start = cursor.pos;
            const record_type = try cursor.readUleb128();
            const type_size = cursor.pos - type_start;
            if (record_size < type_size) break;
            const record_data_size = std.math.cast(usize, record_size - type_size) orelse return error.ResourceException;
            const header_consumed = cursor.pos - record_start;
            const consumed = try bounds.addUsize(header_consumed, record_data_size);
            switch (record_type) {
                // REDIR marks a file system redirect; no link surface exists
                // here, so the record is skipped.
                rar5_extra_redir => _ = try cursor.readSlice(record_data_size),
                rar5_extra_crypt => {
                    // Layout: version and flags vInts, 1-byte KDF count,
                    // 16-byte salt and IV, then optional password check and checksum.
                    var record_cursor = binary.ReadCursor.init(try cursor.readSlice(record_data_size));
                    const version = try record_cursor.readUleb128();
                    const enc_flags = try record_cursor.readUleb128();
                    if (version > 0) return error.UnsupportedException;
                    const lg2count = try record_cursor.readU8();
                    var crypt: Crypt = .{ .rar5 = .{
                        .lg2count = lg2count,
                        .salt = undefined,
                        .iv = undefined,
                        .pswcheck = null,
                        .hashmac = enc_flags & rar5_crypt_hashmac != 0,
                    } };
                    @memcpy(&crypt.rar5.salt, try record_cursor.readSlice(16));
                    @memcpy(&crypt.rar5.iv, try record_cursor.readSlice(16));
                    if (enc_flags & rar5_crypt_pswcheck != 0) {
                        const check_bytes = try record_cursor.readSlice(8);
                        var check: [8]u8 = undefined;
                        @memcpy(&check, check_bytes);
                        const csum_bytes = try record_cursor.readSlice(4);
                        var csum: [4]u8 = undefined;
                        @memcpy(&csum, csum_bytes);
                        // The reference drops a password check whose SHA-256 csum
                        // disagrees, so damage cannot masquerade as a wrong password.
                        if (rar5PswCheckValid(provider, &check, &csum)) crypt.rar5.pswcheck = check;
                    }
                    result.crypt = crypt;
                },
                rar5_extra_hash => {
                    const record_data = try cursor.readSlice(record_data_size);
                    var record_cursor = binary.ReadCursor.init(record_data);
                    const hash_type = try record_cursor.readUleb128();
                    if (hash_type == rar5_hash_blake2sp) {
                        const hash_bytes = try record_cursor.readSlice(32);
                        var hash: [32]u8 = undefined;
                        @memcpy(&hash, hash_bytes);
                        result.blake2 = hash;
                    }
                },
                else => _ = try cursor.readSlice(record_data_size),
            }
            extra_remaining -= consumed;
        }
    }
}

pub const rar5_crypt_pswcheck: u64 = 0x0001;
pub const rar5_crypt_hashmac: u64 = 0x0002;

fn parseRar5Block(archive: []const u8, cursor: *usize, provider: crypto.Provider) Exception!Rar5Block {
    const crc_offset = cursor.*;
    const crc_bytes = try bounds.slice(archive, crc_offset, 4);
    cursor.* = try bounds.addUsize(cursor.*, 4);
    const header_start = cursor.*;
    var size_reader = binary.ReadCursor.init(archive[cursor.*..]);
    const size = try size_reader.readUleb128();
    if (size == 0 or size > 2 * 1024 * 1024) return error.DataException;
    const header_body_start = cursor.* + size_reader.pos;
    const header_body_end = try bounds.addUsize(header_body_start, std.math.cast(usize, size) orelse return error.ResourceException);
    if (header_body_end > archive.len) return error.DataException;
    const recorded_crc = std.mem.readInt(u32, crc_bytes[0..4], .little);
    const computed_crc = checksum.crc32With(provider, archive[header_start..header_body_end]);
    if (computed_crc != recorded_crc) return error.IntegrityException;
    var body_cursor = binary.ReadCursor.init(archive[header_body_start..header_body_end]);
    var block = try finishRar5Block(provider, &body_cursor);
    block.data_offset = header_body_end;
    const data_end = try bounds.addUsize(header_body_end, std.math.cast(usize, block.data_size) orelse return error.ResourceException);
    if (data_end > archive.len) return error.DataException;
    cursor.* = data_end;
    return block;
}

// Shared tail of the cleartext and encrypted paths: parse type, flags, and
// body from header bytes.
fn finishRar5Block(provider: crypto.Provider, body: *binary.ReadCursor) Exception!Rar5Block {
    const header_type = try body.readUleb128();
    const flags = try body.readUleb128();
    var extra_size: u64 = 0;
    if (flags & rar5_flag_extra != 0) extra_size = try body.readUleb128();
    var data_size: u64 = 0;
    if (flags & rar5_flag_data != 0) data_size = try body.readUleb128();

    var result: Rar5Block = .{
        .header_type = header_type,
        .flags = flags,
        .data_size = data_size,
    };

    switch (header_type) {
        rar5_type_main => {
            result.archive_flags = try body.readUleb128();
            if (result.archive_flags & rar5_archive_volnum != 0) {
                result.archive_volnum = try body.readUleb128();
            }
        },
        rar5_type_file, rar5_type_service => {
            // The split flags stay walkable here; only the volume walk can
            // parse a split chain.
            try parseRar5FileBody(provider, body, flags, extra_size, &result);
        },
        rar5_type_encryption => {
            const version = try body.readUleb128();
            const enc_flags = try body.readUleb128();
            if (version > 0) return error.UnsupportedException;
            result.enc_lg2count = try body.readU8();
            @memcpy(&result.enc_salt, try body.readSlice(16));
            if (enc_flags & rar5_crypt_pswcheck != 0) {
                const check_bytes = try body.readSlice(8);
                var check: [8]u8 = undefined;
                @memcpy(&check, check_bytes);
                const csum_bytes = try body.readSlice(4);
                var csum: [4]u8 = undefined;
                @memcpy(&csum, csum_bytes);
                // The reference drops a password check whose SHA-256 csum
                // disagrees, so damage cannot masquerade as a wrong password.
                if (rar5PswCheckValid(provider, &check, &csum)) result.enc_pswcheck = check;
            }
        },
        rar5_type_end => {
            result.archive_flags = try body.readUleb128();
        },
        // An unknown type is skipped by size: the reference never enforces
        // HFL_SKIPIFUNKNOWN, so future blocks stay walkable.
        else => {},
    }
    return result;
}

// Encrypted header: [cleartext IV][AES-256-CBC, padded to 16]; the size
// lives in ciphertext, so the first block decrypts alone.
fn parseRar5BlockEncrypted(
    archive: []const u8,
    cursor: *usize,
    keys: *const Rar5Keys,
    provider: crypto.Provider,
    scratch: []u8,
) Exception!Rar5Block {
    const iv_bytes = try bounds.slice(archive, cursor.*, 16);
    cursor.* = try bounds.addUsize(cursor.*, 16);
    const first = try bounds.slice(archive, cursor.*, 16);
    if (scratch.len < 16) return error.CapacityException;
    crypto.aesCbcDecrypt(provider, keys.key[0..], iv_bytes[0..16].*, scratch[0..16], first) catch return error.DataException;
    const recorded_crc = std.mem.readInt(u32, scratch[0..4], .little);
    var size_cursor = binary.ReadCursor.init(scratch[4..16]);
    const block_size = size_cursor.readUleb128() catch return error.DataException;
    const size_bytes = size_cursor.pos;
    const header_size = try bounds.addUsize(try bounds.addUsize(4, size_bytes), std.math.cast(usize, block_size) orelse return error.ResourceException);
    if (header_size > std.math.maxInt(usize) - 15) return error.ResourceException;
    const enc_len = std.mem.alignForward(usize, header_size, 16);
    if (scratch.len < enc_len) return error.CapacityException;
    if (enc_len > 16) {
        const rest_start = try bounds.addUsize(cursor.*, 16);
        const rest = try bounds.slice(archive, rest_start, enc_len - 16);
        // The CBC chaining value is the first cipher block.
        crypto.aesCbcDecrypt(provider, keys.key[0..], first[0..16].*, scratch[16..enc_len], rest) catch return error.DataException;
    }
    if (checksum.crc32With(provider, scratch[4..header_size]) != recorded_crc) return error.IntegrityException;
    var body_cursor = binary.ReadCursor.init(scratch[4 + size_bytes .. header_size]);
    var block = try finishRar5Block(provider, &body_cursor);
    const block_end = try bounds.addUsize(cursor.*, enc_len);
    block.data_offset = block_end;
    const data_end = try bounds.addUsize(block_end, std.math.cast(usize, block.data_size) orelse return error.ResourceException);
    if (data_end > archive.len) return error.DataException;
    cursor.* = data_end;
    return block;
}

// File-entry construction shared by both walks; the caller supplies the
// packed total and opening crypt record.
fn rar5FileEntry(header: Rar5Block, ordinal: usize, packed_total: u64, crypt: ?Crypt) Exception!Entry {
    var entry: Entry = .{
        .info = .{
            .name = header.name,
            .size = header.unpacked_size,
            .data_offset = header.data_offset,
            .packed_size = packed_total,
            .crc = header.data_crc32,
            .has_crc = header.file_flags & rar5_file_crc32 != 0,
            .ordinal = ordinal,
            .mtime = header.mtime,
        },
        .family = .rar5,
        .is_directory = header.is_directory,
        .method = 0,
        .unpack_version = 0,
        .solid = false,
        .file_flags = 0,
        .dict_bits = 0,
        .blake2 = header.blake2,
        .crypt = crypt,
    };
    if (!header.is_directory) {
        if (header.file_flags & rar5_file_size_unknown != 0) return error.UnsupportedException;
        if (header.flags & rar5_flag_data == 0) return error.UnsupportedException;
        const method = (header.compression >> 7) & 0x7;
        const algo_raw: u8 = @intCast(header.compression & 0x3F);
        const compat_flag = (header.compression >> 20) & 1 != 0;
        if (method == 0) {
            // Encrypted store pads to the AES block, so packed may exceed
            // unpacked_size by 15; plaintext store matches exactly.
            if (crypt) |c| {
                if (c != .rar5) return error.UnsupportedException;
                if (packed_total < header.unpacked_size or packed_total > header.unpacked_size + 15) return error.UnsupportedException;
            } else if (packed_total != header.unpacked_size) return error.UnsupportedException;
            entry.method = 0;
        } else {
            if (method > 5) return error.UnsupportedException;
            // The raw algorithm version: 0 is RAR5, 1 is RAR7, and nothing
            // above has an unpacker.
            if (algo_raw > 1) return error.UnsupportedException;
            // A too-small window silently truncates history, so refuse it,
            // never clamp it (unrar arcread.cpp ReadHeader50).
            const window_bits_field: u6 = @intCast((header.compression >> 10) & (if (algo_raw == 0) @as(u64, 0x0F) else 0x1F));
            var window_bytes: u64 = @as(u64, 0x20000) << window_bits_field;
            if (algo_raw == 1) {
                // The RAR7 window adds a 5-bit 1/32 fraction; the 64 GiB
                // ceiling rejects the result (unrar VER_UNKNOWN).
                window_bytes += window_bytes / 32 * ((header.compression >> 15) & 0x1F);
                if (window_bytes > 0x1000000000) return error.UnsupportedException;
            }
            entry.method = @intCast(method);
            entry.unpack_version = if (compat_flag) 50 else if (algo_raw == 0) 50 else 70;
            entry.dict_bits = windowBitsCeil(window_bytes);
            entry.solid = (header.compression >> 6) & 1 != 0;
        }
        // Integrity coverage is CRC32 or better; a block with neither is
        // refused, not delivered unverifiable.
        if (header.file_flags & rar5_file_crc32 == 0 and header.blake2 == null)
            return error.UnsupportedException;
    }
    entry.info.family = .rar5;
    entry.info.method = entry.method;
    entry.info.unpack_version = entry.unpack_version;
    entry.info.window_bytes = if (entry.method == 0) 0 else @as(u64, 1) << entry.dict_bits;
    entry.info.solid = entry.solid;
    return entry;
}

// Walk the archive, verifying each header CRC; `visit` sees files in
// archive order, and HEAD_CRYPT decrypts the rest.
fn walkRar5(archive: []const u8, offset: usize, opts: DecodeOptions, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Exception!void) Exception!void {
    var cursor = offset + rar5_signature.len;
    var seen_main = false;
    var ordinal: usize = 0;
    var header_crypt: ?Rar5Keys = null;
    while (cursor < archive.len) {
        const header = if (header_crypt) |*keys|
            try parseRar5BlockEncrypted(archive, &cursor, keys, opts.provider, opts.scratch)
        else
            try parseRar5Block(archive, &cursor, opts.provider);
        switch (header.header_type) {
            rar5_type_encryption => {
                // The HEAD_CRYPT block precedes the encrypted main header in a -hp
                // archive, so no seen_main requirement applies here.
                if (header.enc_lg2count > rar5_kdf_lg2_count_max) return error.UnsupportedException;
                const password = opts.password orelse return error.UnsupportedException;
                const keys = try rar5Kdf(password, &header.enc_salt, header.enc_lg2count, opts);
                if (header.enc_pswcheck) |expected| {
                    if (!crypto.constantTimeEql(&rar5PswCheck(&keys.pswcheck), &expected)) {
                        if (opts.failure_cause) |cause| cause.* = .wrong_password;
                        return error.IntegrityException;
                    }
                }
                header_crypt = keys;
            },
            rar5_type_main => {
                const flags = header.archive_flags;
                if (flags & (rar5_archive_volume | rar5_archive_volnum) != 0) return error.UnsupportedException;
                if (header.flags & (rar5_flag_data | rar5_flag_split_before | rar5_flag_split_after | rar5_flag_child | rar5_flag_inherited) != 0)
                    return error.UnsupportedException;
                seen_main = true;
            },
            rar5_type_end => {
                if (!seen_main) return error.DataException;
                if (header.archive_flags & rar5_archive_volume != 0) return error.UnsupportedException;
                return;
            },
            rar5_type_service => {
                if (!seen_main) return error.DataException;
                // A split service header needs the peer volume; service
                // blocks like QuickOpen carry no payload here.
                if (header.flags & (rar5_flag_split_before | rar5_flag_split_after) != 0)
                    return error.UnsupportedException;
                continue;
            },
            rar5_type_file => {
                if (!seen_main) return error.DataException;
                // Splits need the peer volume, which this walk never reads.
                if (header.flags & (rar5_flag_split_before | rar5_flag_split_after) != 0)
                    return error.UnsupportedException;
                const entry = try rar5FileEntry(header, ordinal, header.data_size, header.crypt);
                // Ordinals count readable entries: a directory is listed but
                // never exposed, so it must not shift ordinals.
                if (!entry.is_directory) {
                    ordinal = try bounds.addUsize(ordinal, 1);
                    try visit(ctx, entry);
                }
            },
            else => {},
        }
    }
    // EOF on a block boundary is a clean end: UnexpEndArcMsg stays silent there.
    if (!seen_main) return error.DataException;
}

fn windowBitsCeil(window_bytes: u64) u6 {
    const bits: u6 = @intCast(64 - @clz(window_bytes -| 1));
    // A RAR5 window is 0x20000 << dict_bits, so bits is already at least 17.
    return @max(bits, 17);
}

// The RAR4 window exponent is the dictionary-size field (flags >> 5) & 7;
// code 7 marks a directory.
fn dictBitsRar4(file_flags: u16) u5 {
    const dict_code: u5 = @intCast((file_flags >> 5) & 7);
    return if (dict_code > 6) 22 else 16 + dict_code;
}

// The legacy HEAD_CRC is the low 16 bits of CRC-32; CRC-16/ARC of real
// headers matches no producer.

const rar4_mark: u8 = 0x72;
const rar4_main: u8 = 0x73;
const rar4_file: u8 = 0x74;
const rar4_cmt: u8 = 0x75;
const rar4_av: u8 = 0x76;
const rar4_old_service: u8 = 0x77;
const rar4_protect: u8 = 0x78;
const rar4_sign: u8 = 0x79;
const rar4_service: u8 = 0x7a;
const rar4_end: u8 = 0x7b;
const rar4_long_block: u16 = 0x8000;
const rar4_lhd_large: u16 = 0x0100;
const rar4_lhd_split_before: u16 = 0x0001;
const rar4_lhd_split_after: u16 = 0x0002;
const rar4_lhd_password: u16 = 0x0004;
const rar4_lhd_solid: u16 = 0x0010;
const rar4_host_unix: u8 = 3;
const rar4_mhd_volume: u16 = 0x0001;
const rar4_mhd_comment: u16 = 0x0002;
const rar4_mhd_password: u16 = 0x0080;
const rar4_window_mask: u16 = 0x00e0;
const rar4_window_directory: u16 = 0x00e0;
// The UO old-service subheader: its CRC covers fields beyond head_size,
// so unrar exempts it.
const rar4_old_sub_uo: u16 = 0x101;

const Rar4Header = struct {
    header_type: u8,
    flags: u16,
    head_size: u16,
    data_size: u64,
    header_offset: usize,
    // Encrypted (-hp) blocks: decrypted staging bytes and the on-disk length.
    // Cleartext keeps enc_len == head_size and parses from the archive.
    enc_source: ?[]const u8 = null,
    enc_len: usize = 0,
};

// Coverage mirrors vendor GetCRC15 over the bytes ReadHeader15 actually
// reads; 0 exempts a type.
fn rar4CrcCoverage(header_type: u8, flags: u16, head_size: u16, source: []const u8, offset: usize) usize {
    return switch (header_type) {
        rar4_sign, rar4_av => 0,
        rar4_cmt => @min(@as(usize, head_size), 13),
        rar4_main => if (flags & rar4_mhd_comment != 0) @min(@as(usize, head_size), 13) else head_size,
        rar4_old_service => if (head_size >= 13 and
            std.mem.readInt(u16, source[offset + 11 ..][0..2], .little) == rar4_old_sub_uo) 0 else head_size,
        else => head_size,
    };
}

// ReadHeader15 reads add-size at offset 7 for FILE/SERVICE/PROTECT/OLDSERVICE,
// never for MAIN/CMT/ENDARC, else only under LONG_BLOCK; under 11 bytes, nothing.
fn rar4DataSize(header_type: u8, flags: u16, head_size: u16, source: []const u8, offset: usize) u64 {
    const reads_add = switch (header_type) {
        rar4_file, rar4_service, rar4_protect, rar4_old_service => true,
        rar4_main, rar4_cmt, rar4_end => false,
        else => flags & rar4_long_block != 0,
    };
    if (!reads_add or head_size < 11) return 0;
    return std.mem.readInt(u32, source[offset + 7 ..][0..4], .little);
}

fn parseRar4Header(archive: []const u8, offset: usize, provider: crypto.Provider) Exception!Rar4Header {
    const head = try bounds.slice(archive, offset, 7);
    const head_size = std.mem.readInt(u16, head[5..7], .little);
    if (head_size < 7) return error.DataException;
    const header_end = try bounds.addUsize(offset, head_size);
    if (header_end > archive.len) return error.DataException;
    const flags = std.mem.readInt(u16, head[3..5], .little);
    // CRC-32 low 16 bits over the per-type coverage; the marker block (0x72)
    // carries no CRC.
    if (head[2] != rar4_mark) {
        const coverage = rar4CrcCoverage(head[2], flags, head_size, archive, offset);
        if (coverage != 0) {
            const stored_crc = std.mem.readInt(u16, head[0..2], .little);
            const computed_crc: u16 = @truncate(checksum.crc32With(provider, archive[offset + 2 ..][0 .. coverage - 2]));
            if (stored_crc != computed_crc) return error.IntegrityException;
        }
    }
    return .{
        .header_type = head[2],
        .flags = flags,
        .head_size = head_size,
        .data_size = rar4DataSize(head[2], flags, head_size, archive, offset),
        .header_offset = offset,
        .enc_len = head_size,
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
    // RAR4 mtime is Unix time only for Unix producers; other hosts write
    // DOS date/time.
    host_os: u8,
    mtime: u32,
    salt: ?[8]u8,
};

const rar4_lhd_salt: u16 = 0x0400;

fn parseRar4File(archive: []const u8, header: Rar4Header) Exception!Rar4File {
    // The base header ADD_SIZE is PACK_SIZE; a phantom second packed-size
    // field shifts everything later.
    var packed_size: u64 = header.data_size;
    // The add-size at offset 7 is unconditional for FILE, so fields start
    // at +11 (unrar ReadHeader15).
    if (header.head_size < 11) return error.DataException;
    const fields_offset = try bounds.addUsize(header.header_offset, 11);
    const fields_end = try bounds.addUsize(header.header_offset, header.head_size);
    if (fields_end > archive.len) return error.DataException;
    // The cursor is bounded by the header, so an overrun fails instead of
    // reading the next block.
    var cursor = binary.ReadCursor.init(archive[fields_offset..fields_end]);
    const unpacked_size_low = try cursor.readU32Le();
    const host_os = try cursor.readU8();
    const file_crc = try cursor.readU32Le();
    const mtime = try cursor.readU32Le();
    const unpack_version = try cursor.readU8();
    const method_raw = try cursor.readU8();
    const name_size = std.mem.readInt(u16, &(try cursor.readBytes(2)), .little);
    _ = try cursor.readU32Le(); // Attributes.
    var unpacked_size: u64 = unpacked_size_low;
    if (header.flags & rar4_lhd_large != 0) {
        const packed_high = try cursor.readU32Le();
        const unpacked_high = try cursor.readU32Le();
        packed_size |= @as(u64, packed_high) << 32;
        unpacked_size |= @as(u64, unpacked_high) << 32;
    }
    const name = try cursor.readSlice(name_size);
    var salt: ?[8]u8 = null;
    if (header.flags & rar4_lhd_salt != 0) {
        const salt_bytes = try cursor.readSlice(8);
        var salt_copy: [8]u8 = undefined;
        @memcpy(&salt_copy, salt_bytes);
        salt = salt_copy;
    }

    // A dictionary-size field with every bit set marks a directory
    // (LHD_WINDOWMASK == LHD_DIRECTORY == 0x00e0).
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
        .host_os = host_os,
        .mtime = mtime,
        .salt = salt,
    };
}

// Per-block salts re-key lazily; archives repeat one salt, so the memo
// pays the KDF once per walk.
const Rar4HeaderCrypt = struct {
    utf16: [2 * 512]u8,
    utf16_len: usize,
    salt_memo: [8]u8 = undefined,
    have_salt: bool = false,
    keys: Rar4Keys = undefined,
};

// Each -hp block salts and re-keys independently (vendor SetCryptKeys);
// the 7-byte fixed header decrypts alone.
fn parseRar4HeaderEncrypted(
    archive: []const u8,
    offset: usize,
    hcrypt: *Rar4HeaderCrypt,
    opts: DecodeOptions,
    scratch: []u8,
) Exception!Rar4Header {
    const salt = try bounds.slice(archive, offset, 8);
    if (!hcrypt.have_salt or !std.mem.eql(u8, &hcrypt.salt_memo, salt)) {
        var salt_bytes: [8]u8 = undefined;
        @memcpy(&salt_bytes, salt);
        hcrypt.keys = try rar4Kdf(hcrypt.utf16[0..hcrypt.utf16_len], &salt_bytes, opts);
        @memcpy(&hcrypt.salt_memo, &salt_bytes);
        hcrypt.have_salt = true;
    }
    const provider = opts.provider;
    const cipher_start = try bounds.addUsize(offset, 8);
    const first = try bounds.slice(archive, cipher_start, 16);
    if (scratch.len < 16) return error.CapacityException;
    crypto.aesCbcDecrypt(provider, hcrypt.keys.key[0..], hcrypt.keys.iv, scratch[0..16], first) catch return error.DataException;
    const head_size = std.mem.readInt(u16, scratch[5..7], .little);
    if (head_size < 7) return error.DataException;
    const crypt_len = std.mem.alignForward(usize, head_size, 16);
    if (scratch.len < crypt_len) return error.CapacityException;
    if (crypt_len > 16) {
        const rest_start = try bounds.addUsize(cipher_start, 16);
        const rest = try bounds.slice(archive, rest_start, crypt_len - 16);
        crypto.aesCbcDecrypt(provider, hcrypt.keys.key[0..], first[0..16].*, scratch[16..crypt_len], rest) catch return error.DataException;
    }
    const header_type = scratch[2];
    const flags = std.mem.readInt(u16, scratch[3..5], .little);
    const coverage = rar4CrcCoverage(header_type, flags, head_size, scratch, 0);
    if (coverage != 0) {
        const stored_crc = std.mem.readInt(u16, scratch[0..2], .little);
        const computed_crc: u16 = @truncate(checksum.crc32With(provider, scratch[2..][0 .. coverage - 2]));
        if (stored_crc != computed_crc) return error.IntegrityException;
    }
    return .{
        .header_type = header_type,
        .flags = flags,
        .head_size = head_size,
        .data_size = rar4DataSize(header_type, flags, head_size, scratch, 0),
        // The header_offset must be a dummy because the caller parses from the staging buffer.
        .header_offset = 0,
        .enc_source = scratch[0..crypt_len],
        // The on-disk block: the salt plus the padded ciphertext.
        .enc_len = 8 + crypt_len,
    };
}

fn walkRar4(archive: []const u8, opts: DecodeOptions, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Exception!void) Exception!void {
    var cursor: usize = 0;
    var seen_main = false;
    var ordinal: usize = 0;
    var header_crypt: ?Rar4HeaderCrypt = null;
    while (cursor < archive.len) {
        if (archive.len - cursor < 7) return error.DataException;
        var header: Rar4Header = undefined;
        var header_source: []const u8 = archive;
        if (header_crypt) |*crypt| {
            header = try parseRar4HeaderEncrypted(archive, cursor, crypt, opts, opts.scratch);
            header_source = header.enc_source.?;
        } else {
            header = try parseRar4Header(archive, cursor, opts.provider);
        }
        switch (header.header_type) {
            rar4_mark => {},
            rar4_main => {
                // The flag 0x0040 is MHD_PROTECT, a recovery record, and not
                // MHD_PASSWORD, so only the volume flag is refused.
                if (header.flags & rar4_mhd_volume != 0) return error.UnsupportedException;
                if (header.flags & rar4_mhd_password != 0) {
                    // -hp: every block after the main header is encrypted;
                    // keys derive lazily, so the main header stays cleartext.
                    const password = opts.password orelse return error.UnsupportedException;
                    var utf16_buffer: [2 * 512]u8 = undefined;
                    const utf16 = try passwordToUtf16Le(password, &utf16_buffer);
                    header_crypt = .{ .utf16 = utf16_buffer, .utf16_len = utf16.len };
                }
                seen_main = true;
            },
            rar4_file => {
                if (!seen_main) return error.DataException;
                if (header.flags & (rar4_lhd_split_before | rar4_lhd_split_after) != 0)
                    return error.UnsupportedException;
                const file = try parseRar4File(header_source, header);
                var entry: Entry = .{
                    .info = .{
                        .name = file.name,
                        .size = file.unpacked_size,
                        .data_offset = @intCast(cursor + header.enc_len),
                        .packed_size = file.packed_size,
                        .crc = file.file_crc,
                        .ordinal = ordinal,
                        .mtime = if (file.host_os == rar4_host_unix) file.mtime else 0,
                    },
                    .family = .rar4,
                    .is_directory = file.is_directory,
                    .method = 0,
                    .unpack_version = file.unpack_version,
                    .solid = false,
                    .file_flags = header.flags,
                    .dict_bits = 0,
                    .blake2 = null,
                    .crypt = if (header.flags & rar4_lhd_password != 0) blk: {
                        // The versions 13, 15, and 20 use the retired proprietary ciphers.
                        if (file.unpack_version != 29 and file.unpack_version != 36) return error.UnsupportedException;
                        const salt = file.salt orelse return error.DataException;
                        break :blk Crypt{ .rar4 = .{ .salt = salt } };
                    } else null,
                };
                if (!file.is_directory) {
                    if (file.method > 5) return error.UnsupportedException;
                    if (file.unpack_version != 20 and file.unpack_version != 26 and
                        file.unpack_version != 29 and file.unpack_version != 36)
                        return error.UnsupportedException; // Version 15 and unknown future versions.
                    // A 0xffffffff unpacked size marks an unknown size (unrar
                    // INT64NDF), which this facade cannot size ahead of the read.
                    const unknown_size = if (header.flags & rar4_lhd_large != 0)
                        file.unpacked_size == std.math.maxInt(u64)
                    else
                        file.unpacked_size == 0xffffffff;
                    if (unknown_size) return error.UnsupportedException;
                    entry.method = file.method;
                    entry.solid = header.flags & rar4_lhd_solid != 0;
                }
                entry.info.family = .rar4;
                entry.info.method = entry.method;
                entry.info.unpack_version = entry.unpack_version;
                entry.info.window_bytes = if (entry.method == 0) 0 else @as(u64, 1) << dictBitsRar4(entry.file_flags);
                entry.info.solid = entry.solid;
                // See the RAR5 walk: directories are never exposed and do not
                // consume ordinals.
                if (!entry.is_directory) {
                    ordinal = try bounds.addUsize(ordinal, 1);
                    try visit(ctx, entry);
                }
                // Base header holds only low 32 packed-size bits, so advance
                // with the 64-bit value; data area is never header-encrypted.
                const payload_end = try bounds.addUsize(cursor + header.enc_len, std.math.cast(usize, file.packed_size) orelse return error.ResourceException);
                if (payload_end > archive.len) return error.DataException;
                cursor = payload_end;
                continue;
            },
            rar4_end => return,
            else => {
                // Comment, av, protect, sign, and service blocks: only their
                // data is skipped; a protect record is content, not encryption.
            },
        }
        const data_end = try bounds.addUsize(cursor + header.enc_len, std.math.cast(usize, header.data_size) orelse return error.ResourceException);
        if (data_end > archive.len) return error.DataException;
        cursor = data_end;
    }
    // Same EOF rule as the RAR5 walk: UnexpEndArcMsg stays silent at a
    // block boundary.
    if (!seen_main) return error.DataException;
}

const CountCtx = struct { count: usize = 0, max_entries: u64 };

fn countVisit(ctx: *CountCtx, entry: Entry) Exception!void {
    if (entry.is_directory) return;
    if (ctx.count >= ctx.max_entries) return error.ResourceException;
    ctx.count = try bounds.addUsize(ctx.count, 1);
}

fn walkEntriesOpts(archive: []const u8, opts: DecodeOptions, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Exception!void) Exception!void {
    const located = try detectFamily(archive, opts.provider);
    switch (located.family) {
        .rar4 => try walkRar4(archive, opts, ctx, visit),
        .rar5 => try walkRar5(archive, located.offset, opts, ctx, visit),
    }
}

pub fn rarInspectCount(archive: []const u8, max_entries: u64) Exception!usize {
    return rarInspectCountOpts(archive, max_entries, .{});
}

pub fn rarInspectCountOpts(archive: []const u8, max_entries: u64, opts: DecodeOptions) Exception!usize {
    var ctx: CountCtx = .{ .max_entries = max_entries };
    try walkEntriesOpts(archive, opts, &ctx, countVisit);
    return ctx.count;
}

const FindCtx = struct {
    target: usize,
    ordinal: usize = 0,
    found: ?RarInfo = null,
    max_entries: u64,
};

fn findVisit(ctx: *FindCtx, entry: Entry) Exception!void {
    if (entry.is_directory) return;
    if (ctx.ordinal >= ctx.max_entries) return error.ResourceException;
    if (ctx.found == null and ctx.ordinal == ctx.target) {
        ctx.found = entry.info;
    }
    ctx.ordinal = try bounds.addUsize(ctx.ordinal, 1);
}

pub fn rarInspectOrdinalOpts(archive: []const u8, ordinal: usize, max_entries: u64, opts: DecodeOptions) Exception!RarInfo {
    var ctx: FindCtx = .{ .target = ordinal, .max_entries = max_entries };
    try walkEntriesOpts(archive, opts, &ctx, findVisit);
    if (ctx.found) |info| return info;
    return error.DataException;
}

// The largest engine state. The caller carves one buffer this big
// and the active engine is constructed in place.
pub const max_unpacker_bytes = @max(@sizeOf(unpack50.Unpacker), @max(@sizeOf(unpack29.Unpacker), @sizeOf(unpack20.Decoder)));

// Pass 1: locate the target, its group-start ordinal, and the group's
// largest dictionary.
const LocateCtx = struct {
    target: usize,
    ordinal: usize = 0,
    last_group_start: usize = 0,
    group_max_window: u64 = 0,
    group_max_pool: usize = 0,
    target_entry: ?Entry = null,
    group_start: usize = 0,
};

fn locateVisit(ctx: *LocateCtx, entry: Entry) Exception!void {
    if (entry.is_directory) return;
    // Entries past the target cannot affect its group: a later non-solid
    // entry must not reset the window maximum.
    if (ctx.ordinal > ctx.target) return;
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
    ctx.ordinal = try bounds.addUsize(ctx.ordinal, 1);
}

fn entryPayload(entry: Entry, archive: []const u8, opts: DecodeOptions, bufs: *DecodeBuffers) Exception![]const u8 {
    const payload = try bounds.slice(archive, entry.info.data_offset, entry.info.packed_size);
    const crypt = entry.crypt orelse return payload;
    const password = opts.password orelse return error.UnsupportedException;
    if (bufs.packed_stage.len < payload.len) return error.InternalException;
    switch (crypt) {
        .rar5 => |c| {
            if (opts.password_lifetime != 0 and payload.len > opts.password_lifetime) {
                if (opts.failure_cause) |cause| cause.* = .password_lifetime;
                return error.ResourceException;
            }
            const keys = try rar5Kdf(password, &c.salt, c.lg2count, opts);
            if (c.pswcheck) |expected| {
                if (!crypto.constantTimeEql(&rar5PswCheck(&keys.pswcheck), &expected)) {
                    if (opts.failure_cause) |cause| cause.* = .wrong_password;
                    return error.DataException;
                }
            }
            crypto.aesCbcDecrypt(opts.provider, keys.key[0..], c.iv, bufs.packed_stage[0..payload.len], payload) catch return error.DataException;
        },
        .rar4 => |c| {
            if (opts.password_lifetime != 0 and payload.len > opts.password_lifetime) {
                if (opts.failure_cause) |cause| cause.* = .password_lifetime;
                return error.ResourceException;
            }
            var utf16_buffer: [2 * 512]u8 = undefined;
            const utf16 = try passwordToUtf16Le(password, &utf16_buffer);
            const keys = try rar4Kdf(utf16, &c.salt, opts);
            crypto.aesCbcDecrypt(opts.provider, keys.key[0..], keys.iv, bufs.packed_stage[0..payload.len], payload) catch return error.DataException;
        },
    }
    return bufs.packed_stage[0..payload.len];
}

// One replay drives one session, and table sizes differ per version
// class: a mixed solid chain is refused.
fn versionClass(version: u8) u8 {
    return switch (version) {
        20, 26 => 20,
        29, 36 => 29,
        else => version,
    };
}

// Pass 2: replay the group; predecessors feed a discard sink, and the
// target feeds the caller.
fn replayVisit(
    session: anytype,
    archive: []const u8,
    locate: *const LocateCtx,
    entry: Entry,
    output: []u8,
    opts: DecodeOptions,
    bufs: *DecodeBuffers,
    target_version: u8,
) Exception!void {
    if (entry.is_directory) return;
    if (entry.info.ordinal > locate.target) return;
    if (entry.info.ordinal < locate.group_start) return;
    // A store entry never joins a compressed stream, so it never reaches the session.
    if (entry.method == 0) return;
    // The session's tables come from the target's version, so a mixed chain
    // would use wrong table sizes.
    if (versionClass(entry.unpack_version) != versionClass(target_version)) return error.UnsupportedException;
    const payload = try entryPayload(entry, archive, opts, bufs);
    if (entry.info.ordinal == locate.target) {
        const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceException;
        var bs = sink.BufferSink.init(output[0..size]);
        try session.decodeFile(payload, entry.info.size, entry.solid, bs.sink());
        if (bs.overflowed) return error.DataException;
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
    opts: DecodeOptions,
) Exception!usize {
    var kdf_memo: Rar5KdfMemo = .{};
    var memo_opts = opts;
    memo_opts.kdf_memo = &kdf_memo;
    var locate: LocateCtx = .{ .target = ordinal };
    try walkEntriesOpts(archive, memo_opts, &locate, locateVisit);
    const entry = locate.target_entry orelse return error.DataException;
    if (entry.is_directory) return error.DataException;

    const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;

    if (entry.method == 0) {
        const payload = try entryPayload(entry, archive, memo_opts, bufs);
        if (payload.len < size) return error.DataException;
        @memcpy(output[0..size], payload[0..size]);
    } else {
        const window_len = std.math.cast(usize, locate.group_max_window) orelse return error.ResourceException;
        try replayCompressed(archive, memo_opts, &locate, entry, output[0..size], bufs, window_len);
    }

    // Integrity: CRC32 of the delivered bytes, plus BLAKE2sp when present;
    // encrypted RAR5 stores an HMAC conversion.
    var hash_key: ?[32]u8 = null;
    if (entry.crypt) |c| {
        switch (c) {
            .rar5 => |r5| if (r5.hashmac) {
                const password = opts.password orelse return error.UnsupportedException;
                const keys = try rar5Kdf(password, &r5.salt, r5.lg2count, memo_opts);
                hash_key = keys.hash_key;
            },
            .rar4 => {},
        }
    }
    if (entry.info.has_crc) {
        const crc = checksum.crc32With(opts.provider, output[0..size]);
        if (hash_key) |key| {
            const mac = rar5CrcMac(opts.provider, crc, &key);
            if (!crypto.constantTimeEql(std.mem.asBytes(&mac), std.mem.asBytes(&entry.info.crc))) return error.IntegrityException;
        } else if (crc != entry.info.crc) return error.IntegrityException;
    }
    if (entry.blake2) |expected| {
        var got: [32]u8 = undefined;
        blake2sp.blake2sp(output[0..size], &got);
        if (hash_key) |key| {
            const mac = rar5BlakeMac(opts.provider, &got, &key);
            if (!crypto.constantTimeEql(&expected, &mac)) return error.IntegrityException;
        } else if (!crypto.constantTimeEql(&expected, &got)) return error.IntegrityException;
    }
    return size;
}

fn replayCompressed(
    archive: []const u8,
    opts: DecodeOptions,
    locate: *const LocateCtx,
    target: Entry,
    output: []u8,
    bufs: *DecodeBuffers,
    window_len: usize,
) Exception!void {
    if (bufs.window.len < window_len) return error.InternalException;
    if (bufs.filter_scratch.len < window_len + filter_scratch_extra) return error.InternalException;

    switch (target.family) {
        .rar5 => {
            if (bufs.table_pool.len < unpack50.table_pool_words * 4) return error.InternalException;
            if (bufs.pending50.len < unpack50.max_pending_filters) return error.InternalException;
            const st = try bufs.state50();
            var session = try unpack50.Session.init(
                st,
                bufs.window[0..window_len],
                bufs.table_pool[0 .. unpack50.table_pool_words * 4],
                bufs.pending50,
                bufs.filter_scratch,
                target.unpack_version == 70,
            );
            var replay: ReplayCtx(unpack50.Session) = .{ .session = &session, .archive = archive, .locate = locate, .output = output, .opts = opts, .bufs = bufs, .target_version = target.unpack_version };
            try walkEntriesOpts(archive, opts, &replay, replayVisitCtx(unpack50.Session));
        },
        .rar4 => {
            switch (target.unpack_version) {
                29, 36 => {
                    if (bufs.table_pool.len < unpack29.table_pool_words * 4) return error.InternalException;
                    if (bufs.pending29.len < unpack29.max_pending_filters) return error.InternalException;
                    const st = try bufs.state29();
                    var session = try unpack29.Session.init(
                        st,
                        bufs.window[0..window_len],
                        bufs.table_pool[0 .. unpack29.table_pool_words * 4],
                        bufs.pending29,
                        bufs.filter_scratch,
                        bufs.ppm_heap,
                        opts.provider,
                    );
                    var replay: ReplayCtx(unpack29.Session) = .{ .session = &session, .archive = archive, .locate = locate, .output = output, .opts = opts, .bufs = bufs, .target_version = target.unpack_version };
                    try walkEntriesOpts(archive, opts, &replay, replayVisitCtx(unpack29.Session));
                },
                20, 26 => {
                    if (bufs.table_pool.len < unpack20.table_pool_words) return error.InternalException;
                    const st = try bufs.state20();
                    var session = try unpack20.Session.init(
                        st,
                        bufs.window[0..window_len],
                        bufs.table_pool[0..unpack20.table_pool_words],
                    );
                    var replay: ReplayCtx(unpack20.Session) = .{ .session = &session, .archive = archive, .locate = locate, .output = output, .opts = opts, .bufs = bufs, .target_version = target.unpack_version };
                    try walkEntriesOpts(archive, opts, &replay, replayVisitCtx(unpack20.Session));
                },
                else => return error.UnsupportedException,
            }
        },
    }
}

fn ReplayCtx(comptime Session: type) type {
    return struct {
        session: *Session,
        archive: []const u8,
        locate: *const LocateCtx,
        output: []u8,
        opts: DecodeOptions,
        bufs: *DecodeBuffers,
        target_version: u8,
    };
}

fn replayVisitCtx(comptime Session: type) fn (*ReplayCtx(Session), Entry) Exception!void {
    return struct {
        fn visit(ctx: *ReplayCtx(Session), entry: Entry) Exception!void {
            try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output, ctx.opts, ctx.bufs, ctx.target_version);
        }
    }.visit;
}

// The split chain's head identity, hashed because -hp header-scratch
// reuse would dangle a name pointer.
const VolumeWalkState = struct {
    name_hash: u32,
    name_len: usize,
    compression: u64,
    last_volume: usize,
    first_crypt: ?Crypt = null,
    part_count: usize = 0,
    total_packed: usize = 0,
};

// Walk an ordered RAR5 volume set: volume 0 opens it, later volumes match
// numbers, and non-final volumes end with EARC_NEXT_VOLUME.
fn walkRar5Volumes(
    volumes: []const []const u8,
    parts_scratch: []SplitPart,
    opts: DecodeOptions,
    ctx: anytype,
    comptime visit: fn (@TypeOf(ctx), Entry) Exception!void,
) Exception!void {
    if (volumes.len == 0) return error.DataException;
    var ordinal: usize = 0;
    var chain: ?VolumeWalkState = null;
    for (volumes, 0..) |archive, volume_index| {
        if (archive.len < rar5_signature.len or
            !std.mem.eql(u8, archive[0..rar5_signature.len], &rar5_signature))
        {
            // A RAR4 volume would need the legacy walk, which this path never drives.
            if (archive.len >= rar4_signature.len and
                std.mem.eql(u8, archive[0..rar4_signature.len], &rar4_signature))
                return error.UnsupportedException;
            return error.DataException;
        }
        var cursor = rar5_signature.len;
        var seen_main = false;
        var header_crypt: ?Rar5Keys = null;
        var ended = false;
        while (cursor < archive.len) {
            const header = if (header_crypt) |*keys|
                try parseRar5BlockEncrypted(archive, &cursor, keys, opts.provider, opts.scratch)
            else
                try parseRar5Block(archive, &cursor, opts.provider);
            switch (header.header_type) {
                rar5_type_encryption => {
                    // -hp repeats the encryption block on every volume, so the
                    // headers decrypt standalone; the KDF memo makes the repeat free.
                    if (header.enc_lg2count > rar5_kdf_lg2_count_max) return error.UnsupportedException;
                    const password = opts.password orelse return error.UnsupportedException;
                    const keys = try rar5Kdf(password, &header.enc_salt, header.enc_lg2count, opts);
                    if (header.enc_pswcheck) |expected| {
                        if (!crypto.constantTimeEql(&rar5PswCheck(&keys.pswcheck), &expected)) {
                            if (opts.failure_cause) |cause| cause.* = .wrong_password;
                            return error.IntegrityException;
                        }
                    }
                    header_crypt = keys;
                },
                rar5_type_main => {
                    if (header.flags & (rar5_flag_data | rar5_flag_split_before | rar5_flag_split_after | rar5_flag_child | rar5_flag_inherited) != 0)
                        return error.UnsupportedException;
                    if (volume_index == 0) {
                        // Volume 0 never carries a number (unrar FirstVolume);
                        // a single-volume list also accepts a plain archive.
                        if (header.archive_flags & rar5_archive_volnum != 0) return error.DataException;
                        if (volumes.len > 1 and header.archive_flags & rar5_archive_volume == 0)
                            return error.DataException;
                    } else {
                        if (header.archive_flags & rar5_archive_volume == 0) return error.DataException;
                        if (header.archive_flags & rar5_archive_volnum == 0) return error.DataException;
                        if (header.archive_volnum != volume_index) return error.DataException;
                    }
                    seen_main = true;
                },
                rar5_type_end => {
                    if (!seen_main) return error.DataException;
                    if (header.archive_flags & rar5_earc_next_volume != 0) {
                        // The set must continue with the next volume in order.
                        if (volume_index + 1 >= volumes.len) return error.DataException;
                        ended = true;
                        break;
                    }
                    if (volume_index + 1 != volumes.len) return error.DataException;
                    if (chain != null) return error.DataException;
                    return;
                },
                rar5_type_service => {
                    if (!seen_main) return error.DataException;
                    continue;
                },
                rar5_type_file => {
                    if (!seen_main) return error.DataException;
                    const split_before = header.flags & rar5_flag_split_before != 0;
                    const split_after = header.flags & rar5_flag_split_after != 0;
                    // A directory is walked but never split: a producer that
                    // marks one is reporting a layout this reader cannot name.
                    if (header.is_directory and (split_before or split_after))
                        return error.DataException;
                    if (header.is_directory) continue;
                    if (chain == null) {
                        // A chain opens only at a part-0 header.
                        if (split_before) return error.DataException;
                        chain = .{
                            .name_hash = checksum.crc32With(opts.provider, header.name),
                            .name_len = header.name.len,
                            .compression = header.compression,
                            .last_volume = volume_index,
                            .first_crypt = header.crypt,
                        };
                    } else {
                        // A continuation must match its head's name and
                        // compression and arrive from a strictly later volume.
                        if (!split_before) return error.DataException;
                        if (checksum.crc32With(opts.provider, header.name) != chain.?.name_hash or
                            header.name.len != chain.?.name_len or
                            header.compression != chain.?.compression)
                            return error.DataException;
                        if (volume_index <= chain.?.last_volume) return error.DataException;
                        chain.?.last_volume = volume_index;
                        if (chain.?.first_crypt == null) chain.?.first_crypt = header.crypt;
                    }
                    const part_packed = std.math.cast(usize, header.data_size) orelse return error.ResourceException;
                    chain.?.total_packed = try bounds.addUsize(chain.?.total_packed, part_packed);
                    if (parts_scratch.len > 0) {
                        if (chain.?.part_count >= parts_scratch.len) return error.InternalException;
                        parts_scratch[chain.?.part_count] = .{
                            .volume = volume_index,
                            .offset = header.data_offset,
                            .packed_size = part_packed,
                        };
                    }
                    chain.?.part_count = try bounds.addUsize(chain.?.part_count, 1);
                    if (!split_after) {
                        const head = chain.?;
                        var entry = try rar5FileEntry(header, ordinal, head.total_packed, head.first_crypt);
                        if (parts_scratch.len > 0) {
                            entry.parts = parts_scratch[0..head.part_count];
                            entry.info.data_offset = parts_scratch[0].offset;
                        }
                        chain = null;
                        ordinal = try bounds.addUsize(ordinal, 1);
                        try visit(ctx, entry);
                    }
                },
                else => {},
            }
        }
        if (ended) continue;
        // A block-boundary EOF without the end block, which older producers
        // write; the same ordering rules apply.
        if (!seen_main) return error.DataException;
        if (volume_index + 1 != volumes.len) return error.DataException;
        if (chain != null) return error.DataException;
        return;
    }
    // Unreachable in a valid set: every volume ends through the end block
    // or the EOF rule.
    return error.DataException;
}

// Gather a split entry's parts; encrypted chains decrypt as one CBC
// stream across parts (unrar extract.cpp).
fn volumeGather(
    entry: Entry,
    volumes: []const []const u8,
    opts: DecodeOptions,
    bufs: *DecodeBuffers,
) Exception![]const u8 {
    if (entry.parts.len == 0) return error.InternalException;
    var total: usize = 0;
    for (entry.parts) |part| total = try bounds.addUsize(total, part.packed_size);
    const crypt = entry.crypt orelse {
        if (entry.parts.len == 1) {
            const part = entry.parts[0];
            return bounds.slice(volumes[part.volume], part.offset, part.packed_size);
        }
        if (bufs.packed_stage.len < total) return error.InternalException;
        var staged: usize = 0;
        for (entry.parts) |part| {
            const src = try bounds.slice(volumes[part.volume], part.offset, part.packed_size);
            @memcpy(bufs.packed_stage[staged..][0..src.len], src);
            staged += src.len;
        }
        if (staged != total) return error.InternalException;
        return bufs.packed_stage[0..total];
    };
    switch (crypt) {
        // The RAR4 file crypt has no split surface here: the legacy walk never
        // drives a volume set.
        .rar4 => return error.UnsupportedException,
        .rar5 => |c| {
            const password = opts.password orelse return error.UnsupportedException;
            if (opts.password_lifetime != 0 and total > opts.password_lifetime) {
                if (opts.failure_cause) |cause| cause.* = .password_lifetime;
                return error.ResourceException;
            }
            const keys = try rar5Kdf(password, &c.salt, c.lg2count, opts);
            if (c.pswcheck) |expected| {
                if (!crypto.constantTimeEql(&rar5PswCheck(&keys.pswcheck), &expected)) {
                    if (opts.failure_cause) |cause| cause.* = .wrong_password;
                    return error.DataException;
                }
            }
            if (bufs.packed_stage.len < total) return error.InternalException;
            var chain_iv: [16]u8 = undefined;
            var staged: usize = 0;
            for (entry.parts, 0..) |part, i| {
                const src = try bounds.slice(volumes[part.volume], part.offset, part.packed_size);
                // Every part with data is a whole number of AES blocks;
                // the final part carries the stream's zero padding.
                if (total != 0 and (src.len < crypto.block_length or src.len % crypto.block_length != 0))
                    return error.DataException;
                const iv: *const [16]u8 = if (i == 0) &c.iv else &chain_iv;
                const dst = bufs.packed_stage[staged..][0..src.len];
                crypto.aesCbcDecrypt(opts.provider, keys.key[0..], iv.*, dst, src) catch return error.DataException;
                staged += src.len;
                if (i + 1 < entry.parts.len) @memcpy(&chain_iv, src[src.len - 16 ..][0..16]);
            }
            if (staged != total) return error.InternalException;
            return bufs.packed_stage[0..total];
        },
    }
}

// Store decode of a volume set: a second walk fires at the target
// because the part scratch is reused.
const VolumeStoreCtx = struct {
    target: usize,
    done: bool = false,
    volumes: []const []const u8,
    output: []u8,
    opts: DecodeOptions,
    bufs: *DecodeBuffers,

    fn visit(ctx: *VolumeStoreCtx, entry: Entry) Exception!void {
        if (ctx.done) return;
        if (entry.info.ordinal != ctx.target) return;
        const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceException;
        const payload = try volumeGather(entry, ctx.volumes, ctx.opts, ctx.bufs);
        if (payload.len < size) return error.DataException;
        @memcpy(ctx.output[0..size], payload[0..size]);
        ctx.done = true;
    }
};

// Compressed replay of a volume set: parts are gathered at each entry's
// own visit, before the scratch is reused.
const VolumeReplayCtx = struct {
    session: *unpack50.Session,
    volumes: []const []const u8,
    locate: *const LocateCtx,
    output: []u8,
    opts: DecodeOptions,
    bufs: *DecodeBuffers,
    target_version: u8,

    fn visit(ctx: *VolumeReplayCtx, entry: Entry) Exception!void {
        if (entry.info.ordinal > ctx.locate.target) return;
        if (entry.info.ordinal < ctx.locate.group_start) return;
        // A store entry never joins a compressed stream, so it never reaches the session.
        if (entry.method == 0) return;
        // The session's tables come from the target's version, so a mixed
        // chain would use wrong table sizes.
        if (versionClass(entry.unpack_version) != versionClass(ctx.target_version)) return error.UnsupportedException;
        const payload = try volumeGather(entry, ctx.volumes, ctx.opts, ctx.bufs);
        if (entry.info.ordinal == ctx.locate.target) {
            const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceException;
            var bs = sink.BufferSink.init(ctx.output[0..size]);
            try ctx.session.decodeFile(payload, entry.info.size, entry.solid, bs.sink());
            if (bs.overflowed) return error.DataException;
        } else {
            var discard = sink.DiscardSink{};
            try ctx.session.decodeFile(payload, entry.info.size, entry.solid, discard.sink());
        }
    }
};

fn replayVolumesCompressed(
    volumes: []const []const u8,
    opts: DecodeOptions,
    locate: *const LocateCtx,
    target: Entry,
    output: []u8,
    bufs: *DecodeBuffers,
    window_len: usize,
) Exception!void {
    if (bufs.window.len < window_len) return error.InternalException;
    if (bufs.filter_scratch.len < window_len + filter_scratch_extra) return error.InternalException;
    if (bufs.table_pool.len < unpack50.table_pool_words * 4) return error.InternalException;
    if (bufs.pending50.len < unpack50.max_pending_filters) return error.InternalException;
    const st = try bufs.state50();
    var session = try unpack50.Session.init(
        st,
        bufs.window[0..window_len],
        bufs.table_pool[0 .. unpack50.table_pool_words * 4],
        bufs.pending50,
        bufs.filter_scratch,
        target.unpack_version == 70,
    );
    var replay: VolumeReplayCtx = .{
        .session = &session,
        .volumes = volumes,
        .locate = locate,
        .output = output,
        .opts = opts,
        .bufs = bufs,
        .target_version = target.unpack_version,
    };
    try walkRar5Volumes(volumes, bufs.split_parts, opts, &replay, VolumeReplayCtx.visit);
}

// Counts the readable entries of an ordered multi-volume RAR5 set.
pub fn rarVolumeCount(volumes: []const []const u8, max_entries: u64, opts: DecodeOptions) Exception!usize {
    var ctx: CountCtx = .{ .max_entries = max_entries };
    try walkRar5Volumes(volumes, &.{}, opts, &ctx, countVisit);
    return ctx.count;
}

// Decode one entry of a RAR5 volume set; the locate pass needs no parts,
// and the integrity tail matches rarDecodeOrdinal.
pub fn rarVolumeDecodeOrdinal(
    volumes: []const []const u8,
    ordinal: usize,
    output: []u8,
    bufs: *DecodeBuffers,
    opts: DecodeOptions,
) Exception!usize {
    var kdf_memo: Rar5KdfMemo = .{};
    var memo_opts = opts;
    memo_opts.kdf_memo = &kdf_memo;
    var locate: LocateCtx = .{ .target = ordinal };
    try walkRar5Volumes(volumes, &.{}, memo_opts, &locate, locateVisit);
    const entry = locate.target_entry orelse return error.DataException;
    if (entry.is_directory) return error.DataException;

    const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceException;
    if (output.len < size) return error.CapacityException;

    if (entry.method == 0) {
        var store: VolumeStoreCtx = .{
            .target = ordinal,
            .volumes = volumes,
            .output = output,
            .opts = memo_opts,
            .bufs = bufs,
        };
        try walkRar5Volumes(volumes, bufs.split_parts, memo_opts, &store, VolumeStoreCtx.visit);
        if (!store.done) return error.DataException;
    } else {
        const window_len = std.math.cast(usize, locate.group_max_window) orelse return error.ResourceException;
        try replayVolumesCompressed(volumes, memo_opts, &locate, entry, output[0..size], bufs, window_len);
    }

    var hash_key: ?[32]u8 = null;
    if (entry.crypt) |c| {
        switch (c) {
            .rar5 => |r5| if (r5.hashmac) {
                const password = opts.password orelse return error.UnsupportedException;
                const keys = try rar5Kdf(password, &r5.salt, r5.lg2count, memo_opts);
                hash_key = keys.hash_key;
            },
            .rar4 => {},
        }
    }
    if (entry.info.has_crc) {
        const crc = checksum.crc32With(opts.provider, output[0..size]);
        if (hash_key) |key| {
            const mac = rar5CrcMac(opts.provider, crc, &key);
            if (!crypto.constantTimeEql(std.mem.asBytes(&mac), std.mem.asBytes(&entry.info.crc))) return error.IntegrityException;
        } else if (crc != entry.info.crc) return error.IntegrityException;
    }
    if (entry.blake2) |expected| {
        var got: [32]u8 = undefined;
        blake2sp.blake2sp(output[0..size], &got);
        if (hash_key) |key| {
            const mac = rar5BlakeMac(opts.provider, &got, &key);
            if (!crypto.constantTimeEql(&expected, &mac)) return error.IntegrityException;
        } else if (!crypto.constantTimeEql(&expected, &got)) return error.IntegrityException;
    }
    return size;
}

test "rar4 kdf reproduces the unrar sha1_process_rar29 self-modification" {
    // Expected bytes transcribe vendor/unrar/sha1.cpp and crypt3.cpp SetKey30;
    // a plain SHA-1 KDF would yield 1ac08ded32dd4d33dcae099781825ea5 here.
    const salt = [8]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const long_pw = "This password is deliberately long enough to trigger the RAR3 KDF buffer self-modification quirk";
    var utf16: [2 * 512]u8 = undefined;
    const encoded = try passwordToUtf16Le(long_pw, &utf16);

    const salted = try rar4Kdf(encoded, &salt, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xe9, 0x82, 0x51, 0x88, 0x21, 0xfe, 0x66, 0x83,
        0xf5, 0xec, 0xd9, 0x15, 0xbb, 0xf5, 0xbc, 0xf1,
    }, &salted.key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xe0, 0xe6, 0x27, 0x15, 0x3e, 0x38, 0x23, 0xf4,
        0x39, 0x7a, 0x91, 0x90, 0x0e, 0x2c, 0xdc, 0x17,
    }, &salted.iv);

    const unsalted = try rar4Kdf(encoded, null, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x87, 0x5c, 0x15, 0xb5, 0x6a, 0xf4, 0x22, 0x99,
        0xd2, 0xc7, 0xf6, 0x83, 0x26, 0xc9, 0x7a, 0x97,
    }, &unsalted.key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xd4, 0xb9, 0x8d, 0x87, 0x43, 0x2c, 0x30, 0xc6,
        0xee, 0xa6, 0x35, 0x04, 0x00, 0x37, 0xae, 0x6a,
    }, &unsalted.iv);

    // The short-password regime never rewrites RawPsw, matching a plain
    // SHA-1 KDF; the oracle fixtures use this salt and password.
    const short = try rar4Kdf(try passwordToUtf16Le("PASS", &utf16), &salt, .{});
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xb4, 0x04, 0x43, 0x32, 0x88, 0x40, 0x9e, 0xe0,
        0x4a, 0x04, 0x7d, 0xd5, 0x7a, 0xa6, 0x1c, 0x4e,
    }, &short.key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xec, 0xc3, 0xb1, 0xed, 0x6b, 0x73, 0xdd, 0x0b,
        0x78, 0xe8, 0x8c, 0xfc, 0xbd, 0x1b, 0xfd, 0x17,
    }, &short.iv);
}

// The fixtures below build walk-test wire bytes; each caller pins its CRC
// coverage, so regressions break the stored CRC.

const TestEntries = struct {
    count: usize = 0,
    names: [4][64]u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) },
    name_lens: [4]usize = @splat(0),
    sizes: [4]u64 = @splat(0),
    data_offsets: [4]u64 = @splat(0),
    packed_sizes: [4]u64 = @splat(0),
    unpack_versions: [4]u8 = @splat(0),
    window_bytes: [4]u64 = @splat(0),
    pswchecks: [4]?[8]u8 = @splat(null),

    fn name(self: *const TestEntries, index: usize) []const u8 {
        return self.names[index][0..self.name_lens[index]];
    }
};

// The walk stages headers in reused scratch, so the visit copies what it keeps.
fn testEntryVisit(ctx: *TestEntries, entry: Entry) Exception!void {
    if (ctx.count >= 4) return error.ResourceException;
    const index = ctx.count;
    const entry_name = entry.info.name;
    @memcpy(ctx.names[index][0..entry_name.len], entry_name);
    ctx.name_lens[index] = entry_name.len;
    ctx.sizes[index] = entry.info.size;
    ctx.data_offsets[index] = entry.info.data_offset;
    ctx.packed_sizes[index] = entry.info.packed_size;
    ctx.unpack_versions[index] = entry.info.unpack_version;
    ctx.window_bytes[index] = entry.info.window_bytes;
    ctx.pswchecks[index] = if (entry.crypt) |crypt| switch (crypt) {
        .rar5 => |state| state.pswcheck,
        .rar4 => null,
    } else null;
    ctx.count += 1;
}

// Writes a RAR4 block header; the caller pre-zeros the buffer first, and
// coverage 0 stores a deliberately wrong CRC.
fn rar4FixtureHeader(out: []u8, header_type: u8, flags: u16, head_size: usize, coverage: usize) []u8 {
    out[2] = header_type;
    std.mem.writeInt(u16, out[3..5], flags, .little);
    std.mem.writeInt(u16, out[5..7], @intCast(head_size), .little);
    if (coverage == 0) {
        std.mem.writeInt(u16, out[0..2], 0xDEAD, .little);
    } else {
        const crc: u16 = @truncate(checksum.crc32With(crypto.default_provider, out[2..][0 .. coverage - 2]));
        std.mem.writeInt(u16, out[0..2], crc, .little);
    }
    return out[0..head_size];
}

// A RAR4 file header with fixed fields; the CRC covers the full header,
// like a real producer.
fn rar4FixtureFileHead(out: []u8, flags: u16, unpacked: u32, name: []const u8) []u8 {
    const head_size = 32 + name.len;
    @memset(out[0..head_size], 0);
    out[2] = rar4_file;
    std.mem.writeInt(u16, out[3..5], flags, .little);
    std.mem.writeInt(u16, out[5..7], @intCast(head_size), .little);
    std.mem.writeInt(u32, out[7..11], 5, .little);
    std.mem.writeInt(u32, out[11..15], unpacked, .little);
    out[15] = rar4_host_unix;
    std.mem.writeInt(u32, out[16..20], 0xDEADBEEF, .little);
    std.mem.writeInt(u32, out[20..24], 123456789, .little);
    out[24] = 29;
    out[25] = 0x30;
    std.mem.writeInt(u16, out[26..28], @intCast(name.len), .little);
    std.mem.writeInt(u32, out[28..32], 0x81A4, .little);
    @memcpy(out[32..head_size], name);
    const crc: u16 = @truncate(checksum.crc32With(crypto.default_provider, out[2..head_size]));
    std.mem.writeInt(u16, out[0..2], crc, .little);
    return out[0..head_size];
}

// Wraps a plaintext header as a -hp block: an 8-byte salt, then AES-128-CBC
// of the zero-padded header.
fn rar4FixtureEncryptedBlock(out: []u8, plaintext: []const u8, key: []const u8, iv: [16]u8, salt: [8]u8) Exception![]u8 {
    const crypt_len = std.mem.alignForward(usize, plaintext.len, 16);
    var padded: [64]u8 = @splat(0);
    @memcpy(padded[0..plaintext.len], plaintext);
    @memcpy(out[0..8], &salt);
    try crypto.aesCbcEncrypt(crypto.default_provider, key, iv, out[8..][0..crypt_len], padded[0..crypt_len]);
    return out[0 .. 8 + crypt_len];
}

// Wraps a RAR5 header body as a block: a CRC32 of the size vint and the body.
fn rar5FixtureBlock(out: []u8, body: []const u8) Exception![]u8 {
    var cursor = binary.WriteCursor.init(out[4..]);
    try cursor.writeUleb128(body.len);
    const size_bytes = cursor.pos;
    @memcpy(out[4 + size_bytes ..][0..body.len], body);
    const block_len = 4 + size_bytes + body.len;
    const crc = checksum.crc32With(crypto.default_provider, out[4..block_len]);
    std.mem.writeInt(u32, out[0..4], crc, .little);
    return out[0..block_len];
}

// A three-byte main or end body: type, zero header flags, zero archive flags.
fn rar5FixtureSimpleBody(out: []u8, header_type: u64) Exception![]u8 {
    var cursor = binary.WriteCursor.init(out);
    try cursor.writeUleb128(header_type);
    try cursor.writeUleb128(0);
    try cursor.writeUleb128(0);
    return out[0..cursor.pos];
}

// A file or service body in the ReadHeader50 field order; header flags
// gate the data and extra vints.
fn rar5FixtureFileBody(
    out: []u8,
    header_type: u64,
    header_flags: u64,
    data_size: u64,
    file_flags: u64,
    unpacked: u64,
    compression: u64,
    name: []const u8,
    file_crc: u32,
    extra: []const u8,
) Exception![]u8 {
    var cursor = binary.WriteCursor.init(out);
    try cursor.writeUleb128(header_type);
    try cursor.writeUleb128(header_flags);
    if (header_flags & rar5_flag_extra != 0) try cursor.writeUleb128(extra.len);
    if (header_flags & rar5_flag_data != 0) try cursor.writeUleb128(data_size);
    try cursor.writeUleb128(file_flags);
    try cursor.writeUleb128(unpacked);
    try cursor.writeUleb128(0);
    if (file_flags & rar5_file_mtime != 0) {
        std.mem.writeInt(u32, cursor.buffer[cursor.pos..][0..4], 0, .little);
        cursor.pos += 4;
    }
    if (file_flags & rar5_file_crc32 != 0) {
        std.mem.writeInt(u32, cursor.buffer[cursor.pos..][0..4], file_crc, .little);
        cursor.pos += 4;
    }
    try cursor.writeUleb128(compression);
    try cursor.writeUleb128(0);
    try cursor.writeUleb128(name.len);
    @memcpy(cursor.buffer[cursor.pos..][0..name.len], name);
    cursor.pos += name.len;
    @memcpy(cursor.buffer[cursor.pos..][0..extra.len], extra);
    cursor.pos += extra.len;
    return out[0..cursor.pos];
}

test "rar4 hp archives salt every encrypted header block" {
    // A -hp archive encrypts every block after the main header; keys
    // re-derive only when the salt changes.
    const salt = [8]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    var utf16: [2 * 512]u8 = undefined;
    const keys = try rar4Kdf(try passwordToUtf16Le("PASS", &utf16), &salt, .{});

    var archive: [105]u8 = @splat(0);
    @memcpy(archive[0..7], &rar4_signature);
    _ = rar4FixtureHeader(archive[7..20], rar4_main, rar4_mhd_password, 13, 13);
    var plain: [64]u8 = @splat(0);
    const file_head = rar4FixtureFileHead(&plain, 0x8000, 5, "t.txt");
    _ = try rar4FixtureEncryptedBlock(archive[20..76], file_head, &keys.key, keys.iv, salt);
    @memcpy(archive[76..81], "hello");
    @memset(&plain, 0);
    _ = rar4FixtureHeader(&plain, rar4_end, 0x0000, 7, 7);
    _ = try rar4FixtureEncryptedBlock(archive[81..105], plain[0..7], &keys.key, keys.iv, salt);

    var entries: TestEntries = .{};
    var scratch: [4096]u8 = undefined;
    try walkEntriesOpts(&archive, .{ .password = "PASS", .scratch = &scratch }, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
    try std.testing.expectEqualStrings("t.txt", entries.name(0));
    try std.testing.expectEqual(@as(u64, 5), entries.sizes[0]);
    try std.testing.expectEqual(@as(u64, 76), entries.data_offsets[0]);
    try std.testing.expectEqual(@as(u64, 5), entries.packed_sizes[0]);

    var negative: [97]u8 = @splat(0);
    @memcpy(negative[0..81], archive[0..81]);
    @memcpy(negative[81..97], archive[60..76]);
    var negative_entries: TestEntries = .{};
    try std.testing.expectError(error.DataException, walkEntriesOpts(
        &negative,
        .{ .password = "PASS", .scratch = &scratch },
        &negative_entries,
        testEntryVisit,
    ));
    try std.testing.expectEqual(@as(usize, 1), negative_entries.count);
}

test "rar4 header crc coverage follows the raw read size" {
    // ReadHeader15 covers 13 bytes for main-with-comment and comment
    // blocks; SIGN and AV stay exempt, but non-UO services verify.
    var archive: [113]u8 = @splat(0);
    @memcpy(archive[0..7], &rar4_signature);
    _ = rar4FixtureHeader(archive[7..24], rar4_main, rar4_mhd_comment, 17, 13);
    @memset(archive[20..24], 0xAA);
    _ = rar4FixtureHeader(archive[24..41], rar4_cmt, 0x0000, 17, 13);
    @memset(archive[37..41], 0xAA);
    _ = rar4FixtureHeader(archive[41..48], rar4_sign, 0x0000, 7, 0);
    _ = rar4FixtureHeader(archive[48..55], rar4_av, 0x0000, 7, 0);
    archive[66] = 0x01;
    archive[67] = 0x01;
    _ = rar4FixtureHeader(archive[55..68], rar4_old_service, 0x0000, 13, 0);
    var plain: [64]u8 = @splat(0);
    @memcpy(archive[68..101], rar4FixtureFileHead(&plain, 0x8000, 5, "a"));
    @memcpy(archive[101..106], "hello");
    _ = rar4FixtureHeader(archive[106..113], rar4_end, 0x0000, 7, 7);

    var entries: TestEntries = .{};
    try walkEntriesOpts(&archive, .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
    try std.testing.expectEqualStrings("a", entries.name(0));
    try std.testing.expectEqual(@as(u64, 101), entries.data_offsets[0]);
    try std.testing.expectEqual(@as(u64, 5), entries.packed_sizes[0]);

    var negative: [40]u8 = @splat(0);
    @memcpy(negative[0..7], &rar4_signature);
    _ = rar4FixtureHeader(negative[7..20], rar4_main, 0x0000, 13, 13);
    var head_buf: [13]u8 = @splat(0);
    std.mem.writeInt(u16, head_buf[11..13], 0x0100, .little);
    _ = rar4FixtureHeader(&head_buf, rar4_old_service, 0x0000, 13, 13);
    std.mem.writeInt(u16, head_buf[0..2], 0xDEAD, .little);
    @memcpy(negative[20..33], &head_buf);
    _ = rar4FixtureHeader(negative[33..40], rar4_end, 0x0000, 7, 7);
    var negative_entries: TestEntries = .{};
    try std.testing.expectError(
        error.IntegrityException,
        walkEntriesOpts(&negative, .{}, &negative_entries, testEntryVisit),
    );
}

test "rar4 file header add size is unconditional" {
    // ADD_SIZE at offset 7 is a file field, not a LONG_BLOCK extra,
    // so its read never depends on LONG_BLOCK.
    var archive: [65]u8 = @splat(0);
    @memcpy(archive[0..7], &rar4_signature);
    _ = rar4FixtureHeader(archive[7..20], rar4_main, 0x0000, 13, 13);
    var plain: [64]u8 = @splat(0);
    @memcpy(archive[20..53], rar4FixtureFileHead(&plain, 0x0000, 5, "a"));
    @memcpy(archive[53..58], "hello");
    _ = rar4FixtureHeader(archive[58..65], rar4_end, 0x0000, 7, 7);

    var entries: TestEntries = .{};
    try walkEntriesOpts(&archive, .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
    try std.testing.expectEqualStrings("a", entries.name(0));
    try std.testing.expectEqual(@as(u64, 53), entries.data_offsets[0]);
    try std.testing.expectEqual(@as(u64, 5), entries.packed_sizes[0]);
}

test "rar4 unknown unpacked size is refused" {
    // The 0xffffffff unpacked size is unrar's unknown-size marker; this
    // facade sizes output ahead, so the entry is refused.
    var archive: [65]u8 = @splat(0);
    @memcpy(archive[0..7], &rar4_signature);
    _ = rar4FixtureHeader(archive[7..20], rar4_main, 0x0000, 13, 13);
    var plain: [64]u8 = @splat(0);
    @memcpy(archive[20..53], rar4FixtureFileHead(&plain, 0x8000, 0xffffffff, "a"));
    @memcpy(archive[53..58], "hello");
    _ = rar4FixtureHeader(archive[58..65], rar4_end, 0x0000, 7, 7);

    var entries: TestEntries = .{};
    try std.testing.expectError(
        error.UnsupportedException,
        walkEntriesOpts(&archive, .{}, &entries, testEntryVisit),
    );
}

test "rar5 child and inherited file blocks are walked" {
    // A child block lists as its own entry, and an interleaved service
    // block never consumes an ordinal.
    var archive: [94]u8 = @splat(0);
    var body: [32]u8 = undefined;
    @memcpy(archive[0..8], &rar5_signature);
    _ = try rar5FixtureBlock(archive[8..16], try rar5FixtureSimpleBody(&body, rar5_type_main));
    _ = try rar5FixtureBlock(archive[16..39], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data,
        5,
        rar5_file_crc32,
        5,
        0x01,
        "c.txt",
        0x3610A686,
        &.{},
    ));
    @memcpy(archive[39..44], "hello");
    _ = try rar5FixtureBlock(archive[44..58], try rar5FixtureFileBody(
        &body,
        rar5_type_service,
        0,
        0,
        0,
        0,
        0,
        "Q",
        0,
        &.{},
    ));
    _ = try rar5FixtureBlock(archive[58..81], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data | rar5_flag_child | rar5_flag_inherited,
        5,
        rar5_file_crc32,
        5,
        0x01,
        "d.txt",
        0,
        &.{},
    ));
    @memcpy(archive[81..86], "world");
    _ = try rar5FixtureBlock(archive[86..94], try rar5FixtureSimpleBody(&body, rar5_type_end));

    var entries: TestEntries = .{};
    try walkEntriesOpts(&archive, .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 2), entries.count);
    try std.testing.expectEqualStrings("c.txt", entries.name(0));
    try std.testing.expectEqualStrings("d.txt", entries.name(1));
    try std.testing.expectEqual(@as(u64, 39), entries.data_offsets[0]);
    try std.testing.expectEqual(@as(u64, 81), entries.data_offsets[1]);
    try std.testing.expectEqual(@as(u64, 5), entries.packed_sizes[0]);
    try std.testing.expectEqual(@as(u64, 5), entries.packed_sizes[1]);
}

test "rar5 rar7 window fraction and compat mask" {
    // 0x104081: compat bit set, version 50; 0xFA881: window bits 10
    // plus a 31/32 fraction, version 70; 0xCC81 overflows.
    var archive: [68]u8 = @splat(0);
    var body: [32]u8 = undefined;
    @memcpy(archive[0..8], &rar5_signature);
    _ = try rar5FixtureBlock(archive[8..16], try rar5FixtureSimpleBody(&body, rar5_type_main));
    _ = try rar5FixtureBlock(archive[16..37], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data,
        1,
        rar5_file_crc32,
        1,
        1065089,
        "A",
        0,
        &.{},
    ));
    @memcpy(archive[37..38], "A");
    _ = try rar5FixtureBlock(archive[38..59], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data,
        1,
        rar5_file_crc32,
        1,
        1026177,
        "B",
        0,
        &.{},
    ));
    @memcpy(archive[59..60], "B");
    _ = try rar5FixtureBlock(archive[60..68], try rar5FixtureSimpleBody(&body, rar5_type_end));

    var entries: TestEntries = .{};
    try walkEntriesOpts(&archive, .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 2), entries.count);
    try std.testing.expectEqualStrings("A", entries.name(0));
    try std.testing.expectEqualStrings("B", entries.name(1));
    try std.testing.expectEqual(@as(u8, 50), entries.unpack_versions[0]);
    try std.testing.expectEqual(@as(u8, 70), entries.unpack_versions[1]);
    try std.testing.expectEqual(@as(u64, 1) << 33, entries.window_bytes[0]);
    try std.testing.expectEqual(@as(u64, 1) << 28, entries.window_bytes[1]);

    var overflow: [46]u8 = @splat(0);
    @memcpy(overflow[0..8], &rar5_signature);
    _ = try rar5FixtureBlock(overflow[8..16], try rar5FixtureSimpleBody(&body, rar5_type_main));
    _ = try rar5FixtureBlock(overflow[16..37], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data,
        1,
        rar5_file_crc32,
        1,
        52353,
        "C",
        0,
        &.{},
    ));
    @memcpy(overflow[37..38], "C");
    _ = try rar5FixtureBlock(overflow[38..46], try rar5FixtureSimpleBody(&body, rar5_type_end));
    var overflow_entries: TestEntries = .{};
    try std.testing.expectError(
        error.UnsupportedException,
        walkEntriesOpts(&overflow, .{}, &overflow_entries, testEntryVisit),
    );
}

test "rar5 solid chains refuse to mix unpack versions" {
    // Vendor switches ExtraDist per file; this single-session replay refuses
    // mixed chains. The payloads stay opaque; the guard fires first.
    var archive: [68]u8 = @splat(0);
    var body: [32]u8 = undefined;
    @memcpy(archive[0..8], &rar5_signature);
    _ = try rar5FixtureBlock(archive[8..16], try rar5FixtureSimpleBody(&body, rar5_type_main));
    _ = try rar5FixtureBlock(archive[16..36], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data,
        2,
        rar5_file_crc32,
        2,
        0xC0,
        "A",
        0,
        &.{},
    ));
    @memcpy(archive[36..38], "AA");
    _ = try rar5FixtureBlock(archive[38..58], try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data,
        2,
        rar5_file_crc32,
        2,
        0xC1,
        "B",
        0,
        &.{},
    ));
    @memcpy(archive[58..60], "BB");
    _ = try rar5FixtureBlock(archive[60..68], try rar5FixtureSimpleBody(&body, rar5_type_end));

    var entries: TestEntries = .{};
    try walkEntriesOpts(&archive, .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 2), entries.count);
    try std.testing.expectEqual(@as(u8, 50), entries.unpack_versions[0]);
    try std.testing.expectEqual(@as(u8, 70), entries.unpack_versions[1]);

    const allocator = std.testing.allocator;
    const window = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(window);
    const state_store = try allocator.alloc(u64, (max_unpacker_bytes + 7) / 8);
    defer allocator.free(state_store);
    const table_pool = try allocator.alloc(u16, table_pool_words);
    defer allocator.free(table_pool);
    const pending50 = try allocator.alloc(filters50.Filter, max_pending50);
    defer allocator.free(pending50);
    const pending29 = try allocator.alloc(unpack29.PendingFilter, max_pending29);
    defer allocator.free(pending29);
    const filter_scratch = try allocator.alloc(u8, window.len + filter_scratch_extra);
    defer allocator.free(filter_scratch);
    const ppm_heap = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(ppm_heap);
    const bufs = DecodeBuffers{
        .state = std.mem.sliceAsBytes(state_store),
        .window = window,
        .table_pool = table_pool,
        .pending50 = pending50,
        .pending29 = pending29,
        .filter_scratch = filter_scratch,
        .ppm_heap = ppm_heap,
    };
    var out: [2]u8 = undefined;
    try std.testing.expectError(
        error.UnsupportedException,
        rarDecodeOrdinal(&archive, 1, &out, @constCast(&bufs), .{}),
    );
}

// The first four SHA-256 bytes, the csum of a stored password check.
fn fixtureSha256Csum(input: []const u8) [4]u8 {
    var sha = crypto.Sha256.bind(crypto.default_provider, .{});
    sha.update(input);
    const digest = sha.finalResult();
    return .{ digest[0], digest[1], digest[2], digest[3] };
}

// A FHEXTRA_CRYPT record: type, version, flags, KDF count, salt, IV,
// check, and csum.
fn rar5FixtureCryptRecord(out: *[49]u8, salt: *const [16]u8, check: [8]u8, csum: [4]u8) Exception!void {
    var cursor = binary.WriteCursor.init(out[1..]);
    try cursor.writeUleb128(rar5_extra_crypt);
    try cursor.writeUleb128(0); // version.
    try cursor.writeUleb128(rar5_crypt_pswcheck); // flags.
    try cursor.writeU8(0); // KDF count: a single round.
    @memcpy(cursor.buffer[cursor.pos..][0..16], salt);
    cursor.pos += 16;
    @memcpy(cursor.buffer[cursor.pos..][0..16], salt); // The IV is arbitrary here.
    cursor.pos += 16;
    @memcpy(cursor.buffer[cursor.pos..][0..8], &check);
    cursor.pos += 8;
    @memcpy(cursor.buffer[cursor.pos..][0..4], &csum);
    cursor.pos += 4;
    out[0] = @intCast(cursor.pos); // The record size: the type and data.
}

// A RAR5 -hp encrypted header: a cleartext IV, then AES-256-CBC of the
// zero-padded CRC, size vint, and body.
fn rar5FixtureEncryptedHeader(out: []u8, body: []const u8, key: []const u8, iv: [16]u8) Exception![]u8 {
    var padded: [80]u8 = @splat(0);
    var cursor = binary.WriteCursor.init(padded[4..]);
    try cursor.writeUleb128(body.len);
    @memcpy(padded[4 + cursor.pos ..][0..body.len], body);
    const header_size = 4 + cursor.pos + body.len;
    const crc = checksum.crc32With(crypto.default_provider, padded[4..header_size]);
    std.mem.writeInt(u32, padded[0..4], crc, .little);
    const enc_len = std.mem.alignForward(usize, header_size, 16);
    @memcpy(out[0..16], &iv);
    try crypto.aesCbcEncrypt(crypto.default_provider, key, iv, out[16..][0..enc_len], padded[0..enc_len]);
    return out[0 .. 16 + enc_len];
}

// A cleartext RAR5 archive with one stored file carrying the given extra area.
fn rar5FixtureFileArchive(out: []u8, name: []const u8, data_size: u64, extra: []const u8) Exception!usize {
    @memcpy(out[0..8], &rar5_signature);
    var pos: usize = 8;
    var body: [80]u8 = undefined;
    var block: [96]u8 = undefined;
    const main = try rar5FixtureSimpleBody(&body, rar5_type_main);
    const main_block = try rar5FixtureBlock(&block, main);
    @memcpy(out[pos..][0..main_block.len], main_block);
    pos += main_block.len;
    const file_body = try rar5FixtureFileBody(
        &body,
        rar5_type_file,
        rar5_flag_data | rar5_flag_extra,
        data_size,
        rar5_file_crc32,
        data_size,
        0x01,
        name,
        checksum.crc32With(crypto.default_provider, "hello"[0..@intCast(data_size)]),
        extra,
    );
    const file_block = try rar5FixtureBlock(&block, file_body);
    @memcpy(out[pos..][0..file_block.len], file_block);
    pos += file_block.len;
    const copy_size: usize = @intCast(data_size);
    @memcpy(out[pos..][0..copy_size], "hello"[0..copy_size]);
    pos += copy_size;
    const end = try rar5FixtureSimpleBody(&body, rar5_type_end);
    const end_block = try rar5FixtureBlock(&block, end);
    @memcpy(out[pos..][0..end_block.len], end_block);
    pos += end_block.len;
    return pos;
}

// A -hp RAR5 archive: a cleartext HEAD_CRYPT block, then encrypted main
// and end blocks.
fn rar5FixtureHpArchive(out: []u8, salt: *const [16]u8, check: [8]u8, csum: [4]u8, keys: *const Rar5Keys) Exception!usize {
    @memcpy(out[0..8], &rar5_signature);
    var pos: usize = 8;
    var body: [48]u8 = undefined;
    var block: [64]u8 = undefined;
    var cursor = binary.WriteCursor.init(&body);
    try cursor.writeUleb128(rar5_type_encryption);
    try cursor.writeUleb128(0); // Header flags.
    try cursor.writeUleb128(0); // version.
    try cursor.writeUleb128(rar5_crypt_pswcheck); // flags.
    try cursor.writeU8(0); // KDF count: a single round.
    @memcpy(cursor.buffer[cursor.pos..][0..16], salt);
    cursor.pos += 16;
    @memcpy(cursor.buffer[cursor.pos..][0..8], &check);
    cursor.pos += 8;
    @memcpy(cursor.buffer[cursor.pos..][0..4], &csum);
    cursor.pos += 4;
    const crypt_block = try rar5FixtureBlock(&block, body[0..cursor.pos]);
    @memcpy(out[pos..][0..crypt_block.len], crypt_block);
    pos += crypt_block.len;
    var iv: [16]u8 = @splat(0);
    iv[0] = 1;
    const main = try rar5FixtureSimpleBody(&body, rar5_type_main);
    const main_block = try rar5FixtureEncryptedHeader(&block, main, keys.key[0..], iv);
    @memcpy(out[pos..][0..main_block.len], main_block);
    pos += main_block.len;
    iv[0] = 2;
    const end = try rar5FixtureSimpleBody(&body, rar5_type_end);
    const end_block = try rar5FixtureEncryptedHeader(&block, end, keys.key[0..], iv);
    @memcpy(out[pos..][0..end_block.len], end_block);
    pos += end_block.len;
    return pos;
}

test "rar5 extra record scan stops at short and trailing records" {
    // ProcessExtra50 stops the record scan at short or malformed records;
    // RAR 5.21 wrote SUBDATA one byte short.
    var extra: [40]u8 = @splat(0);
    var archive: [96]u8 = undefined;
    var entries: TestEntries = .{};

    // A hash record plus the byte the short record does not cover.
    extra[0] = 0x22; // Record size: the type, hash type, and 32 digest bytes.
    extra[1] = @intCast(rar5_extra_hash);
    extra[2] = @intCast(rar5_hash_blake2sp);
    extra[35] = 0xAB; // The trailing byte.
    var len = try rar5FixtureFileArchive(&archive, "e.txt", 5, extra[0..36]);
    try walkEntriesOpts(archive[0..len], .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
    try std.testing.expectEqualStrings("e.txt", entries.name(0));

    // A zero record size ends the scan.
    extra[0] = 0;
    len = try rar5FixtureFileArchive(&archive, "e.txt", 5, extra[0..2]);
    entries = .{};
    try walkEntriesOpts(archive[0..len], .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);

    // A type vint longer than the record size ends the scan.
    extra[0] = 0x01; // A record size below the two-byte type vint.
    extra[1] = 0x81;
    extra[2] = 0x00;
    len = try rar5FixtureFileArchive(&archive, "e.txt", 5, extra[0..3]);
    entries = .{};
    try walkEntriesOpts(archive[0..len], .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
}

test "rar5 redir extra record is skipped" {
    // A FHEXTRA_REDIR record carries a symlink target this facade has no
    // surface for, so the walk skips it.
    var record: [16]u8 = undefined;
    var cursor = binary.WriteCursor.init(record[1..]);
    try cursor.writeUleb128(rar5_extra_redir); // Marks a symlink or hardlink.
    try cursor.writeUleb128(0); // The redirect target type.
    try cursor.writeUleb128(0); // The flags.
    try cursor.writeUleb128(3); // The target name size.
    @memcpy(cursor.buffer[cursor.pos..][0..3], "tgt");
    cursor.pos += 3;
    record[0] = @intCast(cursor.pos); // The record size: the type and data.

    var archive: [64]u8 = undefined;
    const len = try rar5FixtureFileArchive(&archive, "l", 0, record[0 .. cursor.pos + 1]);
    var entries: TestEntries = .{};
    try walkEntriesOpts(archive[0..len], .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
    try std.testing.expectEqualStrings("l", entries.name(0));
    try std.testing.expectEqual(@as(u64, 0), entries.sizes[0]);
    try std.testing.expectEqual(@as(u64, 0), entries.packed_sizes[0]);
}

test "rar5 hp pswcheck csum gates the wrong password check" {
    // The reference drops a HEAD_CRYPT check whose SHA-256 csum disagrees;
    // a valid csum over foreign bytes reports the wrong password.
    const salt = [16]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08 };
    const keys = try rar5Kdf("PW", &salt, 0, .{});
    const check = rar5PswCheck(&keys.pswcheck);
    const foreign: [8]u8 = @splat(0xFF);
    var scratch: [64]u8 = undefined;
    var cause: crypto.FailureCause = undefined;
    var archive: [112]u8 = undefined;

    // A damaged record: the csum disagrees, so the walk drops the check and
    // decrypts the rest with the correct password.
    var len = try rar5FixtureHpArchive(&archive, &salt, foreign, @splat(0xAA), &keys);
    var entries: TestEntries = .{};
    try walkEntriesOpts(
        archive[0..len],
        .{ .password = "PW", .scratch = &scratch, .failure_cause = &cause },
        &entries,
        testEntryVisit,
    );
    try std.testing.expectEqual(@as(usize, 0), entries.count);

    // A valid csum over foreign check bytes: the check fires.
    len = try rar5FixtureHpArchive(&archive, &salt, foreign, fixtureSha256Csum(&foreign), &keys);
    var foreign_entries: TestEntries = .{};
    try std.testing.expectError(error.IntegrityException, walkEntriesOpts(
        archive[0..len],
        .{ .password = "PW", .scratch = &scratch, .failure_cause = &cause },
        &foreign_entries,
        testEntryVisit,
    ));
    try std.testing.expectEqual(crypto.FailureCause.wrong_password, cause);

    // A valid csum over the true check: the walk decrypts the rest.
    len = try rar5FixtureHpArchive(&archive, &salt, check, fixtureSha256Csum(&check), &keys);
    var valid_entries: TestEntries = .{};
    try walkEntriesOpts(
        archive[0..len],
        .{ .password = "PW", .scratch = &scratch, .failure_cause = &cause },
        &valid_entries,
        testEntryVisit,
    );
    try std.testing.expectEqual(@as(usize, 0), valid_entries.count);
}

test "rar5 file crypt record keeps the pswcheck only on a valid csum" {
    // A FHEXTRA_CRYPT record stores the check behind a SHA-256 csum; the
    // entry keeps it only when the csum agrees.
    const salt = [16]u8{ 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F, 0x1F };
    const keys = try rar5Kdf("PW", &salt, 0, .{});
    const check = rar5PswCheck(&keys.pswcheck);

    var record: [49]u8 = undefined;
    var archive: [128]u8 = undefined;
    try rar5FixtureCryptRecord(&record, &salt, check, fixtureSha256Csum(&check));
    var len = try rar5FixtureFileArchive(&archive, "f", 2, &record);
    var entries: TestEntries = .{};
    try walkEntriesOpts(archive[0..len], .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
    try std.testing.expectEqual(@as(?[8]u8, check), entries.pswchecks[0]);

    // A broken csum drops the check without touching the entry.
    try rar5FixtureCryptRecord(&record, &salt, check, @splat(0xAA));
    len = try rar5FixtureFileArchive(&archive, "f", 2, &record);
    var damaged_entries: TestEntries = .{};
    try walkEntriesOpts(archive[0..len], .{}, &damaged_entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), damaged_entries.count);
    try std.testing.expectEqual(@as(?[8]u8, null), damaged_entries.pswchecks[0]);
}
