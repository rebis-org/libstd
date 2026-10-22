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

// Every buffer comes from the caller, so the decode path allocates nothing.

pub const Family = enum { rar4, rar5 };

pub const RarInfo = struct {
    name: []const u8,
    size: u64,
    data_offset: u64,
    packed_size: u64,
    crc: u32,
    // False when the producer recorded no CRC32 (a RAR5 blake2-only entry),
    // because 0 is a legitimate CRC32 value and presence must be tracked.
    has_crc: bool = true,
    ordinal: usize,
    // The walk resolves the engine and the window before the caller sizes the
    // buffers, so the decode path never has to ask again. The window is 0 for a store entry.
    family: Family = .rar5,
    method: u8 = 0,
    unpack_version: u8 = 0,
    window_bytes: u64 = 0,
    // Modification time in Unix seconds, or 0 when the entry has none. Solid marks
    // an entry whose decode replays from its group start.
    mtime: u64 = 0,
    solid: bool = false,
};

pub const Entry = struct {
    info: RarInfo,
    family: Family,
    is_directory: bool,
    // The normalized method, where 0 is store and 1-5 are LZ levels. RAR4 takes the
    // low nibble of the 0x30-0x35 byte, and RAR5 the method field of the compression info.
    method: u8,
    // The unpack version in RAR4 (15/20/26/29/36), and the normalized
    // algorithm version in RAR5 (50 or 70).
    unpack_version: u8,
    solid: bool,
    file_flags: u16, // The raw RAR4 flags, which hold the dictionary code.
    dict_bits: u6, // The RAR5 window exponent from the compression info.
    blake2: ?[32]u8,
    // The encryption parameters from the header of the entry, for -p and -m file data. The
    // walk handles -hp header encryption and does not set this field.
    crypt: ?Crypt = null,
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
    // The staging for header decryption of -hp archives. It must cover the largest
    // header (RAR5 caps at 2 MiB, RAR4 at 64 KiB aligned).
    scratch: []u8 = &.{},
    // The caller-side KDF budget in HMAC/SHA rounds: it refuses work above the
    // limit with .kdf_limit instead of running it. 0 means no limit.
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

// The decode-side buffers, carved by the caller from the call workspace. One engine
// state is live at a time, so `state` holds it and `ppm_heap` is the last PPMd carve.
pub const DecodeBuffers = struct {
    // The staging for decrypted packed data, because AES-CBC needs a mutable copy.
    packed_stage: []u8 = &.{},
    state: []align(8) u8,
    window: []u8,
    table_pool: []u16,
    pending50: []filters50.Filter,
    pending29: []unpack29.PendingFilter,
    filter_scratch: []u8,
    ppm_heap: []u8,

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

// The largest table pool across the engines, so one buffer serves every session:
// four tables of 446 words for unpack50, four of 404 for unpack29, 1402 for unpack20.
pub const table_pool_words = unpack50.table_pool_words * 4;

// The window ceilings per family: RAR4 caps at 4 MB (dict code 6), and RAR5/RAR7
// declare their own window inside the compression info (base 0x20000 << field,
// 4-bit exponent for v50, 5-bit plus a 5/32 fraction for v70).

fn detectFamily(archive: []const u8, provider: crypto.Provider) Exception!struct { family: Family, offset: usize } {
    if (archive.len >= rar4_signature.len and
        std.mem.eql(u8, archive[0..rar4_signature.len], &rar4_signature))
        return .{ .family = .rar4, .offset = 0 };

    // An SFX prefix moves the signature away from offset 0, so the scan looks for it
    // and confirms that a main block follows the match.
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
pub const rar5_flag_split_before: u64 = 0x0008;
const rar5_flag_split_after: u64 = 0x0010;
// HFL_CHILD and HFL_INHERITED: a child block refines its parent and inherits
// nothing on its own; listing counts a HEAD_FILE child and skips a service one.
const rar5_flag_child: u64 = 0x0020;
const rar5_flag_inherited: u64 = 0x0040;
const rar5_archive_volume: u64 = 0x0001;
const rar5_archive_volnum: u64 = 0x0002;
pub const rar5_file_directory: u64 = 0x0001;
pub const rar5_file_mtime: u64 = 0x0002;
pub const rar5_file_crc32: u64 = 0x0004;
const rar5_file_size_unknown: u64 = 0x0008;
pub const rar5_extra_crypt: u64 = 0x01;
pub const rar5_extra_hash: u64 = 0x02;
const rar5_extra_redir: u64 = 0x05;
const rar5_hash_blake2sp: u64 = 0x00;

pub const Rar5Keys = struct { key: [32]u8, hash_key: [32]u8, pswcheck: [32]u8 };

// A single-entry memo for rar5Kdf. Encrypted archives carry one KDF record per
// entry, and a walk plus its replay used to pay the derivation twice for the
// same (password, salt, count); callers running many passes can share one memo
// to pay it once. The key is a password fingerprint, so a memo never serves a
// different password.
pub const Rar5KdfMemo = struct {
    populated: bool = false,
    lg2count: u8 = 0,
    salt: [16]u8 = @splat(0),
    password_fp: [16]u8 = @splat(0),
    keys: Rar5Keys = undefined,
};

// The decryption step that RAR5 needs because its PBKDF2-HMAC-SHA256 covers the
// first block only; the hash key and the password check continue the same chain 16 times each.
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

// The stored password check is valid only when its SHA-256 csum matches, which
// is how the reference keeps a damaged record from masquerading as a wrong
// password (arcread.cpp HEAD_CRYPT and FHEXTRA_CRYPT).
fn rar5PswCheckValid(provider: crypto.Provider, check: *const [8]u8, csum: *const [4]u8) bool {
    var sha = crypto.Sha256.bind(provider, .{});
    sha.update(check);
    const digest = sha.finalResult();
    return std.mem.eql(u8, digest[0..4], csum);
}

// The RAR5 conversion of a file CRC32 for an encrypted entry: an HMAC-SHA256 of the
// little-endian CRC, folded bytewise into 32 bits (unrar ConvertHashToMAC).
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

// SetKey30 hashes a self-modifying RawPsw: each full block hashed in place
// receives the transform's final schedule words (vendor sha1.cpp).
// A plain SHA-1 KDF diverges past 127 bytes of buffered state.
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
        // The vendor expands the schedule in place, so after the final round the
        // 16 workspace words are W[64..79]; process_rar29 writes them back to the
        // caller's buffer little-endian.
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

    // The rar29 variant: after each transform sourced directly from data, the
    // hashed bytes receive the final schedule words. The partial block filled
    // through the internal buffer and the tail are never written back.
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

// SetKey30: 0x40000 rar29 rounds over RawPsw||round-le24, an IV byte from every
// 0x4000th fork, UTF-16LE password with salt as RawPsw (vendor crypt3.cpp).
fn rar4Kdf(password_utf16le: []const u8, salt: ?[]const u8, opts: DecodeOptions) Exception!Rar4Keys {
    const hash_rounds: u32 = 0x40000;
    if (opts.kdf_rounds_limit != 0 and hash_rounds > opts.kdf_rounds_limit) {
        if (opts.failure_cause) |cause| cause.* = .kdf_limit;
        return error.ResourceException;
    }
    var raw: [2 * 512 + 8]u8 = undefined;
    if (password_utf16le.len > raw.len - 8) return error.UnsupportedException;
    @memcpy(raw[0..password_utf16le.len], password_utf16le);
    var raw_len = password_utf16le.len;
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
        // The reference stops at a short or malformed record instead of failing
        // (ProcessExtra50): RAR 5.21 and earlier write the SUBDATA record one
        // byte short, which leaves a valid trailing byte that must not abort
        // the walk, and a zero record size ends the scan the same way.
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
                // A REDIR record marks a symbolic link or another file system
                // redirect. The reference parses the target name and continues;
                // this facade has no link surface, so the entry stays a zero
                // size file and the record is skipped.
                rar5_extra_redir => _ = try cursor.readSlice(record_data_size),
                rar5_extra_crypt => {
                    // The record layout: version and flags as vInt, the KDF count in
                    // 1 byte, a 16-byte salt and IV, then the optional password check and checksum.
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
                        // The reference drops the password check when its SHA-256
                        // csum disagrees, so a damaged record cannot masquerade
                        // as a wrong password.
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

// The shared tail of the cleartext and encrypted paths: parse type, flags, and
// body from a cursor over the header body bytes, which can be a decrypted staging buffer.
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
                _ = try body.readUleb128();
            }
        },
        rar5_type_file, rar5_type_service => {
            // Splits need the peer volume, which this facade never reads. The child
            // and inherited bits refine a parent block and stay walkable: unrar lists
            // a HEAD_FILE child as its own entry and skips a service child entirely.
            if (flags & (rar5_flag_split_before | rar5_flag_split_after) != 0)
                return error.UnsupportedException;
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
                // The reference drops the password check when its SHA-256 csum
                // disagrees, so a damaged record cannot masquerade as a wrong
                // password.
                if (rar5PswCheckValid(provider, &check, &csum)) result.enc_pswcheck = check;
            }
        },
        rar5_type_end => {
            result.archive_flags = try body.readUleb128();
        },
        // An unknown type is skipped by size below: the reference parses HFL_SKIPIFUNKNOWN
        // but never enforces it, so a block that a future version adds is walked past, not fatal.
        else => {},
    }
    return result;
}

// An encrypted header block is [a cleartext IV][AES-256-CBC of crc4|size|type|flags|body,
// padded to 16]; the size lives in the ciphertext, so the first cipher block is decrypted alone.
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

// Walk the archive and call `visit` for every file entry in archive order, verifying each
// header CRC; a directory is walked but not visited, and a HEAD_CRYPT block decrypts the rest.
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
                // Service blocks, such as QuickOpen, carry no payload for this
                // facade, so skip their data.
                continue;
            },
            rar5_type_file => {
                if (!seen_main) return error.DataException;
                var entry: Entry = .{
                    .info = .{
                        .name = header.name,
                        .size = header.unpacked_size,
                        .data_offset = header.data_offset,
                        .packed_size = header.data_size,
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
                    .crypt = header.crypt,
                };
                if (!header.is_directory) {
                    if (header.file_flags & rar5_file_size_unknown != 0) return error.UnsupportedException;
                    if (header.flags & rar5_flag_data == 0) return error.UnsupportedException;
                    const method = (header.compression >> 7) & 0x7;
                    const algo_raw: u8 = @intCast(header.compression & 0x3F);
                    const compat_flag = (header.compression >> 20) & 1 != 0;
                    if (method == 0) {
                        // An encrypted stored file still pads its data to the
                        // AES block, so data_size can exceed unpacked_size by
                        // up to 15 bytes; plaintext stored must match exactly.
                        if (header.crypt) |c| {
                            if (c != .rar5) return error.UnsupportedException;
                            if (header.data_size < header.unpacked_size or header.data_size > header.unpacked_size + 15) return error.UnsupportedException;
                        } else if (header.data_size != header.unpacked_size) return error.UnsupportedException;
                        entry.method = 0;
                    } else {
                        if (method > 5) return error.UnsupportedException;
                        // The version field is the raw algorithm version: 0 is RAR5,
                        // 1 is RAR7, and anything above has no unpacker here or upstream.
                        if (algo_raw > 1) return error.UnsupportedException;
                        // The window that the entry requires. A smaller window silently truncates
                        // history, so a window that does not fit is refused, never clamped. The
                        // exponent mask follows the raw version, not the compat-mapped one
                        // (unrar arcread.cpp ReadHeader50): 4 bits for v50, 5 bits for v70.
                        const window_bits_field: u6 = @intCast((header.compression >> 10) & (if (algo_raw == 0) @as(u64, 0x0F) else 0x1F));
                        var window_bytes: u64 = @as(u64, 0x20000) << window_bits_field;
                        if (algo_raw == 1) {
                            // The RAR7 window adds a 5-bit fraction of 1/32 steps, and the
                            // 64 GiB unpacker ceiling rejects the result (unrar VER_UNKNOWN).
                            window_bytes += window_bytes / 32 * ((header.compression >> 15) & 0x1F);
                            if (window_bytes > 0x1000000000) return error.UnsupportedException;
                        }
                        entry.method = @intCast(method);
                        entry.unpack_version = if (compat_flag) 50 else if (algo_raw == 0) 50 else 70;
                        entry.dict_bits = windowBitsCeil(window_bytes);
                        entry.solid = (header.compression >> 6) & 1 != 0;
                    }
                    // Integrity coverage is CRC32 or better; a file block that carries neither
                    // (some producers strip both) is refused rather than delivered unverifiable.
                    if (header.file_flags & rar5_file_crc32 == 0 and header.blake2 == null)
                        return error.UnsupportedException;
                }
                entry.info.family = .rar5;
                entry.info.method = entry.method;
                entry.info.unpack_version = entry.unpack_version;
                entry.info.window_bytes = if (entry.method == 0) 0 else @as(u64, 1) << entry.dict_bits;
                entry.info.solid = entry.solid;
                // Ordinals count the entries that a caller can read: the walk lists a directory
                // but never exposes it, so a directory must not shift the file ordinals.
                if (!entry.is_directory) {
                    ordinal = try bounds.addUsize(ordinal, 1);
                    try visit(ctx, entry);
                }
            },
            else => {},
        }
    }
    // An EOF exactly on a block boundary is a clean end, because UnexpEndArcMsg stays
    // silent there; an older producer omits the end block and a truncation fails above.
    if (!seen_main) return error.DataException;
}

fn windowBitsCeil(window_bytes: u64) u6 {
    const bits: u6 = @intCast(64 - @clz(window_bytes -| 1));
    // A RAR5 window is 0x20000 << dict_bits, so bits is already at least 17.
    return @max(bits, 17);
}

// The RAR4 window exponent comes from the dictionary-size field of the file flags,
// which is (flags >> 5) & 7 in every legacy version, where code 7 is the directory marker.
fn dictBitsRar4(file_flags: u16) u5 {
    const dict_code: u5 = @intCast((file_flags >> 5) & 7);
    return if (dict_code > 6) 22 else 16 + dict_code;
}

// The RAR legacy HEAD_CRC is the low 16 bits of CRC-32, not CRC-16/ARC, despite the
// width of the field: CRC-16/ARC of real header bytes gives a value that no producer stores.

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
// The UO old-service subheader, whose CRC covers string fields that the header
// size excludes, so unrar exempts it from the generic check entirely.
const rar4_old_sub_uo: u16 = 0x101;

const Rar4Header = struct {
    header_type: u8,
    flags: u16,
    head_size: u16,
    data_size: u64,
    header_offset: usize,
    // Encrypted (-hp) blocks: decrypted staging bytes and the on-disk length.
    // Cleartext blocks keep enc_len == head_size and parse from the archive.
    enc_source: ?[]const u8 = null,
    enc_len: usize = 0,
};

// GetCRC15 covers the bytes ReadHeader15 actually reads: 13 for CMT and
// comment-bearing MAIN, nothing for SIGN/AV and old-service UO, else all.
// 0 exempts; `source` is the archive at `offset` or staging at 0 for -hp.
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
    // CRC-32 low 16 bits over the per-type coverage, except the marker block
    // (0x72), whose first two bytes are the "Ra" signature and carry no CRC.
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
    // RAR4 mtime is Unix time only for Unix producers. Other host systems
    // write DOS date/time, which has no timezone-free Unix conversion.
    host_os: u8,
    mtime: u32,
    salt: ?[8]u8,
};

const rar4_lhd_salt: u16 = 0x0400;

fn parseRar4File(archive: []const u8, header: Rar4Header) Exception!Rar4File {
    // In RAR4 the base header ADD_SIZE is PACK_SIZE; there is no second
    // packed-size field. Reading one anyway shifts every later field by 4 bytes
    // and empties the name.
    var packed_size: u64 = header.data_size;
    // The add-size at offset 7 is unconditional for a FILE header, so the file
    // fields always start at +11, LONG_BLOCK or not (unrar ReadHeader15).
    if (header.head_size < 11) return error.DataException;
    const fields_offset = try bounds.addUsize(header.header_offset, 11);
    const fields_end = try bounds.addUsize(header.header_offset, header.head_size);
    if (fields_end > archive.len) return error.DataException;
    // The cursor is bounded by the header, so a field that overruns head_size
    // fails instead of reading the next block's bytes.
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

// Per-block salts re-key lazily: archives repeat one salt, so the memo pays
// the 0x40000-round KDF once per walk, not per header.
const Rar4HeaderCrypt = struct {
    utf16: [2 * 512]u8,
    utf16_len: usize,
    salt_memo: [8]u8 = undefined,
    have_salt: bool = false,
    keys: Rar4Keys = undefined,
};

// Each -hp block salts and re-keys independently (vendor SetCryptKeys), so CBC
// restarts from the KDF IV and the 7-byte fixed header decrypts alone.
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
                    // -hp: every block after the main header is encrypted, each
                    // with its own salt; the keys derive lazily from the first
                    // encrypted block, so the main header itself stays cleartext
                    // and the common advance below moves the cursor past it.
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
                // The base header holds only the low 32 bits of the packed size, so the walk
                // advances with the 64-bit value, and the data area is never header-encrypted.
                const payload_end = try bounds.addUsize(cursor + header.enc_len, std.math.cast(usize, file.packed_size) orelse return error.ResourceException);
                if (payload_end > archive.len) return error.DataException;
                cursor = payload_end;
                continue;
            },
            rar4_end => return,
            else => {
                // The comment, av, protect, sign, and service blocks have a verified header CRC, so only
                // their data is skipped, and a protect record is content, not encryption.
            },
        }
        const data_end = try bounds.addUsize(cursor + header.enc_len, std.math.cast(usize, header.data_size) orelse return error.ResourceException);
        if (data_end > archive.len) return error.DataException;
        cursor = data_end;
    }
    // Same EOF rule as the RAR5 walk: the UnexpEndArcMsg of unrar stays silent at
    // a block boundary, and a RAR 1.5 archive never wrote an end block.
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

// Pass 1: locate the target entry, the ordinal where its compression group started, and
// the largest dictionary that any group member declares, which sizes the shared session.
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
    // entry must not reset the window maximum the target's replay needs.
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

// One replay drives one session built from the target's tables, and table sizes
// differ per version class: a mixed solid chain is refused, never misdecoded.
fn versionClass(version: u8) u8 {
    return switch (version) {
        20, 26 => 20,
        29, 36 => 29,
        else => version,
    };
}

// Pass 2: replay the compression group through the session. An entry before the group start
// costs a header walk only, a predecessor feeds a discard sink, and the target feeds the caller.
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
    // The session's tables come from the target's unpack version, so a mixed
    // chain would feed predecessors through the wrong table sizes.
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

    // The integrity check covers the CRC32 of the delivered bytes, plus BLAKE2sp when the
    // entry carries the hash record, and an encrypted RAR5 entry stores an HMAC conversion.
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

test "rar4 kdf reproduces the unrar sha1_process_rar29 self-modification" {
    // The expected bytes come from a transcription of vendor/unrar/sha1.cpp and
    // crypt3.cpp SetKey30: a plain SHA-1 KDF produces a different key for the
    // long password (1ac08ded32dd4d33dcae099781825ea5), because only the rar29
    // process rewrites hashed RawPsw blocks with the final schedule words.
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

    // The short-password regime never rewrites RawPsw, so it doubles as an
    // anchor shared with a plain SHA-1 KDF; "PASS" with this salt is the byte
    // pattern the encrypted RAR4 fixtures in the oracle suite use.
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

// The fixtures below build the wire bytes for the walk tests. A fixture never
// derives its CRC coverage from rar4CrcCoverage: the caller pins the coverage,
// so a coverage regression in the walk breaks the stored CRC instead of
// reproducing itself inside the fixture.

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

// The walk stages every header in caller memory, so an entry name points into
// scratch that the next block overwrites: the visit copies what it keeps.
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

// Writes a RAR4 block header with a pinned CRC coverage. The caller pre-zeros
// the buffer and sets type-specific bytes, such as an old-service subheader,
// before the call, because the coverage depends on them. A coverage of 0
// stores a deliberately wrong CRC, which only an exempt block accepts.
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

// A RAR4 file header with a five-byte packed size and a fixed field set; the
// CRC covers the full header, like a real producer.
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

// Wraps a plaintext header as a -hp block: an 8-byte salt, then AES-128-CBC of
// the zero-padded header, chained from the KDF IV like the walk decrypts it.
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

// A file or service body in the ReadHeader50 field order: the data flag in the
// header flags controls the data-size vint, the extra flag controls the
// extra-size vint, and the file flags control the mtime and CRC32 fields.
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
    // A -hp archive keeps the marker and the main header cleartext, then salts
    // and encrypts every later block; the walk re-derives the keys only when
    // the salt changes, like unrar's per-block SetCryptKeys. The truncation
    // below must fail inside the next encrypted block, after its own salted
    // KDF, not return success from the visited file.
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
    // The Raw buffer of unrar's ReadHeader15 stops after 13 bytes for a main
    // header with a comment and for a comment block, so header bytes past 13
    // are comment data the stored CRC never covers. SIGN and AV blocks never
    // carried a valid CRC, and an old-service UO subheader is exempt, but the
    // exemption is scoped: a non-UO old service header still verifies over its
    // full size.
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
    // The ADD_SIZE at offset 7 is a file field, not a LONG_BLOCK extra, so a
    // file header without LONG_BLOCK still reads it: the packed size and the
    // data offset do not shift.
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
    // The 0xffffffff unpacked size is unrar's unknown-size marker: this facade
    // sizes the output ahead of the read, so the entry is refused, never
    // guessed.
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
    // A HEAD_FILE child block lists as its own entry, a service block between
    // files is skipped without consuming an ordinal, and the data offsets stay
    // exact across the interleaved service header.
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
    // Compression info 0x104081: RAR7 raw version, window bits 16 (2^33),
    // compat bit set, so the entry lists as version 50. 0xFA881: window bits
    // 10 plus a 31/32 fraction (264241152 bytes), no compat bit, so the entry
    // lists as version 70. 0xCC81 overflows the 64 GiB ceiling and is refused.
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
    // Vendor switches ExtraDist per file, so it can decode a solid chain that
    // mixes versions; this replay drives one session built from the target's
    // tables, so the mixed chain is refused rather than decoded through the
    // wrong table size. Compression 0xC0: version 50, solid, method 1, a
    // 128 KiB window; 0xC1: version 70 with the same shape. The compressed
    // payloads stay opaque: the guard fires before the first decode.
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

// A FHEXTRA_CRYPT record: the size, type, version, flags, KDF count, salt, IV,
// password check, and its csum, sized to the bytes the walk parses.
fn rar5FixtureCryptRecord(out: *[49]u8, salt: *const [16]u8, check: [8]u8, csum: [4]u8) Exception!void {
    var cursor = binary.WriteCursor.init(out[1..]);
    try cursor.writeUleb128(rar5_extra_crypt);
    try cursor.writeUleb128(0); // version.
    try cursor.writeUleb128(rar5_crypt_pswcheck); // flags.
    try cursor.writeU8(0); // KDF count: a single round.
    @memcpy(cursor.buffer[cursor.pos..][0..16], salt);
    cursor.pos += 16;
    @memcpy(cursor.buffer[cursor.pos..][0..16], salt); // the IV is arbitrary here.
    cursor.pos += 16;
    @memcpy(cursor.buffer[cursor.pos..][0..8], &check);
    cursor.pos += 8;
    @memcpy(cursor.buffer[cursor.pos..][0..4], &csum);
    cursor.pos += 4;
    out[0] = @intCast(cursor.pos); // the record size: the type and data.
}

// A RAR5 -hp encrypted header block: a cleartext IV, then AES-256-CBC of the
// CRC, size vint, and body, zero padded to the cipher block length.
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

// A cleartext RAR5 archive with one stored file whose header carries the given
// extra area, so each extra-record case stays one fixture line.
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

// A -hp RAR5 archive: a cleartext HEAD_CRYPT block with the given password
// check and csum, then the encrypted main and end blocks under the keys.
fn rar5FixtureHpArchive(out: []u8, salt: *const [16]u8, check: [8]u8, csum: [4]u8, keys: *const Rar5Keys) Exception!usize {
    @memcpy(out[0..8], &rar5_signature);
    var pos: usize = 8;
    var body: [48]u8 = undefined;
    var block: [64]u8 = undefined;
    var cursor = binary.WriteCursor.init(&body);
    try cursor.writeUleb128(rar5_type_encryption);
    try cursor.writeUleb128(0); // header flags.
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
    // unrar's ProcessExtra50 stops the record scan at a zero record size, a
    // size the type vint exceeds, or bytes a record does not cover, instead of
    // failing: RAR 5.21 and earlier write the SUBDATA record one byte short,
    // so a trailing byte after a hash record must not abort the walk.
    var extra: [40]u8 = @splat(0);
    var archive: [96]u8 = undefined;
    var entries: TestEntries = .{};

    // A hash record plus the byte the short record does not cover.
    extra[0] = 0x22; // record size: the type, hash type, and 32 digest bytes.
    extra[1] = @intCast(rar5_extra_hash);
    extra[2] = @intCast(rar5_hash_blake2sp);
    extra[35] = 0xAB; // the trailing byte.
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
    extra[0] = 0x01; // a record size below the two-byte type vint.
    extra[1] = 0x81;
    extra[2] = 0x00;
    len = try rar5FixtureFileArchive(&archive, "e.txt", 5, extra[0..3]);
    entries = .{};
    try walkEntriesOpts(archive[0..len], .{}, &entries, testEntryVisit);
    try std.testing.expectEqual(@as(usize, 1), entries.count);
}

test "rar5 redir extra record is skipped" {
    // A FHEXTRA_REDIR record carries a symlink target, which this facade has
    // no surface for: the walk skips the record and lists the entry as a
    // zero-size file instead of aborting the whole archive.
    var record: [16]u8 = undefined;
    var cursor = binary.WriteCursor.init(record[1..]);
    try cursor.writeUleb128(rar5_extra_redir); // a symlink or hardlink.
    try cursor.writeUleb128(0); // the redirect target type.
    try cursor.writeUleb128(0); // the flags.
    try cursor.writeUleb128(3); // the target name size.
    @memcpy(cursor.buffer[cursor.pos..][0..3], "tgt");
    cursor.pos += 3;
    record[0] = @intCast(cursor.pos); // the record size: the type and data.

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
    // unrar checks the HEAD_CRYPT password check against its SHA-256 csum and
    // drops it when the csum disagrees: a damaged record must not turn a
    // correct password into a wrong-password failure, while a valid csum over
    // foreign check bytes still reports the wrong password.
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
    // A FHEXTRA_CRYPT record stores the password check behind a SHA-256 csum;
    // the entry keeps the check only when the csum agrees, like the reference.
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
