const std = @import("std");

const binary = @import("../common/primitive/binary.zig");
const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;

const sink = @import("../common/sink.zig");
const blake2sp = @import("rar/blake2sp.zig");
const filters50 = @import("rar/filters50.zig");
const unpack50 = @import("rar/unpack50.zig");
const unpack29 = @import("rar/unpack29.zig");
const unpack20 = @import("rar/unpack20.zig");

// Every buffer comes from the caller, so the decode path allocates nothing.

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
    family: enum { rar4, rar5 } = .rar5,
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
    family: enum { rar4, rar5 },
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
    // The primitive provider for KDF and block decryption on this call.
    provider: crypto.Provider = crypto.default_provider,
};

const rar5_kdf_lg2_count_max = 24;

const Family = @TypeOf(@as(Entry, undefined).family);

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

// The largest table pool across the engines, so one buffer serves every session:
// four tables of 446 words for unpack50, four of 404 for unpack29, 1402 for unpack20.
pub const table_pool_words = unpack50.table_pool_words * 4;

// The window ceilings per family: RAR4 caps at 4 MB (dict code 6), and RAR5 declares
// its own (base 0x20000 << dict_bits, 4-bit exponent for v50).
pub const max_rar4_window: usize = 4 * 1024 * 1024;
pub const max_rar5_window_bits: u6 = 31; // 0x20000 << 14 is already 2^31, so a wider window does not fit the address space.
pub const max_pending50 = unpack50.max_pending_filters;
pub const max_pending29 = unpack29.max_pending_filters;
pub const PendingFilter50 = filters50.Filter;
pub const PendingFilter29 = unpack29.PendingFilter;
pub const filter_scratch_extra = filters50.max_filter_block;

fn detectFamily(archive: []const u8, provider: crypto.Provider) Failure!struct { family: Family, offset: usize } {
    if (archive.len >= rar4_signature.len and
        std.mem.eql(u8, archive[0..rar4_signature.len], &rar4_signature))
        return .{ .family = .rar4, .offset = 0 };

    // An SFX prefix moves the signature away from offset 0, so the scan looks for it
    // and confirms that a main block follows the match.
    const signature = rar5_signature;
    if (archive.len < signature.len) return error.InvalidData;
    const limit = @min(archive.len, sfx_scan_limit);
    var offset: usize = 0;
    while (offset <= limit - signature.len) : (offset += 1) {
        if (!std.mem.eql(u8, archive[offset..][0..signature.len], &signature)) continue;
        if (offset == 0) return .{ .family = .rar5, .offset = 0 };
        var cursor = offset + signature.len;
        const header = parseRar5Block(archive, &cursor, provider) catch continue;
        if (header.header_type == rar5_type_main) return .{ .family = .rar5, .offset = offset };
    }
    return error.InvalidData;
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
const rar5_flag_solid_dep: u64 = 0x0020;
const rar5_flag_child: u64 = 0x0040;
const rar5_archive_volume: u64 = 0x0001;
const rar5_archive_volnum: u64 = 0x0002;
pub const rar5_file_directory: u64 = 0x0001;
pub const rar5_file_mtime: u64 = 0x0002;
pub const rar5_file_crc32: u64 = 0x0004;
const rar5_file_size_unknown: u64 = 0x0008;
const rar5_extra_crypt: u64 = 0x01;
const rar5_extra_hash: u64 = 0x02;
const rar5_extra_redir: u64 = 0x05;
const rar5_hash_blake2sp: u64 = 0x00;

const crypto = @import("../common/primitive/crypto.zig");

const Rar5Keys = struct { key: [32]u8, hash_key: [32]u8, pswcheck: [32]u8 };

// The decryption step that RAR5 needs because its PBKDF2-HMAC-SHA256 covers the
// first block only; the hash key and the password check continue the same chain 16 times each.
fn rar5Kdf(password: []const u8, salt: *const [16]u8, lg2count: u8, opts: DecodeOptions) Failure!Rar5Keys {
    if (lg2count > rar5_kdf_lg2_count_max) return error.Unsupported;
    const rounds: u64 = @as(u64, 1) << @intCast(lg2count);
    if (opts.kdf_rounds_limit != 0 and rounds > opts.kdf_rounds_limit) {
        if (opts.failure_cause) |cause| cause.* = .kdf_limit;
        return error.ResourceLimit;
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
    return keys;
}

fn rar5PswCheck(kdf_value: *const [32]u8) [8]u8 {
    var check: [8]u8 = @splat(0);
    for (kdf_value, 0..) |byte, i| check[i % 8] ^= byte;
    return check;
}

// The RAR5 conversion of a file CRC32 for an encrypted entry: an HMAC-SHA256 of the
// little-endian CRC, folded bytewise into 32 bits (unrar ConvertHashToMAC).
fn rar5CrcMac(provider: crypto.Provider, crc: u32, hash_key: *const [32]u8) u32 {
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

// The RAR 2.x-4.x KDF accumulates SHA1 over RawPsw||round-le24 for 0x40000 rounds, takes
// one IV byte from every 0x4000th digest fork, and uses the UTF-16LE password with salt as RawPsw.
fn rar4Kdf(password_utf16le: []const u8, salt: ?[]const u8, opts: DecodeOptions) Failure!Rar4Keys {
    var sha = crypto.Sha1.bind(opts.provider, .{});
    const hash_rounds: u32 = 0x40000;
    if (opts.kdf_rounds_limit != 0 and hash_rounds > opts.kdf_rounds_limit) {
        if (opts.failure_cause) |cause| cause.* = .kdf_limit;
        return error.ResourceLimit;
    }
    var raw: [2 * 127 + 8]u8 = undefined;
    if (password_utf16le.len > raw.len - 8) return error.Unsupported;
    @memcpy(raw[0..password_utf16le.len], password_utf16le);
    var raw_len = password_utf16le.len;
    if (salt) |salt_bytes| {
        @memcpy(raw[raw_len..][0..salt_bytes.len], salt_bytes);
        raw_len += salt_bytes.len;
    }
    var keys: Rar4Keys = undefined;
    var round: u32 = 0;
    while (round < hash_rounds) : (round += 1) {
        sha.update(raw[0..raw_len]);
        var round_le24: [3]u8 = .{ @truncate(round), @truncate(round >> 8), @truncate(round >> 16) };
        sha.update(&round_le24);
        if (round % (hash_rounds / 16) == 0) {
            var fork = sha;
            var digest: [20]u8 = undefined;
            digest = fork.finalResult();
            keys.iv[round / (hash_rounds / 16)] = digest[19];
        }
    }
    var digest: [20]u8 = undefined;
    digest = sha.finalResult();
    // The key reverses the byte order of each 4-byte digest word:
    // AESKey[I*4+J] = (byte)(state_word[I] >> J*8) (unrar SetKey30).
    for (0..4) |i| {
        for (0..4) |j| {
            keys.key[i * 4 + j] = digest[i * 4 + (3 - j)];
        }
    }
    return keys;
}

fn passwordToUtf16Le(password: []const u8, utf16le: []u8) Failure![]u8 {
    var units: usize = 0;
    var i: usize = 0;
    while (i < password.len) {
        const len = std.unicode.utf8ByteSequenceLength(password[i]) catch return error.InvalidData;
        if (i + len > password.len) return error.InvalidData;
        const code_point = std.unicode.utf8Decode(password[i..][0..len]) catch return error.InvalidData;
        i += len;
        if (code_point < 0x10000) {
            if ((units + 1) * 2 > utf16le.len) return error.ResourceLimit;
            std.mem.writeInt(u16, utf16le[2 * units ..][0..2], @intCast(code_point), .little);
            units += 1;
        } else {
            if ((units + 2) * 2 > utf16le.len) return error.ResourceLimit;
            const high = @as(u32, code_point) - 0x10000;
            std.mem.writeInt(u16, utf16le[2 * units ..][0..2], @intCast(0xD800 + (high >> 10)), .little);
            std.mem.writeInt(u16, utf16le[2 * units + 2 ..][0..2], @intCast(0xDC00 + (high & 0x3FF)), .little);
            units += 2;
        }
    }
    return utf16le[0 .. 2 * units];
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

fn parseRar5FileBody(cursor: *binary.ReadCursor, flags: u64, extra_size: u64, result: *Rar5Block) Failure!void {
    result.file_flags = try cursor.readULEB128();
    result.unpacked_size = try cursor.readULEB128();
    _ = try cursor.readULEB128(); // Attributes.
    if (result.file_flags & rar5_file_mtime != 0) {
        // The RAR5 mtime is Unix time, stored directly.
        result.mtime = try cursor.readU32le();
    }
    if (result.file_flags & rar5_file_crc32 != 0) {
        result.data_crc32 = try cursor.readU32le();
    }
    result.compression = try cursor.readULEB128();
    _ = try cursor.readULEB128(); // Host OS.
    const name_length = try cursor.readULEB128();
    result.name = try cursor.readSlice(std.math.cast(usize, name_length) orelse return error.ResourceLimit);
    result.is_directory = result.file_flags & rar5_file_directory != 0;
    if (flags & rar5_flag_extra != 0) {
        const extra_size_usize = std.math.cast(usize, extra_size) orelse return error.ResourceLimit;
        var extra_remaining: usize = extra_size_usize;
        while (extra_remaining > 0) {
            const record_start = cursor.pos;
            const record_size = try cursor.readULEB128();
            const type_start = cursor.pos;
            const record_type = try cursor.readULEB128();
            const type_size = cursor.pos - type_start;
            if (record_size < type_size) return error.InvalidData;
            const record_data_size = std.math.cast(usize, record_size - type_size) orelse return error.ResourceLimit;
            const header_consumed = cursor.pos - record_start;
            const consumed = try bounds.addUsize(header_consumed, record_data_size);
            if (consumed > extra_remaining) return error.InvalidData;
            switch (record_type) {
                rar5_extra_redir => return error.Unsupported,
                rar5_extra_crypt => {
                    // The record layout: version and flags as vInt, the KDF count in
                    // 1 byte, a 16-byte salt and IV, then the optional password check and checksum.
                    var record_cursor = binary.ReadCursor.init(try cursor.readSlice(record_data_size));
                    const version = try record_cursor.readULEB128();
                    const enc_flags = try record_cursor.readULEB128();
                    if (version > 0) return error.Unsupported;
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
                        crypt.rar5.pswcheck = check;
                    }
                    result.crypt = crypt;
                },
                rar5_extra_hash => {
                    const record_data = try cursor.readSlice(record_data_size);
                    var record_cursor = binary.ReadCursor.init(record_data);
                    const hash_type = try record_cursor.readULEB128();
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

const rar5_crypt_pswcheck: u64 = 0x0001;
const rar5_crypt_hashmac: u64 = 0x0002;

fn parseRar5Block(archive: []const u8, cursor: *usize, provider: crypto.Provider) Failure!Rar5Block {
    const crc_offset = cursor.*;
    const crc_bytes = try bounds.slice(archive, crc_offset, 4);
    cursor.* = try bounds.addUsize(cursor.*, 4);
    const header_start = cursor.*;
    var size_reader = binary.ReadCursor.init(archive[cursor.*..]);
    const size = try size_reader.readULEB128();
    if (size == 0 or size > 2 * 1024 * 1024) return error.InvalidData;
    const header_body_start = cursor.* + size_reader.pos;
    const header_body_end = try bounds.addUsize(header_body_start, std.math.cast(usize, size) orelse return error.ResourceLimit);
    if (header_body_end > archive.len) return error.InvalidData;
    const recorded_crc = std.mem.readInt(u32, crc_bytes[0..4], .little);
    const computed_crc = checksum.crc32With(provider, archive[header_start..header_body_end]);
    if (computed_crc != recorded_crc) return error.IntegrityFailure;
    var body_cursor = binary.ReadCursor.init(archive[header_body_start..header_body_end]);
    var block = try finishRar5Block(&body_cursor);
    block.data_offset = header_body_end;
    const data_end = try bounds.addUsize(header_body_end, std.math.cast(usize, block.data_size) orelse return error.ResourceLimit);
    if (data_end > archive.len) return error.InvalidData;
    cursor.* = data_end;
    return block;
}

// The shared tail of the cleartext and encrypted paths: parse type, flags, and
// body from a cursor over the header body bytes, which can be a decrypted staging buffer.
fn finishRar5Block(body: *binary.ReadCursor) Failure!Rar5Block {
    const header_type = try body.readULEB128();
    const flags = try body.readULEB128();
    var extra_size: u64 = 0;
    if (flags & rar5_flag_extra != 0) extra_size = try body.readULEB128();
    var data_size: u64 = 0;
    if (flags & rar5_flag_data != 0) data_size = try body.readULEB128();

    var result: Rar5Block = .{
        .header_type = header_type,
        .flags = flags,
        .data_size = data_size,
    };

    switch (header_type) {
        rar5_type_main => {
            result.archive_flags = try body.readULEB128();
            if (result.archive_flags & rar5_archive_volnum != 0) {
                _ = try body.readULEB128();
            }
        },
        rar5_type_file, rar5_type_service => {
            if (flags & (rar5_flag_split_before | rar5_flag_split_after | rar5_flag_solid_dep | rar5_flag_child) != 0)
                return error.Unsupported;
            try parseRar5FileBody(body, flags, extra_size, &result);
        },
        rar5_type_encryption => {
            const version = try body.readULEB128();
            const enc_flags = try body.readULEB128();
            if (version > 0) return error.Unsupported;
            result.enc_lg2count = try body.readU8();
            @memcpy(&result.enc_salt, try body.readSlice(16));
            if (enc_flags & rar5_crypt_pswcheck != 0) {
                const check_bytes = try body.readSlice(8);
                var check: [8]u8 = undefined;
                @memcpy(&check, check_bytes);
                result.enc_pswcheck = check;
            }
        },
        rar5_type_end => {
            result.archive_flags = try body.readULEB128();
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
) Failure!Rar5Block {
    const iv_bytes = try bounds.slice(archive, cursor.*, 16);
    cursor.* = try bounds.addUsize(cursor.*, 16);
    const first = try bounds.slice(archive, cursor.*, 16);
    if (scratch.len < 16) return error.InsufficientCapacity;
    crypto.aesCbcDecrypt(provider, keys.key[0..], iv_bytes[0..16].*, scratch[0..16], first) catch return error.InvalidData;
    const recorded_crc = std.mem.readInt(u32, scratch[0..4], .little);
    var size_cursor = binary.ReadCursor.init(scratch[4..16]);
    const block_size = size_cursor.readULEB128() catch return error.InvalidData;
    const size_bytes = size_cursor.pos;
    const header_size = 4 + size_bytes + (std.math.cast(usize, block_size) orelse return error.ResourceLimit);
    const enc_len = std.mem.alignForward(usize, header_size, 16);
    if (scratch.len < enc_len) return error.InsufficientCapacity;
    if (enc_len > 16) {
        const rest = try bounds.slice(archive, cursor.* + 16, enc_len - 16);
        // The CBC chaining value is the first cipher block.
        crypto.aesCbcDecrypt(provider, keys.key[0..], first[0..16].*, scratch[16..enc_len], rest) catch return error.InvalidData;
    }
    if (checksum.crc32With(provider, scratch[4..header_size]) != recorded_crc) return error.IntegrityFailure;
    var body_cursor = binary.ReadCursor.init(scratch[4 + size_bytes .. header_size]);
    var block = try finishRar5Block(&body_cursor);
    const block_end = try bounds.addUsize(cursor.*, enc_len);
    block.data_offset = block_end;
    const data_end = try bounds.addUsize(block_end, std.math.cast(usize, block.data_size) orelse return error.ResourceLimit);
    if (data_end > archive.len) return error.InvalidData;
    cursor.* = data_end;
    return block;
}

// Walk the archive and call `visit` for every file entry in archive order, verifying each
// header CRC; a directory is walked but not visited, and a HEAD_CRYPT block decrypts the rest.
fn walkRar5(archive: []const u8, offset: usize, opts: DecodeOptions, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
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
                if (header.enc_lg2count > rar5_kdf_lg2_count_max) return error.Unsupported;
                const password = opts.password orelse return error.Unsupported;
                const keys = try rar5Kdf(password, &header.enc_salt, header.enc_lg2count, opts);
                if (header.enc_pswcheck) |expected| {
                    if (!crypto.constantTimeEqual(&rar5PswCheck(&keys.pswcheck), &expected)) return error.IntegrityFailure;
                }
                header_crypt = keys;
            },
            rar5_type_main => {
                const flags = header.archive_flags;
                if (flags & (rar5_archive_volume | rar5_archive_volnum) != 0) return error.Unsupported;
                if (header.flags & (rar5_flag_data | rar5_flag_split_before | rar5_flag_split_after | rar5_flag_solid_dep | rar5_flag_child) != 0)
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
                // Service blocks, such as QuickOpen, carry no payload for this
                // facade, so skip their data.
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
                    if (header.file_flags & rar5_file_size_unknown != 0) return error.Unsupported;
                    if (header.flags & rar5_flag_data == 0) return error.Unsupported;
                    const method = (header.compression >> 7) & 0x7;
                    const algo_raw: u8 = @intCast(header.compression & 0x3F);
                    const compat_flag = (header.compression >> 20) & 1 != 0;
                    const version: u8 = if (algo_raw == 0) 50 else if (algo_raw == 1) (if (compat_flag) @as(u8, 50) else 70) else algo_raw;
                    if (method == 0) {
                        if (header.data_size != header.unpacked_size) return error.Unsupported;
                        entry.method = 0;
                    } else {
                        if (method > 5) return error.Unsupported;
                        if (version != 50 and version != 70) return error.Unsupported;
                        const window_bits_field: u6 = @intCast((header.compression >> 10) & (if (version == 70) @as(u64, 0x1F) else 0x0F));
                        // The window that the entry requires. A smaller window silently truncates
                        // history, so a window that does not fit is refused, never clamped.
                        const window_bytes: u64 = (@as(u64, 0x20000) << window_bits_field);
                        if (window_bits_field > max_rar5_window_bits) return error.ResourceLimit;
                        entry.method = @intCast(method);
                        entry.unpack_version = version;
                        entry.dict_bits = windowBitsCeil(window_bytes);
                        entry.solid = (header.compression >> 6) & 1 != 0;
                    }
                    // Integrity coverage is CRC32 or better; a file block that carries neither
                    // (some producers strip both) is refused rather than delivered unverifiable.
                    if (header.file_flags & rar5_file_crc32 == 0 and header.blake2 == null)
                        return error.Unsupported;
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
    if (!seen_main) return error.InvalidData;
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
const rar4_end: u8 = 0x7b;
const rar4_long_block: u16 = 0x8000;
const rar4_lhd_large: u16 = 0x0100;
const rar4_lhd_split_before: u16 = 0x0001;
const rar4_lhd_split_after: u16 = 0x0002;
const rar4_lhd_password: u16 = 0x0004;
const rar4_lhd_solid: u16 = 0x0010;
const rar4_host_unix: u8 = 3;
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
    // Encrypted (-hp) blocks: decrypted staging bytes and the on-disk length.
    // Cleartext blocks keep enc_len == head_size and parse from the archive.
    enc_source: ?[]const u8 = null,
    enc_len: usize = 0,
};

fn parseRar4Header(archive: []const u8, offset: usize, provider: crypto.Provider) Failure!Rar4Header {
    const head = try bounds.slice(archive, offset, 7);
    const head_size = std.mem.readInt(u16, head[5..7], .little);
    if (head_size < 7) return error.InvalidData;
    const header_end = try bounds.addUsize(offset, head_size);
    if (header_end > archive.len) return error.InvalidData;
    const flags = std.mem.readInt(u16, head[3..5], .little);
    // CRC-32 low 16 bits over bytes [2..head_size], except the marker block (0x72),
    // whose first two bytes are the "Ra" signature and carry no CRC (unrar exempts HEAD3_SIGN).
    if (head[2] != rar4_mark) {
        const stored_crc = std.mem.readInt(u16, head[0..2], .little);
        const computed_crc: u16 = @truncate(checksum.crc32With(provider, archive[offset + 2 .. header_end]));
        if (stored_crc != computed_crc) return error.IntegrityFailure;
    }
    var data_size: u64 = 0;
    if (flags & rar4_long_block != 0) {
        const add_size_bytes = try bounds.slice(archive, offset + 7, 4);
        data_size = std.mem.readInt(u32, add_size_bytes[0..4], .little);
    }
    return .{
        .header_type = head[2],
        .flags = flags,
        .head_size = head_size,
        .data_size = data_size,
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

fn parseRar4File(archive: []const u8, header: Rar4Header) Failure!Rar4File {
    // In a RAR4 file block the base header ADD_SIZE field is PACK_SIZE and there is no
    // second packed-size field; reading one shifts every later field by 4 bytes and empties the name.
    var packed_size: u64 = header.data_size;
    const fields_offset = try bounds.addUsize(header.header_offset, 7 + @as(usize, if (header.flags & rar4_long_block != 0) 4 else 0));
    var cursor = binary.ReadCursor.init(archive[fields_offset..]);
    const unpacked_size_low = try cursor.readU32le();
    const host_os = try cursor.readU8();
    const file_crc = try cursor.readU32le();
    const mtime = try cursor.readU32le();
    const unpack_version = try cursor.readU8();
    const method_raw = try cursor.readU8();
    const name_size = std.mem.readInt(u16, &(try cursor.readBytes(2)), .little);
    _ = try cursor.readU32le(); // Attributes.
    var unpacked_size: u64 = unpacked_size_low;
    if (header.flags & rar4_lhd_large != 0) {
        const packed_high = try cursor.readU32le();
        const unpacked_high = try cursor.readU32le();
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

const Rar4HeaderCrypt = struct { keys: Rar4Keys, iv: [16]u8 };

// A -hp encrypted block occupies align16(hsize) bytes on disk, and the 7-byte fixed header
// is inside the ciphertext, so the first cipher block is decrypted alone; CBC uses the last block.
fn parseRar4HeaderEncrypted(
    archive: []const u8,
    offset: usize,
    hcrypt: *Rar4HeaderCrypt,
    provider: crypto.Provider,
    scratch: []u8,
) Failure!Rar4Header {
    const first = try bounds.slice(archive, offset, 16);
    if (scratch.len < 16) return error.InsufficientCapacity;
    crypto.aesCbcDecrypt(provider, hcrypt.keys.key[0..], hcrypt.iv, scratch[0..16], first) catch return error.InvalidData;
    const head_size = std.mem.readInt(u16, scratch[5..7], .little);
    if (head_size < 7) return error.InvalidData;
    const enc_len = std.mem.alignForward(usize, head_size, 16);
    if (scratch.len < enc_len) return error.InsufficientCapacity;
    if (enc_len > 16) {
        const rest = try bounds.slice(archive, offset + 16, enc_len - 16);
        crypto.aesCbcDecrypt(provider, hcrypt.keys.key[0..], first[0..16].*, scratch[16..enc_len], rest) catch return error.InvalidData;
    }
    const stored_crc = std.mem.readInt(u16, scratch[0..2], .little);
    const computed_crc: u16 = @truncate(checksum.crc32With(provider, scratch[2..head_size]));
    if (stored_crc != computed_crc) return error.IntegrityFailure;
    @memcpy(&hcrypt.iv, archive[offset + enc_len - 16 ..][0..16]);
    const flags = std.mem.readInt(u16, scratch[3..5], .little);
    var data_size: u64 = 0;
    if (flags & rar4_long_block != 0) {
        data_size = std.mem.readInt(u32, scratch[7..11], .little);
    }
    return .{
        .header_type = scratch[2],
        .flags = flags,
        .head_size = head_size,
        .data_size = data_size,
        // The header_offset must be a dummy because the caller parses from the staging buffer.
        .header_offset = 0,
        .enc_source = scratch[0..enc_len],
        .enc_len = enc_len,
    };
}

fn walkRar4(archive: []const u8, opts: DecodeOptions, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
    var cursor: usize = 0;
    var seen_main = false;
    var ordinal: usize = 0;
    var header_crypt: ?Rar4HeaderCrypt = null;
    while (cursor < archive.len) {
        if (archive.len - cursor < 7) return error.InvalidData;
        var header: Rar4Header = undefined;
        var header_source: []const u8 = archive;
        if (header_crypt) |*crypt| {
            header = try parseRar4HeaderEncrypted(archive, cursor, crypt, opts.provider, opts.scratch);
            header_source = header.enc_source.?;
        } else {
            header = try parseRar4Header(archive, cursor, opts.provider);
        }
        switch (header.header_type) {
            rar4_mark => {},
            rar4_main => {
                // The flag 0x0040 is MHD_PROTECT, a recovery record, and not
                // MHD_PASSWORD, so only the volume flag is refused.
                if (header.flags & rar4_mhd_volume != 0) return error.Unsupported;
                if (header.flags & rar4_mhd_password != 0) {
                    const password = opts.password orelse return error.Unsupported;
                    const salt = try bounds.slice(archive, cursor + header.head_size, 8);
                    var salt_bytes: [8]u8 = undefined;
                    @memcpy(&salt_bytes, salt);
                    var utf16_buffer: [2 * 127]u8 = undefined;
                    const utf16 = try passwordToUtf16Le(password, &utf16_buffer);
                    const keys = try rar4Kdf(utf16, &salt_bytes, opts);
                    header_crypt = .{ .keys = keys, .iv = keys.iv };
                    cursor = try bounds.addUsize(cursor, header.head_size + 8);
                    seen_main = true;
                    continue;
                }
                seen_main = true;
            },
            rar4_file => {
                if (!seen_main) return error.InvalidData;
                if (header.flags & (rar4_lhd_split_before | rar4_lhd_split_after) != 0)
                    return error.Unsupported;
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
                        if (file.unpack_version != 29 and file.unpack_version != 36) return error.Unsupported;
                        const salt = file.salt orelse return error.InvalidData;
                        break :blk Crypt{ .rar4 = .{ .salt = salt } };
                    } else null,
                };
                if (!file.is_directory) {
                    if (file.method > 5) return error.Unsupported;
                    if (file.unpack_version != 20 and file.unpack_version != 26 and
                        file.unpack_version != 29 and file.unpack_version != 36)
                        return error.Unsupported; // Version 15 and unknown future versions.
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
                const payload_end = try bounds.addUsize(cursor + header.enc_len, std.math.cast(usize, file.packed_size) orelse return error.ResourceLimit);
                if (payload_end > archive.len) return error.InvalidData;
                cursor = payload_end;
                continue;
            },
            rar4_end => return,
            else => {
                // The comment, av, protect, sign, and service blocks have a verified header CRC, so only
                // their data is skipped, and a protect record is content, not encryption.
            },
        }
        const data_end = try bounds.addUsize(cursor + header.enc_len, std.math.cast(usize, header.data_size) orelse return error.ResourceLimit);
        if (data_end > archive.len) return error.InvalidData;
        cursor = data_end;
    }
    // Same EOF rule as the RAR5 walk: the UnexpEndArcMsg of unrar stays silent at
    // a block boundary, and a RAR 1.5 archive never wrote an end block.
    if (!seen_main) return error.InvalidData;
}

const CountCtx = struct { count: usize = 0, max_entries: u64 };

fn countVisit(ctx: *CountCtx, entry: Entry) Failure!void {
    if (entry.is_directory) return;
    if (ctx.count >= ctx.max_entries) return error.ResourceLimit;
    ctx.count = try bounds.addUsize(ctx.count, 1);
}

fn walkEntriesOpts(archive: []const u8, opts: DecodeOptions, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
    const located = try detectFamily(archive, opts.provider);
    switch (located.family) {
        .rar4 => try walkRar4(archive, opts, ctx, visit),
        .rar5 => try walkRar5(archive, located.offset, opts, ctx, visit),
    }
}

fn walkEntries(archive: []const u8, ctx: anytype, comptime visit: fn (@TypeOf(ctx), Entry) Failure!void) Failure!void {
    try walkEntriesOpts(archive, .{}, ctx, visit);
}

pub fn rarInspectCount(archive: []const u8, max_entries: u64) Failure!usize {
    return rarInspectCountOpts(archive, max_entries, .{});
}

pub fn rarInspectCountOpts(archive: []const u8, max_entries: u64, opts: DecodeOptions) Failure!usize {
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

fn findVisit(ctx: *FindCtx, entry: Entry) Failure!void {
    if (entry.is_directory) return;
    if (ctx.ordinal >= ctx.max_entries) return error.ResourceLimit;
    if (ctx.found == null and ctx.ordinal == ctx.target) {
        ctx.found = entry.info;
    }
    ctx.ordinal = try bounds.addUsize(ctx.ordinal, 1);
}

pub fn rarInspectOrdinal(archive: []const u8, ordinal: usize, max_entries: u64) Failure!RarInfo {
    return rarInspectOrdinalOpts(archive, ordinal, max_entries, .{});
}

pub fn rarInspectOrdinalOpts(archive: []const u8, ordinal: usize, max_entries: u64, opts: DecodeOptions) Failure!RarInfo {
    var ctx: FindCtx = .{ .target = ordinal, .max_entries = max_entries };
    try walkEntriesOpts(archive, opts, &ctx, findVisit);
    if (ctx.found) |info| return info;
    return error.InvalidData;
}

// The largest engine state. The caller carves one buffer this big
// and the active engine is constructed in place.
pub const max_state_bytes = @max(@sizeOf(unpack50.State), @max(@sizeOf(unpack29.State), @sizeOf(unpack20.State)));

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
    ctx.ordinal = try bounds.addUsize(ctx.ordinal, 1);
}

fn entryPayload(entry: Entry, archive: []const u8, opts: DecodeOptions, bufs: *DecodeBuffers) Failure![]const u8 {
    const payload = try bounds.slice(archive, entry.info.data_offset, entry.info.packed_size);
    const crypt = entry.crypt orelse return payload;
    const password = opts.password orelse return error.Unsupported;
    if (bufs.packed_stage.len < payload.len) return error.InternalFailure;
    switch (crypt) {
        .rar5 => |c| {
            if (opts.password_lifetime != 0 and payload.len > opts.password_lifetime) {
                if (opts.failure_cause) |cause| cause.* = .password_lifetime;
                return error.ResourceLimit;
            }
            const keys = try rar5Kdf(password, &c.salt, c.lg2count, opts);
            if (c.pswcheck) |expected| {
                if (!crypto.constantTimeEqual(&rar5PswCheck(&keys.pswcheck), &expected)) return error.InvalidData;
            }
            crypto.aesCbcDecrypt(opts.provider, keys.key[0..], c.iv, bufs.packed_stage[0..payload.len], payload) catch return error.InvalidData;
        },
        .rar4 => |c| {
            if (opts.password_lifetime != 0 and payload.len > opts.password_lifetime) {
                if (opts.failure_cause) |cause| cause.* = .password_lifetime;
                return error.ResourceLimit;
            }
            var utf16_buffer: [2 * 127]u8 = undefined;
            const utf16 = try passwordToUtf16Le(password, &utf16_buffer);
            const keys = try rar4Kdf(utf16, &c.salt, opts);
            crypto.aesCbcDecrypt(opts.provider, keys.key[0..], keys.iv, bufs.packed_stage[0..payload.len], payload) catch return error.InvalidData;
        },
    }
    return bufs.packed_stage[0..payload.len];
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
) Failure!void {
    if (entry.is_directory) return;
    if (entry.info.ordinal > locate.target) return;
    if (entry.info.ordinal < locate.group_start) return;
    // A store entry never joins a compressed stream, so it never reaches the session.
    if (entry.method == 0) return;
    const payload = try entryPayload(entry, archive, opts, bufs);
    if (entry.info.ordinal == locate.target) {
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
    opts: DecodeOptions,
) Failure!usize {
    var locate: LocateCtx = .{ .target = ordinal };
    try walkEntriesOpts(archive, opts, &locate, locateVisit);
    const entry = locate.target_entry orelse return error.InvalidData;
    if (entry.is_directory) return error.InvalidData;

    const size = std.math.cast(usize, entry.info.size) orelse return error.ResourceLimit;
    if (output.len < size) return error.InsufficientCapacity;

    if (entry.method == 0) {
        const payload = try entryPayload(entry, archive, opts, bufs);
        if (payload.len < size) return error.InvalidData;
        @memcpy(output[0..size], payload[0..size]);
    } else {
        const window_len = std.math.cast(usize, locate.group_max_window) orelse return error.ResourceLimit;
        try replayCompressed(archive, opts, &locate, entry, output[0..size], bufs, window_len);
    }

    // The integrity check covers the CRC32 of the delivered bytes, plus BLAKE2sp when the
    // entry carries the hash record, and an encrypted RAR5 entry stores an HMAC conversion.
    var hash_key: ?[32]u8 = null;
    if (entry.crypt) |c| {
        switch (c) {
            .rar5 => |r5| if (r5.hashmac) {
                const password = opts.password orelse return error.Unsupported;
                const keys = try rar5Kdf(password, &r5.salt, r5.lg2count, opts);
                hash_key = keys.hash_key;
            },
            .rar4 => {},
        }
    }
    if (entry.info.has_crc) {
        const crc = checksum.crc32With(opts.provider, output[0..size]);
        if (hash_key) |key| {
            if (rar5CrcMac(opts.provider, crc, &key) != entry.info.crc) return error.IntegrityFailure;
        } else if (crc != entry.info.crc) return error.IntegrityFailure;
    }
    if (entry.blake2) |expected| {
        var got: [32]u8 = undefined;
        blake2sp.blake2sp(output[0..size], &got);
        if (hash_key) |key| {
            if (!std.mem.eql(u8, &expected, &rar5BlakeMac(opts.provider, &got, &key))) return error.IntegrityFailure;
        } else if (!std.mem.eql(u8, &expected, &got)) return error.IntegrityFailure;
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
            var replay: ReplayCtx50 = .{ .session = &session, .archive = archive, .locate = locate, .output = output, .opts = opts, .bufs = bufs };
            try walkEntriesOpts(archive, opts, &replay, replayVisit50);
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
                        opts.provider,
                    );
                    var replay: ReplayCtx29 = .{ .session = &session, .archive = archive, .locate = locate, .output = output, .opts = opts, .bufs = bufs };
                    try walkEntriesOpts(archive, opts, &replay, replayVisit29);
                },
                20, 26 => {
                    if (bufs.table_pool.len < unpack20.table_pool_words) return error.InternalFailure;
                    const st = try bufs.state20();
                    var session = try unpack20.Session.init(
                        st,
                        bufs.window[0..window_len],
                        bufs.table_pool[0..unpack20.table_pool_words],
                    );
                    var replay: ReplayCtx20 = .{ .session = &session, .archive = archive, .locate = locate, .output = output, .opts = opts, .bufs = bufs };
                    try walkEntriesOpts(archive, opts, &replay, replayVisit20);
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
    opts: DecodeOptions,
    bufs: *DecodeBuffers,
};
const ReplayCtx29 = struct {
    session: *unpack29.Session,
    archive: []const u8,
    locate: *const LocateCtx,
    output: []u8,
    opts: DecodeOptions,
    bufs: *DecodeBuffers,
};
const ReplayCtx20 = struct {
    session: *unpack20.Session,
    archive: []const u8,
    locate: *const LocateCtx,
    output: []u8,
    opts: DecodeOptions,
    bufs: *DecodeBuffers,
};

fn replayVisit50(ctx: *ReplayCtx50, entry: Entry) Failure!void {
    try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output, ctx.opts, ctx.bufs);
}
fn replayVisit29(ctx: *ReplayCtx29, entry: Entry) Failure!void {
    try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output, ctx.opts, ctx.bufs);
}
fn replayVisit20(ctx: *ReplayCtx20, entry: Entry) Failure!void {
    try replayVisit(ctx.session, ctx.archive, ctx.locate, entry, ctx.output, ctx.opts, ctx.bufs);
}
