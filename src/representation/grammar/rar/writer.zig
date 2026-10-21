const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const crypto = @import("../../../common/primitive/crypto.zig");
const exception = @import("../../../common/primitive/exception.zig");
const finder = @import("finder.zig");
const rar = @import("onprem.zig");
const pack50 = @import("pack50.zig");

const Exception = exception.Exception;
pub const LzToken = finder.LzToken;
pub const pack50Sizes = pack50.workspacesFor;

pub const RarEntry = struct {
    name: []const u8,
    data: []const u8 = &.{},
    mtime: u32 = 0,
    is_directory: bool = false,
    method: u8 = 0, // 0 = store, 1-5 = LZ level.
};

// The encryption policy for a create call. `password` encrypts file data
// (-p); `encrypt_headers` additionally encrypts every block header (-hp) and
// requires a password. The KDF is RAR5's PBKDF2-HMAC-SHA256 at 2^lg2 rounds.
pub const WriteOptions = struct {
    password: []const u8 = &.{},
    encrypt_headers: bool = false,
    kdf_lg2_count: u8 = 15,
    kdf_rounds_limit: u64 = 0,
    failure_cause: ?*crypto.FailureCause = null,
};

// Every buffer is caller-provided, so this struct never allocates.
pub const WriteBuffers = struct {
    hash: []u32,
    hash2: []u32,
    hash3: []u32,
    bt_left: []u32,
    bt_right: []u32,
    tokens: []finder.LzToken,
    staging: []u8,
    packed_buf: []u8, // All entries' packed data, laid out back to back.
    packed_sizes: []usize,
    // Per-entry AES salt and IV, filled while packing encrypted entries.
    crypt_salts: [][16]u8 = &.{},
    crypt_ivs: [][16]u8 = &.{},
};

pub fn packedBound(entry: RarEntry) usize {
    return packedBoundEx(entry, false);
}

pub fn packedBoundEx(entry: RarEntry, encrypted: bool) usize {
    // Encrypted entries carry up to 15 bytes of zero padding.
    const slack: usize = if (encrypted) 15 else 0;
    if (entry.is_directory or entry.data.len == 0 or entry.method == 0) return entry.data.len + slack;
    return entry.data.len * pack50.max_expansion + pack50.output_slack + slack;
}

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

// The compression_info field sets algo 0, solid 0, method 1-5, and dict_bits 3 (1 MiB window).
fn compressionInfoVint(method: u3) u64 {
    return (@as(u64, method) << 7) | (@as(u64, 3) << 10);
}

// The FHEXTRA_CRYPT record: a size vint, the type vint, then version and
// flags vints, the KDF count byte, salt, IV, password check, and its checksum.
// The record size counts the type and payload, not the size vint itself.
const crypt_payload_size = 1 + 1 + 1 + 16 + 16 + 8 + 4;
const crypt_record_size = 1 + crypt_payload_size;

fn cryptExtraSize() usize {
    return 2 + crypt_record_size;
}

// The FHEXTRA_CRYPT payload: version and flags vints, then the KDF count
// byte, salt, IV, password check, and its checksum.
fn writeCryptExtra(record: []u8, lg2count: u8, salt: *const [16]u8, iv: *const [16]u8, pswcheck: *const [8]u8, check_csum: *const [4]u8) usize {
    var cursor: usize = 0;
    cursor += writeVint(0, record[cursor..]);
    cursor += writeVint(rar.rar5_crypt_pswcheck | rar.rar5_crypt_hashmac, record[cursor..]);
    record[cursor] = lg2count;
    cursor += 1;
    @memcpy(record[cursor..][0..16], salt);
    cursor += 16;
    @memcpy(record[cursor..][0..16], iv);
    cursor += 16;
    @memcpy(record[cursor..][0..8], pswcheck);
    cursor += 8;
    @memcpy(record[cursor..][0..4], check_csum);
    cursor += 4;
    return cursor;
}

fn pswCheckCsum(pswcheck: *const [8]u8, provider: crypto.Provider) [4]u8 {
    var sha = crypto.Sha256.bind(provider, .{});
    sha.update(pswcheck);
    var digest: [32]u8 = undefined;
    digest = sha.finalResult();
    return digest[0..4].*;
}

const block_writer = struct {
    // Serialize `contents` (already starting with the type vint) as one
    // header: CRC32 over [size_vint .. End], little-endian, then the bytes.
    // With header encryption, the CRC+size+body run is AES-256-CBC encrypted
    // behind a per-block random IV, zero-padded to the 16-byte block.
    fn emitHeader(out: []u8, pos: usize, contents: []const u8, header_keys: ?*const rar.Rar5Keys, provider: crypto.Provider) Exception!usize {
        var size_buf: [10]u8 = undefined;
        const size_len = writeVint(contents.len, &size_buf);
        // The CRC range must match the reader, which checksums from the size field through the body end.
        var crc_state = checksum.Crc32.init();
        crc_state.update(size_buf[0..size_len]);
        crc_state.update(contents);
        const plain_len = 4 + size_len + contents.len;
        if (header_keys) |keys| {
            const padded = std.mem.alignForward(usize, plain_len, 16);
            if (out.len < pos + 16 + padded) return error.CapacityException;
            var iv: [16]u8 = undefined;
            try crypto.fillRandom(&iv);
            @memcpy(out[pos..][0..16], &iv);
            const region = out[pos + 16 ..][0..padded];
            std.mem.writeInt(u32, region[0..4], crc_state.final(), .little);
            @memcpy(region[4..][0..size_len], size_buf[0..size_len]);
            @memcpy(region[4 + size_len ..][0..contents.len], contents);
            @memset(region[plain_len..], 0);
            try crypto.aesCbcEncrypt(provider, keys.key[0..], iv, region, region);
            return pos + 16 + padded;
        }
        if (out.len < pos + plain_len) return error.CapacityException;
        std.mem.writeInt(u32, out[pos..][0..4], crc_state.final(), .little);
        var cursor = pos + 4;
        @memcpy(out[cursor..][0..size_len], size_buf[0..size_len]);
        cursor += size_len;
        @memcpy(out[cursor..][0..contents.len], contents);
        return pos + plain_len;
    }

    fn mainBlockSize(encrypted: bool) usize {
        // Contents are type, flags, and archive flags (3 bytes), plus a one-byte size vint and 4 CRC bytes.
        const plain = 4 + 1 + 3;
        if (!encrypted) return plain;
        return 16 + std.mem.alignForward(usize, plain, 16);
    }

    fn writeMainBlock(out: []u8, pos: usize, header_keys: ?*const rar.Rar5Keys, provider: crypto.Provider) Exception!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_main, contents[c..]);
        c += writeVint(0, contents[c..]);
        c += writeVint(0, contents[c..]);
        return emitHeader(out, pos, contents[0..c], header_keys, provider);
    }

    // The -hp encryption block carries the header KDF parameters: block
    // flags, then the version and flags vints, the KDF count byte, the salt,
    // and the password check with its checksum. Every later block's header
    // is encrypted with this key.
    fn encryptionBlockSize() usize {
        const contents = 1 + 1 + 1 + 1 + 1 + 16 + 8 + 4;
        return 4 + 1 + contents;
    }

    fn writeEncryptionBlock(out: []u8, pos: usize, lg2count: u8, salt: *const [16]u8, pswcheck: *const [8]u8, check_csum: *const [4]u8, provider: crypto.Provider) Exception!usize {
        var contents: [40]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_encryption, contents[c..]);
        c += writeVint(0, contents[c..]);
        c += writeVint(0, contents[c..]);
        c += writeVint(rar.rar5_crypt_pswcheck, contents[c..]);
        contents[c] = lg2count;
        c += 1;
        @memcpy(contents[c..][0..16], salt);
        c += 16;
        @memcpy(contents[c..][0..8], pswcheck);
        c += 8;
        @memcpy(contents[c..][0..4], check_csum);
        c += 4;
        return emitHeader(out, pos, contents[0..c], null, provider);
    }

    fn endBlockSize(header_crypt: bool) usize {
        // Contents are type, flags, and end flags (3 bytes), plus a one-byte size vint and 4 CRC bytes.
        const plain = 4 + 1 + 3;
        if (!header_crypt) return plain;
        return 16 + std.mem.alignForward(usize, plain, 16);
    }

    fn writeEndBlock(out: []u8, pos: usize, header_keys: ?*const rar.Rar5Keys, provider: crypto.Provider) Exception!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_end, contents[c..]);
        c += writeVint(0, contents[c..]);
        c += writeVint(0, contents[c..]);
        return emitHeader(out, pos, contents[0..c], header_keys, provider);
    }

    fn fileBlockSize(entry: RarEntry, packed_len: usize, options: WriteOptions) usize {
        const data_encrypted = options.password.len != 0 and !entry.is_directory;
        var file_flags: u64 = rar.rar5_file_mtime;
        if (entry.is_directory) {
            file_flags |= rar.rar5_file_directory;
        } else {
            file_flags |= rar.rar5_file_crc32;
        }
        // The attributes are unix st_mode values, because host_os is 1 below:
        // the reference chmods extracted files with this field (extract.cpp).
        const attributes: u64 = if (entry.is_directory) 0o40755 else 0o100644;

        var body: usize = 0;
        body += vintSize(file_flags);
        body += vintSize(if (entry.is_directory) 0 else entry.data.len);
        body += vintSize(attributes);
        body += 4;
        if (!entry.is_directory) body += 4;
        body += vintSize(if (entry.method == 0) 0 else compressionInfoVint(@intCast(entry.method)));
        body += vintSize(1); // The host_os value 1 means unix (RAR5 table: 0=windows, 1=unix).
        body += vintSize(entry.name.len);
        body += entry.name.len;

        var contents: usize = 0;
        contents += vintSize(rar.rar5_type_file);
        // The walk requires HFL_DATA on file blocks, and the RAR5 table sets it even when data_size is 0.
        var block_flags: u64 = if (entry.is_directory) 0 else rar.rar5_flag_data;
        if (data_encrypted) block_flags |= rar.rar5_flag_extra;
        contents += vintSize(block_flags);
        if (!entry.is_directory) contents += vintSize(packed_len);
        if (data_encrypted) contents += cryptExtraSize();
        contents += body;

        const plain = 4 + vintSize(contents) + contents;
        const header_size = if (options.encrypt_headers) 16 + std.mem.alignForward(usize, plain, 16) else plain;
        return header_size + packed_len;
    }

    fn writeFileBlock(
        out: []u8,
        pos: usize,
        entry: RarEntry,
        packed_data: []const u8,
        options: WriteOptions,
        header_keys: ?*const rar.Rar5Keys,
        entry_index: usize,
        ws: *WriteBuffers,
        provider: crypto.Provider,
    ) Exception!usize {
        const data_encrypted = options.password.len != 0 and !entry.is_directory;
        var file_flags: u64 = rar.rar5_file_mtime;
        if (entry.is_directory) {
            file_flags |= rar.rar5_file_directory;
        } else {
            file_flags |= rar.rar5_file_crc32;
        }
        // The attributes are unix st_mode values, because host_os is 1 below:
        // the reference chmods extracted files with this field (extract.cpp).
        const attributes: u64 = if (entry.is_directory) 0o40755 else 0o100644;
        var data_crc = if (entry.is_directory) 0 else checksum.crc32With(provider, entry.data);
        var keys: ?rar.Rar5Keys = null;
        if (data_encrypted) {
            // The stored CRC is the MAC of the plaintext CRC so the header
            // leaks nothing about the data (unrar ConvertHashToMAC).
            const decode_opts: rar.DecodeOptions = .{ .provider = provider };
            keys = try rar.rar5Kdf(options.password, &ws.crypt_salts[entry_index], options.kdf_lg2_count, decode_opts);
            data_crc = rar.rar5CrcMac(provider, data_crc, &keys.?.hash_key);
        }

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
        b += writeVint(1, body[b..]); // The host_os value 1 means unix.
        b += writeVint(entry.name.len, body[b..]);
        @memcpy(body[b..][0..entry.name.len], entry.name);
        b += entry.name.len;

        var extra: [64]u8 = undefined;
        var extra_len: usize = 0;
        if (data_encrypted) {
            var record: [56]u8 = undefined;
            var r: usize = 0;
            r += writeVint(crypt_record_size, record[r..]);
            r += writeVint(rar.rar5_extra_crypt, record[r..]);
            const pswcheck = rar.rar5PswCheck(&keys.?.pswcheck);
            const csum = pswCheckCsum(&pswcheck, provider);
            r += writeCryptExtra(record[r..], options.kdf_lg2_count, &ws.crypt_salts[entry_index], &ws.crypt_ivs[entry_index], &pswcheck, &csum);
            @memcpy(extra[0..r], record[0..r]);
            extra_len = r;
        }

        const data_size: usize = if (entry.is_directory) 0 else packed_data.len;
        var contents: [4400]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_file, contents[c..]);
        var block_flags: u64 = if (entry.is_directory) 0 else rar.rar5_flag_data;
        if (data_encrypted) block_flags |= rar.rar5_flag_extra;
        c += writeVint(block_flags, contents[c..]);
        if (data_encrypted) c += writeVint(extra_len, contents[c..]);
        if (!entry.is_directory) c += writeVint(data_size, contents[c..]);
        @memcpy(contents[c..][0..b], body[0..b]);
        c += b;
        if (data_encrypted) {
            @memcpy(contents[c..][0..extra_len], extra[0..extra_len]);
            c += extra_len;
        }

        var cursor = try emitHeader(out, pos, contents[0..c], header_keys, provider);
        if (data_size > 0) {
            if (out.len < cursor + packed_data.len) return error.CapacityException;
            @memcpy(out[cursor..][0..packed_data.len], packed_data);
            cursor += packed_data.len;
        }
        return cursor;
    }
};

fn checkWriteEntries(entries: []const RarEntry, options: WriteOptions) Exception!void {
    if (options.encrypt_headers and options.password.len == 0) return error.CallException;
    if (options.kdf_lg2_count > 24) return error.CallException;
    for (entries) |entry| {
        if (entry.name.len > 4096) return error.CallException;
        if (entry.method > 5) return error.CallException;
    }
    if (entries.len > 65535) return error.ResourceException;
}

// The sizing query and the commit pass each run this, so one encode compresses twice.
fn packEntries(entries: []const RarEntry, ws: *WriteBuffers, options: WriteOptions) Exception!usize {
    const data_encryption = options.password.len != 0;
    var total: usize = undefined;
    if (options.encrypt_headers) {
        // -hp leads with the encryption block and an encrypted main block;
        // every later block's header rides behind its own IV.
        total = rar.rar5_signature.len + block_writer.encryptionBlockSize() + block_writer.mainBlockSize(true) + block_writer.endBlockSize(true);
    } else {
        total = rar.rar5_signature.len + block_writer.mainBlockSize(false) + block_writer.endBlockSize(false);
    }
    var packed_cursor: usize = 0;
    for (entries, 0..) |entry, i| {
        var packed_len: usize = if (entry.is_directory or entry.data.len == 0 or entry.method == 0) blk: {
            // The encode pass reads every entry back from the packed region, so a stored
            // entry must lay its raw bytes there.
            if (ws.packed_buf.len - packed_cursor < entry.data.len) return error.InternalException;
            @memcpy(ws.packed_buf[packed_cursor .. packed_cursor + entry.data.len], entry.data);
            break :blk entry.data.len;
        } else blk: {
            const bound = packedBoundEx(entry, data_encryption and !entry.is_directory);
            if (ws.packed_buf.len - packed_cursor < bound) return error.InternalException;
            const slice = ws.packed_buf[packed_cursor .. packed_cursor + bound];
            const sizes = pack50.workspacesFor(entry.data.len);
            if (ws.hash.len < sizes.hash_words or ws.hash2.len < sizes.hash2_words or
                ws.hash3.len < sizes.hash3_words or ws.bt_left.len < sizes.bt_words or
                ws.bt_right.len < sizes.bt_words or ws.tokens.len < sizes.token_count or
                ws.staging.len < sizes.staging_bytes) return error.InternalException;
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
        if (data_encryption and !entry.is_directory) {
            if (ws.crypt_salts.len < entries.len or ws.crypt_ivs.len < entries.len) return error.InternalException;
            try crypto.fillRandom(&ws.crypt_salts[i]);
            try crypto.fillRandom(&ws.crypt_ivs[i]);
            const decode_opts: rar.DecodeOptions = .{
                .kdf_rounds_limit = options.kdf_rounds_limit,
                .failure_cause = options.failure_cause,
                .provider = crypto.default_provider,
            };
            const keys = try rar.rar5Kdf(options.password, &ws.crypt_salts[i], options.kdf_lg2_count, decode_opts);
            const padded = std.mem.alignForward(usize, packed_len, crypto.block_length);
            if (ws.packed_buf.len - packed_cursor < padded) return error.InternalException;
            @memset(ws.packed_buf[packed_cursor + packed_len .. packed_cursor + padded], 0);
            crypto.aesCbcEncrypt(crypto.default_provider, keys.key[0..], ws.crypt_ivs[i], ws.packed_buf[packed_cursor .. packed_cursor + padded], ws.packed_buf[packed_cursor .. packed_cursor + padded]) catch return error.CallException;
            packed_len = padded;
        }
        if (ws.packed_sizes.len < entries.len) return error.InternalException;
        ws.packed_sizes[i] = packed_len;
        packed_cursor = try bounds.addUsize(packed_cursor, packed_len);
        total = try bounds.addUsize(total, block_writer.fileBlockSize(entry, packed_len, options));
    }
    return total;
}

pub fn rarWriteSize(entries: []const RarEntry, ws: *WriteBuffers) Exception!usize {
    return rarWriteSizeEx(entries, ws, .{});
}

pub fn rarWriteSizeEx(entries: []const RarEntry, ws: *WriteBuffers, options: WriteOptions) Exception!usize {
    try checkWriteEntries(entries, options);
    return packEntries(entries, ws, options);
}

pub fn rarEncode(entries: []const RarEntry, output: []u8, ws: *WriteBuffers, provider: crypto.Provider) Exception!usize {
    return rarEncodeEx(entries, output, ws, provider, .{});
}

pub fn rarEncodeEx(entries: []const RarEntry, output: []u8, ws: *WriteBuffers, provider: crypto.Provider, options: WriteOptions) Exception!usize {
    const required = try rarWriteSizeEx(entries, ws, options);
    if (output.len < required) return error.CapacityException;

    var header_keys: ?rar.Rar5Keys = null;
    var header_salt: [16]u8 = @splat(0);
    if (options.encrypt_headers) {
        const decode_opts: rar.DecodeOptions = .{
            .kdf_rounds_limit = options.kdf_rounds_limit,
            .failure_cause = options.failure_cause,
            .provider = provider,
        };
        try crypto.fillRandom(&header_salt);
        header_keys = try rar.rar5Kdf(options.password, &header_salt, options.kdf_lg2_count, decode_opts);
    }

    var pos: usize = 0;
    @memcpy(output[pos..][0..rar.rar5_signature.len], &rar.rar5_signature);
    pos += rar.rar5_signature.len;
    if (options.encrypt_headers) {
        const pswcheck = rar.rar5PswCheck(&header_keys.?.pswcheck);
        const csum = pswCheckCsum(&pswcheck, provider);
        pos = try block_writer.writeEncryptionBlock(output, pos, options.kdf_lg2_count, &header_salt, &pswcheck, &csum, provider);
        pos = try block_writer.writeMainBlock(output, pos, &header_keys.?, provider);
    } else {
        pos = try block_writer.writeMainBlock(output, pos, null, provider);
    }

    var i: usize = 0;
    var cursor: usize = 0;
    while (i < entries.len) : (i += 1) {
        const entry = entries[i];
        const packed_len = ws.packed_sizes[i];
        const packed_slice = ws.packed_buf[cursor .. cursor + packed_len];
        pos = try block_writer.writeFileBlock(output, pos, entry, packed_slice, options, if (options.encrypt_headers) &header_keys.? else null, i, ws, provider);
        cursor = try bounds.addUsize(cursor, packed_len);
    }

    pos = try block_writer.writeEndBlock(output, pos, if (options.encrypt_headers) &header_keys.? else null, provider);
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
    try std.testing.expectEqual(vintSize(0), 1);
}

test "file headers carry unix st_mode attributes" {
    // host_os is 1 (unix), so the attributes field must be a real st_mode,
    // not a Windows attribute: extractors chmod extracted files with it.
    const testing = std.testing;
    const allocator = testing.allocator;
    const entries = [_]RarEntry{
        .{ .name = "a", .data = "hi", .method = 0 },
        .{ .name = "d", .is_directory = true },
    };

    const sizes = pack50.workspacesFor(2);
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
    const tokens = try allocator.alloc(finder.LzToken, sizes.token_count);
    defer allocator.free(tokens);
    const staging = try allocator.alloc(u8, sizes.staging_bytes);
    defer allocator.free(staging);
    const packed_buf = try allocator.alloc(u8, packedBound(entries[0]));
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
    const written = try rarEncode(&entries, archive, &ws, crypto.default_provider);
    try testing.expectEqual(required, written);

    // Signature (8) + main block (8) place the first file block at 16; the
    // block prefix holds type, flags, and data_size, so the body follows at 24.
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA4, 0x83, 0x02 }, archive[26..29]); // 0o100644
    try testing.expectEqual(@as(u8, 1), archive[38]); // host_os = unix.
    // The directory block follows the stored data at 43; its attrs sit at 52.
    try testing.expectEqualSlices(u8, &[_]u8{ 0xED, 0x83, 0x01 }, archive[52..55]); // 0o40755.
}

test "created archive round-trips through the facade reader (store and lz)" {
    const testing = std.testing;
    const data1 = "hello rar5 stored";
    const data2 = comptime blk: {
        const phrase = "The quick brown fox jumps over the lazy dog. ";
        var buf: [phrase.len * 8]u8 = undefined;
        for (&buf, 0..) |*byte, i| byte.* = phrase[i % phrase.len];
        break :blk buf;
    };
    const allocator = testing.allocator;

    const window = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(window);
    const state_store = try allocator.alloc(u64, (rar.max_unpacker_bytes + 7) / 8);
    defer allocator.free(state_store);
    const table_pool = try allocator.alloc(u16, rar.table_pool_words);
    defer allocator.free(table_pool);
    const pending50 = try allocator.alloc(rar.PendingFilter50, rar.max_pending50);
    defer allocator.free(pending50);
    const pending29 = try allocator.alloc(rar.PendingFilter29, rar.max_pending29);
    defer allocator.free(pending29);
    const filter_scratch = try allocator.alloc(u8, window.len + rar.filter_scratch_extra);
    defer allocator.free(filter_scratch);
    const ppm_heap = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(ppm_heap);

    for ([_]u8{ 0, 3 }) |method| {
        const entries = [_]RarEntry{
            .{ .name = "m1.txt", .data = data1, .method = method },
            .{ .name = "m2.txt", .data = &data2, .method = method },
            // An empty file round trips because the block carries HFL_DATA with data_size 0.
            .{ .name = "empty.txt", .data = "", .method = method },
        };
        const sizes = pack50.workspacesFor(@max(data1.len, data2.len));
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
        const tokens = try allocator.alloc(finder.LzToken, sizes.token_count);
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
        const written = try rarEncode(&entries, archive, &ws, crypto.default_provider);
        try testing.expectEqual(required, written);

        try testing.expectEqual(@as(usize, 3), try rar.rarInspectCount(archive, 128));
        const out1 = try allocator.alloc(u8, data1.len);
        defer allocator.free(out1);
        const out2 = try allocator.alloc(u8, data2.len);
        defer allocator.free(out2);
        const bufs = rar.DecodeBuffers{
            .state = std.mem.sliceAsBytes(state_store),
            .window = window,
            .table_pool = table_pool,
            .pending50 = pending50,
            .pending29 = pending29,
            .filter_scratch = filter_scratch,
            .ppm_heap = ppm_heap,
        };
        try testing.expectEqual(@as(usize, data1.len), try rar.rarDecodeOrdinal(archive, 0, out1, @constCast(&bufs), .{}));
        try testing.expectEqualSlices(u8, data1, out1);
        try testing.expectEqual(@as(usize, data2.len), try rar.rarDecodeOrdinal(archive, 1, out2, @constCast(&bufs), .{}));
        try testing.expectEqualSlices(u8, &data2, out2);
        try testing.expectEqual(@as(usize, 0), try rar.rarDecodeOrdinal(archive, 2, &.{}, @constCast(&bufs), .{}));
    }
}

test "created encrypted archives roundtrip through the facade reader" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const data1 = "hello encrypted rar5 stored";
    var data2: [600]u8 = undefined;
    for (&data2, 0..) |*byte, i| byte.* = @truncate(i *% 13 +% (i >> 3));
    const password = "secret-pw";

    const window = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(window);
    const state_store = try allocator.alloc(u64, (rar.max_unpacker_bytes + 7) / 8);
    defer allocator.free(state_store);
    const table_pool = try allocator.alloc(u16, rar.table_pool_words);
    defer allocator.free(table_pool);
    const pending50 = try allocator.alloc(rar.PendingFilter50, rar.max_pending50);
    defer allocator.free(pending50);
    const pending29 = try allocator.alloc(rar.PendingFilter29, rar.max_pending29);
    defer allocator.free(pending29);
    const filter_scratch = try allocator.alloc(u8, window.len + rar.filter_scratch_extra);
    defer allocator.free(filter_scratch);
    const ppm_heap = try allocator.alloc(u8, 1 << 20);
    defer allocator.free(ppm_heap);
    var header_scratch: [4096]u8 = undefined;
    var packed_stage: [1024]u8 = undefined;

    const cases = [_]WriteOptions{
        .{ .password = password },
        .{ .password = password, .encrypt_headers = true },
    };
    for (cases) |options| {
        const entries = [_]RarEntry{
            .{ .name = "e1.txt", .data = data1, .method = 0 },
            .{ .name = "e2.bin", .data = &data2, .method = 3 },
            .{ .name = "sub", .data = &.{}, .is_directory = true },
        };
        const sizes = pack50.workspacesFor(data2.len);
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
        const tokens = try allocator.alloc(finder.LzToken, sizes.token_count);
        defer allocator.free(tokens);
        const staging = try allocator.alloc(u8, sizes.staging_bytes);
        defer allocator.free(staging);
        var packed_total: usize = 0;
        for (entries) |e| packed_total += packedBoundEx(e, options.password.len != 0 and !e.is_directory);
        const packed_buf = try allocator.alloc(u8, packed_total);
        defer allocator.free(packed_buf);
        const packed_sizes = try allocator.alloc(usize, entries.len);
        defer allocator.free(packed_sizes);
        const crypt_salts = try allocator.alloc([16]u8, entries.len);
        defer allocator.free(crypt_salts);
        const crypt_ivs = try allocator.alloc([16]u8, entries.len);
        defer allocator.free(crypt_ivs);
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
            .crypt_salts = crypt_salts,
            .crypt_ivs = crypt_ivs,
        };
        const required = try rarWriteSizeEx(&entries, &ws, options);
        const archive = try allocator.alloc(u8, required);
        defer allocator.free(archive);
        const written = try rarEncodeEx(&entries, archive, &ws, crypto.default_provider, options);
        try testing.expectEqual(required, written);

        const decode_opts: rar.DecodeOptions = .{
            .password = password,
            .scratch = &header_scratch,
            .failure_cause = null,
        };
        // Directories are listed but not counted as readable entries.
        try testing.expectEqual(@as(usize, 2), try rar.rarInspectCountOpts(archive, 128, decode_opts));
        const out1 = try allocator.alloc(u8, data1.len);
        defer allocator.free(out1);
        const out2 = try allocator.alloc(u8, data2.len);
        defer allocator.free(out2);
        const bufs = rar.DecodeBuffers{
            .state = std.mem.sliceAsBytes(state_store),
            .window = window,
            .table_pool = table_pool,
            .pending50 = pending50,
            .pending29 = pending29,
            .filter_scratch = filter_scratch,
            .ppm_heap = ppm_heap,
            .packed_stage = &packed_stage,
        };
        _ = try rar.rarDecodeOrdinal(archive, 0, out1, @constCast(&bufs), decode_opts);
        try testing.expectEqualSlices(u8, data1, out1);
        _ = try rar.rarDecodeOrdinal(archive, 1, out2, @constCast(&bufs), decode_opts);
        try testing.expectEqualSlices(u8, &data2, out2);

        // The wrong password fails; with -hp even the count walk refuses.
        var cause: crypto.FailureCause = .none;
        const wrong_opts: rar.DecodeOptions = .{
            .password = "wrong",
            .scratch = &header_scratch,
            .failure_cause = &cause,
        };
        if (options.encrypt_headers) {
            try testing.expectError(error.IntegrityException, rar.rarInspectCountOpts(archive, 128, wrong_opts));
        } else {
            try testing.expectError(error.DataException, rar.rarDecodeOrdinal(archive, 0, out1, @constCast(&bufs), wrong_opts));
        }
        try testing.expectEqual(crypto.FailureCause.wrong_password, cause);
    }
}
