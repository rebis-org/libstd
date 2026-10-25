const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const crypto = @import("../../../common/primitive/crypto.zig");
const exception = @import("../../../common/primitive/exception.zig");
const finder = @import("finder.zig");
const rar = @import("onprem.zig");
const pack50 = @import("pack50.zig");
const recovery = @import("recovery.zig");

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

// The `password` option is -p on file data; `encrypt_headers` adds -hp
// on every block header.
pub const WriteOptions = struct {
    password: []const u8 = &.{},
    encrypt_headers: bool = false,
    kdf_lg2_count: u8 = 15,
    kdf_rounds_limit: u64 = 0,
    failure_cause: ?*crypto.FailureCause = null,
    // Non-zero switches to multi-volume mode; each volume holds at most
    // this many bytes.
    volume_size: usize = 0,
    // Recovery redundancy in percent; the reference caps it at 1000 and
    // refuses it with volumes or header encryption.
    recovery_percent: u16 = 0,
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
    // GF(2^16) exponent and log tables for the recovery record; empty
    // slices reject a recovery request.
    rs_exp: []u16 = &.{},
    rs_log: []u32 = &.{},
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

// The locator encodes both offsets as exactly four bytes, keeping the
// archive layout fixed.
fn writeVintFixed4(value: u64, out: *[4]u8) void {
    for (0..3) |n| out[n] = @intCast(((value >> @intCast(7 * n)) & 0x7F) | 0x80);
    out[3] = @intCast(value >> 21);
}

// The compression_info field sets algo 0, solid 0, method 1-5, and dict_bits 3 (1 MiB window).
fn compressionInfoVint(method: u3) u64 {
    return (@as(u64, method) << 7) | (@as(u64, 3) << 10);
}

// The FHEXTRA_CRYPT record size counts the type and payload, not the size
// vint.
const crypt_payload_size = 1 + 1 + 1 + 16 + 16 + 8 + 4;
const crypt_record_size = 1 + crypt_payload_size;

fn cryptExtraSize() usize {
    return 2 + crypt_record_size;
}

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
    // With header encryption, the CRC, size, and body run is AES-256-CBC
    // encrypted behind a per-block random IV.
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

    fn mainBlockSize(encrypted: bool, volume_index: usize, rr: bool) usize {
        // Contents add a volume number vint after the first volume, plus a
        // 12-byte MHEXTRA_LOCATOR record when a recovery record follows.
        var contents: usize = 3;
        if (volume_index >= 1) contents += vintSize(volume_index);
        if (rr) contents += 12;
        const plain = 4 + 1 + contents;
        if (!encrypted) return plain;
        return 16 + std.mem.alignForward(usize, plain, 16);
    }

    fn writeMainBlock(out: []u8, pos: usize, volume_index: usize, multi: bool, recovery_offset: ?usize, header_keys: ?*const rar.Rar5Keys, provider: crypto.Provider) Exception!usize {
        var contents: [32]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_main, contents[c..]);
        var block_flags: u64 = 0;
        if (recovery_offset != null) block_flags |= rar.rar5_flag_extra | rar.rar5_flag_skip_if_unknown;
        c += writeVint(block_flags, contents[c..]);
        // The extra-area size vint rides before the archive flags; the records
        // themselves close the block.
        if (recovery_offset != null) c += writeVint(11, contents[c..]);
        // MHFL_VOLUME marks every volume; MHFL_VOLNUMBER carries the
        // zero-based number, set only after the first (headers5.hpp).
        var archive_flags: u64 = 0;
        if (multi) archive_flags |= rar.rar5_archive_volume;
        if (volume_index >= 1) archive_flags |= rar.rar5_archive_volnum;
        if (recovery_offset != null) archive_flags |= rar.rar5_archive_protect;
        c += writeVint(archive_flags, contents[c..]);
        if (volume_index >= 1) c += writeVint(volume_index, contents[c..]);
        if (recovery_offset != null) {
            // Locator record: size 10 covers type, flags, and both fixed four-byte
            // offsets; the recovery offset is relative to this block.
            const ro = recovery_offset.?;
            if (ro < pos) return error.InternalException;
            const rel = ro - pos;
            if (rel >= 1 << 28) return error.CallException;
            c += writeVint(10, contents[c..]);
            c += writeVint(rar.rar5_main_extra_locator, contents[c..]);
            contents[c] = @intCast(rar.rar5_locator_qlist | rar.rar5_locator_rr);
            c += 1;
            writeVintFixed4(0, contents[c..][0..4]);
            c += 4;
            writeVintFixed4(rel, contents[c..][0..4]);
            c += 4;
        }
        return emitHeader(out, pos, contents[0..c], header_keys, provider);
    }

    // The -hp block establishes the header key; every later block header is
    // encrypted with it.
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
        const plain = 4 + 1 + 3;
        if (!header_crypt) return plain;
        return 16 + std.mem.alignForward(usize, plain, 16);
    }

    fn writeEndBlock(out: []u8, pos: usize, next_volume: bool, header_keys: ?*const rar.Rar5Keys, provider: crypto.Provider) Exception!usize {
        var contents: [8]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_end, contents[c..]);
        c += writeVint(0, contents[c..]);
        // EARC_NEXT_VOLUME tells a reader that another volume follows.
        c += writeVint(if (next_volume) rar.rar5_earc_next_volume else 0, contents[c..]);
        return emitHeader(out, pos, contents[0..c], header_keys, provider);
    }

    // The RR service header; the caller appends the encoded recovery stream
    // as its data area.
    fn rrBlockSize(percent: u64, data_size: usize) usize {
        const subdata = 1 + vintSize(percent);
        const contents = 10 + 2 * vintSize(data_size) + (vintSize(subdata) + subdata);
        return 4 + vintSize(contents) + contents + data_size;
    }

    fn writeRrBlock(out: []u8, pos: usize, percent: u64, data_size: usize, provider: crypto.Provider) Exception!usize {
        var contents: [64]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_service, contents[c..]);
        c += writeVint(rar.rar5_flag_extra | rar.rar5_flag_data | rar.rar5_flag_skip_if_unknown, contents[c..]);
        // The FHEXTRA_SUBDATA record holds only the recovery percent; a
        // repair pass re-derives the rest.
        const subdata = 1 + vintSize(percent);
        c += writeVint(subdata + 1, contents[c..]);
        c += writeVint(data_size, contents[c..]);
        // The unpacked size matches the data size because the record stores
        // its own data.
        c += writeVint(0, contents[c..]);
        c += writeVint(data_size, contents[c..]);
        c += writeVint(0, contents[c..]);
        c += writeVint(0, contents[c..]);
        c += writeVint(1, contents[c..]);
        contents[c] = 2;
        c += 1;
        contents[c] = 'R';
        contents[c + 1] = 'R';
        c += 2;
        c += writeVint(subdata, contents[c..]);
        c += writeVint(rar.rar5_extra_subdata, contents[c..]);
        c += writeVint(percent, contents[c..]);
        return emitHeader(out, pos, contents[0..c], null, provider);
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
        // Readers reject a file block without HFL_DATA, even a directory or
        // an empty file.
        var block_flags: u64 = rar.rar5_flag_data;
        if (data_encrypted) block_flags |= rar.rar5_flag_extra;
        contents += vintSize(block_flags);
        contents += vintSize(if (entry.is_directory) 0 else packed_len);
        if (data_encrypted) contents += cryptExtraSize();
        contents += body;

        const plain = 4 + vintSize(contents) + contents;
        const header_size = if (options.encrypt_headers) 16 + std.mem.alignForward(usize, plain, 16) else plain;
        return header_size + packed_len;
    }

    // Non-final split parts carry the closing volume's packed-byte hash; unrar
    // verifies it at each volume switch (volume.cpp).
    fn writeFileBlock(
        out: []u8,
        pos: usize,
        entry: RarEntry,
        packed_data: []const u8,
        split_before: bool,
        split_after: bool,
        options: WriteOptions,
        header_keys: ?*const rar.Rar5Keys,
        data_keys: ?*const rar.Rar5Keys,
        record_iv: ?*const [16]u8,
        part_crc: ?u32,
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
        var data_crc: u32 = if (part_crc) |pc| pc else if (entry.is_directory) 0 else checksum.crc32With(provider, entry.data);
        var keys: ?rar.Rar5Keys = null;
        if (data_encrypted) {
            // The stored CRC is the MAC of the plaintext CRC so the header
            // leaks nothing about the data (unrar ConvertHashToMAC).
            if (data_keys) |dk| {
                keys = dk.*;
            } else {
                const decode_opts: rar.DecodeOptions = .{ .provider = provider };
                keys = try rar.rar5Kdf(options.password, &ws.crypt_salts[entry_index], options.kdf_lg2_count, decode_opts);
            }
            if (part_crc == null) data_crc = rar.rar5CrcMac(provider, data_crc, &keys.?.hash_key);
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
            const iv: *const [16]u8 = if (record_iv) |riv| riv else &ws.crypt_ivs[entry_index];
            r += writeCryptExtra(record[r..], options.kdf_lg2_count, &ws.crypt_salts[entry_index], iv, &pswcheck, &csum);
            @memcpy(extra[0..r], record[0..r]);
            extra_len = r;
        }

        const data_size: usize = if (entry.is_directory) 0 else packed_data.len;
        var contents: [4400]u8 = undefined;
        var c: usize = 0;
        c += writeVint(rar.rar5_type_file, contents[c..]);
        var block_flags: u64 = rar.rar5_flag_data;
        if (split_before) block_flags |= rar.rar5_flag_split_before;
        if (split_after) block_flags |= rar.rar5_flag_split_after;
        if (data_encrypted) block_flags |= rar.rar5_flag_extra;
        c += writeVint(block_flags, contents[c..]);
        if (data_encrypted) c += writeVint(extra_len, contents[c..]);
        c += writeVint(data_size, contents[c..]);
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
    // The reference caps rr at 1000 percent and refuses it alongside volumes
    // or header encryption.
    if (options.recovery_percent > 1000) return error.CallException;
    if (options.recovery_percent != 0 and (options.volume_size != 0 or options.encrypt_headers)) return error.CallException;
    for (entries) |entry| {
        if (entry.name.len > 4096) return error.CallException;
        if (entry.method > 5) return error.CallException;
    }
    if (entries.len > 65535) return error.ResourceException;
}

// The sizing query and the commit pass each run this, so one encode compresses twice.
fn packEntries(entries: []const RarEntry, ws: *WriteBuffers, options: WriteOptions) Exception!usize {
    const data_encryption = options.password.len != 0;
    const with_rr = options.recovery_percent != 0;
    var total: usize = undefined;
    if (options.encrypt_headers) {
        // -hp leads with the encryption block and an encrypted main block;
        // every later block's header rides behind its own IV.
        total = rar.rar5_signature.len + block_writer.encryptionBlockSize() + block_writer.mainBlockSize(true, 0, false) + block_writer.endBlockSize(true);
    } else if (with_rr) {
        // The recovery record sits between the last file block and the end
        // block so the locator can point at it.
        total = rar.rar5_signature.len + block_writer.mainBlockSize(false, 0, true);
    } else {
        total = rar.rar5_signature.len + block_writer.mainBlockSize(false, 0, false) + block_writer.endBlockSize(false);
    }
    var packed_cursor: usize = 0;
    for (entries, 0..) |entry, i| {
        var packed_len: usize = if (entry.is_directory or entry.data.len == 0 or entry.method == 0) blk: {
            // The encode pass reads entries back from the packed region, so
            // a stored entry must place its raw bytes there.
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
            if (ws.crypt_salts.len < entries.len) return error.InternalException;
            try crypto.fillRandom(&ws.crypt_salts[i]);
            if (options.volume_size == 0) {
                // Volume mode leaves the packed bytes plaintext; each part
                // is encrypted later with its chained IV.
                if (ws.crypt_ivs.len < entries.len) return error.InternalException;
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
        }
        if (ws.packed_sizes.len < entries.len) return error.InternalException;
        ws.packed_sizes[i] = packed_len;
        packed_cursor = try bounds.addUsize(packed_cursor, packed_len);
        total = try bounds.addUsize(total, block_writer.fileBlockSize(entry, packed_len, options));
    }
    if (with_rr) {
        // The recovery stream protects the main block through the last file
        // byte; the locator's fixed vint bounds its offset.
        const rr_offset = total;
        if (rr_offset - rar.rar5_signature.len >= 1 << 28) return error.CallException;
        const layout = try recovery.layoutFor(rr_offset, options.recovery_percent);
        const data_len = try layout.dataLen();
        if (ws.rs_exp.len < recovery.gf_exp_len or ws.rs_log.len < recovery.gf_log_len) return error.InternalException;
        total = try bounds.addUsize(total, block_writer.rrBlockSize(options.recovery_percent, data_len));
        total = try bounds.addUsize(total, block_writer.endBlockSize(false));
    }
    return total;
}

pub fn rarWriteSize(entries: []const RarEntry, ws: *WriteBuffers) Exception!usize {
    return rarWriteSizeEx(entries, ws, .{});
}

pub fn rarWriteSizeEx(entries: []const RarEntry, ws: *WriteBuffers, options: WriteOptions) Exception!usize {
    if (options.volume_size != 0) return error.CallException;
    try checkWriteEntries(entries, options);
    return packEntries(entries, ws, options);
}

pub fn rarEncode(entries: []const RarEntry, output: []u8, ws: *WriteBuffers, provider: crypto.Provider) Exception!usize {
    return rarEncodeEx(entries, output, ws, provider, .{});
}

pub fn rarEncodeEx(entries: []const RarEntry, output: []u8, ws: *WriteBuffers, provider: crypto.Provider, options: WriteOptions) Exception!usize {
    if (options.volume_size != 0) return error.CallException;
    const with_rr = options.recovery_percent != 0;
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

    // rarWriteSizeEx already packed every entry, so the pinned per-entry
    // sizes place the recovery header exactly.
    var rr_offset: usize = 0;
    if (with_rr) {
        rr_offset = rar.rar5_signature.len + block_writer.mainBlockSize(false, 0, true);
        for (entries, 0..) |entry, i| {
            rr_offset = try bounds.addUsize(rr_offset, block_writer.fileBlockSize(entry, ws.packed_sizes[i], options));
        }
    }

    var pos: usize = 0;
    @memcpy(output[pos..][0..rar.rar5_signature.len], &rar.rar5_signature);
    pos += rar.rar5_signature.len;
    if (options.encrypt_headers) {
        const pswcheck = rar.rar5PswCheck(&header_keys.?.pswcheck);
        const csum = pswCheckCsum(&pswcheck, provider);
        pos = try block_writer.writeEncryptionBlock(output, pos, options.kdf_lg2_count, &header_salt, &pswcheck, &csum, provider);
        pos = try block_writer.writeMainBlock(output, pos, 0, false, null, &header_keys.?, provider);
    } else {
        pos = try block_writer.writeMainBlock(output, pos, 0, false, if (with_rr) rr_offset else null, null, provider);
    }

    var i: usize = 0;
    var cursor: usize = 0;
    while (i < entries.len) : (i += 1) {
        const entry = entries[i];
        const packed_len = ws.packed_sizes[i];
        const packed_slice = ws.packed_buf[cursor .. cursor + packed_len];
        pos = try block_writer.writeFileBlock(output, pos, entry, packed_slice, false, false, options, if (options.encrypt_headers) &header_keys.? else null, null, null, null, i, ws, provider);
        cursor = try bounds.addUsize(cursor, packed_len);
    }

    if (with_rr) {
        if (pos != rr_offset) return error.InternalException;
        const layout = try recovery.layoutFor(rr_offset, options.recovery_percent);
        const data_len = try layout.dataLen();
        // One random slot per archive, shared by every sub-block.
        var slot: u64 = undefined;
        try crypto.fillRandom(std.mem.asBytes(&slot));
        pos = try block_writer.writeRrBlock(output, pos, options.recovery_percent, data_len, provider);
        try recovery.initTables(ws.rs_exp, ws.rs_log);
        try recovery.encodeUnits(output[0..rr_offset], layout, slot, output[pos..][0..data_len], ws.rs_exp, ws.rs_log);
        pos = try bounds.addUsize(pos, data_len);
    }

    pos = try block_writer.writeEndBlock(output, pos, false, if (options.encrypt_headers) &header_keys.? else null, provider);
    return pos;
}

// The `data_len` field counts plaintext bytes; `part_len` is the on-wire
// size, including the final part's CBC padding.
pub const VolumePart = struct {
    entry_index: usize,
    data_offset: usize,
    data_len: usize,
    part_len: usize,
    split_before: bool,
    split_after: bool,
};

// The layout engine reports volumes, parts, and ends in order; sizing and
// emit walk the same steps.
pub const VolumeStep = union(enum) {
    volume: usize,
    part: VolumePart,
    end: bool,
};

// Every volume repeats the signature and, under -hp, the encryption block,
// so each volume's headers decrypt standalone.
fn volumePrefixSize(volume_index: usize, options: WriteOptions) usize {
    var size: usize = rar.rar5_signature.len;
    if (options.encrypt_headers) {
        size += block_writer.encryptionBlockSize() + block_writer.mainBlockSize(true, volume_index, false);
    } else {
        size += block_writer.mainBlockSize(false, volume_index, false);
    }
    return size;
}

// A part with stream remaining always closes the volume; the reader sizes
// its part scratch from the volume count.
fn layoutVolumes(
    entries: []const RarEntry,
    ws: *WriteBuffers,
    options: WriteOptions,
    ctx: anytype,
    comptime onStep: fn (@TypeOf(ctx), VolumeStep) Exception!void,
) Exception!void {
    const data_encryption = options.password.len != 0;
    var volume: usize = 0;
    var used: usize = volumePrefixSize(0, options);
    if (used > options.volume_size) return error.CallException;
    try onStep(ctx, .{ .volume = 0 });
    var stream_base: usize = 0;
    for (entries, 0..) |entry, ei| {
        const encrypted = data_encryption and !entry.is_directory;
        const raw = ws.packed_sizes[ei];
        const padded_total: usize = if (encrypted) std.mem.alignForward(usize, raw, crypto.block_length) else raw;
        const step: usize = if (encrypted) crypto.block_length else 1;
        var offset: usize = 0;
        var first = true;
        while (true) {
            const free = options.volume_size - used;
            var ds: usize = @min(padded_total - offset, free);
            if (encrypted) ds &= ~@as(usize, crypto.block_length - 1);
            while (ds > 0 and block_writer.fileBlockSize(entry, ds, options) > free) ds -= step;
            const remaining = padded_total - offset;
            const min_ds: usize = if (remaining == 0) 0 else step;
            const fits = ds >= min_ds and block_writer.fileBlockSize(entry, ds, options) <= free;
            if (!fits) {
                // A fresh volume is the widest fit; if even its prefix plus
                // this part overflows, no layout exists.
                if (used == volumePrefixSize(volume, options)) return error.CallException;
                try onStep(ctx, .{ .end = true });
                volume += 1;
                used = volumePrefixSize(volume, options);
                if (used > options.volume_size) return error.CallException;
                try onStep(ctx, .{ .volume = volume });
                continue;
            }
            const is_last = offset + ds >= padded_total;
            const data_len: usize = if (is_last) raw - offset else ds;
            try onStep(ctx, .{ .part = .{
                .entry_index = ei,
                .data_offset = try bounds.addUsize(stream_base, offset),
                .data_len = data_len,
                .part_len = ds,
                .split_before = !first,
                .split_after = !is_last,
            } });
            used = try bounds.addUsize(used, block_writer.fileBlockSize(entry, ds, options));
            if (is_last) break;
            offset += ds;
            first = false;
            // Stream remains, so this volume is done; open the next one.
            try onStep(ctx, .{ .end = true });
            volume += 1;
            used = volumePrefixSize(volume, options);
            if (used > options.volume_size) return error.CallException;
            try onStep(ctx, .{ .volume = volume });
        }
        stream_base = try bounds.addUsize(stream_base, raw);
    }
    try onStep(ctx, .{ .end = false });
}

pub const VolumePlan = struct {
    count: usize,
    total: usize,
};

const VolumeSizeCtx = struct {
    entries: []const RarEntry,
    options: WriteOptions,
    count: usize = 0,
    total: usize = 0,

    fn step(self: *VolumeSizeCtx, s: VolumeStep) Exception!void {
        switch (s) {
            .volume => |v| {
                self.count = v + 1;
                self.total = try bounds.addUsize(self.total, volumePrefixSize(v, self.options));
            },
            .part => |p| {
                self.total = try bounds.addUsize(self.total, block_writer.fileBlockSize(self.entries[p.entry_index], p.part_len, self.options));
            },
            .end => {
                self.total = try bounds.addUsize(self.total, block_writer.endBlockSize(self.options.encrypt_headers));
            },
        }
    }
};

const VolumeEmitCtx = struct {
    entries: []const RarEntry,
    options: WriteOptions,
    ws: *WriteBuffers,
    provider: crypto.Provider,
    header_keys: ?*const rar.Rar5Keys,
    header_salt: *const [16]u8,
    header_pswcheck: *const [8]u8,
    header_csum: *const [4]u8,
    output: []u8,
    volume_slices: [][]u8,
    pos: usize = 0,
    volume_start: usize = 0,
    volume_index: usize = 0,
    current: usize = std.math.maxInt(usize),
    data_keys: rar.Rar5Keys = undefined,
    entry_iv: [16]u8 = undefined,
    chain_iv: [16]u8 = undefined,

    fn step(self: *VolumeEmitCtx, s: VolumeStep) Exception!void {
        switch (s) {
            .volume => |v| {
                self.volume_start = self.pos;
                self.volume_index = v;
                if (self.output.len < self.pos + rar.rar5_signature.len) return error.CapacityException;
                @memcpy(self.output[self.pos..][0..rar.rar5_signature.len], &rar.rar5_signature);
                self.pos += rar.rar5_signature.len;
                if (self.options.encrypt_headers) {
                    self.pos = try block_writer.writeEncryptionBlock(self.output, self.pos, self.options.kdf_lg2_count, self.header_salt, self.header_pswcheck, self.header_csum, self.provider);
                    self.pos = try block_writer.writeMainBlock(self.output, self.pos, v, true, null, self.header_keys, self.provider);
                } else {
                    self.pos = try block_writer.writeMainBlock(self.output, self.pos, v, true, null, null, self.provider);
                }
            },
            .part => |p| {
                const entry = self.entries[p.entry_index];
                const encrypted = self.options.password.len != 0 and !entry.is_directory;
                if (p.entry_index != self.current) {
                    // First part of this entry: a fresh record IV and the
                    // per-entry data keys; every part header repeats them.
                    self.current = p.entry_index;
                    try crypto.fillRandom(&self.entry_iv);
                    if (encrypted) {
                        const decode_opts: rar.DecodeOptions = .{
                            .kdf_rounds_limit = self.options.kdf_rounds_limit,
                            .failure_cause = self.options.failure_cause,
                            .provider = self.provider,
                        };
                        self.data_keys = try rar.rar5Kdf(self.options.password, &self.ws.crypt_salts[p.entry_index], self.options.kdf_lg2_count, decode_opts);
                        self.chain_iv = self.entry_iv;
                    }
                }
                var wire: []const u8 = undefined;
                if (encrypted) {
                    const data_end = try bounds.addUsize(p.data_offset, p.data_len);
                    if (self.ws.packed_buf.len < data_end) return error.InternalException;
                    if (self.ws.staging.len < p.part_len) return error.InternalException;
                    // Parts chain CBC from the previous part's last ciphertext block;
                    // unrar decrypts split files as one stream (extract.cpp).
                    @memcpy(self.ws.staging[0..p.data_len], self.ws.packed_buf[p.data_offset..][0..p.data_len]);
                    @memset(self.ws.staging[p.data_len..p.part_len], 0);
                    crypto.aesCbcEncrypt(self.provider, self.data_keys.key[0..], self.chain_iv, self.ws.staging[0..p.part_len], self.ws.staging[0..p.part_len]) catch return error.CallException;
                    wire = self.ws.staging[0..p.part_len];
                    if (p.split_after) self.chain_iv = self.ws.staging[p.part_len - crypto.block_length ..][0..crypto.block_length].*;
                } else {
                    const data_end = try bounds.addUsize(p.data_offset, p.data_len);
                    if (self.ws.packed_buf.len < data_end) return error.InternalException;
                    wire = self.ws.packed_buf[p.data_offset..][0..p.data_len];
                    if (wire.len != p.part_len) return error.InternalException;
                }
                // Non-final parts hash their own on-disk bytes, so an
                // encrypted part hashes its ciphertext.
                var part_crc: ?u32 = null;
                if (p.split_after) {
                    const pc = checksum.crc32With(self.provider, wire);
                    part_crc = if (encrypted) rar.rar5CrcMac(self.provider, pc, &self.data_keys.hash_key) else pc;
                }
                self.pos = try block_writer.writeFileBlock(
                    self.output,
                    self.pos,
                    entry,
                    wire,
                    p.split_before,
                    p.split_after,
                    self.options,
                    self.header_keys,
                    if (encrypted) &self.data_keys else null,
                    if (encrypted) &self.entry_iv else null,
                    part_crc,
                    p.entry_index,
                    self.ws,
                    self.provider,
                );
            },
            .end => |has_next| {
                self.pos = try block_writer.writeEndBlock(self.output, self.pos, has_next, self.header_keys, self.provider);
                if (self.volume_slices.len <= self.volume_index) return error.CapacityException;
                self.volume_slices[self.volume_index] = self.output[self.volume_start..self.pos];
            },
        }
    }
};

// Packs the entries, then lays them out; returns the volume count and total
// bytes.
pub fn rarVolumeSize(entries: []const RarEntry, ws: *WriteBuffers, options: WriteOptions) Exception!VolumePlan {
    if (options.volume_size == 0) return error.CallException;
    try checkWriteEntries(entries, options);
    _ = try packEntries(entries, ws, options);
    var ctx = VolumeSizeCtx{ .entries = entries, .options = options };
    try layoutVolumes(entries, ws, options, &ctx, VolumeSizeCtx.step);
    return .{ .count = ctx.count, .total = ctx.total };
}

// The `output` buffer must hold the plan's total and `volume_slices` at
// least the plan's count.
pub fn rarEncodeVolumes(entries: []const RarEntry, output: []u8, volume_slices: [][]u8, ws: *WriteBuffers, provider: crypto.Provider, options: WriteOptions) Exception!usize {
    if (options.volume_size == 0) return error.CallException;
    try checkWriteEntries(entries, options);
    _ = try packEntries(entries, ws, options);

    var header_keys: ?rar.Rar5Keys = null;
    var header_salt: [16]u8 = @splat(0);
    var header_pswcheck: [8]u8 = @splat(0);
    var header_csum: [4]u8 = @splat(0);
    if (options.encrypt_headers) {
        const decode_opts: rar.DecodeOptions = .{
            .kdf_rounds_limit = options.kdf_rounds_limit,
            .failure_cause = options.failure_cause,
            .provider = provider,
        };
        try crypto.fillRandom(&header_salt);
        header_keys = try rar.rar5Kdf(options.password, &header_salt, options.kdf_lg2_count, decode_opts);
        header_pswcheck = rar.rar5PswCheck(&header_keys.?.pswcheck);
        header_csum = pswCheckCsum(&header_pswcheck, provider);
    }

    var ctx = VolumeEmitCtx{
        .entries = entries,
        .options = options,
        .ws = ws,
        .provider = provider,
        .header_keys = if (options.encrypt_headers) &header_keys.? else null,
        .header_salt = &header_salt,
        .header_pswcheck = &header_pswcheck,
        .header_csum = &header_csum,
        .output = output,
        .volume_slices = volume_slices,
    };
    try layoutVolumes(entries, ws, options, &ctx, VolumeEmitCtx.step);
    return ctx.volume_index + 1;
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
    // host_os is 1 (unix), so the attributes must be a real st_mode:
    // extractors chmod with it.
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

    // Searching rather than addressing keeps the check independent of the
    // block prefix's length.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, archive, &[_]u8{ 0xA4, 0x83, 0x02 })); // 0o100644.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, archive, &[_]u8{ 0xED, 0x83, 0x01 })); // 0o40755.
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

// Test-only harnesses: the write side allocates the workspace and plan-sized
// output; the decode side reuses one buffer set.

const VolumeTestWrite = struct {
    ws: WriteBuffers = .{
        .hash = &.{},
        .hash2 = &.{},
        .hash3 = &.{},
        .bt_left = &.{},
        .bt_right = &.{},
        .tokens = &.{},
        .staging = &.{},
        .packed_buf = &.{},
        .packed_sizes = &.{},
    },
    plan: VolumePlan = .{ .count = 0, .total = 0 },
    output: []u8 = &.{},
    volume_slices: [][]u8 = &.{},
    view: [][]const u8 = &.{},
    written: usize = 0,

    fn init(allocator: std.mem.Allocator, entries: []const RarEntry, options: WriteOptions) Exception!VolumeTestWrite {
        var self = VolumeTestWrite{};
        errdefer self.deinit(allocator);
        const sizes = pack50.workspacesFor(maxEntryInput(entries));
        const data_encryption = options.password.len != 0;
        // Staging also holds one encrypted part, so it must cover the
        // largest entry's aligned part.
        var stage_bound: usize = sizes.staging_bytes;
        var packed_total: usize = 0;
        for (entries) |e| {
            const encrypted = data_encryption and !e.is_directory;
            packed_total += packedBoundEx(e, encrypted);
            if (encrypted) stage_bound = @max(stage_bound, std.mem.alignForward(usize, packedBoundEx(e, true), crypto.block_length));
        }
        self.ws.hash = allocator.alloc(u32, sizes.hash_words) catch return error.ResourceException;
        self.ws.hash2 = allocator.alloc(u32, sizes.hash2_words) catch return error.ResourceException;
        self.ws.hash3 = allocator.alloc(u32, sizes.hash3_words) catch return error.ResourceException;
        self.ws.bt_left = allocator.alloc(u32, sizes.bt_words) catch return error.ResourceException;
        self.ws.bt_right = allocator.alloc(u32, sizes.bt_words) catch return error.ResourceException;
        self.ws.tokens = allocator.alloc(finder.LzToken, sizes.token_count) catch return error.ResourceException;
        self.ws.staging = allocator.alloc(u8, stage_bound) catch return error.ResourceException;
        self.ws.packed_buf = allocator.alloc(u8, packed_total) catch return error.ResourceException;
        self.ws.packed_sizes = allocator.alloc(usize, entries.len) catch return error.ResourceException;
        if (data_encryption) self.ws.crypt_salts = allocator.alloc([16]u8, entries.len) catch return error.ResourceException;
        self.plan = try rarVolumeSize(entries, &self.ws, options);
        self.output = allocator.alloc(u8, self.plan.total) catch return error.ResourceException;
        self.volume_slices = allocator.alloc([]u8, self.plan.count) catch return error.ResourceException;
        self.written = try rarEncodeVolumes(entries, self.output, self.volume_slices, &self.ws, crypto.default_provider, options);
        self.view = allocator.alloc([]const u8, self.plan.count) catch return error.ResourceException;
        for (self.view, self.volume_slices) |*dst, src| dst.* = src;
        return self;
    }

    fn deinit(self: *VolumeTestWrite, allocator: std.mem.Allocator) void {
        allocator.free(self.view);
        allocator.free(self.volume_slices);
        allocator.free(self.output);
        allocator.free(self.ws.crypt_salts);
        allocator.free(self.ws.packed_sizes);
        allocator.free(self.ws.packed_buf);
        allocator.free(self.ws.staging);
        allocator.free(self.ws.tokens);
        allocator.free(self.ws.bt_right);
        allocator.free(self.ws.bt_left);
        allocator.free(self.ws.hash3);
        allocator.free(self.ws.hash2);
        allocator.free(self.ws.hash);
    }
};

fn maxEntryInput(entries: []const RarEntry) usize {
    var max_input: usize = 0;
    for (entries) |e| max_input = @max(max_input, e.data.len);
    return max_input;
}

const VolumeTestDecode = struct {
    state_store: []u64 = &.{},
    window: []u8 = &.{},
    table_pool: []u16 = &.{},
    pending50: []rar.PendingFilter50 = &.{},
    pending29: []rar.PendingFilter29 = &.{},
    filter_scratch: []u8 = &.{},
    ppm_heap: []u8 = &.{},

    fn init(allocator: std.mem.Allocator) Exception!VolumeTestDecode {
        var self = VolumeTestDecode{};
        errdefer self.deinit(allocator);
        self.window = allocator.alloc(u8, 1 << 20) catch return error.ResourceException;
        self.state_store = allocator.alloc(u64, (rar.max_unpacker_bytes + 7) / 8) catch return error.ResourceException;
        self.table_pool = allocator.alloc(u16, rar.table_pool_words) catch return error.ResourceException;
        self.pending50 = allocator.alloc(rar.PendingFilter50, rar.max_pending50) catch return error.ResourceException;
        self.pending29 = allocator.alloc(rar.PendingFilter29, rar.max_pending29) catch return error.ResourceException;
        self.filter_scratch = allocator.alloc(u8, (1 << 20) + rar.filter_scratch_extra) catch return error.ResourceException;
        self.ppm_heap = allocator.alloc(u8, 1 << 20) catch return error.ResourceException;
        return self;
    }

    // The split-part scratch and the packed stage stay per-test locals, because
    // their sizing is part of what the tests pin.
    fn buffers(self: *VolumeTestDecode, split_parts: []rar.SplitPart, packed_stage: []u8) rar.DecodeBuffers {
        return .{
            .state = std.mem.sliceAsBytes(self.state_store),
            .window = self.window,
            .table_pool = self.table_pool,
            .pending50 = self.pending50,
            .pending29 = self.pending29,
            .filter_scratch = self.filter_scratch,
            .ppm_heap = self.ppm_heap,
            .split_parts = split_parts,
            .packed_stage = packed_stage,
        };
    }

    fn deinit(self: *VolumeTestDecode, allocator: std.mem.Allocator) void {
        allocator.free(self.ppm_heap);
        allocator.free(self.filter_scratch);
        allocator.free(self.pending29);
        allocator.free(self.pending50);
        allocator.free(self.table_pool);
        allocator.free(self.state_store);
        allocator.free(self.window);
    }
};

test "multi-volume archives round-trip through the volume reader" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var data2: [600]u8 = undefined;
    // Incompressible bytes: a repeating pattern would shrink the packed
    // stream enough that the split paths never fire.
    var seed: u32 = 0x9E3779B9;
    for (&data2) |*byte| {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        byte.* = @truncate(seed);
    }
    const entries = [_]RarEntry{
        .{ .name = "m1.txt", .data = "hello rar5 stored", .method = 0 },
        .{ .name = "m2.txt", .data = &data2, .method = 3 },
        .{ .name = "empty.txt", .data = "", .method = 0 },
        .{ .name = "sub", .data = &.{}, .is_directory = true },
    };

    var w = try VolumeTestWrite.init(allocator, &entries, .{ .volume_size = 200 });
    defer w.deinit(allocator);
    try testing.expect(w.plan.count >= 3);
    try testing.expectEqual(w.plan.count, w.written);
    // Directories are listed but not counted as readable entries.
    try testing.expectEqual(@as(usize, 3), try rar.rarVolumeCount(w.view, 128, .{}));

    var d = try VolumeTestDecode.init(allocator);
    defer d.deinit(allocator);
    var split_parts: [32]rar.SplitPart = undefined;
    var packed_stage: [8192]u8 = undefined;
    const bufs = d.buffers(&split_parts, &packed_stage);

    const out1 = try allocator.alloc(u8, "hello rar5 stored".len);
    defer allocator.free(out1);
    const out2 = try allocator.alloc(u8, data2.len);
    defer allocator.free(out2);
    try testing.expectEqual(out1.len, try rar.rarVolumeDecodeOrdinal(w.view, 0, out1, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, "hello rar5 stored", out1);
    try testing.expectEqual(out2.len, try rar.rarVolumeDecodeOrdinal(w.view, 1, out2, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &data2, out2);
    try testing.expectEqual(@as(usize, 0), try rar.rarVolumeDecodeOrdinal(w.view, 2, &.{}, @constCast(&bufs), .{}));
}

test "multi-volume encrypted splits round-trip and reject wrong passwords" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const password = "secret-pw";
    var data2: [600]u8 = undefined;
    // Incompressible bytes, so the encrypted split spans several parts.
    var seed: u32 = 0x9E3779B9;
    for (&data2) |*byte| {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        byte.* = @truncate(seed);
    }
    const entries = [_]RarEntry{
        .{ .name = "e1.txt", .data = "hello encrypted rar5 stored", .method = 0 },
        .{ .name = "e2.bin", .data = &data2, .method = 3 },
        .{ .name = "sub", .data = &.{}, .is_directory = true },
    };

    var d = try VolumeTestDecode.init(allocator);
    defer d.deinit(allocator);
    var header_scratch: [4096]u8 = undefined;
    var split_parts: [32]rar.SplitPart = undefined;
    var packed_stage: [8192]u8 = undefined;
    const out1 = try allocator.alloc(u8, "hello encrypted rar5 stored".len);
    defer allocator.free(out1);
    const out2 = try allocator.alloc(u8, data2.len);
    defer allocator.free(out2);

    const cases = [_]WriteOptions{
        .{ .password = password, .volume_size = 220 },
        .{ .password = password, .encrypt_headers = true, .volume_size = 512 },
    };
    for (cases) |options| {
        var w = try VolumeTestWrite.init(allocator, &entries, options);
        defer w.deinit(allocator);
        try testing.expect(w.plan.count >= 2);
        try testing.expectEqual(w.plan.count, w.written);

        const decode_opts: rar.DecodeOptions = .{
            .password = password,
            .scratch = &header_scratch,
        };
        const bufs = d.buffers(&split_parts, &packed_stage);
        try testing.expectEqual(@as(usize, 2), try rar.rarVolumeCount(w.view, 128, decode_opts));
        try testing.expectEqual(out1.len, try rar.rarVolumeDecodeOrdinal(w.view, 0, out1, @constCast(&bufs), decode_opts));
        try testing.expectEqualSlices(u8, "hello encrypted rar5 stored", out1);
        try testing.expectEqual(out2.len, try rar.rarVolumeDecodeOrdinal(w.view, 1, out2, @constCast(&bufs), decode_opts));
        try testing.expectEqualSlices(u8, &data2, out2);

        // The wrong password fails as in single-volume mode: -p at the entry
        // check, -hp at the header check.
        var cause: crypto.FailureCause = .none;
        const wrong_opts: rar.DecodeOptions = .{
            .password = "wrong",
            .scratch = &header_scratch,
            .failure_cause = &cause,
        };
        if (options.encrypt_headers) {
            try testing.expectError(error.IntegrityException, rar.rarVolumeCount(w.view, 128, wrong_opts));
        } else {
            try testing.expectError(error.DataException, rar.rarVolumeDecodeOrdinal(w.view, 0, out1, @constCast(&bufs), wrong_opts));
        }
        try testing.expectEqual(crypto.FailureCause.wrong_password, cause);
    }
}

test "volume headers pin the volume number and next-volume end marker" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var data: [500]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @truncate(i *% 7 +% (i >> 2));

    const entries = [_]RarEntry{
        .{ .name = "big.bin", .data = &data, .method = 0 },
    };

    var w = try VolumeTestWrite.init(allocator, &entries, .{ .volume_size = 180 });
    defer w.deinit(allocator);
    try testing.expect(w.plan.count >= 3);
    try testing.expectEqual(w.plan.count, w.written);

    for (w.view, 0..) |vol, v| {
        const final = v + 1 == w.view.len;
        // The CRC spans the size vint and body, so the pins start after it.
        try testing.expectEqualSlices(u8, &rar.rar5_signature, vol[0..8]);
        if (v == 0) {
            try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x01, 0x00, 0x01 }, vol[12..16]);
        } else {
            try testing.expectEqual(@as(u8, 0x04), vol[12]);
            try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x03, @intCast(v) }, vol[13..17]);
        }
        // Every volume closes with an end block; the next-volume flag is
        // clear only on the final volume.
        const tail: [4]u8 = if (final) .{ 0x03, 0x05, 0x00, 0x00 } else .{ 0x03, 0x05, 0x00, 0x01 };
        try testing.expectEqualSlices(u8, &tail, vol[vol.len - 4 ..]);
    }

    var d = try VolumeTestDecode.init(allocator);
    defer d.deinit(allocator);
    var split_parts: [16]rar.SplitPart = undefined;
    var packed_stage: [1024]u8 = undefined;
    const bufs = d.buffers(&split_parts, &packed_stage);
    try testing.expectEqual(@as(usize, 1), try rar.rarVolumeCount(w.view, 128, .{}));
    const out = try allocator.alloc(u8, data.len);
    defer allocator.free(out);
    try testing.expectEqual(data.len, try rar.rarVolumeDecodeOrdinal(w.view, 0, out, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &data, out);
}

test "volume reader rejects short, misordered, and single-volume reads" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var a_data: [300]u8 = undefined;
    for (&a_data, 0..) |*byte, i| byte.* = @truncate(i *% 7 +% (i >> 2));
    var b_data: [600]u8 = undefined;
    // Incompressible bytes: a compressible stream could pack both entries
    // into too few volumes to exercise the split paths.
    var seed: u32 = 0x9E3779B9;
    for (&b_data) |*byte| {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        byte.* = @truncate(seed);
    }
    const entries = [_]RarEntry{
        .{ .name = "a.txt", .data = &a_data, .method = 0 },
        .{ .name = "b.bin", .data = &b_data, .method = 3 },
    };

    var w = try VolumeTestWrite.init(allocator, &entries, .{ .volume_size = 170 });
    defer w.deinit(allocator);
    try testing.expect(w.plan.count >= 3);
    try testing.expectEqual(w.plan.count, w.written);

    var d = try VolumeTestDecode.init(allocator);
    defer d.deinit(allocator);
    var split_parts: [32]rar.SplitPart = undefined;
    var packed_stage: [8192]u8 = undefined;
    const bufs = d.buffers(&split_parts, &packed_stage);
    const out_a = try allocator.alloc(u8, a_data.len);
    defer allocator.free(out_a);
    const out_b = try allocator.alloc(u8, b_data.len);
    defer allocator.free(out_b);

    try testing.expectEqual(@as(usize, 2), try rar.rarVolumeCount(w.view, 128, .{}));
    try testing.expectEqual(a_data.len, try rar.rarVolumeDecodeOrdinal(w.view, 0, out_a, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &a_data, out_a);
    try testing.expectEqual(b_data.len, try rar.rarVolumeDecodeOrdinal(w.view, 1, out_b, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &b_data, out_b);

    // The walk refuses a hole (the survivors renumber), a dropped head, and a
    // lone non-final volume.
    const gap = try allocator.alloc([]const u8, w.written - 1);
    defer allocator.free(gap);
    gap[0] = w.view[0];
    @memcpy(gap[1..], w.view[2..]);
    try testing.expectError(error.DataException, rar.rarVolumeCount(gap, 128, .{}));
    try testing.expectError(error.DataException, rar.rarVolumeCount(w.view[1..w.written], 128, .{}));
    try testing.expectError(error.DataException, rar.rarVolumeCount(w.view[0..1], 128, .{}));

    // The single-volume facade refuses volume-set members: a main block with
    // the volume flags never passes the single-volume walk.
    try testing.expectError(error.UnsupportedException, rar.rarInspectCount(w.view[0], 128));
    try testing.expectError(error.UnsupportedException, rar.rarDecodeOrdinal(w.view[1], 0, out_a, @constCast(&bufs), .{}));

    // An empty part scratch cannot record a split entry's chain.
    const no_parts = d.buffers(&.{}, &packed_stage);
    try testing.expectError(error.InternalException, rar.rarVolumeDecodeOrdinal(w.view, 0, out_a, @constCast(&no_parts), .{}));
    try testing.expectError(error.InternalException, rar.rarVolumeDecodeOrdinal(w.view, 1, out_b, @constCast(&no_parts), .{}));

    // A budget below the fixed prefix refuses, and the single-volume calls
    // reject a volume budget.
    try testing.expectError(error.CallException, rarVolumeSize(&entries, &w.ws, .{ .volume_size = 8 }));
    try testing.expectError(error.CallException, rarWriteSizeEx(&entries, &w.ws, .{ .volume_size = 170 }));
    var tiny: [64]u8 = undefined;
    try testing.expectError(error.CallException, rarEncodeEx(&entries, &tiny, &w.ws, crypto.default_provider, .{ .volume_size = 170 }));

    // The volume reader also accepts a one-volume set: the writer marks even a
    // single volume with MHFL_VOLUME.
    var sw = try VolumeTestWrite.init(allocator, &entries, .{ .volume_size = 1 << 16 });
    defer sw.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), sw.plan.count);
    try testing.expectEqual(@as(usize, 2), try rar.rarVolumeCount(sw.view, 128, .{}));
    try testing.expectEqual(a_data.len, try rar.rarVolumeDecodeOrdinal(sw.view, 0, out_a, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &a_data, out_a);
    try testing.expectEqual(b_data.len, try rar.rarVolumeDecodeOrdinal(sw.view, 1, out_b, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &b_data, out_b);
}

test "locator offsets use fixed four-byte vints" {
    var buf: [4]u8 = undefined;
    writeVintFixed4(0, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x80, 0x80, 0x00 }, &buf);
    writeVintFixed4(4149, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb5, 0xa0, 0x80, 0x00 }, &buf);
    writeVintFixed4(4158, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xbe, 0xa0, 0x80, 0x00 }, &buf);
    writeVintFixed4((1 << 28) - 1, &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xff, 0xff, 0xff, 0x7f }, &buf);
}

test "recovery record round-trips and pins the r1 wire form" {
    const testing = std.testing;
    const allocator = testing.allocator;
    var source: [4096]u8 = undefined;
    var seed: u32 = 0x9E3779B9;
    for (&source) |*byte| {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        byte.* = @truncate(seed);
    }
    const entries = [_]RarEntry{.{ .name = "rnd.bin", .data = &source, .method = 0 }};
    const sizes = pack50.workspacesFor(4096);
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
    const packed_buf = try allocator.alloc(u8, 4096);
    defer allocator.free(packed_buf);
    const packed_sizes = try allocator.alloc(usize, 1);
    defer allocator.free(packed_sizes);
    const rs_exp = try allocator.alloc(u16, recovery.gf_exp_len);
    defer allocator.free(rs_exp);
    const rs_log = try allocator.alloc(u32, recovery.gf_log_len);
    defer allocator.free(rs_log);
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
        .rs_exp = rs_exp,
        .rs_log = rs_log,
    };

    // Reference-imposed limits: a percent above 1000, or a recovery record
    // alongside header encryption, refuse the call before any packing.
    try testing.expectError(error.CallException, rarWriteSizeEx(&entries, &ws, .{ .recovery_percent = 1001 }));
    try testing.expectError(error.CallException, rarWriteSizeEx(&entries, &ws, .{ .password = "pw", .encrypt_headers = true, .recovery_percent = 10 }));
    // An empty GF table surface refuses the recovery sizing.
    ws.rs_exp = &.{};
    try testing.expectError(error.InternalException, rarWriteSizeEx(&entries, &ws, .{ .recovery_percent = 10 }));
    ws.rs_exp = rs_exp;

    const required = try rarWriteSizeEx(&entries, &ws, .{ .recovery_percent = 10 });
    try testing.expectEqual(@as(usize, 5131), required);
    const archive = try allocator.alloc(u8, required);
    defer allocator.free(archive);
    const written = try rarEncodeEx(&entries, archive, &ws, crypto.default_provider, .{ .recovery_percent = 10 });
    try testing.expectEqual(@as(usize, 5131), written);

    // Main block: 15 content bytes, the locator naming the RR header at
    // relative offset 4149 through a fixed four-byte vint.
    try testing.expectEqual(@as(u8, 0x0f), archive[12]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x05, 0x0b, 0x08, 0x0a, 0x01, 0x03, 0x80, 0x80, 0x80, 0x00, 0xb5, 0xa0, 0x80, 0x00 }, archive[13..28]);
    // The stored payload sits between the file header and the RR header.
    try testing.expectEqualSlices(u8, &source, archive[61..4157]);
    // RR header contents: the FHEXTRA_SUBDATA record holds percent 10, and
    // data_size matches the 944-byte single unit.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x07, 0x03, 0xb0, 0x07, 0x00, 0xb0, 0x07, 0x00, 0x00, 0x01, 0x02, 0x52, 0x52, 0x02, 0x07, 0x0a }, archive[4162..4179]);

    // The random slot and the parity oracle stay unpinned; the trailing
    // checksum covers everything but itself.
    const unit0 = archive[4179..5123];
    try testing.expectEqual(@as(u32, 0x7d42527b), std.mem.readInt(u32, unit0[0..4], .little));
    try testing.expectEqual(@as(u32, 944), std.mem.readInt(u32, unit0[12..16], .little));
    try testing.expectEqual(@as(u32, 112), std.mem.readInt(u32, unit0[16..20], .little));
    try testing.expectEqual(@as(u8, 1), unit0[20]);
    try testing.expectEqual(@as(u8, 1), unit0[21]);
    try testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, unit0[22..30], .little));
    try testing.expectEqual(@as(u32, 829), std.mem.readInt(u32, unit0[30..34], .little));
    try testing.expectEqual(@as(u64, 4157), std.mem.readInt(u64, unit0[34..42], .little));
    try testing.expectEqual(@as(u64, 832), std.mem.readInt(u64, unit0[42..50], .little));
    try testing.expectEqual(@as(u64, 944), std.mem.readInt(u64, unit0[50..58], .little));
    try testing.expectEqual(@as(u16, 5), std.mem.readInt(u16, unit0[58..60], .little));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, unit0[60..62], .little));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, unit0[62..64], .little));
    for (0..5) |k| {
        const clen: usize = if (k < 4) 832 else 829;
        try testing.expectEqual(recovery.crc64Raw(archive[k * 832 .. k * 832 + clen]), std.mem.readInt(u64, unit0[64 + k * 8 ..][0..8], .little));
    }
    var c1c2 = checksum.XzCrc64.init();
    c1c2.update(unit0[12..944]);
    try testing.expectEqual(c1c2.final(), std.mem.readInt(u64, unit0[4..12], .little));

    // The end block closes the archive.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x05, 0x00, 0x00 }, archive[5127..5131]);

    // The facade reader skips the service block and decodes the one file.
    try testing.expectEqual(@as(usize, 1), try rar.rarInspectCount(archive, 128));
    var d = try VolumeTestDecode.init(allocator);
    defer d.deinit(allocator);
    const bufs = d.buffers(&.{}, &.{});
    const out = try allocator.alloc(u8, source.len);
    defer allocator.free(out);
    try testing.expectEqual(source.len, try rar.rarDecodeOrdinal(archive, 0, out, @constCast(&bufs), .{}));
    try testing.expectEqualSlices(u8, &source, out);
}
