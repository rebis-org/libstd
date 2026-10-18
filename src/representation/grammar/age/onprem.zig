const builtin = @import("builtin");
const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");

pub const Exception = exception_prim.Exception;

// age v1 file encryption per C2SP age.md; vectors from the CCTV age testkit
// and the reference Go implementation in vendor/age. The v1.1 hardware
// recipient types are out of scope.

pub const scratch_size: usize = 64 * 1024;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    size: u64,
    ordinal: u64,
};

pub const Options = struct {
    password: []const u8 = &.{}, // scrypt recipient
    identity: []const u8 = &.{}, // AGE-SECRET-KEY-... (decrypt)
    recipient: []const u8 = &.{}, // age1... (encrypt)
    work_factor: u8 = 18, // scrypt logN when password is set
    armor: bool = false,
};

pub const scrypt_work_factor_max: u8 = 22;

const version_line = "age-encryption.org/v1";
const x25519_info = "age-encryption.org/v1/X25519";
const scrypt_label = "age-encryption.org/v1/scrypt";
const header_info = "header";
const payload_info = "payload";
const armor_label = "AGE ENCRYPTED FILE";
const armor_begin = "-----BEGIN AGE ENCRYPTED FILE-----";
const armor_end = "-----END AGE ENCRYPTED FILE-----";
const chunk_size: usize = 64 * 1024;
const file_key_len: usize = 16;
const mac_encoded_len: usize = 43;

// OS entropy without a libc dependency on Linux: the getrandom syscall
// directly, libc's arc4random_buf on Apple platforms.
fn randomBytes(comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    switch (builtin.target.os.tag) {
        .linux => {
            var filled: usize = 0;
            while (filled < n) {
                const rc = std.os.linux.getrandom(out[filled..].ptr, n - filled, 0);
                if (std.os.linux.E.init(rc) != .SUCCESS) @panic("getrandom failed");
                filled += rc;
            }
        },
        .macos, .ios, .tvos, .watchos, .visionos => std.c.arc4random_buf(&out, n),
        else => @compileError("age: no OS entropy source for this target"),
    }
    return out;
}

const b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64EncodedLen(n: usize) usize {
    return (n / 3) * 4 + switch (n % 3) {
        0 => @as(usize, 0),
        1 => 2,
        else => 3,
    };
}

fn b64Encode(dst: []u8, src: []const u8) void {
    var i: usize = 0;
    var o: usize = 0;
    while (i + 3 <= src.len) : (i += 3) {
        const v = (@as(u32, src[i]) << 16) | (@as(u32, src[i + 1]) << 8) | src[i + 2];
        dst[o] = b64_alphabet[(v >> 18) & 63];
        dst[o + 1] = b64_alphabet[(v >> 12) & 63];
        dst[o + 2] = b64_alphabet[(v >> 6) & 63];
        dst[o + 3] = b64_alphabet[v & 63];
        o += 4;
    }
    const rest = src.len - i;
    if (rest == 1) {
        const v = @as(u32, src[i]) << 16;
        dst[o] = b64_alphabet[(v >> 18) & 63];
        dst[o + 1] = b64_alphabet[(v >> 12) & 63];
    } else if (rest == 2) {
        const v = (@as(u32, src[i]) << 16) | (@as(u32, src[i + 1]) << 8);
        dst[o] = b64_alphabet[(v >> 18) & 63];
        dst[o + 1] = b64_alphabet[(v >> 12) & 63];
        dst[o + 2] = b64_alphabet[(v >> 6) & 63];
    }
}

fn b64Value(c: u8) ?u32 {
    return switch (c) {
        'A'...'Z' => c - 'A',
        'a'...'z' => c - 'a' + 26,
        '0'...'9' => c - '0' + 52,
        '+' => 62,
        '/' => 63,
        else => null,
    };
}

fn b64DecodedLen(n: usize) usize {
    return n / 4 * 3 + switch (n % 4) {
        0 => @as(usize, 0),
        2 => 1,
        3 => 2,
        else => unreachable,
    };
}

fn b64Quad(chars: []const u8) Exception!u32 {
    var v: u32 = 0;
    for (chars) |c| {
        const value = b64Value(c) orelse return error.DataException;
        v = (v << 6) | value;
    }
    return v & 0xffffff;
}

// Strict canonical decode: reject non-alphabet characters, non-canonical
// trailing bits, and any '=' padding.
fn b64Decode(dst: []u8, src: []const u8) Exception!void {
    if (src.len % 4 == 1) return error.DataException;
    if (dst.len != b64DecodedLen(src.len)) return error.CallException;
    var i: usize = 0;
    var o: usize = 0;
    while (i + 4 <= src.len) : (i += 4) {
        const v = try b64Quad(src[i..][0..4]);
        dst[o] = @truncate(v >> 16);
        dst[o + 1] = @truncate(v >> 8);
        dst[o + 2] = @truncate(v);
        o += 3;
    }
    const rest = src.len - i;
    if (rest == 2) {
        var tail = [4]u8{ src[i], src[i + 1], 'A', 'A' };
        _ = &tail;
        const v = try b64Quad(&tail);
        if (v & 0xffff != 0) return error.DataException;
        dst[o] = @truncate(v >> 16);
    } else if (rest == 3) {
        var tail = [4]u8{ src[i], src[i + 1], src[i + 2], 'A' };
        _ = &tail;
        const v = try b64Quad(&tail);
        if (v & 0xff != 0) return error.DataException;
        dst[o] = @truncate(v >> 16);
        dst[o + 1] = @truncate(v >> 8);
    }
}

// Bech32 per BIP 173 without length limits; the lowercase-checksum rule is
// why uppercase strings decode by lowercasing first.

const bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32Polymod(values: []const u5) u32 {
    const generators = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    for (values) |value| {
        const b = (chk >> 25) & 0x1f;
        chk = ((chk & 0x1ffffff) << 5) ^ value;
        for (generators, 0..) |g, j| {
            if ((b >> @intCast(j)) & 1 != 0) chk ^= g;
        }
    }
    return chk;
}

fn bech32HrpExpand(hrp: []const u8, out: []u5) []u5 {
    var i: usize = 0;
    for (hrp) |c| {
        out[i] = @intCast(c >> 5);
        i += 1;
    }
    out[i] = 0;
    i += 1;
    for (hrp) |c| {
        out[i] = @intCast(c & 0x1f);
        i += 1;
    }
    return out[0..i];
}

fn bytesTo5Bits(data: []const u8, out: []u5) Exception![]u5 {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var i: usize = 0;
    for (data) |byte| {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (i >= out.len) return error.DataException;
            out[i] = @intCast((acc >> bits) & 0x1f);
            i += 1;
        }
    }
    if (bits != 0) {
        if (i >= out.len) return error.DataException;
        out[i] = @intCast((acc << (5 - bits)) & 0x1f);
        i += 1;
    }
    return out[0..i];
}

fn fiveBitsToBytes(data: []const u5, out: []u8) Exception![]u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var i: usize = 0;
    for (data) |value| {
        acc = (acc << 5) | value;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            if (i >= out.len) return error.DataException;
            out[i] = @truncate(acc >> bits);
            i += 1;
        }
    }
    if (bits >= 5 or (acc & ((@as(u32, 1) << bits) - 1)) != 0) return error.DataException;
    return out[0..i];
}

fn bech32CreateChecksum(hrp_upper: []const u8, data: []const u5, out: []u5) void {
    // The checksum is always computed over the lowercase HRP (BIP 173), even
    // though the emitted string may be uppercase.
    var hrp_buf: [128]u8 = undefined;
    const hrp = std.ascii.lowerString(hrp_buf[0..hrp_upper.len], hrp_upper);
    var expanded: [2 * 128 + 1]u5 = undefined;
    const hrp_expanded = bech32HrpExpand(hrp, &expanded);
    var chk_input: [3 * 128]u5 = undefined;
    @memcpy(chk_input[0..hrp_expanded.len], hrp_expanded);
    @memcpy(chk_input[hrp_expanded.len..][0..data.len], data);
    for (0..6) |i| chk_input[hrp_expanded.len + data.len + i] = 0;
    const polymod = bech32Polymod(chk_input[0 .. hrp_expanded.len + data.len + 6]) ^ 1;
    for (0..6) |i| {
        out[i] = @intCast((polymod >> @intCast(5 * (5 - i))) & 0x1f);
    }
}

fn bech32Encode(hrp: []const u8, data: []const u8, out: []u8) Exception![]const u8 {
    var data5: [2 * 256]u5 = undefined;
    const data5_slice = try bytesTo5Bits(data, &data5);
    if (out.len < hrp.len + 1 + data5_slice.len + 6) return error.CapacityException;
    @memcpy(out[0..hrp.len], hrp);
    out[hrp.len] = '1';
    for (data5_slice, 0..) |value, i| {
        out[hrp.len + 1 + i] = bech32_charset[value];
    }
    var checksum: [6]u5 = undefined;
    bech32CreateChecksum(hrp, data5_slice, &checksum);
    for (checksum, 0..) |value, i| {
        out[hrp.len + 1 + data5_slice.len + i] = bech32_charset[value];
    }
    const encoded = out[0 .. hrp.len + 1 + data5_slice.len + 6];
    // BIP 173 strings are either all lowercase or all uppercase; an uppercase
    // HRP (age identity convention) forces the data part uppercase too.
    if (hrp.len != 0 and hrp[0] >= 'A' and hrp[0] <= 'Z') {
        return std.ascii.upperString(encoded[0..encoded.len], encoded);
    }
    return encoded;
}

fn bech32Decode(encoded: []const u8, hrp_out: []u8, data_out: []u8) Exception!struct { hrp: []const u8, data: []const u8 } {
    if (encoded.len < 8 or encoded.len > 1024) return error.DataException;
    var lower = false;
    var upper = false;
    for (encoded) |c| {
        if (c < 33 or c > 126) return error.DataException;
        if (c >= 'a' and c <= 'z') lower = true;
        if (c >= 'A' and c <= 'Z') upper = true;
    }
    if (lower and upper) return error.DataException;
    var buf: [1024]u8 = undefined;
    const text = std.ascii.lowerString(&buf, encoded);
    const sep = std.mem.lastIndexOfScalar(u8, text, '1') orelse return error.DataException;
    if (sep == 0 or sep + 7 > text.len) return error.DataException;
    const hrp = text[0..sep];
    if (hrp.len > hrp_out.len) return error.DataException;
    @memcpy(hrp_out[0..hrp.len], hrp);
    const value_len = text.len - sep - 1;
    var values: [1024]u5 = undefined;
    for (text[sep + 1 ..], 0..) |c, i| {
        const idx = std.mem.indexOfScalar(u8, bech32_charset, c) orelse return error.DataException;
        values[i] = @intCast(idx);
    }
    var expanded: [2 * 1024 + 1]u5 = undefined;
    const hrp_expanded = bech32HrpExpand(hrp, &expanded);
    var chk_input: [3 * 1024]u5 = undefined;
    @memcpy(chk_input[0..hrp_expanded.len], hrp_expanded);
    @memcpy(chk_input[hrp_expanded.len..][0..value_len], values[0..value_len]);
    if (bech32Polymod(chk_input[0 .. hrp_expanded.len + value_len]) != 1) return error.DataException;
    const data = try fiveBitsToBytes(values[0 .. value_len - 6], data_out);
    return .{ .hrp = hrp_out[0..hrp.len], .data = data };
}

const Stanza = struct {
    args: []const []const u8,
    body: []const u8,
};

const Header = struct {
    stanzas: []const Stanza,
    // The MAC covers input[0 .. mac_line_start + 3], through the "---" mark.
    mac_line_start: usize,
    payload_offset: usize,
};

fn parseHeader(input: []const u8, alloc: std.mem.Allocator) Exception!Header {
    const first_eol = std.mem.indexOfScalar(u8, input, '\n') orelse return error.DataException;
    const version = input[0..first_eol];
    if (!std.mem.eql(u8, version, version_line)) {
        if (std.mem.startsWith(u8, version, "age-encryption.org/")) return error.UnsupportedException;
        return error.DataException;
    }
    var pos: usize = first_eol + 1;
    var stanzas: std.ArrayListUnmanaged(Stanza) = .empty;
    while (true) {
        const eol = std.mem.indexOfScalarPos(u8, input, pos, '\n') orelse return error.DataException;
        const line = input[pos..eol];
        if (std.mem.startsWith(u8, line, "---")) {
            if (line.len != 4 + mac_encoded_len or line[3] != ' ') return error.DataException;
            var mac: [32]u8 = undefined;
            try b64Decode(&mac, line[4..]);
            const payload_offset = eol + 1;
            return .{ .stanzas = stanzas.items, .mac_line_start = pos, .payload_offset = payload_offset };
        }
        if (!std.mem.startsWith(u8, line, "-> ") or line.len == 3) return error.DataException;
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, line[3..], ' ');
        while (it.next()) |arg| {
            args.append(alloc, arg) catch return error.ResourceException;
        }
        if (args.items.len == 0) return error.DataException;
        var body: std.ArrayListUnmanaged(u8) = .empty;
        var body_pos = eol + 1;
        while (true) {
            const line_end = std.mem.indexOfScalarPos(u8, input, body_pos, '\n') orelse return error.DataException;
            const body_line = input[body_pos..line_end];
            if (body_line.len == 64) {
                body.appendSlice(alloc, body_line) catch return error.ResourceException;
                body_pos = line_end + 1;
                continue;
            }
            if (body_line.len > 64) return error.DataException;
            body.appendSlice(alloc, body_line) catch return error.ResourceException;
            body_pos = line_end + 1;
            break;
        }
        const body_text = body.items;
        const body_bin = alloc.alloc(u8, b64DecodedLen(body_text.len)) catch return error.ResourceException;
        try b64Decode(body_bin, body_text);
        stanzas.append(alloc, .{ .args = args.items, .body = body_bin }) catch return error.ResourceException;
        pos = body_pos;
    }
}

const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const X25519 = std.crypto.dh.X25519;
const scrypt = std.crypto.pwhash.scrypt;

const zero_nonce: [12]u8 = std.mem.zeroes([12]u8);

fn hkdfSha256(ikm: []const u8, salt: []const u8, info: []const u8) [32]u8 {
    const prk = HkdfSha256.extract(salt, ikm);
    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, info, prk);
    return out;
}

fn headerMacKey(file_key: [file_key_len]u8) [32]u8 {
    return hkdfSha256(&file_key, "", header_info);
}

fn payloadKey(file_key: [file_key_len]u8, nonce: [16]u8) [32]u8 {
    return hkdfSha256(&file_key, &nonce, payload_info);
}

fn wrapX25519(file_key: [file_key_len]u8, recipient: [32]u8, ephemeral: [32]u8, body_out: *[48]u8) [32]u8 {
    const share = X25519.recoverPublicKey(ephemeral);
    var salt: [64]u8 = undefined;
    @memcpy(salt[0..32], &share);
    @memcpy(salt[32..64], &recipient);
    const shared = X25519.scalarmult(ephemeral, recipient) catch unreachable;
    const wrap_key = hkdfSha256(&shared, &salt, x25519_info);
    ChaCha20Poly1305.encrypt(body_out, &file_key, "", zero_nonce, wrap_key);
    return share;
}

fn unwrapX25519(stanza: Stanza, identity: [32]u8) Exception![file_key_len]u8 {
    if (stanza.args.len != 2 or !std.mem.eql(u8, stanza.args[0], "X25519")) return error.UnsupportedException;
    if (stanza.body.len != file_key_len + 16) return error.DataException;
    var share: [32]u8 = undefined;
    try b64Decode(&share, stanza.args[1]);
    const shared = X25519.scalarmult(identity, share) catch return error.IntegrityException;
    var salt: [64]u8 = undefined;
    @memcpy(salt[0..32], &share);
    const recipient = X25519.recoverPublicKey(identity);
    @memcpy(salt[32..64], &recipient);
    const wrap_key = hkdfSha256(&shared, &salt, x25519_info);
    var file_key: [file_key_len]u8 = undefined;
    if (stanza.body.len != file_key_len + 16) return error.DataException;
    ChaCha20Poly1305.decrypt(&file_key, stanza.body[0..file_key_len], stanza.body[file_key_len..][0..16].*, "", zero_nonce, wrap_key) catch return error.IntegrityException;
    return file_key;
}

fn scryptWrapKey(password: []const u8, salt: [16]u8, work_factor: u8, scratch: []u8) Exception![32]u8 {
    var full_salt: [28 + 16]u8 = undefined;
    @memcpy(full_salt[0..28], scrypt_label);
    @memcpy(full_salt[28..44], &salt);
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    var key: [32]u8 = undefined;
    scrypt.kdf(fba.allocator(), &key, password, &full_salt, .{ .ln = @intCast(work_factor), .r = 8, .p = 1 }) catch |err| switch (err) {
        error.OutOfMemory => return error.ResourceException,
        error.WeakParameters, error.OutputTooLong => return error.DataException,
        else => return error.InternalException,
    };
    return key;
}

fn payloadCiphertextLen(plain_len: u64) u64 {
    const chunks = if (plain_len == 0) 1 else (plain_len + chunk_size - 1) / chunk_size;
    return 16 + plain_len + chunks * 16;
}

fn encryptPayload(file_key: [file_key_len]u8, source: []const u8, dest: []u8) Exception!void {
    if (dest.len < payloadCiphertextLen(source.len)) return error.CapacityException;
    const nonce: [16]u8 = randomBytes(16);
    @memcpy(dest[0..16], &nonce);
    const key = payloadKey(file_key, nonce);
    var offset: usize = 16;
    var counter: u64 = 0;
    var pos: usize = 0;
    while (true) {
        const take = @min(chunk_size, source.len - pos);
        const final = pos + take == source.len;
        var chunk_nonce: [12]u8 = @splat(0);
        std.mem.writeInt(u64, chunk_nonce[3..11], counter, .big);
        chunk_nonce[11] = if (final) 1 else 0;
        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(dest[offset..][0..take], &tag, source[pos..][0..take], "", chunk_nonce, key);
        @memcpy(dest[offset + take ..][0..16], &tag);
        offset += take + 16;
        pos += take;
        counter += 1;
        if (final) break;
    }
}

// Framing is derivable from the total length because only the final chunk
// may be short (or empty, when the plaintext is empty).
fn chunkCount(ciphertext_payload: usize) Exception!usize {
    if (ciphertext_payload < 16) return error.DataException;
    if (ciphertext_payload == 16) return 1; // empty plaintext, single empty final chunk
    const n = (ciphertext_payload - 16 + chunk_size - 1) / chunk_size;
    const plain = ciphertext_payload - n * 16;
    if (n != (plain + chunk_size - 1) / chunk_size) return error.DataException;
    return n;
}

fn decryptPayload(file_key: [file_key_len]u8, source: []const u8, dest: []u8) Exception!usize {
    if (source.len < 16) return error.DataException;
    var nonce: [16]u8 = undefined;
    @memcpy(&nonce, source[0..16]);
    const key = payloadKey(file_key, nonce);
    const n = try chunkCount(source.len - 16);
    var offset: usize = 16;
    var out: usize = 0;
    for (0..n) |i| {
        const remaining = source.len - offset;
        const take = @min(chunk_size, remaining - 16);
        const final = i == n - 1;
        var chunk_nonce: [12]u8 = @splat(0);
        std.mem.writeInt(u64, chunk_nonce[3..11], @as(u64, @intCast(i)), .big);
        chunk_nonce[11] = if (final) 1 else 0;
        if (dest.len < out + take) return error.CapacityException;
        ChaCha20Poly1305.decrypt(dest[out..][0..take], source[offset..][0..take], source[offset + take ..][0..16].*, "", chunk_nonce, key) catch return error.IntegrityException;
        offset += take + 16;
        out += take;
        if (final and offset != source.len) return error.DataException;
    }
    return out;
}

pub const Identity = struct {
    secret: [32]u8,

    pub fn fromString(text: []const u8) Exception!Identity {
        var hrp_buf: [64]u8 = undefined;
        var data: [64]u8 = undefined;
        const decoded = bech32Decode(text, &hrp_buf, &data) catch return error.DataException;
        if (!std.mem.eql(u8, decoded.hrp, "age-secret-key-") or decoded.data.len != 32) return error.DataException;
        var secret: [32]u8 = undefined;
        @memcpy(&secret, decoded.data[0..32]);
        return .{ .secret = secret };
    }

    pub fn toString(self: Identity, out: []u8) Exception![]const u8 {
        return bech32Encode("AGE-SECRET-KEY-", &self.secret, out);
    }

    pub fn recipientString(self: Identity, out: []u8) Exception![]const u8 {
        const public = X25519.recoverPublicKey(self.secret);
        return bech32Encode("age", &public, out);
    }
};

pub const Recipient = struct {
    public: [32]u8,

    pub fn fromString(text: []const u8) Exception!Recipient {
        var hrp_buf: [16]u8 = undefined;
        var data: [64]u8 = undefined;
        const decoded = bech32Decode(text, &hrp_buf, &data) catch return error.DataException;
        if (!std.mem.eql(u8, decoded.hrp, "age") or decoded.data.len != 32) return error.DataException;
        var public: [32]u8 = undefined;
        @memcpy(&public, decoded.data[0..32]);
        return .{ .public = public };
    }
};

fn wrapStanzas(file_key: [file_key_len]u8, options: Options, alloc: std.mem.Allocator, scratch: []u8) Exception![]Stanza {
    var list: std.ArrayListUnmanaged(Stanza) = .empty;
    if (options.password.len != 0 and options.recipient.len != 0) return error.CallException;
    if (options.password.len == 0 and options.recipient.len == 0) return error.CallException;
    if (options.password.len != 0) {
        if (options.work_factor < 1 or options.work_factor > scrypt_work_factor_max) return error.UnsupportedException;
        const salt: [16]u8 = randomBytes(16);
        var salt_b64: [b64EncodedLen(16)]u8 = undefined;
        b64Encode(&salt_b64, &salt);
        var work_buf: [8]u8 = undefined;
        const work = std.fmt.bufPrint(&work_buf, "{d}", .{options.work_factor}) catch return error.InternalException;
        const wrap_key = try scryptWrapKey(options.password, salt, options.work_factor, scratch);
        var body: [file_key_len + 16]u8 = undefined;
        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(body[0..file_key_len], &tag, &file_key, "", zero_nonce, wrap_key);
        @memcpy(body[file_key_len..][0..16], &tag);
        const args = alloc.alloc([]const u8, 3) catch return error.ResourceException;
        args[0] = "scrypt";
        args[1] = alloc.dupe(u8, &salt_b64) catch return error.ResourceException;
        args[2] = alloc.dupe(u8, work) catch return error.ResourceException;
        const body_copy = alloc.dupe(u8, &body) catch return error.ResourceException;
        list.append(alloc, .{ .args = args, .body = body_copy }) catch return error.ResourceException;
        return list.items;
    }
    const recipient = Recipient.fromString(options.recipient) catch return error.CallException;
    const ephemeral: [32]u8 = randomBytes(32);
    var body: [file_key_len + 16]u8 = undefined;
    var tag: [16]u8 = undefined;
    const shared = X25519.scalarmult(ephemeral, recipient.public) catch return error.InternalException;
    var salt: [64]u8 = undefined;
    const ephemeral_share = X25519.recoverPublicKey(ephemeral);
    @memcpy(salt[0..32], &ephemeral_share);
    @memcpy(salt[32..64], &recipient.public);
    const wrap_key = hkdfSha256(&shared, &salt, x25519_info);
    ChaCha20Poly1305.encrypt(body[0..file_key_len], &tag, &file_key, "", zero_nonce, wrap_key);
    @memcpy(body[file_key_len..][0..16], &tag);
    var share_b64: [b64EncodedLen(32)]u8 = undefined;
    b64Encode(&share_b64, &ephemeral_share);
    const args = alloc.alloc([]const u8, 2) catch return error.ResourceException;
    args[0] = "X25519";
    args[1] = alloc.dupe(u8, &share_b64) catch return error.ResourceException;
    const body_copy = alloc.dupe(u8, &body) catch return error.ResourceException;
    list.append(alloc, .{ .args = args, .body = body_copy }) catch return error.ResourceException;
    return list.items;
}

fn decimalWorkFactor(text: []const u8) Exception!u8 {
    if (text.len == 0 or text.len > 2) return error.DataException;
    if (text[0] < '1' or text[0] > '9') return error.DataException;
    var value: u8 = text[0] - '0';
    for (text[1..]) |c| {
        if (c < '0' or c > '9') return error.DataException;
        value = value * 10 + (c - '0');
    }
    return value;
}

fn unwrapFileKey(stanzas: []const Stanza, options: Options, scratch: []u8) Exception![file_key_len]u8 {
    if (options.password.len != 0) {
        if (stanzas.len != 1 or !std.mem.eql(u8, stanzas[0].args[0], "scrypt")) {
            // A scrypt stanza must be the only stanza; any header without
            // exactly one is not passphrase-encrypted.
            return error.IntegrityException;
        }
        const stanza = stanzas[0];
        if (stanza.args.len != 3) return error.DataException;
        var salt: [16]u8 = undefined;
        try b64Decode(&salt, stanza.args[1]);
        const work_factor = try decimalWorkFactor(stanza.args[2]);
        if (work_factor > scrypt_work_factor_max) return error.UnsupportedException;
        if (stanza.body.len != file_key_len + 16) return error.DataException;
        const wrap_key = try scryptWrapKey(options.password, salt, work_factor, scratch);
        var file_key: [file_key_len]u8 = undefined;
        ChaCha20Poly1305.decrypt(&file_key, stanza.body[0..file_key_len], stanza.body[file_key_len..][0..16].*, "", zero_nonce, wrap_key) catch return error.IntegrityException;
        return file_key;
    }
    if (options.identity.len != 0) {
        const identity = Identity.fromString(options.identity) catch return error.CallException;
        for (stanzas) |stanza| {
            if (stanza.args.len == 0 or !std.mem.eql(u8, stanza.args[0], "X25519")) continue;
            return unwrapX25519(stanza, identity.secret) catch |err| switch (err) {
                error.UnsupportedException => continue,
                error.DataException => return error.DataException,
                error.IntegrityException => continue,
                else => return err,
            };
        }
        return error.IntegrityException;
    }
    return error.CallException;
}

fn writeHeader(file_key: [file_key_len]u8, stanzas: []const Stanza, dest: []u8) Exception!usize {
    var pos: usize = 0;
    @memcpy(dest[pos..][0..version_line.len], version_line);
    pos += version_line.len;
    dest[pos] = '\n';
    pos += 1;
    for (stanzas) |stanza| {
        if (dest.len - pos < 4) return error.CapacityException;
        @memcpy(dest[pos..][0..3], "-> ");
        pos += 3;
        for (stanza.args, 0..) |arg, i| {
            if (i != 0) {
                dest[pos] = ' ';
                pos += 1;
            }
            if (dest.len - pos < arg.len + 1) return error.CapacityException;
            @memcpy(dest[pos..][0..arg.len], arg);
            pos += arg.len;
        }
        dest[pos] = '\n';
        pos += 1;
        var encoded: [b64EncodedLen(48)]u8 = undefined;
        const body_b64 = encoded[0..b64EncodedLen(stanza.body.len)];
        b64Encode(body_b64, stanza.body);
        var at: usize = 0;
        while (at < body_b64.len) {
            const take = @min(64, body_b64.len - at);
            if (dest.len - pos < take + 1) return error.CapacityException;
            @memcpy(dest[pos..][0..take], body_b64[at..][0..take]);
            pos += take;
            dest[pos] = '\n';
            pos += 1;
            at += take;
        }
    }
    if (dest.len - pos < 4 + mac_encoded_len + 1) return error.CapacityException;
    @memcpy(dest[pos..][0..3], "---");
    pos += 3;
    const mac_key = headerMacKey(file_key);
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, dest[0..pos], &mac_key);
    var mac_b64: [mac_encoded_len]u8 = undefined;
    b64Encode(&mac_b64, &mac);
    dest[pos] = ' ';
    pos += 1;
    @memcpy(dest[pos..][0..mac_encoded_len], &mac_b64);
    pos += mac_encoded_len;
    dest[pos] = '\n';
    pos += 1;
    return pos;
}

fn verifyHeaderMac(input: []const u8, header: Header, file_key: [file_key_len]u8) Exception!void {
    const mac_key = headerMacKey(file_key);
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, input[0 .. header.mac_line_start + 3], &mac_key);
    const line = input[header.mac_line_start .. header.payload_offset - 1];
    if (line.len != 4 + mac_encoded_len or line[3] != ' ') return error.DataException;
    var expected: [32]u8 = undefined;
    try b64Decode(&expected, line[4..]);
    if (!std.mem.eql(u8, &mac, &expected)) return error.IntegrityException;
}

fn armoredLen(binary_len: usize) usize {
    const b64_len = std.base64.standard.Encoder.calcSize(binary_len);
    const lines = (b64_len + 63) / 64;
    return armor_begin.len + 1 + lines * 65 + armor_end.len + 1;
}

fn armorEncode(binary: []const u8, dest: []u8) Exception!usize {
    if (dest.len < armoredLen(binary.len)) return error.CapacityException;
    var pos: usize = 0;
    @memcpy(dest[pos..][0..armor_begin.len], armor_begin);
    pos += armor_begin.len;
    dest[pos] = '\n';
    pos += 1;
    var line: [64]u8 = undefined;
    var at: usize = 0;
    while (at < binary.len) {
        const take = @min(48, binary.len - at);
        const encoded = std.base64.standard.Encoder.encode(&line, binary[at..][0..take]);
        @memcpy(dest[pos..][0..encoded.len], encoded);
        pos += encoded.len;
        dest[pos] = '\n';
        pos += 1;
        at += take;
    }
    @memcpy(dest[pos..][0..armor_end.len], armor_end);
    pos += armor_end.len;
    dest[pos] = '\n';
    pos += 1;
    return pos;
}

// Whitespace (LF/CRLF/space/tab) may surround the PEM block; nothing else.
fn armorDecode(text: []const u8, alloc: std.mem.Allocator) Exception![]const u8 {
    var start: usize = 0;
    var end: usize = text.len;
    while (start < end and isArmorSpace(text[start])) start += 1;
    while (end > start and isArmorSpace(text[end - 1])) end -= 1;
    const body = text[start..end];
    if (!std.mem.startsWith(u8, body, armor_begin)) return error.DataException;
    if (body.len < armor_begin.len + 1 + armor_end.len) return error.DataException;
    if (body[armor_begin.len] != '\n') {
        if (!(body[armor_begin.len] == '\r' and body[armor_begin.len + 1] == '\n')) return error.DataException;
    }
    var inner = body[armor_begin.len..];
    if (inner[0] == '\r') inner = inner[1..];
    inner = inner[1..];
    const close = std.mem.lastIndexOf(u8, inner, armor_end) orelse return error.DataException;
    const payload = inner[0..close];
    if (payload.len == 0 or payload[payload.len - 1] != '\n') return error.DataException;
    const b64_text = payload[0 .. payload.len - 1];
    const cleaned = alloc.alloc(u8, b64_text.len) catch return error.ResourceException;
    var n: usize = 0;
    var line_start: usize = 0;
    while (line_start < b64_text.len) {
        const eol = std.mem.indexOfScalarPos(u8, b64_text, line_start, '\n') orelse b64_text.len;
        var line = b64_text[line_start..eol];
        if (line.len != 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (line.len > 64) return error.DataException;
        @memcpy(cleaned[n..][0..line.len], line);
        n += line.len;
        line_start = if (eol == b64_text.len) eol else eol + 1;
    }
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(cleaned[0..n]) catch return error.DataException;
    const decoded = alloc.alloc(u8, decoded_len) catch return error.ResourceException;
    std.base64.standard.Decoder.decode(decoded, cleaned[0..n]) catch return error.DataException;
    return decoded;
}

fn isArmorSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

fn dearmor(input: []const u8, alloc: std.mem.Allocator) Exception!struct { binary: []const u8, armored: bool } {
    const trimmed = std.mem.trim(u8, input, " \t\n\r");
    if (std.mem.startsWith(u8, trimmed, armor_begin)) {
        return .{ .binary = try armorDecode(input, alloc), .armored = true };
    }
    if (std.mem.indexOf(u8, trimmed, armor_begin) != null) return error.DataException;
    return .{ .binary = input, .armored = false };
}

pub fn stanzaSize(options: Options) usize {
    if (options.password.len != 0) {
        const digits: usize = if (options.work_factor < 10) 1 else 2;
        return 10 + 22 + 1 + digits + 1 + 44;
    }
    return 10 + 43 + 1 + 44;
}

pub fn headerSize(options: Options) usize {
    return version_line.len + 1 + stanzaSize(options) + 4 + mac_encoded_len + 1;
}

pub fn archiveSize(entries: []const Entry, options: Options, scratch: []u8) Exception!u64 {
    _ = scratch;
    if (entries.len != 1) return error.CallException;
    const binary_len = headerSize(options) + payloadCiphertextLen(entries[0].data.len);
    if (!options.armor) return binary_len;
    return armoredLen(@intCast(binary_len));
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8, options: Options) Exception!usize {
    if (entries.len != 1) return error.CallException;
    // The plan allocator and the scrypt scratch must not overlap: scrypt's
    // peak memory (128 * r * N) is carved from the back half.
    const split = scratch.len / 2;
    var fba = std.heap.FixedBufferAllocator.init(scratch[0..split]);
    const file_key: [file_key_len]u8 = randomBytes(file_key_len);
    const stanzas = try wrapStanzas(file_key, options, fba.allocator(), scratch[split..]);
    const header_len = headerSize(options);
    const payload_len = payloadCiphertextLen(entries[0].data.len);
    if (!options.armor) {
        const total = header_len + payload_len;
        if (output.len < total) return error.CapacityException;
        const written = try writeHeader(file_key, stanzas, output[0..header_len]);
        try encryptPayload(file_key, entries[0].data, output[written..]);
        return total;
    }
    const binary_len = header_len + payload_len;
    const staging = fba.allocator().alloc(u8, binary_len) catch return error.ResourceException;
    const written = try writeHeader(file_key, stanzas, staging[0..header_len]);
    try encryptPayload(file_key, entries[0].data, staging[written..]);
    return armorEncode(staging, output);
}

// Parse-time allocations live in an arena over the front half of the
// caller scratch; the scrypt KDF carves its peak memory from the back half.
fn peelAndParse(input: []const u8, scratch: []u8) Exception!struct { binary: []const u8, header: Header, scrypt_scratch: []u8 } {
    const split = scratch.len / 2;
    var fba = std.heap.FixedBufferAllocator.init(scratch[0..split]);
    var arena = std.heap.ArenaAllocator.init(fba.allocator());
    const peeled = try dearmor(input, arena.allocator());
    const header = try parseHeader(peeled.binary, arena.allocator());
    return .{ .binary = peeled.binary, .header = header, .scrypt_scratch = scratch[split..] };
}

pub fn inspectCount(input: []const u8, scratch: []u8) Exception!u64 {
    const parsed = try peelAndParse(input, scratch);
    if (parsed.header.stanzas.len == 0) return error.DataException;
    return 1;
}

pub fn decodedSize(input: []const u8, options: Options, scratch: []u8) Exception!u64 {
    const parsed = try peelAndParse(input, scratch);
    const file_key = try unwrapFileKey(parsed.header.stanzas, options, parsed.scrypt_scratch);
    try verifyHeaderMac(parsed.binary, parsed.header, file_key);
    const payload = parsed.binary[parsed.header.payload_offset..];
    const n = try chunkCount(payload.len - 16);
    const total = payload.len - 16;
    return total - n * 16;
}

pub fn inspectOrdinal(input: []const u8, ordinal: u64, options: Options, scratch: []u8) Exception!EntryInfo {
    if (ordinal != 0) return error.DataException;
    const size = try decodedSize(input, options, scratch);
    return .{ .size = size, .ordinal = 0 };
}

pub fn decodeOrdinal(input: []const u8, ordinal: u64, output: []u8, scratch: []u8, options: Options) Exception!usize {
    if (ordinal != 0) return error.DataException;
    const parsed = try peelAndParse(input, scratch);
    const file_key = try unwrapFileKey(parsed.header.stanzas, options, parsed.scrypt_scratch);
    try verifyHeaderMac(parsed.binary, parsed.header, file_key);
    return decryptPayload(file_key, parsed.binary[parsed.header.payload_offset..], output);
}

const testing = std.testing;

// CCTV age testdata/x25519: expect success, payload 013f54400c82da08037759ada907a8b8...
const vec_x25519 = [_]u8{
    0x61, 0x67, 0x65, 0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x2f, 0x76, 0x31, 0x0a, 0x2d, 0x3e, 0x20, 0x58, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20,
    0x54, 0x45, 0x69, 0x46, 0x30, 0x79, 0x70, 0x71, 0x72, 0x2b, 0x62, 0x70, 0x76, 0x63, 0x71, 0x58,
    0x4e, 0x79, 0x43, 0x56, 0x4a, 0x70, 0x4c, 0x37, 0x4f, 0x75, 0x77, 0x50, 0x64, 0x56, 0x77, 0x50,
    0x4c, 0x37, 0x4b, 0x51, 0x45, 0x62, 0x46, 0x44, 0x4f, 0x43, 0x63, 0x0a, 0x68, 0x6a, 0x61, 0x62,
    0x47, 0x58, 0x77, 0x53, 0x4c, 0x51, 0x39, 0x63, 0x33, 0x53, 0x36, 0x4c, 0x77, 0x32, 0x69, 0x2b,
    0x53, 0x32, 0x54, 0x75, 0x32, 0x66, 0x69, 0x77, 0x51, 0x48, 0x48, 0x73, 0x6c, 0x62, 0x42, 0x4e,
    0x36, 0x42, 0x34, 0x31, 0x46, 0x4c, 0x45, 0x0a, 0x2d, 0x2d, 0x2d, 0x20, 0x57, 0x79, 0x4a, 0x70,
    0x39, 0x46, 0x2f, 0x39, 0x46, 0x4f, 0x5a, 0x68, 0x37, 0x67, 0x4a, 0x64, 0x68, 0x65, 0x71, 0x32,
    0x57, 0x49, 0x4a, 0x63, 0x77, 0x48, 0x67, 0x59, 0x63, 0x38, 0x4e, 0x49, 0x56, 0x68, 0x33, 0x64,
    0x64, 0x77, 0x68, 0x72, 0x63, 0x4e, 0x67, 0x0a, 0xee, 0xcf, 0x62, 0xc7, 0xce, 0x91, 0xb4, 0x33,
    0x27, 0x4e, 0x68, 0xd4, 0xf2, 0xf9, 0x13, 0x4c, 0xb7, 0x4c, 0x5b, 0xfe, 0xf7, 0xbe, 0xaa, 0x52,
    0xc8, 0xf0, 0xbc, 0x0e, 0x99, 0x2c, 0x1e, 0x83, 0x31, 0xfb, 0x66,
};
const meta_x25519_identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
const meta_x25519_payload = "013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab";
const meta_x25519_file_key = "59454c4c4f57205355424d4152494e45";
// CCTV age testdata/armor_x25519: expect success, payload 013f54400c82da08037759ada907a8b8...
const vec_armor_x25519 = [_]u8{
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x41, 0x47, 0x45, 0x20, 0x45,
    0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x20, 0x46, 0x49, 0x4c, 0x45, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x0a, 0x59, 0x57, 0x64, 0x6c, 0x4c, 0x57, 0x56, 0x75, 0x59, 0x33, 0x4a, 0x35, 0x63,
    0x48, 0x52, 0x70, 0x62, 0x32, 0x34, 0x75, 0x62, 0x33, 0x4a, 0x6e, 0x4c, 0x33, 0x59, 0x78, 0x43,
    0x69, 0x30, 0x2b, 0x49, 0x46, 0x67, 0x79, 0x4e, 0x54, 0x55, 0x78, 0x4f, 0x53, 0x42, 0x55, 0x52,
    0x57, 0x6c, 0x47, 0x4d, 0x48, 0x6c, 0x77, 0x63, 0x58, 0x49, 0x72, 0x59, 0x6e, 0x42, 0x32, 0x59,
    0x33, 0x46, 0x59, 0x0a, 0x54, 0x6e, 0x6c, 0x44, 0x56, 0x6b, 0x70, 0x77, 0x54, 0x44, 0x64, 0x50,
    0x64, 0x58, 0x64, 0x51, 0x5a, 0x46, 0x5a, 0x33, 0x55, 0x45, 0x77, 0x33, 0x53, 0x31, 0x46, 0x46,
    0x59, 0x6b, 0x5a, 0x45, 0x54, 0x30, 0x4e, 0x6a, 0x43, 0x6d, 0x68, 0x71, 0x59, 0x57, 0x4a, 0x48,
    0x57, 0x48, 0x64, 0x54, 0x54, 0x46, 0x45, 0x35, 0x59, 0x7a, 0x4e, 0x54, 0x4e, 0x6b, 0x78, 0x33,
    0x4d, 0x6d, 0x6b, 0x72, 0x0a, 0x55, 0x7a, 0x4a, 0x55, 0x64, 0x54, 0x4a, 0x6d, 0x61, 0x58, 0x64,
    0x52, 0x53, 0x45, 0x68, 0x7a, 0x62, 0x47, 0x4a, 0x43, 0x54, 0x6a, 0x5a, 0x43, 0x4e, 0x44, 0x46,
    0x47, 0x54, 0x45, 0x55, 0x4b, 0x4c, 0x53, 0x30, 0x74, 0x49, 0x46, 0x64, 0x35, 0x53, 0x6e, 0x41,
    0x35, 0x52, 0x69, 0x38, 0x35, 0x52, 0x6b, 0x39, 0x61, 0x61, 0x44, 0x64, 0x6e, 0x53, 0x6d, 0x52,
    0x6f, 0x5a, 0x58, 0x45, 0x79, 0x0a, 0x56, 0x30, 0x6c, 0x4b, 0x59, 0x33, 0x64, 0x49, 0x5a, 0x31,
    0x6c, 0x6a, 0x4f, 0x45, 0x35, 0x4a, 0x56, 0x6d, 0x67, 0x7a, 0x5a, 0x47, 0x52, 0x33, 0x61, 0x48,
    0x4a, 0x6a, 0x54, 0x6d, 0x63, 0x4b, 0x37, 0x73, 0x39, 0x69, 0x78, 0x38, 0x36, 0x52, 0x74, 0x44,
    0x4d, 0x6e, 0x54, 0x6d, 0x6a, 0x55, 0x38, 0x76, 0x6b, 0x54, 0x54, 0x4c, 0x64, 0x4d, 0x57, 0x2f,
    0x37, 0x33, 0x76, 0x71, 0x70, 0x53, 0x0a, 0x79, 0x50, 0x43, 0x38, 0x44, 0x70, 0x6b, 0x73, 0x48,
    0x6f, 0x4d, 0x78, 0x2b, 0x32, 0x59, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44,
    0x20, 0x41, 0x47, 0x45, 0x20, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x20, 0x46,
    0x49, 0x4c, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
};
const meta_armor_x25519_identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
const meta_armor_x25519_file_key = "59454c4c4f57205355424d4152494e45";
// CCTV age testdata/scrypt: expect success, payload 013f54400c82da08037759ada907a8b8...
const vec_scrypt = [_]u8{
    0x61, 0x67, 0x65, 0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x2f, 0x76, 0x31, 0x0a, 0x2d, 0x3e, 0x20, 0x73, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20,
    0x72, 0x46, 0x30, 0x2f, 0x4e, 0x77, 0x62, 0x6c, 0x55, 0x48, 0x48, 0x54, 0x70, 0x67, 0x51, 0x67,
    0x52, 0x70, 0x65, 0x35, 0x43, 0x51, 0x20, 0x31, 0x30, 0x0a, 0x67, 0x55, 0x6a, 0x45, 0x79, 0x6d,
    0x46, 0x4b, 0x4d, 0x56, 0x58, 0x51, 0x45, 0x4b, 0x64, 0x4d, 0x4d, 0x48, 0x4c, 0x32, 0x34, 0x6f,
    0x59, 0x65, 0x78, 0x6a, 0x45, 0x33, 0x54, 0x49, 0x43, 0x30, 0x4f, 0x30, 0x7a, 0x47, 0x53, 0x71,
    0x4a, 0x32, 0x61, 0x55, 0x59, 0x0a, 0x2d, 0x2d, 0x2d, 0x20, 0x49, 0x4f, 0x58, 0x69, 0x51, 0x59,
    0x53, 0x74, 0x6b, 0x6f, 0x54, 0x31, 0x6d, 0x76, 0x5a, 0x57, 0x32, 0x74, 0x46, 0x4f, 0x71, 0x5a,
    0x64, 0x68, 0x52, 0x56, 0x76, 0x6a, 0x35, 0x38, 0x65, 0x67, 0x41, 0x42, 0x78, 0x2f, 0x73, 0x57,
    0x66, 0x5a, 0x51, 0x62, 0x63, 0x0a, 0x1b, 0x35, 0xc6, 0xe6, 0x87, 0xdd, 0x00, 0xda, 0x3a, 0xc3,
    0x79, 0xac, 0x9f, 0x74, 0x2c, 0x21, 0xfd, 0x18, 0x5a, 0x1b, 0x9e, 0x3d, 0xed, 0x73, 0x9d, 0x14,
    0xac, 0x6a, 0x9a, 0x50, 0x12, 0x4d, 0xb8, 0x66, 0xd8,
};
const meta_scrypt_passphrase = "password";
const meta_scrypt_file_key = "59454c4c4f57205355424d4152494e45";
// CCTV age testdata/x25519_no_match: expect no match.
const vec_x25519_no_match = [_]u8{
    0x61, 0x67, 0x65, 0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x2f, 0x76, 0x31, 0x0a, 0x2d, 0x3e, 0x20, 0x58, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20,
    0x61, 0x6a, 0x74, 0x71, 0x41, 0x76, 0x44, 0x45, 0x6b, 0x56, 0x4e, 0x72, 0x32, 0x42, 0x37, 0x7a,
    0x55, 0x4f, 0x74, 0x71, 0x32, 0x6d, 0x41, 0x51, 0x58, 0x44, 0x53, 0x42, 0x6c, 0x4e, 0x72, 0x56,
    0x41, 0x75, 0x4d, 0x2f, 0x64, 0x4b, 0x62, 0x35, 0x73, 0x54, 0x34, 0x0a, 0x48, 0x55, 0x4b, 0x74,
    0x7a, 0x30, 0x52, 0x32, 0x6a, 0x35, 0x42, 0x6c, 0x32, 0x45, 0x52, 0x37, 0x48, 0x68, 0x41, 0x5a,
    0x72, 0x55, 0x52, 0x69, 0x6b, 0x43, 0x46, 0x70, 0x69, 0x49, 0x6a, 0x4e, 0x61, 0x30, 0x4b, 0x6a,
    0x48, 0x63, 0x6a, 0x62, 0x41, 0x47, 0x55, 0x0a, 0x2d, 0x2d, 0x2d, 0x20, 0x72, 0x72, 0x70, 0x54,
    0x6c, 0x76, 0x4b, 0x45, 0x4b, 0x72, 0x4b, 0x33, 0x45, 0x71, 0x68, 0x6f, 0x4f, 0x50, 0x4a, 0x65,
    0x50, 0x31, 0x4b, 0x45, 0x38, 0x4f, 0x31, 0x64, 0x32, 0x61, 0x72, 0x72, 0x52, 0x65, 0x7a, 0x37,
    0x37, 0x6d, 0x77, 0x65, 0x6b, 0x52, 0x63, 0x0a, 0xdd, 0xdf, 0x72, 0xd0, 0x6f, 0xbc, 0xab, 0x57,
    0xdf, 0x3d, 0x0d, 0x31, 0x24, 0x96, 0xad, 0x21, 0x8c, 0xd7, 0xfd, 0x6f, 0x80, 0x78, 0xbb, 0xf8,
    0x81, 0x2d, 0xd8, 0x79, 0x47, 0x15, 0x5e, 0xb7, 0xbd, 0x5e, 0x88,
};
const meta_x25519_no_match_identity = "AGE-SECRET-KEY-143WN7DCXU4G8R5AXQSSYD9AEPYDNT3HXSLWSPK36CDU6E8M59SSSAGZ3KG";
// CCTV age testdata/hmac_bad; expect HMAC failure.
const vec_hmac_bad = [_]u8{
    0x61, 0x67, 0x65, 0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x2f, 0x76, 0x31, 0x0a, 0x2d, 0x3e, 0x20, 0x58, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20,
    0x54, 0x45, 0x69, 0x46, 0x30, 0x79, 0x70, 0x71, 0x72, 0x2b, 0x62, 0x70, 0x76, 0x63, 0x71, 0x58,
    0x4e, 0x79, 0x43, 0x56, 0x4a, 0x70, 0x4c, 0x37, 0x4f, 0x75, 0x77, 0x50, 0x64, 0x56, 0x77, 0x50,
    0x4c, 0x37, 0x4b, 0x51, 0x45, 0x62, 0x46, 0x44, 0x4f, 0x43, 0x63, 0x0a, 0x68, 0x6a, 0x61, 0x62,
    0x47, 0x58, 0x77, 0x53, 0x4c, 0x51, 0x39, 0x63, 0x33, 0x53, 0x36, 0x4c, 0x77, 0x32, 0x69, 0x2b,
    0x53, 0x32, 0x54, 0x75, 0x32, 0x66, 0x69, 0x77, 0x51, 0x48, 0x48, 0x73, 0x6c, 0x62, 0x42, 0x4e,
    0x36, 0x42, 0x34, 0x31, 0x46, 0x4c, 0x45, 0x0a, 0x2d, 0x2d, 0x2d, 0x20, 0x38, 0x4d, 0x63, 0x45,
    0x33, 0x69, 0x78, 0x39, 0x52, 0x33, 0x34, 0x45, 0x2f, 0x76, 0x4c, 0x72, 0x51, 0x76, 0x33, 0x79,
    0x65, 0x70, 0x73, 0x48, 0x6a, 0x6f, 0x2f, 0x4c, 0x58, 0x68, 0x66, 0x73, 0x32, 0x32, 0x41, 0x62,
    0x33, 0x55, 0x79, 0x49, 0x6e, 0x6d, 0x67, 0x0a, 0xee, 0xcf, 0x62, 0xc7, 0xce, 0x91, 0xb4, 0x33,
    0x27, 0x4e, 0x68, 0xd4, 0xf2, 0xf9, 0x13, 0x4c, 0xb7, 0x4c, 0x5b, 0xfe, 0xf7, 0xbe, 0xaa, 0x52,
    0xc8, 0xf0, 0xbc, 0x0e, 0x99, 0x2c, 0x1e, 0x83, 0x31, 0xfb, 0x66,
};
const meta_hmac_bad_identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
// CCTV age testdata/version_unsupported: expect header failure.
const vec_version_unsupported = [_]u8{
    0x61, 0x67, 0x65, 0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x2f, 0x76, 0x31, 0x32, 0x33, 0x34, 0x0a, 0x2d, 0x3e, 0x20, 0x58, 0x32, 0x35, 0x35,
    0x31, 0x39, 0x20, 0x54, 0x45, 0x69, 0x46, 0x30, 0x79, 0x70, 0x71, 0x72, 0x2b, 0x62, 0x70, 0x76,
    0x63, 0x71, 0x58, 0x4e, 0x79, 0x43, 0x56, 0x4a, 0x70, 0x4c, 0x37, 0x4f, 0x75, 0x77, 0x50, 0x64,
    0x56, 0x77, 0x50, 0x4c, 0x37, 0x4b, 0x51, 0x45, 0x62, 0x46, 0x44, 0x4f, 0x43, 0x63, 0x0a, 0x68,
    0x6a, 0x61, 0x62, 0x47, 0x58, 0x77, 0x53, 0x4c, 0x51, 0x39, 0x63, 0x33, 0x53, 0x36, 0x4c, 0x77,
    0x32, 0x69, 0x2b, 0x53, 0x32, 0x54, 0x75, 0x32, 0x66, 0x69, 0x77, 0x51, 0x48, 0x48, 0x73, 0x6c,
    0x62, 0x42, 0x4e, 0x36, 0x42, 0x34, 0x31, 0x46, 0x4c, 0x45, 0x0a, 0x2d, 0x2d, 0x2d, 0x20, 0x54,
    0x76, 0x2b, 0x68, 0x34, 0x78, 0x33, 0x74, 0x4e, 0x38, 0x4f, 0x34, 0x6b, 0x41, 0x57, 0x6e, 0x66,
    0x37, 0x44, 0x62, 0x70, 0x53, 0x6b, 0x6d, 0x4e, 0x6c, 0x78, 0x6c, 0x79, 0x78, 0x53, 0x56, 0x66,
    0x59, 0x37, 0x55, 0x6f, 0x50, 0x46, 0x6b, 0x68, 0x6e, 0x6f, 0x0a, 0xee, 0xcf, 0x62, 0xc7, 0xce,
    0x91, 0xb4, 0x33, 0x27, 0x4e, 0x68, 0xd4, 0xf2, 0xf9, 0x13, 0x4c, 0xb7, 0x4c, 0x5b, 0xfe, 0xf7,
    0xbe, 0xaa, 0x52, 0xc8, 0xf0, 0xbc, 0x0e, 0x99, 0x2c, 0x1e, 0x83, 0x31, 0xfb, 0x66,
};
const meta_version_unsupported_identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
// CCTV age testdata/armor_garbage_leading: expect armor failure.
const vec_armor_garbage_leading = [_]u8{
    0x67, 0x61, 0x72, 0x62, 0x61, 0x67, 0x65, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47,
    0x49, 0x4e, 0x20, 0x41, 0x47, 0x45, 0x20, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44,
    0x20, 0x46, 0x49, 0x4c, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x59, 0x57, 0x64, 0x6c, 0x4c,
    0x57, 0x56, 0x75, 0x59, 0x33, 0x4a, 0x35, 0x63, 0x48, 0x52, 0x70, 0x62, 0x32, 0x34, 0x75, 0x62,
    0x33, 0x4a, 0x6e, 0x4c, 0x33, 0x59, 0x78, 0x43, 0x69, 0x30, 0x2b, 0x49, 0x46, 0x67, 0x79, 0x4e,
    0x54, 0x55, 0x78, 0x4f, 0x53, 0x42, 0x55, 0x52, 0x57, 0x6c, 0x47, 0x4d, 0x48, 0x6c, 0x77, 0x63,
    0x58, 0x49, 0x72, 0x59, 0x6e, 0x42, 0x32, 0x59, 0x33, 0x46, 0x59, 0x0a, 0x54, 0x6e, 0x6c, 0x44,
    0x56, 0x6b, 0x70, 0x77, 0x54, 0x44, 0x64, 0x50, 0x64, 0x58, 0x64, 0x51, 0x5a, 0x46, 0x5a, 0x33,
    0x55, 0x45, 0x77, 0x33, 0x53, 0x31, 0x46, 0x46, 0x59, 0x6b, 0x5a, 0x45, 0x54, 0x30, 0x4e, 0x6a,
    0x43, 0x6d, 0x68, 0x71, 0x59, 0x57, 0x4a, 0x48, 0x57, 0x48, 0x64, 0x54, 0x54, 0x46, 0x45, 0x35,
    0x59, 0x7a, 0x4e, 0x54, 0x4e, 0x6b, 0x78, 0x33, 0x4d, 0x6d, 0x6b, 0x72, 0x0a, 0x55, 0x7a, 0x4a,
    0x55, 0x64, 0x54, 0x4a, 0x6d, 0x61, 0x58, 0x64, 0x52, 0x53, 0x45, 0x68, 0x7a, 0x62, 0x47, 0x4a,
    0x43, 0x54, 0x6a, 0x5a, 0x43, 0x4e, 0x44, 0x46, 0x47, 0x54, 0x45, 0x55, 0x4b, 0x4c, 0x53, 0x30,
    0x74, 0x49, 0x46, 0x64, 0x35, 0x53, 0x6e, 0x41, 0x35, 0x52, 0x69, 0x38, 0x35, 0x52, 0x6b, 0x39,
    0x61, 0x61, 0x44, 0x64, 0x6e, 0x53, 0x6d, 0x52, 0x6f, 0x5a, 0x58, 0x45, 0x79, 0x0a, 0x56, 0x30,
    0x6c, 0x4b, 0x59, 0x33, 0x64, 0x49, 0x5a, 0x31, 0x6c, 0x6a, 0x4f, 0x45, 0x35, 0x4a, 0x56, 0x6d,
    0x67, 0x7a, 0x5a, 0x47, 0x52, 0x33, 0x61, 0x48, 0x4a, 0x6a, 0x54, 0x6d, 0x63, 0x4b, 0x37, 0x73,
    0x39, 0x69, 0x78, 0x38, 0x36, 0x52, 0x74, 0x44, 0x4d, 0x6e, 0x54, 0x6d, 0x6a, 0x55, 0x38, 0x76,
    0x6b, 0x54, 0x54, 0x4c, 0x64, 0x4d, 0x57, 0x2f, 0x37, 0x33, 0x76, 0x71, 0x70, 0x53, 0x0a, 0x79,
    0x50, 0x43, 0x38, 0x44, 0x70, 0x6b, 0x73, 0x48, 0x6f, 0x4d, 0x78, 0x2b, 0x32, 0x59, 0x3d, 0x0a,
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x41, 0x47, 0x45, 0x20, 0x45, 0x4e, 0x43,
    0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x20, 0x46, 0x49, 0x4c, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x0a,
};
const meta_armor_garbage_leading_identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
// CCTV age testdata/scrypt_work_factor_23: expect header failure.
const vec_scrypt_work_factor_23 = [_]u8{
    0x61, 0x67, 0x65, 0x2d, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x2f, 0x76, 0x31, 0x0a, 0x2d, 0x3e, 0x20, 0x73, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20,
    0x72, 0x46, 0x30, 0x2f, 0x4e, 0x77, 0x62, 0x6c, 0x55, 0x48, 0x48, 0x54, 0x70, 0x67, 0x51, 0x67,
    0x52, 0x70, 0x65, 0x35, 0x43, 0x51, 0x20, 0x32, 0x33, 0x0a, 0x71, 0x57, 0x39, 0x65, 0x56, 0x73,
    0x54, 0x30, 0x4e, 0x56, 0x62, 0x2f, 0x56, 0x73, 0x77, 0x74, 0x77, 0x38, 0x6b, 0x50, 0x49, 0x78,
    0x55, 0x6e, 0x61, 0x59, 0x6d, 0x6d, 0x39, 0x50, 0x78, 0x31, 0x64, 0x59, 0x6d, 0x71, 0x32, 0x2b,
    0x34, 0x2b, 0x71, 0x5a, 0x41, 0x0a, 0x2d, 0x2d, 0x2d, 0x20, 0x33, 0x38, 0x54, 0x70, 0x51, 0x4d,
    0x78, 0x51, 0x52, 0x52, 0x4e, 0x4d, 0x66, 0x6d, 0x59, 0x59, 0x70, 0x42, 0x58, 0x36, 0x44, 0x44,
    0x72, 0x50, 0x78, 0x34, 0x2f, 0x51, 0x59, 0x35, 0x55, 0x6d, 0x4a, 0x6e, 0x68, 0x50, 0x79, 0x56,
    0x6f, 0x58, 0x2f, 0x63, 0x77, 0x0a, 0xac, 0x5d, 0x3f, 0x37, 0x06, 0xe5, 0x50, 0x71, 0xd3, 0xa6,
    0x04, 0x20, 0x46, 0x97, 0xb9, 0x09, 0x05, 0x95, 0xc2, 0xf7, 0xf5, 0xdb, 0xae, 0xe8, 0x0d, 0x7a,
    0x01, 0x8c, 0x28, 0x72, 0x05, 0x8a, 0xf3, 0xce, 0x7c,
};
const meta_scrypt_work_factor_23_passphrase = "password";
// CCTV age testdata/empty; expect header failure.
const vec_empty = [_]u8{

};
// CCTV age testdata/stream_trailing_garbage_short: expect payload failure.
const vec_stream_trailing_garbage_short = [_]u8{
    0x78, 0xda, 0xec, 0xc0, 0xb1, 0x6e, 0x12, 0x01, 0x00, 0x00, 0x50, 0x66, 0xd2, 0xb8, 0x18, 0x13,
    0x1d, 0x9a, 0x90, 0x38, 0x38, 0x34, 0xd7, 0xca, 0x61, 0x8b, 0x2c, 0x0e, 0xad, 0x9c, 0x14, 0x2f,
    0x47, 0x09, 0x0d, 0x45, 0x9d, 0x7a, 0x07, 0xde, 0x61, 0x4c, 0x7b, 0xa0, 0xe5, 0xc2, 0xe2, 0xec,
    0xa8, 0x1f, 0xe1, 0x1f, 0xb8, 0x3a, 0xeb, 0xa4, 0x31, 0xba, 0x9a, 0x38, 0x19, 0x17, 0x1d, 0xdc,
    0xdc, 0xfa, 0x23, 0xef, 0x9d, 0xe6, 0xb3, 0x60, 0x76, 0x96, 0x2d, 0xd7, 0xe5, 0xcb, 0xf9, 0xf9,
    0xd9, 0xf6, 0xf9, 0x32, 0xdf, 0x59, 0x35, 0xeb, 0xc1, 0xbd, 0xc6, 0x24, 0xdc, 0xdd, 0x6d, 0x76,
    0x1a, 0xc7, 0xdd, 0x79, 0x74, 0x7b, 0x5d, 0x2e, 0x96, 0x5b, 0x69, 0xb9, 0xca, 0x16, 0x93, 0x64,
    0x7d, 0x30, 0xee, 0x97, 0x71, 0x7b, 0x70, 0x51, 0x1d, 0x4d, 0xc7, 0xd5, 0x51, 0xdc, 0x7e, 0x38,
    0xec, 0xa6, 0xd1, 0xfd, 0xc1, 0x41, 0x56, 0x2f, 0x9e, 0x9d, 0xa6, 0x0f, 0x26, 0xd5, 0x28, 0x1e,
    0x76, 0xb2, 0xd6, 0x68, 0x2f, 0xae, 0xc2, 0xf9, 0xd6, 0x28, 0x3c, 0xbe, 0x08, 0x9f, 0xce, 0xab,
    0x61, 0xaf, 0xf7, 0xe2, 0x79, 0xba, 0x9f, 0xec, 0xed, 0xdf, 0x69, 0x46, 0x71, 0xb7, 0x1e, 0x04,
    0x41, 0xe3, 0x64, 0xdd, 0x2f, 0x3b, 0xd1, 0x4e, 0x27, 0x1a, 0x3c, 0x2e, 0xda, 0x79, 0x7f, 0x5a,
    0xcc, 0x16, 0xe1, 0xc9, 0x61, 0x3f, 0xab, 0x7a, 0xf9, 0xa3, 0xec, 0x6e, 0x72, 0x38, 0x2e, 0x5a,
    0xd3, 0x69, 0x55, 0x2c, 0xb3, 0x24, 0xaf, 0xff, 0xfd, 0x92, 0x7e, 0xfc, 0xfc, 0xf6, 0x7d, 0xeb,
    0x56, 0x52, 0x7c, 0xff, 0xf7, 0xff, 0x6a, 0x5c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x5a, 0xad, 0xf6, 0xae, 0xda, 0x78, 0x73, 0xe3,
    0xf5, 0xb5, 0x1f, 0x7f, 0xbe, 0x86, 0xaf, 0x36, 0x83, 0x9f, 0xd7, 0x9f, 0x6c, 0xfe, 0xfa, 0xbd,
    0x7d, 0x65, 0xe3, 0xc3, 0xb7, 0x9b, 0x9f, 0xaa, 0xcb, 0x00, 0x00, 0x00, 0xff, 0xff, 0xfe, 0xbd,
    0x4b, 0x89,
};
const meta_stream_trailing_garbage_short_identity = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// The CCTV `payload` field is the SHA-256 of the expected plaintext, not the
// plaintext itself.
fn expectPayloadHash(out: []const u8, comptime hex: []const u8) !void {
    const expected = comptime hexToBytes(hex);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(out, &digest, .{});
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "CCTV x25519 vector decrypts" {
    var scratch: [256 * 1024]u8 = undefined;
    var out: [64]u8 = undefined;
    const n = try decodeOrdinal(&vec_x25519, 0, &out, &scratch, .{ .identity = meta_x25519_identity });
    try expectPayloadHash(out[0..n], meta_x25519_payload);
    const size = try decodedSize(&vec_x25519, .{ .identity = meta_x25519_identity }, &scratch);
    try testing.expectEqual(@as(u64, n), size);
}

test "CCTV armor x25519 vector decrypts" {
    var scratch: [256 * 1024]u8 = undefined;
    var out: [64]u8 = undefined;
    const n = try decodeOrdinal(&vec_armor_x25519, 0, &out, &scratch, .{ .identity = meta_armor_x25519_identity });
    try expectPayloadHash(out[0..n], "013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab");
}

test "CCTV scrypt vector decrypts" {
    // The reference vector uses work factor 18: 128 * 8 * 2^18 = 256 MiB of
    // scrypt scratch, so this test allocates instead of using the stack.
    const scratch = try testing.allocator.alloc(u8, 260 * 1024 * 1024);
    defer testing.allocator.free(scratch);
    var out: [64]u8 = undefined;
    const n = try decodeOrdinal(&vec_scrypt, 0, &out, scratch, .{ .password = meta_scrypt_passphrase });
    try expectPayloadHash(out[0..n], "013f54400c82da08037759ada907a8b864e97de81c088a182062c4b5622fd2ab");
}

test "CCTV negative vectors reject" {
    var scratch: [256 * 1024]u8 = undefined;
    var out: [64]u8 = undefined;
    try testing.expectError(error.IntegrityException, decodeOrdinal(&vec_x25519_no_match, 0, &out, &scratch, .{ .identity = meta_x25519_no_match_identity }));
    try testing.expectError(error.IntegrityException, decodeOrdinal(&vec_hmac_bad, 0, &out, &scratch, .{ .identity = meta_hmac_bad_identity }));
    try testing.expectError(error.UnsupportedException, decodeOrdinal(&vec_version_unsupported, 0, &out, &scratch, .{ .identity = meta_version_unsupported_identity }));
    try testing.expectError(error.DataException, decodeOrdinal(&vec_armor_garbage_leading, 0, &out, &scratch, .{ .identity = meta_armor_garbage_leading_identity }));
    try testing.expectError(error.UnsupportedException, decodeOrdinal(&vec_scrypt_work_factor_23, 0, &out, &scratch, .{ .password = meta_scrypt_work_factor_23_passphrase }));
    try testing.expectError(error.DataException, decodeOrdinal(&vec_empty, 0, &out, &scratch, .{ .password = "x" }));
}

test "base64 raw round trip and canonical rejection" {
    const plain = "Nobody inspects the spammish repetition";
    var encoded: [b64EncodedLen(plain.len)]u8 = undefined;
    b64Encode(&encoded, plain);
    try testing.expectEqualStrings("Tm9ib2R5IGluc3BlY3RzIHRoZSBzcGFtbWlzaCByZXBldGl0aW9u", &encoded);
    var decoded: [plain.len]u8 = undefined;
    try b64Decode(&decoded, &encoded);
    try testing.expectEqualStrings(plain, &decoded);
    // Non-canonical trailing bits in a partial group: "TW" keeps 4 bits that
    // must be zero in canonical encoding.
    var bad: [2]u8 = .{ 'T', 'W' };
    var one: [1]u8 = undefined;
    try testing.expectError(error.DataException, b64Decode(&one, &bad));
    var padded: [3]u8 = .{ 'T', 'W', '=' };
    var two: [2]u8 = undefined;
    try testing.expectError(error.DataException, b64Decode(&two, &padded));
}

test "bech32 identity round trip" {
    const text = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
    const identity = try Identity.fromString(text);
    var out: [80]u8 = undefined;
    const encoded = try identity.toString(&out);
    // The encoding is case-preserving lowercase; the input was uppercase.
    var upper_buf: [80]u8 = undefined;
    const as_upper = std.ascii.upperString(&upper_buf, encoded);
    try testing.expectEqualStrings(text, as_upper);
    const recipient = try identity.recipientString(&out);
    try testing.expectEqualStrings("age1", recipient[0..4]);
}

test "x25519 passwordless round trip" {
    var id_buf: [80]u8 = undefined;
    const secret: [32]u8 = randomBytes(32);
    const identity = Identity{ .secret = secret };
    const identity_text = try identity.toString(&id_buf);
    var rec_buf: [100]u8 = undefined;
    const recipient = try identity.recipientString(&rec_buf);
    const entries = [_]Entry{.{ .name = "payload", .data = "hello age world" }};
    var scratch: [256 * 1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const written = try encode(&entries, &out, &scratch, .{ .recipient = recipient });
    var plain: [64]u8 = undefined;
    const n = try decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .identity = identity_text });
    try testing.expectEqualStrings("hello age world", plain[0..n]);
}

test "scrypt round trip with small work factor" {
    const entries = [_]Entry{.{ .name = "payload", .data = "secret under password" }};
    var scratch: [8 * 1024 * 1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const options = Options{ .password = "correct horse battery staple", .work_factor = 4 };
    const written = try encode(&entries, &out, &scratch, options);
    var plain: [64]u8 = undefined;
    const n = try decodeOrdinal(out[0..written], 0, &plain, &scratch, options);
    try testing.expectEqualStrings("secret under password", plain[0..n]);
    // Wrong passphrase fails authentication.
    try testing.expectError(error.IntegrityException, decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .password = "wrong", .work_factor = 4 }));
}

test "armor round trip and garbage rejection" {
    const entries = [_]Entry{.{ .name = "payload", .data = "armored payload" }};
    var scratch: [256 * 1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const options = Options{ .recipient = "", .password = "pw", .work_factor = 4, .armor = true };
    _ = options;
    const id = Identity{ .secret = randomBytes(32) };
    var id_buf: [80]u8 = undefined;
    var rec_buf: [100]u8 = undefined;
    const written = try encode(&entries, &out, &scratch, .{ .recipient = try id.recipientString(&rec_buf), .armor = true });
    try testing.expectEqualStrings(armor_begin, out[0..armor_begin.len]);
    var plain: [64]u8 = undefined;
    const n = try decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .identity = try id.toString(&id_buf) });
    try testing.expectEqualStrings("armored payload", plain[0..n]);
    // Garbage before the armor block is rejected.
    var bad: [4200]u8 = undefined;
    @memcpy(bad[0..7], "garbage");
    @memcpy(bad[7..][0..written], out[0..written]);
    try testing.expectError(error.DataException, decodeOrdinal(bad[0 .. 7 + written], 0, &plain, &scratch, .{ .identity = try id.toString(&id_buf) }));
}

test "multi chunk payload round trip" {
    var payload: [200 * 1024]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    const entries = [_]Entry{.{ .name = "payload", .data = &payload }};
    var scratch: [256 * 1024]u8 = undefined;
    var out: [220 * 1024]u8 = undefined;
    const id = Identity{ .secret = randomBytes(32) };
    var id_buf: [80]u8 = undefined;
    var rec_buf: [100]u8 = undefined;
    const options = Options{ .recipient = try id.recipientString(&rec_buf) };
    const written = try encode(&entries, &out, &scratch, options);
    try testing.expectEqual(try archiveSize(&entries, options, &scratch), written);
    const info = try inspectOrdinal(out[0..written], 0, .{ .identity = try id.toString(&id_buf) }, &scratch);
    try testing.expectEqual(@as(u64, payload.len), info.size);
    var plain: [200 * 1024]u8 = undefined;
    const n = try decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .identity = try id.toString(&id_buf) });
    try testing.expectEqual(payload.len, n);
    try testing.expectEqualSlices(u8, &payload, &plain);
    // Tampering with a middle chunk fails authentication.
    out[written / 2] ^= 0x01;
    try testing.expectError(error.IntegrityException, decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .identity = try id.toString(&id_buf) }));
}

test "empty payload round trip" {
    const entries = [_]Entry{.{ .name = "payload", .data = "" }};
    var scratch: [256 * 1024]u8 = undefined;
    var out: [4096]u8 = undefined;
    const id = Identity{ .secret = randomBytes(32) };
    var id_buf: [80]u8 = undefined;
    var rec_buf: [100]u8 = undefined;
    const written = try encode(&entries, &out, &scratch, .{ .recipient = try id.recipientString(&rec_buf) });
    var plain: [1]u8 = undefined;
    const n = try decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .identity = try id.toString(&id_buf) });
    try testing.expectEqual(@as(usize, 0), n);
}
