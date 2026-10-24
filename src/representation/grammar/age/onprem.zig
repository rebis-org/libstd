const std = @import("std");

const entry_prim = @import("../../../common/entry.zig");
const crypto_prim = @import("../../../common/primitive/crypto.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");

const b64_pad = std.base64.standard;
const b64 = std.base64.standard_no_pad;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const scrypt = std.crypto.pwhash.scrypt;
const testing = std.testing;
pub const Entry = entry_prim.Entry;
pub const EntryInfo = entry_prim.Sized;
pub const Exception = exception_prim.Exception;

// age v1 file encryption per C2SP age.md; vectors from the CCTV age testkit
// and the reference Go implementation in vendor/age. The v1.1 hardware
// recipient types are out of scope.

pub const scratch_size: usize = 64 * 1024;

pub const Options = struct {
    password: []const u8 = &.{},
    identity: []const u8 = &.{},
    recipient: []const u8 = &.{},
    work_factor: u8 = 18,
    armor: bool = false,
};

pub const scrypt_work_factor_max: u8 = 22;

const version_line = "age-encryption.org/v1";
const x25519_info = "age-encryption.org/v1/X25519";
const scrypt_label = "age-encryption.org/v1/scrypt";
const header_info = "header";
const payload_info = "payload";
const armor_begin = "-----BEGIN AGE ENCRYPTED FILE-----";
const armor_end = "-----END AGE ENCRYPTED FILE-----";
const chunk_size: usize = 64 * 1024;
const file_key_len: usize = 16;
const mac_encoded_len: usize = 43;

const zero_nonce: [12]u8 = std.mem.zeroes([12]u8);

fn b64Len(n: usize) usize {
    return b64.Encoder.calcSize(n);
}

fn decodeB64(dst: []u8, src: []const u8) Exception!void {
    // The no-pad decoder rejects non-canonical trailing bits and any '=',
    // both of which the age header grammar forbids.
    if ((b64.Decoder.calcSizeForSlice(src) catch return error.DataException) != dst.len) return error.DataException;
    b64.Decoder.decode(dst, src) catch return error.DataException;
}

fn decodeB64Fixed(comptime n: usize, src: []const u8) Exception![n]u8 {
    var out: [n]u8 = undefined;
    try decodeB64(&out, src);
    return out;
}

fn decodeB64Alloc(alloc: std.mem.Allocator, src: []const u8) Exception![]u8 {
    const n = b64.Decoder.calcSizeForSlice(src) catch return error.DataException;
    const dst = alloc.alloc(u8, n) catch return error.ResourceException;
    try decodeB64(dst, src);
    return dst;
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

fn convertBits(comptime in_t: type, comptime out_t: type, comptime in_bits: u5, comptime out_bits: u5, comptime pad: bool, data: []const in_t, out: []out_t) Exception![]out_t {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var i: usize = 0;
    const maxv: u32 = (@as(u32, 1) << out_bits) - 1;
    for (data) |v| {
        acc = (acc << in_bits) | v;
        bits += in_bits;
        while (bits >= out_bits) {
            bits -= out_bits;
            if (i >= out.len) return error.DataException;
            out[i] = @intCast((acc >> bits) & maxv);
            i += 1;
        }
    }
    if (pad) {
        if (bits != 0) {
            if (i >= out.len) return error.DataException;
            out[i] = @intCast((acc << (out_bits - bits)) & maxv);
            i += 1;
        }
    } else if (bits >= in_bits or (acc & ((@as(u32, 1) << bits) - 1)) != 0) {
        return error.DataException;
    }
    return out[0..i];
}

fn bech32Checksum(hrp_upper: []const u8, data: []const u5) [6]u5 {
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
    var out: [6]u5 = undefined;
    for (0..6) |i| out[i] = @intCast((polymod >> @intCast(5 * (5 - i))) & 0x1f);
    return out;
}

fn bech32Encode(hrp: []const u8, data: []const u8, out: []u8) Exception![]const u8 {
    var data5: [2 * 256]u5 = undefined;
    const data5_slice = try convertBits(u8, u5, 8, 5, true, data, &data5);
    if (out.len < hrp.len + 1 + data5_slice.len + 6) return error.CapacityException;
    @memcpy(out[0..hrp.len], hrp);
    out[hrp.len] = '1';
    for (data5_slice, 0..) |value, i| {
        out[hrp.len + 1 + i] = bech32_charset[value];
    }
    const checksum = bech32Checksum(hrp, data5_slice);
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
    const data = try convertBits(u5, u8, 5, 8, false, values[0 .. value_len - 6], data_out);
    return .{ .hrp = hrp_out[0..hrp.len], .data = data };
}

fn bech32Key(text: []const u8, comptime hrp: []const u8) Exception![32]u8 {
    var hrp_buf: [16]u8 = undefined;
    var data: [64]u8 = undefined;
    const decoded = try bech32Decode(text, &hrp_buf, &data);
    if (!std.mem.eql(u8, decoded.hrp, hrp) or decoded.data.len != 32) return error.DataException;
    return decoded.data[0..32].*;
}

fn randomIdentity() Identity {
    var secret: [32]u8 = undefined;
    crypto_prim.fillRandom(&secret) catch @panic("OS entropy failed");
    return .{ .secret = secret };
}

pub const Identity = struct {
    secret: [32]u8,

    pub fn fromString(text: []const u8) Exception!Identity {
        return .{ .secret = try bech32Key(text, "age-secret-key-") };
    }

    pub fn toString(self: Identity, out: []u8) Exception![]const u8 {
        return bech32Encode("AGE-SECRET-KEY-", &self.secret, out);
    }

    pub fn recipientString(self: Identity, out: []u8) Exception![]const u8 {
        return bech32Encode("age", &X25519.recoverPublicKey(self.secret), out);
    }
};

pub const Recipient = struct {
    public: [32]u8,

    pub fn fromString(text: []const u8) Exception!Recipient {
        return .{ .public = try bech32Key(text, "age") };
    }
};

const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn write(self: *Cursor, bytes: []const u8) Exception!void {
        if (self.buf.len - self.pos < bytes.len) return error.CapacityException;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn byte(self: *Cursor, b: u8) Exception!void {
        try self.write(&[_]u8{b});
    }
};

const Stanza = struct {
    args: []const []const u8,
    body: []const u8,
};

const Header = struct {
    stanzas: []const Stanza,
    // The MAC covers buf[0 .. mac_line_start + 3], through the "---" mark.
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
            try decodeB64(&mac, line[4..]);
            return .{ .stanzas = stanzas.items, .mac_line_start = pos, .payload_offset = eol + 1 };
        }
        if (!std.mem.startsWith(u8, line, "-> ") or line.len == 3) return error.DataException;
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, line[3..], ' ');
        while (it.next()) |arg| {
            args.append(alloc, arg) catch return error.ResourceException;
        }
        var body: std.ArrayListUnmanaged(u8) = .empty;
        var body_pos = eol + 1;
        while (true) {
            const end = std.mem.indexOfScalarPos(u8, input, body_pos, '\n') orelse return error.DataException;
            const part = input[body_pos..end];
            if (part.len > 64) return error.DataException;
            body.appendSlice(alloc, part) catch return error.ResourceException;
            body_pos = end + 1;
            if (part.len < 64) break;
        }
        const body_bin = try decodeB64Alloc(alloc, body.items);
        stanzas.append(alloc, .{ .args = args.items, .body = body_bin }) catch return error.ResourceException;
        pos = body_pos;
    }
}

// HMAC comes from the capability seam, not a second copy in the stdlib, so the
// provider axis covers every keyed hash age derives.
fn hmacSha256(out: *[32]u8, message: []const u8, key: []const u8) void {
    var mac = crypto_prim.HmacSha256.bind(crypto_prim.default_provider, key);
    mac.update(message);
    mac.final(out);
}

// RFC 5869 with a 32-byte output, which is one expand block: every age
// derivation below asks for exactly one.
fn hkdfSha256(ikm: []const u8, salt: []const u8, info: []const u8) [32]u8 {
    var prk: [32]u8 = undefined;
    hmacSha256(&prk, ikm, salt);
    var out: [32]u8 = undefined;
    var mac = crypto_prim.HmacSha256.bind(crypto_prim.default_provider, &prk);
    mac.update(info);
    mac.update(&.{1});
    mac.final(&out);
    return out;
}

fn headerMacKey(file_key: [file_key_len]u8) [32]u8 {
    return hkdfSha256(&file_key, "", header_info);
}

fn payloadKey(file_key: [file_key_len]u8, nonce: [16]u8) [32]u8 {
    return hkdfSha256(&file_key, &nonce, payload_info);
}

// Every stanza type wraps the file key with the same AEAD shape; only the
// wrap key derivation differs.
fn sealFileKey(file_key: [file_key_len]u8, wrap_key: [32]u8) [file_key_len + 16]u8 {
    var body: [file_key_len + 16]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(body[0..file_key_len], &tag, &file_key, "", zero_nonce, wrap_key);
    body[file_key_len..][0..16].* = tag;
    return body;
}

fn openFileKey(body: []const u8, wrap_key: [32]u8) Exception![file_key_len]u8 {
    if (body.len != file_key_len + 16) return error.DataException;
    var file_key: [file_key_len]u8 = undefined;
    ChaCha20Poly1305.decrypt(&file_key, body[0..file_key_len], body[file_key_len..][0..16].*, "", zero_nonce, wrap_key) catch return error.IntegrityException;
    return file_key;
}

fn x25519WrapKey(shared: [32]u8, share: [32]u8, recipient: [32]u8) [32]u8 {
    var salt: [64]u8 = undefined;
    salt[0..32].* = share;
    salt[32..64].* = recipient;
    return hkdfSha256(&shared, &salt, x25519_info);
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

fn decimalWorkFactor(text: []const u8) Exception!u8 {
    if (text.len == 0 or text[0] == '0') return error.DataException;
    return std.fmt.parseInt(u8, text, 10) catch return error.DataException;
}

fn wrapStanzas(file_key: [file_key_len]u8, options: Options, alloc: std.mem.Allocator, scratch: []u8) Exception![]Stanza {
    if (options.password.len != 0 and options.recipient.len != 0) return error.CallException;
    if (options.password.len == 0 and options.recipient.len == 0) return error.CallException;
    var list: std.ArrayListUnmanaged(Stanza) = .empty;
    if (options.password.len != 0) {
        if (options.work_factor < 1 or options.work_factor > scrypt_work_factor_max) return error.UnsupportedException;
        var salt: [16]u8 = undefined;
        try crypto_prim.fillRandom(&salt);
        var salt_b64: [b64Len(16)]u8 = undefined;
        const wrap_key = try scryptWrapKey(options.password, salt, options.work_factor, scratch);
        const args = alloc.alloc([]const u8, 3) catch return error.ResourceException;
        args[0] = "scrypt";
        args[1] = alloc.dupe(u8, b64.Encoder.encode(&salt_b64, &salt)) catch return error.ResourceException;
        args[2] = std.fmt.allocPrint(alloc, "{d}", .{options.work_factor}) catch return error.ResourceException;
        const body = alloc.dupe(u8, &sealFileKey(file_key, wrap_key)) catch return error.ResourceException;
        list.append(alloc, .{ .args = args, .body = body }) catch return error.ResourceException;
        return list.items;
    }
    const recipient = Recipient.fromString(options.recipient) catch return error.CallException;
    var ephemeral: [32]u8 = undefined;
    try crypto_prim.fillRandom(&ephemeral);
    const share = X25519.recoverPublicKey(ephemeral);
    const shared = X25519.scalarmult(ephemeral, recipient.public) catch return error.InternalException;
    const wrap_key = x25519WrapKey(shared, share, recipient.public);
    var share_b64: [b64Len(32)]u8 = undefined;
    const args = alloc.alloc([]const u8, 2) catch return error.ResourceException;
    args[0] = "X25519";
    args[1] = alloc.dupe(u8, b64.Encoder.encode(&share_b64, &share)) catch return error.ResourceException;
    const body = alloc.dupe(u8, &sealFileKey(file_key, wrap_key)) catch return error.ResourceException;
    list.append(alloc, .{ .args = args, .body = body }) catch return error.ResourceException;
    return list.items;
}

fn unwrapX25519(stanza: Stanza, identity: [32]u8) Exception![file_key_len]u8 {
    if (stanza.args.len != 2) return error.DataException;
    const share = try decodeB64Fixed(32, stanza.args[1]);
    const shared = X25519.scalarmult(identity, share) catch return error.IntegrityException;
    return openFileKey(stanza.body, x25519WrapKey(shared, share, X25519.recoverPublicKey(identity)));
}

fn unwrapFileKey(stanzas: []const Stanza, options: Options, scratch: []u8) Exception![file_key_len]u8 {
    if (options.password.len != 0) {
        // A scrypt stanza must be the only stanza; anything else is not a
        // passphrase-encrypted header.
        if (stanzas.len != 1 or !std.mem.eql(u8, stanzas[0].args[0], "scrypt")) return error.IntegrityException;
        const stanza = stanzas[0];
        if (stanza.args.len != 3) return error.DataException;
        const salt = try decodeB64Fixed(16, stanza.args[1]);
        const work_factor = try decimalWorkFactor(stanza.args[2]);
        if (work_factor > scrypt_work_factor_max) return error.UnsupportedException;
        const wrap_key = try scryptWrapKey(options.password, salt, work_factor, scratch);
        return openFileKey(stanza.body, wrap_key);
    }
    if (options.identity.len != 0) {
        const identity = Identity.fromString(options.identity) catch return error.CallException;
        for (stanzas) |stanza| {
            if (stanza.args.len == 0 or !std.mem.eql(u8, stanza.args[0], "X25519")) continue;
            // An authenticated failure means this identity does not own the
            // stanza; the next one may.
            return unwrapX25519(stanza, identity.secret) catch |err| switch (err) {
                error.IntegrityException => continue,
                else => return err,
            };
        }
        return error.IntegrityException;
    }
    return error.CallException;
}

fn writeHeader(file_key: [file_key_len]u8, stanzas: []const Stanza, dest: []u8) Exception!usize {
    var c = Cursor{ .buf = dest };
    try c.write(version_line ++ "\n");
    for (stanzas) |stanza| {
        try c.write("-> ");
        for (stanza.args, 0..) |arg, i| {
            if (i != 0) try c.byte(' ');
            try c.write(arg);
        }
        try c.byte('\n');
        var encoded: [b64Len(48)]u8 = undefined;
        const body_b64 = b64.Encoder.encode(encoded[0..b64Len(stanza.body.len)], stanza.body);
        for (body_b64, 0..) |ch, i| {
            if (i % 64 == 0 and i != 0) try c.byte('\n');
            try c.byte(ch);
        }
        try c.byte('\n');
    }
    try c.write("---");
    const mac_key = headerMacKey(file_key);
    var mac: [32]u8 = undefined;
    hmacSha256(&mac, c.buf[0..c.pos], &mac_key);
    try c.byte(' ');
    var mac_b64: [mac_encoded_len]u8 = undefined;
    try c.write(b64.Encoder.encode(&mac_b64, &mac));
    try c.byte('\n');
    return c.pos;
}

fn verifyHeaderMac(input: []const u8, header: Header, file_key: [file_key_len]u8) Exception!void {
    const mac_key = headerMacKey(file_key);
    var mac: [32]u8 = undefined;
    hmacSha256(&mac, input[0 .. header.mac_line_start + 3], &mac_key);
    const line = input[header.mac_line_start .. header.payload_offset - 1];
    if (line.len != 4 + mac_encoded_len or line[3] != ' ') return error.DataException;
    var expected: [32]u8 = undefined;
    try decodeB64(&expected, line[4..]);
    if (!std.mem.eql(u8, &mac, &expected)) return error.IntegrityException;
}

fn payloadCiphertextLen(plain_len: u64) u64 {
    const chunks = if (plain_len == 0) 1 else (plain_len + chunk_size - 1) / chunk_size;
    return 16 + plain_len + chunks * 16;
}

fn chunkNonce(counter: u64, final: bool) [12]u8 {
    var nonce: [12]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[3..11], counter, .big);
    nonce[11] = @intFromBool(final);
    return nonce;
}

fn encryptPayload(file_key: [file_key_len]u8, source: []const u8, dest: []u8) Exception!void {
    if (dest.len < payloadCiphertextLen(source.len)) return error.CapacityException;
    var nonce: [16]u8 = undefined;
    try crypto_prim.fillRandom(&nonce);
    dest[0..16].* = nonce;
    const key = payloadKey(file_key, nonce);
    var offset: usize = 16;
    var counter: u64 = 0;
    var pos: usize = 0;
    while (true) {
        const take = @min(chunk_size, source.len - pos);
        const final = pos + take == source.len;
        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(dest[offset..][0..take], &tag, source[pos..][0..take], "", chunkNonce(counter, final), key);
        dest[offset + take ..][0..16].* = tag;
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
    if (ciphertext_payload == 16) return 1;
    const n = (ciphertext_payload - 16 + chunk_size - 1) / chunk_size;
    const plain = ciphertext_payload - n * 16;
    if (n != (plain + chunk_size - 1) / chunk_size) return error.DataException;
    return n;
}

fn decryptPayload(file_key: [file_key_len]u8, source: []const u8, dest: []u8) Exception!usize {
    if (source.len < 16) return error.DataException;
    const nonce: [16]u8 = source[0..16].*;
    const key = payloadKey(file_key, nonce);
    const n = try chunkCount(source.len - 16);
    var offset: usize = 16;
    var out: usize = 0;
    for (0..n) |i| {
        const remaining = source.len - offset;
        const take = @min(chunk_size, remaining - 16);
        const final = i == n - 1;
        if (dest.len < out + take) return error.CapacityException;
        ChaCha20Poly1305.decrypt(dest[out..][0..take], source[offset..][0..take], source[offset + take ..][0..16].*, "", chunkNonce(@intCast(i), final), key) catch return error.IntegrityException;
        offset += take + 16;
        out += take;
        if (final and offset != source.len) return error.DataException;
    }
    return out;
}

fn armoredLen(binary_len: usize) usize {
    const b64_len = b64_pad.Encoder.calcSize(binary_len);
    const lines = (b64_len + 63) / 64;
    return armor_begin.len + 1 + lines * 65 + armor_end.len + 1;
}

fn armorEncode(binary: []const u8, dest: []u8) Exception!usize {
    if (dest.len < armoredLen(binary.len)) return error.CapacityException;
    var c = Cursor{ .buf = dest };
    try c.write(armor_begin ++ "\n");
    var line: [64]u8 = undefined;
    var at: usize = 0;
    while (at < binary.len) {
        const take = @min(48, binary.len - at);
        try c.write(b64_pad.Encoder.encode(&line, binary[at..][0..take]));
        try c.byte('\n');
        at += take;
    }
    try c.write(armor_end ++ "\n");
    return c.pos;
}

fn isArmorSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

// Whitespace (LF/CRLF/space/tab) may surround the PEM block; nothing else.
fn armorDecode(text: []const u8, alloc: std.mem.Allocator) Exception![]const u8 {
    const trimmed = std.mem.trim(u8, text, " \t\n\r");
    if (!std.mem.startsWith(u8, trimmed, armor_begin)) return error.DataException;
    const inner = trimmed[armor_begin.len..];
    const after_begin = if (std.mem.startsWith(u8, inner, "\r\n")) inner[2..] else blk: {
        if (!std.mem.startsWith(u8, inner, "\n")) return error.DataException;
        break :blk inner[1..];
    };
    const close = std.mem.lastIndexOf(u8, after_begin, armor_end) orelse return error.DataException;
    const payload = after_begin[0..close];
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
    const decoded_len = b64_pad.Decoder.calcSizeForSlice(cleaned[0..n]) catch return error.DataException;
    const decoded = alloc.alloc(u8, decoded_len) catch return error.ResourceException;
    b64_pad.Decoder.decode(decoded, cleaned[0..n]) catch return error.DataException;
    return decoded;
}

fn dearmor(input: []const u8, alloc: std.mem.Allocator) Exception![]const u8 {
    const trimmed = std.mem.trim(u8, input, " \t\n\r");
    if (std.mem.startsWith(u8, trimmed, armor_begin)) return armorDecode(input, alloc);
    if (std.mem.indexOf(u8, trimmed, armor_begin) != null) return error.DataException;
    return input;
}

// Parse-time allocations live in an arena over the front half of the caller
// scratch; the scrypt KDF carves its peak memory from the back half.
fn peelAndParse(input: []const u8, scratch: []u8) Exception!struct { binary: []const u8, header: Header, scrypt_scratch: []u8 } {
    const split = scratch.len / 2;
    var fba = std.heap.FixedBufferAllocator.init(scratch[0..split]);
    const binary = try dearmor(input, fba.allocator());
    const header = try parseHeader(binary, fba.allocator());
    return .{ .binary = binary, .header = header, .scrypt_scratch = scratch[split..] };
}

pub fn stanzaSize(options: Options) usize {
    if (options.password.len != 0) {
        const digits: usize = if (options.work_factor < 10) 1 else 2;
        return 10 + b64Len(16) + 1 + digits + 1 + b64Len(file_key_len + 16) + 1;
    }
    return 10 + b64Len(32) + 1 + b64Len(file_key_len + 16) + 1;
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
    var file_key: [file_key_len]u8 = undefined;
    try crypto_prim.fillRandom(&file_key);
    const stanzas = try wrapStanzas(file_key, options, fba.allocator(), scratch[split..]);
    // Both sizes address memory below, so they must fit the target.
    const header_len: usize = std.math.cast(usize, headerSize(options)) orelse return error.ResourceException;
    const payload_len: usize = std.math.cast(usize, payloadCiphertextLen(entries[0].data.len)) orelse return error.ResourceException;
    if (!options.armor) {
        const total = header_len + payload_len;
        if (output.len < total) return error.CapacityException;
        const written = try writeHeader(file_key, stanzas, output[0..header_len]);
        try encryptPayload(file_key, entries[0].data, output[written..]);
        return total;
    }
    const staging = fba.allocator().alloc(u8, header_len + payload_len) catch return error.ResourceException;
    const written = try writeHeader(file_key, stanzas, staging[0..header_len]);
    try encryptPayload(file_key, entries[0].data, staging[written..]);
    return armorEncode(staging, output);
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
    return payload.len - 16 - n * 16;
}

pub fn inspectOrdinal(input: []const u8, ordinal: u64, options: Options, scratch: []u8) Exception!EntryInfo {
    if (ordinal != 0) return error.DataException;
    return .{ .size = try decodedSize(input, options, scratch), .ordinal = 0 };
}

pub fn decodeOrdinal(input: []const u8, ordinal: u64, output: []u8, scratch: []u8, options: Options) Exception!usize {
    if (ordinal != 0) return error.DataException;
    const parsed = try peelAndParse(input, scratch);
    const file_key = try unwrapFileKey(parsed.header.stanzas, options, parsed.scrypt_scratch);
    try verifyHeaderMac(parsed.binary, parsed.header, file_key);
    return decryptPayload(file_key, parsed.binary[parsed.header.payload_offset..], output);
}
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
const vec_empty = [_]u8{};
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
    var encoded: [b64Len(plain.len)]u8 = undefined;
    try testing.expectEqualStrings("Tm9ib2R5IGluc3BlY3RzIHRoZSBzcGFtbWlzaCByZXBldGl0aW9u", b64.Encoder.encode(&encoded, plain));
    var decoded: [plain.len]u8 = undefined;
    try decodeB64(&decoded, &encoded);
    try testing.expectEqualStrings(plain, &decoded);
    // Non-canonical trailing bits in a partial group: "TW" keeps 4 bits that
    // must be zero in canonical encoding; padding is never legal unpadded.
    var one: [1]u8 = undefined;
    try testing.expectError(error.DataException, decodeB64(&one, "TW"));
    var two: [2]u8 = undefined;
    try testing.expectError(error.DataException, decodeB64(&two, "TW="));
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
    var secret: [32]u8 = undefined;
    try crypto_prim.fillRandom(&secret);
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
    const id = randomIdentity();
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
    const id = randomIdentity();
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
    const id = randomIdentity();
    var id_buf: [80]u8 = undefined;
    var rec_buf: [100]u8 = undefined;
    const written = try encode(&entries, &out, &scratch, .{ .recipient = try id.recipientString(&rec_buf) });
    var plain: [1]u8 = undefined;
    const n = try decodeOrdinal(out[0..written], 0, &plain, &scratch, .{ .identity = try id.toString(&id_buf) });
    try testing.expectEqual(@as(usize, 0), n);
}
