const std = @import("std");

const Failure = @import("failure.zig").Failure;
const sha1_seam = @import("hash/sha1/seam.zig");
const sha256_seam = @import("hash/sha256/seam.zig");
const hmac_seam = @import("hash/hmac/seam.zig");
const pbkdf2_seam = @import("hash/pbkdf2/seam.zig");
const aes_seam = @import("cipher/aes/seam.zig");

pub const block_length = 16;
pub const hmac_sha1_length = 20;
pub const winzip_verify_length = 2;
pub const winzip_hmac_length = 10;
pub const seven_zip_key_length = 32;
pub const winzip_pbkdf2_rounds = 1000;
pub const seven_zip_cycles_max = 24;
pub const seven_zip_default_cycles = 19;

pub const FailureCause = enum {
    none,
    wrong_password,
    kdf_limit,
    password_lifetime,
    unsupported_algorithm,
};

// Capability seams keep every block primitive swappable per capability; this
// glue never names an implementation directly.
pub const Sha256 = sha256_seam.Sha256;
pub const Sha1 = sha1_seam.Sha1;

pub const HmacSha1 = hmac_seam.HmacSha1;
pub const HmacSha256 = hmac_seam.HmacSha256;
pub const hmac_sha256_length = 32;

pub fn hmacSha1(out: *[hmac_sha1_length]u8, message: []const u8, key: []const u8) void {
    var hmac = HmacSha1.init(key);
    hmac.update(message);
    hmac.final(out);
}

pub fn hmacSha256(out: *[hmac_sha256_length]u8, message: []const u8, key: []const u8) void {
    var hmac = HmacSha256.init(key);
    hmac.update(message);
    hmac.final(out);
}

pub fn winzipKeyLength(strength: u8) Failure!usize {
    return switch (strength) {
        1 => 16,
        2 => 24,
        3 => 32,
        else => error.Unsupported,
    };
}

pub fn winzipSaltLength(strength: u8) Failure!usize {
    return (try winzipKeyLength(strength)) / 2;
}

// 128- and 256-bit keys take the seam contexts; 192-bit keys take the
// on-prem schedule, which std does not provide.
const BlockCipher = union(enum) {
    enc128: aes_seam.Aes128EncCtx,
    dec128: aes_seam.Aes128DecCtx,
    enc256: aes_seam.Aes256EncCtx,
    dec256: aes_seam.Aes256DecCtx,
    hw192_enc: aes_seam.Aes192Hw,
    hw192_dec: aes_seam.Aes192Hw,

    const Direction = enum { encrypt, decrypt };

    fn init(key: []const u8, comptime direction: Direction) Failure!BlockCipher {
        return switch (direction) {
            .encrypt => switch (key.len) {
                16 => .{ .enc128 = aes_seam.Aes128.initEnc(key[0..16].*) },
                24 => .{ .hw192_enc = aes_seam.Aes192Hw.initEnc(key[0..24].*) },
                32 => .{ .enc256 = aes_seam.Aes256.initEnc(key[0..32].*) },
                else => error.InvalidCall,
            },
            .decrypt => switch (key.len) {
                16 => .{ .dec128 = aes_seam.Aes128.initDec(key[0..16].*) },
                24 => .{ .hw192_dec = aes_seam.Aes192Hw.initDec(key[0..24].*) },
                32 => .{ .dec256 = aes_seam.Aes256.initDec(key[0..32].*) },
                else => error.InvalidCall,
            },
        };
    }

    fn encryptBlock(self: BlockCipher, dst: *[block_length]u8, src: *const [block_length]u8) void {
        switch (self) {
            .enc128 => |ctx| ctx.encrypt(dst, src),
            .enc256 => |ctx| ctx.encrypt(dst, src),
            .hw192_enc => |ctx| ctx.encryptBlock(dst, src),
            else => unreachable,
        }
    }

    fn decryptBlock(self: BlockCipher, dst: *[block_length]u8, src: *const [block_length]u8) void {
        switch (self) {
            .dec128 => |ctx| ctx.decrypt(dst, src),
            .dec256 => |ctx| ctx.decrypt(dst, src),
            .hw192_dec => |ctx| ctx.decryptBlock(dst, src),
            else => unreachable,
        }
    }
};

pub fn aesEncryptBlock(key: []const u8, block: [block_length]u8) Failure![block_length]u8 {
    const ctx = try BlockCipher.init(key, .encrypt);
    var out: [block_length]u8 = undefined;
    ctx.encryptBlock(&out, &block);
    return out;
}

pub fn aesDecryptBlock(key: []const u8, block: [block_length]u8) Failure![block_length]u8 {
    const ctx = try BlockCipher.init(key, .decrypt);
    var out: [block_length]u8 = undefined;
    ctx.decryptBlock(&out, &block);
    return out;
}

pub fn winzipCtr(key: []const u8, destination: []u8, source: []const u8) Failure!void {
    if (destination.len < source.len) return error.InvalidCall;
    const ctx = try BlockCipher.init(key, .encrypt);
    var counter: [block_length]u8 = @splat(0);
    counter[0] = 1;
    var offset: usize = 0;
    while (offset < source.len) : (offset += block_length) {
        var keystream: [block_length]u8 = undefined;
        ctx.encryptBlock(&keystream, &counter);
        const count = @min(block_length, source.len - offset);
        for (0..count) |index| destination[offset + index] = source[offset + index] ^ keystream[index];
        var byte_index: usize = 0;
        while (byte_index < 8) : (byte_index += 1) {
            counter[byte_index] +%= 1;
            if (counter[byte_index] != 0) break;
        }
        if (byte_index == 8) return error.ResourceLimit;
    }
    return;
}

// Operates on whole blocks only; the caller supplies the padding.
pub fn aesCbcEncrypt(key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Failure!void {
    if (source.len % block_length != 0 or destination.len < source.len) return error.InvalidCall;
    const ctx = try BlockCipher.init(key, .encrypt);
    var previous = iv;
    var offset: usize = 0;
    while (offset < source.len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        for (0..block_length) |index| block[index] = source[offset + index] ^ previous[index];
        ctx.encryptBlock(destination[offset..][0..block_length], &block);
        @memcpy(&previous, destination[offset..][0..block_length]);
    }
    return;
}

pub fn aesCbcDecrypt(key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Failure!void {
    if (source.len % block_length != 0 or destination.len < source.len) return error.InvalidCall;
    const ctx = try BlockCipher.init(key, .decrypt);
    var previous = iv;
    var offset: usize = 0;
    while (offset < source.len) : (offset += block_length) {
        // Capture the ciphertext block before writing so in-place operation
        // (7z decrypts into the same buffer) keeps the running XOR operand.
        const cipher_block: [block_length]u8 = source[offset..][0..block_length].*;
        var decrypted: [block_length]u8 = undefined;
        ctx.decryptBlock(&decrypted, &cipher_block);
        for (0..block_length) |index| destination[offset + index] = decrypted[index] ^ previous[index];
        previous = cipher_block;
    }
    return;
}

pub fn winzipDeriveKey(password: []const u8, salt: []const u8, key_length: usize, out: []u8) Failure!void {
    const derived_length = std.math.add(usize, 2 * key_length, winzip_verify_length) catch return error.ResourceLimit;
    if (out.len < derived_length) return error.InvalidCall;
    try pbkdf2HmacSha1(out[0..derived_length], password, salt, @intCast(winzip_pbkdf2_rounds));
    return;
}

pub fn sevenZipKdf(password_utf16: []const u8, salt: []const u8, num_cycles_power: u8, out_key: *[seven_zip_key_length]u8) void {
    var sha = Sha256.init(.{});
    const rounds: u64 = @as(u64, 1) << @intCast(num_cycles_power);
    var counter: [8]u8 = @splat(0);
    var index: u64 = 0;
    while (index < rounds) : (index += 1) {
        sha.update(salt);
        sha.update(password_utf16);
        std.mem.writeInt(u32, counter[0..4], @as(u32, @truncate(index)), .little);
        sha.update(&counter);
    }
    out_key.* = sha.finalResult();
}

pub fn pbkdf2HmacSha1(out: []u8, password: []const u8, salt: []const u8, rounds: u32) Failure!void {
    return pbkdf2Hmac(out, password, salt, rounds, HmacSha1);
}

pub fn pbkdf2HmacSha256(out: []u8, password: []const u8, salt: []const u8, rounds: u32) Failure!void {
    return pbkdf2Hmac(out, password, salt, rounds, HmacSha256);
}

fn pbkdf2Hmac(out: []u8, password: []const u8, salt: []const u8, rounds: u32, comptime Prf: type) Failure!void {
    pbkdf2_seam.pbkdf2(out, password, salt, rounds, Prf) catch |err| switch (err) {
        error.WeakParameters => return error.InvalidCall,
        error.OutputTooLong => return error.ResourceLimit,
    };
}

pub fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    // No early return on length mismatch: timing depends only on the public
    // lengths, never on where the contents first differ.
    var accumulator: u8 = @truncate(left.len ^ right.len);
    const common = @min(left.len, right.len);
    for (left[0..common], right[0..common]) |l, r| accumulator |= l ^ r;
    for (left[common..]) |l| accumulator |= l;
    for (right[common..]) |r| accumulator |= r;
    return accumulator == 0;
}

// Fails loudly instead of degrading to predictable material: a caller that
// cannot obtain randomness must not produce salts or IVs derived from the
// password and entry contents.
pub fn fillRandom(bytes: []u8) Failure!void {
    if (comptime @hasDecl(std.posix.system, "arc4random_buf")) {
        std.posix.system.arc4random_buf(bytes.ptr, bytes.len);
        return;
    }
    if (comptime @hasDecl(std.os.linux, "getrandom")) {
        var filled: usize = 0;
        while (filled < bytes.len) {
            const count = std.os.linux.getrandom(bytes.ptr + filled, bytes.len - filled, 0);
            if (@as(isize, @bitCast(count)) < 0) return error.InternalFailure;
            if (count == 0) return error.InternalFailure;
            filled += count;
        }
        return;
    }
    return error.Unsupported;
}

// ZipCrypto (PKWARE traditional cipher). No std equivalent exists; the key
// ladder is CRC-32 based, which is why the table lives here rather than in
// checksum.zig.
const zip_crc_table: [256]u32 = blk: {
    @setEvalBranchQuota(10_000);
    var table: [256]u32 = undefined;
    for (0..256) |i| {
        var crc: u32 = @intCast(i);
        var bit: u32 = 0;
        while (bit < 8) : (bit += 1) {
            crc = if (crc & 1 != 0) (crc >> 1) ^ 0xEDB8_8320 else crc >> 1;
        }
        table[i] = crc;
    }
    break :blk table;
};

fn zipCrcByte(crc: u32, byte: u8) u32 {
    return (crc >> 8) ^ zip_crc_table[(crc ^ byte) & 0xFF];
}

pub const ZipCryptoKeys = struct {
    key0: u32 = 0x1234_5678,
    key1: u32 = 0x2345_6789,
    key2: u32 = 0x3456_7890,

    pub fn init(password: []const u8) ZipCryptoKeys {
        var keys = ZipCryptoKeys{};
        for (password) |byte| keys.update(byte);
        return keys;
    }

    pub fn update(self: *ZipCryptoKeys, byte: u8) void {
        self.key0 = zipCrcByte(self.key0, byte);
        self.key1 = (self.key1 +% (self.key0 & 0xFF)) *% 134775813 +% 1;
        self.key2 = zipCrcByte(self.key2, @truncate(self.key1 >> 24));
    }

    pub fn decryptByte(self: *ZipCryptoKeys) u8 {
        const temp: u16 = @truncate(self.key2 | 2);
        const product = @as(u32, temp) *% (temp ^ 1);
        return @truncate(product >> 8);
    }

    pub fn encryptByte(self: *ZipCryptoKeys) u8 {
        return self.decryptByte();
    }

    pub fn encrypt(self: *ZipCryptoKeys, destination: []u8, source: []const u8) void {
        for (source, 0..) |plain, index| {
            const cipher = self.encryptByte() ^ plain;
            self.update(plain);
            destination[index] = cipher;
        }
    }

    pub fn decrypt(self: *ZipCryptoKeys, destination: []u8, source: []const u8) void {
        for (source, 0..) |cipher, index| {
            const plain = self.decryptByte() ^ cipher;
            self.update(plain);
            destination[index] = plain;
        }
    }
};

// Known-answer vectors pin the glue: FIPS 197, NIST SP 800-38A, RFC 2202,
// RFC 4231, RFC 6070, the scrypt draft, NIST SHA-256, and the 7z KDF layout
// from ip7z/7zip. Each capability's onprem file carries its own
// differential test against std.

test "sha256 known answers" {
    var h = Sha256.init(.{});
    h.update("");
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    }, &h.finalResult());
    h = Sha256.init(.{});
    h.update("abc");
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    }, &h.finalResult());
}

test "hmac known answers" {
    var out: [32]u8 = undefined;
    const key20: [20]u8 = @splat(0x0b);
    hmacSha1(out[0..20], "Hi There", &key20);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00 }, out[0..20]);
    hmacSha1(out[0..20], "what do ya want for nothing?", "Jefe");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79 }, out[0..20]);
    const key32: [32]u8 = @splat(0x0b);
    hmacSha256(&out, "Hi There", &key32);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd,
        0xc5, 0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6,
        0x8c, 0xf7,
    }, &out);
}

test "pbkdf2 known answers" {
    var out: [64]u8 = undefined;
    try pbkdf2HmacSha1(out[0..20], "password", "salt", 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6 }, out[0..20]);
    try pbkdf2HmacSha1(out[0..20], "password", "salt", 2);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57 }, out[0..20]);
    try pbkdf2HmacSha256(out[0..32], "password", "salt", 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8,
        0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b,
        0xe1, 0x7b,
    }, out[0..32]);
}

test "seven zip kdf known answers" {
    var utf16_buf: [32]u16 = undefined;
    var key: [seven_zip_key_length]u8 = undefined;
    const pw_len = std.unicode.utf8ToUtf16Le(&utf16_buf, "password123") catch unreachable;
    sevenZipKdf(std.mem.sliceAsBytes(utf16_buf[0..pw_len]), &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, 8, &key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x32, 0xd1, 0x8a, 0x13, 0x38, 0xaa, 0x7e, 0x60, 0xaa, 0x32, 0x37, 0x66, 0xfc, 0xe9, 0x25,
        0x08, 0xda, 0xa2, 0xc5, 0x47, 0x28, 0xba, 0x3b, 0x45, 0x0c, 0xce, 0xb1, 0x93, 0x35, 0xd0,
        0xa9, 0x94,
    }, &key);
    sevenZipKdf(&.{}, &.{}, 0, &key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xaf, 0x55, 0x70, 0xf5, 0xa1, 0x81, 0x0b, 0x7a, 0xf7, 0x8c, 0xaf, 0x4b, 0xc7, 0x0a, 0x66,
        0x0f, 0x0d, 0xf5, 0x1e, 0x42, 0xba, 0xf9, 0x1d, 0x4d, 0xe5, 0xb2, 0x32, 0x8d, 0xe0, 0xe8,
        0x3d, 0xfc,
    }, &key);
}

test "aes known answers" {
    const pt = [16]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const key128 = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const ct128 = try aesEncryptBlock(&key128, pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }, &ct128);
    try std.testing.expectEqualSlices(u8, &pt, &(try aesDecryptBlock(&key128, ct128)));
    const key192 = [24]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const ct192 = try aesEncryptBlock(&key192, pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }, &ct192);
    try std.testing.expectEqualSlices(u8, &pt, &(try aesDecryptBlock(&key192, ct192)));
    const key256 = [32]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const ct256 = try aesEncryptBlock(&key256, pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }, &ct256);
    try std.testing.expectEqualSlices(u8, &pt, &(try aesDecryptBlock(&key256, ct256)));
}

test "aes cbc sp800-38a" {
    const key = [32]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    };
    const iv = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plain = [32]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
    const expected = [32]u8{ 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d };
    var out: [32]u8 = undefined;
    try aesCbcEncrypt(&key, iv, &out, &plain);
    try std.testing.expectEqualSlices(u8, &expected, &out);
    var back: [32]u8 = undefined;
    try aesCbcDecrypt(&key, iv, &back, &out);
    try std.testing.expectEqualSlices(u8, &plain, &back);
}

test "mode glue matches pre-delegation behavior" {
    // These vectors pin the mode glue (counter layout, CBC chaining,
    // AES-192); any behavior change in the dispatch fails here.
    const msg = "The quick brown fox jumps over the lazy dog. PACK!";
    var key16: [16]u8 = undefined;
    for (&key16, 0..) |*b, i| b.* = @intCast(i *% 7 +% 16);
    var dst: [msg.len]u8 = undefined;
    try winzipCtr(&key16, &dst, msg);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x8b, 0x58, 0x99, 0x67, 0x98, 0x0b, 0xa7, 0x73, 0x3c, 0x19, 0xbd, 0xf8, 0xa9, 0x81, 0xd8,
        0x85, 0xea, 0xb5, 0x32, 0xf9, 0xaf, 0x46, 0x93, 0x6b, 0x88, 0x7d, 0x5a, 0xee, 0x39, 0xf0,
        0xf1, 0xe2, 0x0d, 0x19, 0x24, 0x5e, 0x85, 0xdc, 0x00, 0xad, 0x71, 0x2f, 0xb9, 0x45, 0x8c,
        0x22, 0x41, 0x55, 0x8c, 0x3b,
    }, &dst);
}

test "cbc decrypt operates in place" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i *% 3 +% 1);
    var iv: [16]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @intCast(i *% 5 +% 2);
    const plain = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    var buf: [32]u8 = undefined;
    try aesCbcEncrypt(&key, iv, &buf, plain);
    const ciphertext = buf;
    var isolated: [32]u8 = undefined;
    try aesCbcDecrypt(&key, iv, &isolated, &ciphertext);
    try aesCbcDecrypt(&key, iv, &buf, &buf);
    try std.testing.expectEqualSlices(u8, &isolated, &buf);
    try std.testing.expectEqualSlices(u8, plain, &buf);
}

test "zipcrypto roundtrip" {
    var keys = ZipCryptoKeys.init("password");
    const msg = "hello world, zip crypto!";
    var cipher: [msg.len]u8 = undefined;
    var keys_enc = keys;
    keys_enc.encrypt(&cipher, msg);
    var plain: [msg.len]u8 = undefined;
    keys.decrypt(&plain, &cipher);
    try std.testing.expectEqualSlices(u8, msg, &plain);
}

test "constant time equal" {
    try std.testing.expect(constantTimeEqual("abc", "abc"));
    try std.testing.expect(!constantTimeEqual("abc", "abd"));
    try std.testing.expect(!constantTimeEqual("abc", "abcd"));
    try std.testing.expect(!constantTimeEqual("", "a"));
    try std.testing.expect(constantTimeEqual("", ""));
}
