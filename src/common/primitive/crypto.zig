const builtin = @import("builtin");
const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const aes_seam = @import("cipher/aes/seam.zig");
const hmac_seam = @import("hash/hmac/seam.zig");
const pbkdf2_seam = @import("hash/pbkdf2/seam.zig");
const sha1_seam = @import("hash/sha1/seam.zig");
const sha256_seam = @import("hash/sha256/seam.zig");
const Exception = @import("exception.zig").Exception;

pub const Provider = seam.Provider;
pub const default_provider = seam.default_provider;
pub const HmacSha1 = hmac_seam.HmacSha1;
pub const HmacSha256 = hmac_seam.HmacSha256;
pub const Sha1 = sha1_seam.Sha1;
// Capability seams keep every block primitive swappable; this glue never
// names an implementation directly.
pub const Sha256 = sha256_seam.Sha256;

pub const block_length = 16;
pub const hmac_sha1_length = 20;
pub const hmac_sha256_length = 32;
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

pub fn hmacWith(comptime H: type, provider: Provider, out: *[H.mac_length]u8, message: []const u8, key: []const u8) void {
    var hmac = H.bind(provider, key);
    hmac.update(message);
    hmac.final(out);
}

pub fn hmacSha1(provider: Provider, out: *[hmac_sha1_length]u8, message: []const u8, key: []const u8) void {
    hmacWith(HmacSha1, provider, out, message, key);
}

pub fn hmacSha256(provider: Provider, out: *[hmac_sha256_length]u8, message: []const u8, key: []const u8) void {
    hmacWith(HmacSha256, provider, out, message, key);
}

pub fn winzipKeyLength(strength: u8) Exception!usize {
    return switch (strength) {
        1 => 16,
        2 => 24,
        3 => 32,
        else => error.UnsupportedException,
    };
}

pub fn winzipSaltLength(strength: u8) Exception!usize {
    return (try winzipKeyLength(strength)) / 2;
}

pub const Direction = enum { encrypt, decrypt };

// 192-bit keys use the on-prem schedule (no stdlib arm); direction is a
// comptime parameter, so cross-direction calls are compile errors.
fn BlockCipher(comptime S: type, comptime direction: Direction) type {
    const method = if (direction == .encrypt) "encrypt" else "decrypt";
    return union(enum) {
        bits128: if (direction == .encrypt) S.Enc128 else S.Dec128,
        bits192: aes_seam.Aes192,
        bits256: if (direction == .encrypt) S.Enc256 else S.Dec256,

        fn init(key: []const u8) Exception!@This() {
            return switch (key.len) {
                16 => .{ .bits128 = switch (direction) {
                    .encrypt => S.Enc128.init(key[0..16].*),
                    .decrypt => S.Dec128.init(key[0..16].*),
                } },
                24 => .{ .bits192 = switch (direction) {
                    .encrypt => aes_seam.Aes192.initEnc(key[0..24].*),
                    .decrypt => aes_seam.Aes192.initDec(key[0..24].*),
                } },
                32 => .{ .bits256 = switch (direction) {
                    .encrypt => S.Enc256.init(key[0..32].*),
                    .decrypt => S.Dec256.init(key[0..32].*),
                } },
                else => error.CallException,
            };
        }

        fn cryptBlock(self: @This(), dst: *[block_length]u8, src: *const [block_length]u8) void {
            switch (self) {
                inline else => |ctx| @call(.auto, @field(@TypeOf(ctx), method), .{ ctx, dst, src }),
            }
        }

        fn cryptWide4(self: @This(), dst: *[64]u8, src: *const [64]u8) void {
            switch (self) {
                inline else => |ctx| @call(.auto, @field(@TypeOf(ctx), method ++ "Wide4"), .{ ctx, dst, src }),
            }
        }
    };
}

fn aesBlockWith(comptime S: type, comptime direction: Direction, key: []const u8, block: [block_length]u8) Exception![block_length]u8 {
    const ctx = try BlockCipher(S, direction).init(key);
    var out: [block_length]u8 = undefined;
    ctx.cryptBlock(&out, &block);
    return out;
}

fn assertFixed(provider: Provider) void {
    std.debug.assert(provider == default_provider);
}

// Mergeable builds bind the provider per call; fixed builds assert it;
// every entry point shares this shape.
fn forBothArms(
    comptime impl_flag: anytype,
    provider: Provider,
    comptime with: anytype,
    comptime fixed: type,
    comptime onprem: type,
    comptime offprem: type,
    args: anytype,
) @TypeOf(@call(.auto, with, .{fixed} ++ args)) {
    if (comptime impl_flag == .mergeable) {
        return switch (provider) {
            .onprem => @call(.auto, with, .{onprem} ++ args),
            .offprem => @call(.auto, with, .{offprem} ++ args),
        };
    }
    assertFixed(provider);
    return @call(.auto, with, .{fixed} ++ args);
}

fn aesBlock(comptime direction: Direction, provider: Provider, key: []const u8, block: [block_length]u8) Exception![block_length]u8 {
    return forBothArms(options.aes_impl, provider, aesBlockWith, aes_seam.suite, aes_seam.suite_onprem, aes_seam.suite_offprem, .{ direction, key, block });
}

pub fn aesEncryptBlock(provider: Provider, key: []const u8, block: [block_length]u8) Exception![block_length]u8 {
    return aesBlock(.encrypt, provider, key, block);
}

pub fn aesDecryptBlock(provider: Provider, key: []const u8, block: [block_length]u8) Exception![block_length]u8 {
    return aesBlock(.decrypt, provider, key, block);
}

fn winzipCtrWith(comptime S: type, key: []const u8, destination: []u8, source: []const u8) Exception!void {
    if (destination.len < source.len) return error.CallException;
    const ctx = try BlockCipher(S, .encrypt).init(key);
    var counter: [block_length]u8 = @splat(0);
    counter[0] = 1;
    var offset: usize = 0;
    // Four counters per group hide the aese latency (std ctrSlice parallel shape).
    if (comptime @hasDecl(S.Enc128, "encryptWide4")) {
        var lo = std.mem.readInt(u64, counter[0..8], .little);
        while (offset + 64 <= source.len and lo <= std.math.maxInt(u64) - 4) {
            var counters: [64]u8 = undefined;
            inline for (0..4) |j| {
                counters[j * block_length ..][0..block_length].* = counter;
                std.mem.writeInt(u64, counters[j * block_length ..][0..8], lo +% j, .little);
            }
            var keystream: [64]u8 = undefined;
            ctx.cryptWide4(&keystream, &counters);
            for (0..64) |index| destination[offset + index] = source[offset + index] ^ keystream[index];
            offset += 64;
            lo += 4;
            std.mem.writeInt(u64, counter[0..8], lo, .little);
        }
    }
    while (offset < source.len) : (offset += block_length) {
        var keystream: [block_length]u8 = undefined;
        ctx.cryptBlock(&keystream, &counter);
        const count = @min(block_length, source.len - offset);
        for (0..count) |index| destination[offset + index] = source[offset + index] ^ keystream[index];
        // The counter is little-endian, so the carry walks from index 0;
        // the low u64 cannot overflow within one stream.
        var byte_index: usize = 0;
        while (byte_index < 8) : (byte_index += 1) {
            counter[byte_index] +%= 1;
            if (counter[byte_index] != 0) break;
        }
        if (byte_index == 8) return error.ResourceException;
    }
}

pub fn winzipCtr(provider: Provider, key: []const u8, destination: []u8, source: []const u8) Exception!void {
    return forBothArms(options.aes_impl, provider, winzipCtrWith, aes_seam.suite, aes_seam.suite_onprem, aes_seam.suite_offprem, .{ key, destination, source });
}

// Operates on whole blocks only; the caller supplies the padding.
fn aesCbcEncryptWith(comptime S: type, key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Exception!void {
    if (source.len % block_length != 0 or destination.len < source.len) return error.CallException;
    const ctx = try BlockCipher(S, .encrypt).init(key);
    var previous = iv;
    var offset: usize = 0;
    while (offset < source.len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        for (0..block_length) |index| block[index] = source[offset + index] ^ previous[index];
        ctx.cryptBlock(destination[offset..][0..block_length], &block);
        @memcpy(&previous, destination[offset..][0..block_length]);
    }
    return;
}

fn aesCbcWith(comptime S: type, comptime direction: Direction, key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Exception!void {
    return switch (direction) {
        .encrypt => aesCbcEncryptWith(S, key, iv, destination, source),
        .decrypt => aesCbcDecryptWith(S, key, iv, destination, source),
    };
}

fn aesCbc(comptime direction: Direction, provider: Provider, key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Exception!void {
    return forBothArms(options.aes_impl, provider, aesCbcWith, aes_seam.suite, aes_seam.suite_onprem, aes_seam.suite_offprem, .{ direction, key, iv, destination, source });
}

pub fn aesCbcEncrypt(provider: Provider, key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Exception!void {
    return aesCbc(.encrypt, provider, key, iv, destination, source);
}

fn aesCbcDecryptWith(comptime S: type, key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Exception!void {
    if (source.len % block_length != 0 or destination.len < source.len) return error.CallException;
    const ctx = try BlockCipher(S, .decrypt).init(key);
    var previous = iv;
    var offset: usize = 0;
    // Four blocks in parallel hide the aesd latency; ciphertexts are staged
    // first so in-place operation keeps the chaining operand.
    if (comptime @hasDecl(S.Dec128, "decryptWide4")) {
        while (offset + 64 <= source.len) {
            var cipher: [64]u8 = undefined;
            @memcpy(&cipher, source[offset..][0..64]);
            var raw: [64]u8 = undefined;
            ctx.cryptWide4(&raw, &cipher);
            for (0..block_length) |index| destination[offset + index] = raw[index] ^ previous[index];
            for (block_length..64) |index| destination[offset + index] = raw[index] ^ cipher[index - block_length];
            @memcpy(&previous, cipher[48..64]);
            offset += 64;
        }
    }
    while (offset < source.len) : (offset += block_length) {
        // Capture the ciphertext block before writing so in-place operation
        // (7z decrypts into the same buffer) keeps the running XOR operand.
        const cipher_block: [block_length]u8 = source[offset..][0..block_length].*;
        var decrypted: [block_length]u8 = undefined;
        ctx.cryptBlock(&decrypted, &cipher_block);
        for (0..block_length) |index| destination[offset + index] = decrypted[index] ^ previous[index];
        previous = cipher_block;
    }
    return;
}

pub fn aesCbcDecrypt(provider: Provider, key: []const u8, iv: [block_length]u8, destination: []u8, source: []const u8) Exception!void {
    return aesCbc(.decrypt, provider, key, iv, destination, source);
}

pub fn winzipDeriveKey(provider: Provider, password: []const u8, salt: []const u8, key_length: usize, out: []u8) Exception!void {
    const derived_length = std.math.add(usize, 2 * key_length, winzip_verify_length) catch return error.ResourceException;
    if (out.len < derived_length) return error.CallException;
    try pbkdf2HmacSha1(provider, out[0..derived_length], password, salt, @intCast(winzip_pbkdf2_rounds));
    return;
}

fn sevenZipKdfWith(comptime Sha: type, password_utf16: []const u8, salt: []const u8, num_cycles_power: u8, out_key: *[seven_zip_key_length]u8) void {
    // The 7z writer format caps this at 24; beyond 63 the shift is undefined.
    std.debug.assert(num_cycles_power <= seven_zip_cycles_max);
    var sha = Sha.init(.{});
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

pub fn sevenZipKdf(provider: Provider, password_utf16: []const u8, salt: []const u8, num_cycles_power: u8, out_key: *[seven_zip_key_length]u8) void {
    return forBothArms(options.sha256_impl, provider, sevenZipKdfWith, sha256_seam.Sha256, sha256_seam.Onprem, sha256_seam.Offprem, .{ password_utf16, salt, num_cycles_power, out_key });
}

pub fn pbkdf2HmacSha1(provider: Provider, out: []u8, password: []const u8, salt: []const u8, rounds: u32) Exception!void {
    return pbkdf2Hmac(hmac_seam.HmacSha1Onprem, hmac_seam.HmacSha1Offprem, provider, out, password, salt, rounds);
}

pub fn pbkdf2HmacSha256(provider: Provider, out: []u8, password: []const u8, salt: []const u8, rounds: u32) Exception!void {
    return pbkdf2Hmac(hmac_seam.HmacSha256Onprem, hmac_seam.HmacSha256Offprem, provider, out, password, salt, rounds);
}

fn pbkdf2Hmac(comptime PrfOnprem: type, comptime PrfOffprem: type, provider: Provider, out: []u8, password: []const u8, salt: []const u8, rounds: u32) Exception!void {
    pbkdf2_seam.pbkdf2(PrfOnprem, PrfOffprem, provider, out, password, salt, rounds) catch |err| switch (err) {
        error.WeakParameters => return error.CallException,
        error.OutputTooLong => return error.ResourceException,
    };
}

pub fn constantTimeEql(first: []const u8, second: []const u8) bool {
    // No early return on length mismatch: timing depends only on the public
    // lengths, never on where the contents first differ.
    var accumulator: usize = first.len ^ second.len;
    const common = @min(first.len, second.len);
    for (first[0..common], second[0..common]) |l, r| accumulator |= l ^ r;
    for (first[common..]) |l| accumulator |= l;
    for (second[common..]) |r| accumulator |= r;
    return accumulator == 0;
}

// BCryptGenRandom is a frozen Windows extern; the system-preferred RNG flag
// skips the algorithm provider, so no handle stays open.
extern "bcrypt" fn BCryptGenRandom(
    h_algorithm: ?*anyopaque,
    buffer: [*]u8,
    buffer_len: c_ulong,
    flags: c_ulong,
) callconv(.winapi) std.os.windows.NTSTATUS;
const bcrypt_use_system_preferred_rng: c_ulong = 0x00000002;

// Failing loudly beats predictable fallbacks: salts and IVs must never
// degrade to password-derived material.
pub fn fillRandom(bytes: []u8) Exception!void {
    // The decl resolves to void where libc lacks the symbol.
    if (comptime @hasDecl(std.posix.system, "arc4random_buf") and
        @TypeOf(std.posix.system.arc4random_buf) != void)
    {
        std.posix.system.arc4random_buf(bytes.ptr, bytes.len);
        return;
    }
    // std.os.linux declares getrandom on every target; the syscall ABI exists
    // only on linux-family tags, OpenHarmony included.
    if (comptime builtin.os.tag == .linux) {
        var filled: usize = 0;
        while (filled < bytes.len) {
            const count = std.os.linux.getrandom(bytes.ptr + filled, bytes.len - filled, 0);
            switch (std.os.linux.errno(count)) {
                .INTR => continue,
                // Zero progress cannot happen for a nonzero request; fail
                // rather than spin.
                .SUCCESS => if (count == 0) {
                    return error.InternalException;
                },
                else => return error.InternalException,
            }
            filled += count;
        }
        return;
    }
    // Windows ships no POSIX RNG entry point; BCryptGenRandom fills the
    // buffer in one call and needs no provider handle.
    if (comptime builtin.os.tag == .windows) {
        if (bytes.len == 0) return;
        const status = BCryptGenRandom(null, bytes.ptr, @intCast(bytes.len), bcrypt_use_system_preferred_rng);
        if (status != .SUCCESS) return error.InternalException;
        return;
    }
    return error.UnsupportedException;
}

test "fill random accepts every length class" {
    // Lengths cover the syscall-chunked, zero-request, and arc4random paths,
    // so a broken retry or gate fails here.
    var buf: [65]u8 = undefined;
    for (0..buf.len + 1) |len| try fillRandom(buf[0..len]);
    try fillRandom(&buf);
    // A stubbed or repeated fill repeats; real entropy does not.
    var again: [65]u8 = undefined;
    try fillRandom(&again);
    try std.testing.expect(!std.mem.eql(u8, &buf, &again));
}

// ZipCrypto (PKWARE traditional cipher): the CRC-32-based key ladder has no
// stdlib equivalent; it reuses the shared reflected CRC-32 table.
const zip_crc_table = seam.byteTable(u32, 0xEDB8_8320, true);

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
        const product: u32 = @as(u32, temp) *% (temp ^ 1);
        return @truncate(product >> 8);
    }

    // ZipCrypto is its own inverse: the plaintext advances the key ladder;
    // only its source differs per direction.
    pub fn encrypt(self: *ZipCryptoKeys, destination: []u8, source: []const u8) void {
        for (source, destination) |plain, *out| {
            out.* = self.decryptByte() ^ plain;
            self.update(plain);
        }
    }

    pub fn decrypt(self: *ZipCryptoKeys, destination: []u8, source: []const u8) void {
        for (source, destination) |cipher, *out| {
            out.* = self.decryptByte() ^ cipher;
            self.update(out.*);
        }
    }
};

// Glue KATs: FIPS 197, NIST SP 800-38A, RFC 2202, RFC 4231, RFC 6070,
// scrypt draft, SHA-256, 7z KDF (7-Zip).

test "mergeable digest binds both providers to the same contract" {
    if (options.sha256_impl != .mergeable) return error.SkipZigTest;
    const input = "the seam carries both providers";
    var bound_onprem = sha256_seam.Sha256.bind(.onprem, .{});
    bound_onprem.update(input);
    var bound_offprem = sha256_seam.Sha256.bind(.offprem, .{});
    bound_offprem.update(input);
    try std.testing.expectEqualSlices(u8, &bound_onprem.finalResult(), &bound_offprem.finalResult());
}

test "fixed digest bind rejects the other provider" {
    if (options.sha256_impl == .mergeable) return error.SkipZigTest;
    const fixed_tag: Provider = switch (options.sha256_impl) {
        .onprem => .onprem,
        .offprem => .offprem,
        else => unreachable,
    };
    var bound = sha256_seam.Sha256.bind(fixed_tag, .{});
    bound.update("abc");
    const via_bind = bound.finalResult();
    var plain = sha256_seam.Sha256.init(.{});
    plain.update("abc");
    try std.testing.expectEqualSlices(u8, &plain.finalResult(), &via_bind);
}

test "sha256 matches fips vectors" {
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

test "hmac matches rfc 2202 vectors" {
    var out: [32]u8 = undefined;
    const key20: [20]u8 = @splat(0x0b);
    hmacSha1(default_provider, out[0..20], "Hi There", &key20);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00 }, out[0..20]);
    hmacSha1(default_provider, out[0..20], "what do ya want for nothing?", "Jefe");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79 }, out[0..20]);
    const key32: [32]u8 = @splat(0x0b);
    hmacSha256(default_provider, &out, "Hi There", &key32);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd,
        0xc5, 0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6,
        0x8c, 0xf7,
    }, &out);
}

test "pbkdf2 matches rfc 6070 vectors" {
    var out: [64]u8 = undefined;
    try pbkdf2HmacSha1(default_provider, out[0..20], "password", "salt", 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6 }, out[0..20]);
    try pbkdf2HmacSha1(default_provider, out[0..20], "password", "salt", 2);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57 }, out[0..20]);
    try pbkdf2HmacSha256(default_provider, out[0..32], "password", "salt", 1);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8,
        0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b,
        0xe1, 0x7b,
    }, out[0..32]);
}

test "seven zip kdf matches vendor vectors" {
    var utf16_buf: [32]u16 = undefined;
    var key: [seven_zip_key_length]u8 = undefined;
    const pw_len = std.unicode.utf8ToUtf16Le(&utf16_buf, "password123") catch unreachable;
    sevenZipKdf(default_provider, std.mem.sliceAsBytes(utf16_buf[0..pw_len]), &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, 8, &key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x32, 0xd1, 0x8a, 0x13, 0x38, 0xaa, 0x7e, 0x60, 0xaa, 0x32, 0x37, 0x66, 0xfc, 0xe9, 0x25,
        0x08, 0xda, 0xa2, 0xc5, 0x47, 0x28, 0xba, 0x3b, 0x45, 0x0c, 0xce, 0xb1, 0x93, 0x35, 0xd0,
        0xa9, 0x94,
    }, &key);
    sevenZipKdf(default_provider, &.{}, &.{}, 0, &key);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xaf, 0x55, 0x70, 0xf5, 0xa1, 0x81, 0x0b, 0x7a, 0xf7, 0x8c, 0xaf, 0x4b, 0xc7, 0x0a, 0x66,
        0x0f, 0x0d, 0xf5, 0x1e, 0x42, 0xba, 0xf9, 0x1d, 0x4d, 0xe5, 0xb2, 0x32, 0x8d, 0xe0, 0xe8,
        0x3d, 0xfc,
    }, &key);
}

test "aes matches fips 197 vectors" {
    const pt = [16]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const key128 = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const ct128 = try aesEncryptBlock(default_provider, &key128, pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }, &ct128);
    try std.testing.expectEqualSlices(u8, &pt, &(try aesDecryptBlock(default_provider, &key128, ct128)));
    const key192 = [24]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const ct192 = try aesEncryptBlock(default_provider, &key192, pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }, &ct192);
    try std.testing.expectEqualSlices(u8, &pt, &(try aesDecryptBlock(default_provider, &key192, ct192)));
    const key256 = [32]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const ct256 = try aesEncryptBlock(default_provider, &key256, pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }, &ct256);
    try std.testing.expectEqualSlices(u8, &pt, &(try aesDecryptBlock(default_provider, &key256, ct256)));
}

test "aes cbc matches sp800-38a vectors" {
    const key = [32]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    };
    const iv = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plain = [32]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
    const expected = [32]u8{ 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d };
    var out: [32]u8 = undefined;
    try aesCbcEncrypt(default_provider, &key, iv, &out, &plain);
    try std.testing.expectEqualSlices(u8, &expected, &out);
    var back: [32]u8 = undefined;
    try aesCbcDecrypt(default_provider, &key, iv, &back, &out);
    try std.testing.expectEqualSlices(u8, &plain, &back);
}

test "hmac matches wycheproof vectors" {
    // Source: wycheproof testvectors_v1 (google-wycheproof):
    // hmac_sha256_test.json, hmac_sha1_test.json. Truncated-tag cases compare the tag prefix.
    const Case = struct { key: []const u8, msg: []const u8, tag: []const u8 };
    // tcId 1: empty message.
    const wkey256_1 = [_]u8{
        0x1e, 0x22, 0x5c, 0xaf, 0xb9, 0x03, 0x39, 0xbb, 0xa1, 0xb2, 0x40, 0x76, 0xd4, 0x20, 0x6c, 0x3e,
        0x79, 0xc3, 0x55, 0x80, 0x5d, 0x85, 0x16, 0x82, 0xbc, 0x81, 0x8b, 0xaa, 0x4f, 0x5a, 0x77, 0x79,
    };
    const wmsg256_1 = [_]u8{};
    const wtag256_1 = [_]u8{
        0xb1, 0x75, 0xb5, 0x7d, 0x89, 0xea, 0x6c, 0xb6, 0x06, 0xfb, 0x33, 0x63, 0xf2, 0x53, 0x8a, 0xbd,
        0x73, 0xa4, 0xc0, 0x0b, 0x4a, 0x13, 0x86, 0x90, 0x5b, 0xac, 0x80, 0x90, 0x04, 0xcf, 0x19, 0x33,
    };
    // tcId 2: short message.
    const wkey256_2 = [_]u8{
        0x81, 0x59, 0xfd, 0x15, 0x13, 0x3c, 0xd9, 0x64, 0xc9, 0xa6, 0x96, 0x4c, 0x94, 0xf0, 0xea, 0x26,
        0x9a, 0x80, 0x6f, 0xd9, 0xf4, 0x3f, 0x0d, 0xa5, 0x8b, 0x6c, 0xd1, 0xb3, 0x3d, 0x18, 0x9b, 0x2a,
    };
    const wmsg256_2 = [_]u8{
        0x77,
    };
    const wtag256_2 = [_]u8{
        0xdf, 0xc5, 0x10, 0x5d, 0x5e, 0xec, 0xf7, 0xae, 0x7b, 0x8b, 0x8d, 0xe3, 0x93, 0x0e, 0x76, 0x59,
        0xe8, 0x4c, 0x41, 0x72, 0xf2, 0x55, 0x51, 0x42, 0xf1, 0xe5, 0x68, 0xfc, 0x18, 0x72, 0xad, 0x93,
    };
    // tcId 3: short message.
    const wkey256_3 = [_]u8{
        0x85, 0xa7, 0xcb, 0xaa, 0xe8, 0x25, 0xbb, 0x82, 0xc9, 0xb6, 0xf6, 0xc5, 0xc2, 0xaf, 0x5a, 0xc0,
        0x3d, 0x1f, 0x6d, 0xaa, 0x63, 0xd2, 0xa9, 0x3c, 0x18, 0x99, 0x48, 0xec, 0x41, 0xb9, 0xde, 0xd9,
    };
    const wmsg256_3 = [_]u8{
        0xa5, 0x9b,
    };
    const wtag256_3 = [_]u8{
        0x0f, 0xe2, 0xf1, 0x3b, 0xba, 0x21, 0x98, 0xf6, 0xdd, 0xa1, 0xa0, 0x84, 0xbe, 0x92, 0x8e, 0x30,
        0x4e, 0x9c, 0xb1, 0x6a, 0x56, 0xbc, 0x0b, 0x7b, 0x93, 0x9a, 0x07, 0x32, 0x80, 0x24, 0x43, 0x73,
    };
    // tcId 4: short message.
    const wkey256_4 = [_]u8{
        0x48, 0xf3, 0x02, 0x93, 0x34, 0xe5, 0x5c, 0xfb, 0xd5, 0x74, 0xcc, 0xc7, 0x65, 0xfb, 0x2c, 0x36,
        0x85, 0xaa, 0xb1, 0xf4, 0x83, 0x7d, 0x23, 0x37, 0x08, 0x74, 0xa3, 0xe6, 0x34, 0xc3, 0xa7, 0x6d,
    };
    const wmsg256_4 = [_]u8{
        0xc7, 0xb8, 0xb2,
    };
    const wtag256_4 = [_]u8{
        0x6c, 0x13, 0xf7, 0x9b, 0xb2, 0xd5, 0xb6, 0xf9, 0xa3, 0x15, 0xfe, 0x8f, 0xd6, 0xcb, 0xb5, 0xcb,
        0x81, 0x7a, 0x66, 0x06, 0x87, 0x00, 0x9d, 0xec, 0xcd, 0x88, 0xc3, 0x77, 0x42, 0x9e, 0x59, 0x6d,
    };
    // tcId 5: short message.
    const wkey256_5 = [_]u8{
        0xde, 0x8b, 0x5b, 0x5b, 0x2f, 0x09, 0x64, 0x5b, 0xe4, 0x7e, 0xcb, 0x64, 0x07, 0xa4, 0xe1, 0xd9,
        0xc6, 0xb3, 0x3a, 0xe3, 0xc2, 0xd2, 0x25, 0x17, 0xd3, 0x35, 0x7d, 0xa0, 0x35, 0x7a, 0x31, 0x39,
    };
    const wmsg256_5 = [_]u8{
        0xcc, 0x02, 0x1d, 0x65,
    };
    const wtag256_5 = [_]u8{
        0xe8, 0x75, 0x38, 0xeb, 0x16, 0x7e, 0x62, 0xd7, 0xcb, 0x23, 0x66, 0x90, 0xff, 0x3f, 0x03, 0x4a,
        0x9c, 0x12, 0xd4, 0x17, 0xaa, 0x8d, 0xfa, 0x69, 0x4d, 0x74, 0x05, 0xf9, 0xe1, 0xf8, 0x5f, 0xe8,
    };
    // tcId 6: short message.
    const wkey256_6 = [_]u8{
        0xb7, 0x93, 0x89, 0x10, 0xf5, 0x18, 0xf1, 0x32, 0x05, 0xca, 0x14, 0x92, 0xc6, 0x69, 0x00, 0x1a,
        0x14, 0xff, 0x91, 0x3c, 0x8a, 0xb4, 0xa0, 0xdc, 0x35, 0x64, 0xe7, 0x41, 0x8e, 0x91, 0x29, 0x7c,
    };
    const wmsg256_6 = [_]u8{
        0xa4, 0xa6, 0xef, 0x6e, 0xbd,
    };
    const wtag256_6 = [_]u8{
        0x01, 0xa9, 0x3f, 0x4e, 0xd2, 0x16, 0xd0, 0xb2, 0x80, 0x89, 0x63, 0x01, 0xe3, 0x66, 0xaa, 0x67,
        0xb2, 0x5e, 0x6b, 0x6a, 0x5a, 0x6e, 0x84, 0xf2, 0x91, 0xa1, 0x33, 0x91, 0xc6, 0xe4, 0x96, 0xc5,
    };
    // tcId 27: long message.
    const wkey256_27 = [_]u8{
        0xd1, 0x15, 0xac, 0xc9, 0xa6, 0x36, 0x91, 0x52, 0x41, 0x79, 0x5f, 0x48, 0x85, 0x20, 0x52, 0xe0,
        0x7b, 0x51, 0x27, 0x3a, 0xe2, 0x44, 0x82, 0x51, 0xec, 0x1d, 0x0d, 0x0f, 0x98, 0x07, 0xf3, 0xdb,
    };
    const wmsg256_27 = [_]u8{
        0x69, 0x6d, 0x24, 0x56, 0xde, 0x85, 0x3f, 0xa0, 0x28, 0xf4, 0x86, 0xfe, 0xf4, 0x37, 0xb6, 0xb6,
        0xd1, 0xb5, 0x30, 0xa8, 0x47, 0x5e, 0x29, 0x9d, 0xb3, 0xa9, 0x00, 0x5a, 0xe9, 0xce, 0xf8, 0x40,
        0x19, 0x85, 0xb7, 0xd3, 0x1e, 0x17, 0x2e, 0x8f, 0x43, 0x9c, 0xcd, 0x1a, 0xd1, 0xec, 0x44, 0xc9,
        0xb8, 0x6b, 0x78, 0xf3, 0xf2, 0x43, 0xc1, 0x30, 0x5b, 0x53, 0xbc, 0x21, 0xab, 0xad, 0x7a, 0x8f,
        0xc5, 0x25, 0x63, 0x11, 0xbf, 0xd3, 0x4c, 0x98, 0xe3, 0x7d, 0xfd, 0xc6, 0x49, 0xe7, 0xae, 0x4b,
        0xda, 0x08, 0xcf, 0x29, 0x94, 0xb0, 0x63, 0xc0, 0xc7, 0x10, 0x6e, 0xd0, 0xb0, 0x2a, 0x1f, 0x48,
        0xaf, 0x91, 0x91, 0xcb, 0xfb, 0x0d, 0x6a, 0x95, 0x3b, 0x7e, 0x04, 0x32, 0x7d, 0xfe, 0x8c, 0x93,
        0x77, 0x9c, 0xb5, 0x74, 0xba, 0x9c, 0xba, 0x57, 0x5d, 0x01, 0x67, 0x4e, 0x83, 0x62, 0x1a, 0xa0,
        0xc5, 0xf4, 0x00, 0xd6, 0xe6, 0xcd, 0x24, 0xb3, 0x01, 0xe3, 0x3c, 0x9f, 0x33, 0x03, 0xe7, 0x3b,
        0xf3, 0x57, 0x40, 0x8c, 0x1b, 0xe8, 0x6c, 0x24, 0x89, 0xc0, 0x9d, 0xe9, 0x98, 0xff, 0x2e, 0xf3,
        0x2d, 0xf5, 0x54, 0xf1, 0x24, 0x7d, 0x93, 0x13, 0xce, 0x1a, 0x71, 0x60, 0x11, 0x5d, 0x06, 0xf4,
        0xc1, 0x8d, 0x65, 0x56, 0xff, 0x79, 0x86, 0xef, 0x8a, 0x55, 0xe2, 0xad, 0xcf, 0xa2, 0x7e, 0x4c,
        0x69, 0xc7, 0x1c, 0xc2, 0xff, 0x01, 0x63, 0x9e, 0x9d, 0x49, 0xbd, 0x9e, 0xd0, 0x68, 0x7f, 0x53,
        0x0f, 0xfe, 0xb0, 0x89, 0x01, 0x32, 0x45, 0x7d, 0xf2, 0x08, 0x80, 0x81, 0xbc, 0x4a, 0x2f, 0x7f,
        0x0a, 0x9f, 0x4d, 0xce, 0xa2, 0xc8, 0x0d, 0x99, 0x1d, 0xb7, 0xf3, 0x74, 0x7a, 0x18, 0x03, 0xd7,
        0x61, 0x9a, 0xaf, 0x3d, 0xd3, 0x82, 0xc6, 0x95, 0x36, 0xa0, 0xbc, 0xdb, 0x93, 0x1c, 0xbe,
    };
    const wtag256_27 = [_]u8{
        0x82, 0xf9, 0x29, 0x77, 0xf0, 0xb6, 0x05, 0xea, 0xad, 0xa5, 0x10, 0xff, 0xce, 0xb5, 0x3a, 0xd7,
        0x5f, 0xde, 0x16, 0xa8, 0x02, 0x9f, 0x1b, 0x75, 0xb4, 0x06, 0xa8, 0x42, 0x70, 0xdb, 0xb8, 0xb7,
    };
    // tcId 82: empty message.
    const wkey256_82 = [_]u8{
        0x7b, 0xf9, 0xe5, 0x36, 0xb6, 0x6a, 0x21, 0x5c, 0x22, 0x23, 0x3f, 0xe2, 0xda, 0xaa, 0x74, 0x3a,
        0x89, 0x8b, 0x9a, 0xcb, 0x9f, 0x78, 0x02, 0xde, 0x70, 0xb4, 0x0e, 0x3d, 0x6e, 0x43, 0xef, 0x97,
    };
    const wmsg256_82 = [_]u8{};
    const wtag256_82 = [_]u8{
        0xf4, 0x60, 0x55, 0x85, 0x94, 0x97, 0x47, 0xde, 0x26, 0xf3, 0xee, 0x98, 0xa7, 0x38, 0xb1, 0x72,
    };
    // tcId 83: short message.
    const wkey256_83 = [_]u8{
        0xe7, 0x54, 0x07, 0x6c, 0xea, 0xb3, 0xfd, 0xaf, 0x4f, 0x9b, 0xca, 0xb7, 0xd4, 0xf0, 0xdf, 0x0c,
        0xbb, 0xaf, 0xbc, 0x87, 0x73, 0x1b, 0x8f, 0x9b, 0x7c, 0xd2, 0x16, 0x64, 0x72, 0xe8, 0xee, 0xbc,
    };
    const wmsg256_83 = [_]u8{
        0x40,
    };
    const wtag256_83 = [_]u8{
        0x0d, 0xc0, 0x0d, 0x72, 0x17, 0xbb, 0xaf, 0xe8, 0xd7, 0x8b, 0xf9, 0x61, 0x18, 0x9b, 0x8f, 0xd2,
    };
    // tcId 1: empty message.
    const wkey1_1 = [_]u8{
        0x06, 0xc0, 0xdc, 0xdc, 0x16, 0xff, 0x81, 0xdc, 0xe9, 0x28, 0x07, 0xfa, 0x2c, 0x82, 0xb4, 0x4d,
        0x28, 0xac, 0x17, 0x8a,
    };
    const wmsg1_1 = [_]u8{};
    const wtag1_1 = [_]u8{
        0x7d, 0x91, 0xd1, 0xb4, 0x74, 0x80, 0x77, 0xb2, 0x89, 0x11, 0xb4, 0x50, 0x97, 0x62, 0xb6, 0xdf,
        0x24, 0x36, 0x58, 0x10,
    };
    // tcId 2: short message.
    const wkey1_2 = [_]u8{
        0x4c, 0xd6, 0x4e, 0xfd, 0xb7, 0x6d, 0xf5, 0xa8, 0x5d, 0xce, 0x3d, 0x34, 0x70, 0x12, 0xca, 0xd0,
        0x6b, 0x0c, 0x3d, 0xb4,
    };
    const wmsg1_2 = [_]u8{
        0x6c,
    };
    const wtag1_2 = [_]u8{
        0x6d, 0x3d, 0x37, 0xaf, 0x55, 0xc7, 0x5d, 0x87, 0x2d, 0x2d, 0xa0, 0x7b, 0x9b, 0x90, 0x7b, 0xa2,
        0x2a, 0xd4, 0x87, 0xd4,
    };
    // tcId 3: short message.
    const wkey1_3 = [_]u8{
        0x52, 0xe1, 0x99, 0x50, 0x25, 0x29, 0x7f, 0xe7, 0xb7, 0x93, 0xdc, 0x8e, 0x1e, 0x4f, 0x7d, 0x31,
        0x2f, 0xee, 0x27, 0x00,
    };
    const wmsg1_3 = [_]u8{
        0x29, 0xdf,
    };
    const wtag1_3 = [_]u8{
        0x82, 0xcb, 0x24, 0xbf, 0xa3, 0x8f, 0xbd, 0xc9, 0x1d, 0x1e, 0xea, 0x2d, 0x2d, 0xc1, 0xce, 0x6e,
        0x60, 0xff, 0x88, 0x1e,
    };
    // tcId 4: short message.
    const wkey1_4 = [_]u8{
        0xf3, 0xed, 0xfa, 0x00, 0x3d, 0x89, 0xc4, 0xe2, 0xa6, 0x42, 0x2e, 0x77, 0xa0, 0x1b, 0x8a, 0xdb,
        0xd7, 0xac, 0x26, 0xe4,
    };
    const wmsg1_4 = [_]u8{
        0xb0, 0x15, 0xb7,
    };
    const wtag1_4 = [_]u8{
        0xcb, 0x24, 0x4c, 0xa6, 0xad, 0x23, 0x39, 0x47, 0x37, 0x84, 0x36, 0x07, 0x6f, 0xbf, 0xd2, 0x0c,
        0x9c, 0x8b, 0x84, 0x2b,
    };
    // tcId 5: short message.
    const wkey1_5 = [_]u8{
        0x4b, 0x07, 0xed, 0x4e, 0x0c, 0x8d, 0xda, 0xa1, 0xf7, 0x6c, 0xf0, 0x01, 0x07, 0x28, 0x67, 0x9c,
        0x88, 0x57, 0xe1, 0x8b,
    };
    const wmsg1_5 = [_]u8{
        0x3b, 0x2c, 0x1a, 0xfe,
    };
    const wtag1_5 = [_]u8{
        0x92, 0x41, 0x25, 0x53, 0x2e, 0x6b, 0x62, 0x5e, 0x7c, 0x5a, 0x8d, 0xcd, 0x16, 0x14, 0xe0, 0x43,
        0x34, 0xc0, 0x67, 0xcd,
    };
    const cases256 = [_]Case{
        .{ .key = &wkey256_1, .msg = &wmsg256_1, .tag = &wtag256_1 },
        .{ .key = &wkey256_2, .msg = &wmsg256_2, .tag = &wtag256_2 },
        .{ .key = &wkey256_3, .msg = &wmsg256_3, .tag = &wtag256_3 },
        .{ .key = &wkey256_4, .msg = &wmsg256_4, .tag = &wtag256_4 },
        .{ .key = &wkey256_5, .msg = &wmsg256_5, .tag = &wtag256_5 },
        .{ .key = &wkey256_6, .msg = &wmsg256_6, .tag = &wtag256_6 },
        .{ .key = &wkey256_27, .msg = &wmsg256_27, .tag = &wtag256_27 },
        .{ .key = &wkey256_82, .msg = &wmsg256_82, .tag = &wtag256_82 },
        .{ .key = &wkey256_83, .msg = &wmsg256_83, .tag = &wtag256_83 },
    };
    const cases1 = [_]Case{
        .{ .key = &wkey1_1, .msg = &wmsg1_1, .tag = &wtag1_1 },
        .{ .key = &wkey1_2, .msg = &wmsg1_2, .tag = &wtag1_2 },
        .{ .key = &wkey1_3, .msg = &wmsg1_3, .tag = &wtag1_3 },
        .{ .key = &wkey1_4, .msg = &wmsg1_4, .tag = &wtag1_4 },
        .{ .key = &wkey1_5, .msg = &wmsg1_5, .tag = &wtag1_5 },
    };
    for (cases256) |c| {
        var out: [32]u8 = undefined;
        hmacSha256(default_provider, &out, c.msg, c.key);
        try std.testing.expectEqualSlices(u8, c.tag, out[0..c.tag.len]);
    }
    for (cases1) |c| {
        var out: [20]u8 = undefined;
        hmacSha1(default_provider, &out, c.msg, c.key);
        try std.testing.expectEqualSlices(u8, c.tag, out[0..c.tag.len]);
    }
}

test "aes cbc matches wycheproof raw vectors" {
    // Source: wycheproof aes_cbc_pkcs5_test.json tcIds 2..4 (AES-128), 146..148
    // (AES-256): block-aligned messages with the final PKCS padding block stripped to raw CBC.
    const Case = struct { key: []const u8, iv: [16]u8, msg: []const u8, ct: []const u8 };
    // tcId 2: message size divisible by block size (key 128, 16 bytes).
    const wkey_128_2 = [_]u8{
        0xe0, 0x9e, 0xaa, 0x5a, 0x3f, 0x5e, 0x56, 0xd2, 0x79, 0xd5, 0xe7, 0xa0, 0x33, 0x73, 0xf6, 0xea,
    };
    const wmsg_128_2 = [_]u8{
        0xef, 0x4e, 0xab, 0x37, 0x18, 0x1f, 0x98, 0x42, 0x3e, 0x53, 0xe9, 0x47, 0xe7, 0x05, 0x0f, 0xd0,
    };
    const wct_128_2 = [_]u8{
        0xd1, 0xfa, 0x69, 0x7f, 0x3e, 0x2e, 0x04, 0xd6, 0x4f, 0x1a, 0x0d, 0xa2, 0x03, 0x81, 0x3c, 0xa5,
    };
    // tcId 3: message size divisible by block size (key 128, 32 bytes).
    const wkey_128_3 = [_]u8{
        0x9b, 0xd3, 0x90, 0x2e, 0xd0, 0x99, 0x6c, 0x86, 0x9b, 0x57, 0x22, 0x72, 0xe7, 0x6f, 0x38, 0x89,
    };
    const wmsg_128_3 = [_]u8{
        0xa7, 0xba, 0x19, 0xd4, 0x9e, 0xe1, 0xea, 0x02, 0xf0, 0x98, 0xaa, 0x8e, 0x30, 0xc7, 0x40, 0xd8,
        0x93, 0xa4, 0x45, 0x6c, 0xcc, 0x29, 0x40, 0x40, 0x48, 0x4e, 0xd8, 0xa0, 0x0a, 0x55, 0xf9, 0x3e,
    };
    const wct_128_3 = [_]u8{
        0x51, 0x4c, 0xbc, 0x69, 0xac, 0xed, 0x50, 0x69, 0x26, 0xde, 0xac, 0xde, 0xb0, 0xcc, 0x0a, 0x5a,
        0x07, 0xd5, 0x40, 0xf6, 0x5d, 0x82, 0x5b, 0x65, 0xc7, 0xdb, 0x00, 0x75, 0xcf, 0x93, 0x0a, 0x06,
    };
    // tcId 4: message size divisible by block size (key 128, 48 bytes).
    const wkey_128_4 = [_]u8{
        0x75, 0xce, 0x18, 0x44, 0x47, 0xca, 0xda, 0x67, 0x2e, 0x02, 0x29, 0x03, 0x10, 0xd2, 0x24, 0xf7,
    };
    const wmsg_128_4 = [_]u8{
        0xc7, 0x74, 0x81, 0x0a, 0x31, 0xa6, 0x42, 0x1a, 0xd8, 0xea, 0xaf, 0xd5, 0xc2, 0x2f, 0xa2, 0x45,
        0x5e, 0x2c, 0x16, 0x7f, 0xee, 0x4a, 0x0b, 0x73, 0xff, 0x92, 0x7b, 0x2d, 0x96, 0xc6, 0x9d, 0xa1,
        0xe9, 0x39, 0x40, 0x7b, 0x86, 0xb1, 0xc1, 0x9b, 0xcf, 0xc6, 0x9c, 0x43, 0x4c, 0x3c, 0xf8, 0xa2,
    };
    const wct_128_4 = [_]u8{
        0x13, 0x7c, 0x82, 0x4d, 0x7f, 0x7d, 0xc3, 0x6f, 0x24, 0x21, 0x6d, 0xde, 0x37, 0xc2, 0xe1, 0xc1,
        0x0c, 0xee, 0x53, 0x3f, 0x64, 0x53, 0xde, 0x92, 0xe4, 0x4b, 0x89, 0x8f, 0xc3, 0x03, 0x7d, 0x2e,
        0x9e, 0x19, 0xd6, 0x7a, 0x96, 0x38, 0x71, 0x36, 0xdd, 0x97, 0x17, 0xa5, 0x6e, 0x28, 0x61, 0x4a,
    };
    // tcId 146: message size divisible by block size (key 256, 16 bytes).
    const wkey_256_146 = [_]u8{
        0x61, 0x2e, 0x83, 0x78, 0x43, 0xce, 0xae, 0x7f, 0x61, 0xd4, 0x96, 0x25, 0xfa, 0xa7, 0xe7, 0x49,
        0x4f, 0x92, 0x53, 0xe2, 0x0c, 0xb3, 0xad, 0xce, 0xa6, 0x86, 0x51, 0x2b, 0x04, 0x39, 0x36, 0xcd,
    };
    const wmsg_256_146 = [_]u8{
        0xcc, 0x37, 0xfa, 0xe1, 0x5f, 0x74, 0x5a, 0x2f, 0x40, 0xe2, 0xc8, 0xb1, 0x92, 0xf2, 0xb3, 0x8d,
    };
    const wct_256_146 = [_]u8{
        0x29, 0x92, 0x95, 0xbe, 0x47, 0xe9, 0xf5, 0x44, 0x1f, 0xe8, 0x3a, 0x7a, 0x81, 0x1c, 0x4a, 0xeb,
    };
    // tcId 147: message size divisible by block size (key 256, 32 bytes).
    const wkey_256_147 = [_]u8{
        0x96, 0xe1, 0xe4, 0x89, 0x6f, 0xb2, 0xcd, 0x05, 0xf1, 0x33, 0xa6, 0xa1, 0x00, 0xbc, 0x56, 0x09,
        0xa7, 0xac, 0x3c, 0xa6, 0xd8, 0x17, 0x21, 0xe9, 0x22, 0xda, 0xdd, 0x69, 0xad, 0x07, 0xa8, 0x92,
    };
    const wmsg_256_147 = [_]u8{
        0x91, 0xa1, 0x7e, 0x4d, 0xfc, 0xc3, 0x16, 0x6a, 0x1a, 0xdd, 0x26, 0xff, 0x0e, 0x7c, 0x12, 0x05,
        0x6e, 0x8a, 0x65, 0x4f, 0x28, 0xa6, 0xde, 0x24, 0xf4, 0xba, 0x73, 0x9c, 0xeb, 0x5b, 0x5b, 0x18,
    };
    const wct_256_147 = [_]u8{
        0xa6, 0x15, 0xa3, 0x9f, 0xf8, 0xf5, 0x9f, 0x82, 0xcf, 0x72, 0xed, 0x13, 0xe1, 0xb0, 0x1e, 0x32,
        0x45, 0x97, 0x00, 0x56, 0x1b, 0xe1, 0x12, 0x41, 0x29, 0x61, 0x36, 0x5c, 0x7a, 0x0b, 0x58, 0xaa,
    };
    // tcId 148: message size divisible by block size (key 256, 48 bytes).
    const wkey_256_148 = [_]u8{
        0x64, 0x9e, 0x37, 0x3e, 0x68, 0x1e, 0xf5, 0x2e, 0x3c, 0x10, 0xac, 0x26, 0x54, 0x84, 0x75, 0x09,
        0x32, 0xa9, 0x91, 0x8f, 0x28, 0xfb, 0x82, 0x4f, 0x7c, 0xb5, 0x0a, 0xda, 0xb3, 0x97, 0x81, 0xfe,
    };
    const wmsg_256_148 = [_]u8{
        0x39, 0xb4, 0x47, 0xbd, 0x3a, 0x01, 0x98, 0x3c, 0x1c, 0xb7, 0x61, 0xb4, 0x56, 0xd6, 0x90, 0x00,
        0x94, 0x8c, 0xeb, 0x87, 0x05, 0x62, 0xa5, 0x36, 0x12, 0x6a, 0x0d, 0x18, 0xa8, 0xe7, 0xe4, 0x9b,
        0x16, 0xde, 0x8f, 0xe6, 0x72, 0xf1, 0x3d, 0x08, 0x08, 0xd8, 0xb7, 0xd9, 0x57, 0x89, 0x99, 0x17,
    };
    const wct_256_148 = [_]u8{
        0xed, 0x3e, 0xd8, 0xec, 0xdb, 0xab, 0xc0, 0xa8, 0xc0, 0x62, 0x59, 0xe9, 0x13, 0xf3, 0xab, 0x9a,
        0x1f, 0x1d, 0xc6, 0xd0, 0x5e, 0x5d, 0xfd, 0xd9, 0xc8, 0x0e, 0x10, 0x08, 0xf3, 0x42, 0x30, 0x64,
        0xd5, 0x40, 0x68, 0x12, 0x91, 0xbb, 0xd3, 0xe1, 0x59, 0x82, 0x0f, 0xee, 0x3f, 0xf1, 0x90, 0xa6,
    };
    const cases = [_]Case{
        .{ .key = &wkey_128_2, .iv = .{ 0xc9, 0xee, 0x3c, 0xd7, 0x46, 0xbf, 0x20, 0x8c, 0x65, 0xca, 0x9e, 0x72, 0xa2, 0x66, 0xd5, 0x4f }, .msg = &wmsg_128_2, .ct = &wct_128_2 },
        .{ .key = &wkey_128_3, .iv = .{ 0x8b, 0x2e, 0x86, 0xa9, 0xa1, 0x85, 0xcf, 0xa6, 0xf5, 0x1c, 0x7c, 0xc5, 0x95, 0xb8, 0x22, 0xbc }, .msg = &wmsg_128_3, .ct = &wct_128_3 },
        .{ .key = &wkey_128_4, .iv = .{ 0x27, 0x17, 0xd1, 0x0e, 0xb2, 0xee, 0xa3, 0xb3, 0x9e, 0xc2, 0x57, 0xe4, 0x33, 0x07, 0xa2, 0x60 }, .msg = &wmsg_128_4, .ct = &wct_128_4 },
        .{ .key = &wkey_256_146, .iv = .{ 0x9e, 0xc7, 0xb8, 0x63, 0xac, 0x84, 0x5c, 0xad, 0x5e, 0x46, 0x73, 0xda, 0x21, 0xf5, 0xb6, 0xa9 }, .msg = &wmsg_256_146, .ct = &wct_256_146 },
        .{ .key = &wkey_256_147, .iv = .{ 0xe7, 0x0d, 0x83, 0xa7, 0x7a, 0x2c, 0xe7, 0x22, 0xac, 0x21, 0x4c, 0x00, 0x83, 0x7a, 0xce, 0xdf }, .msg = &wmsg_256_147, .ct = &wct_256_147 },
        .{ .key = &wkey_256_148, .iv = .{ 0xbd, 0x00, 0x3c, 0x0a, 0x9d, 0x80, 0x4c, 0x29, 0xf0, 0x53, 0xa7, 0x7c, 0xb3, 0x80, 0xcb, 0x47 }, .msg = &wmsg_256_148, .ct = &wct_256_148 },
    };
    for (cases) |c| {
        var buf: [64]u8 = undefined;
        try aesCbcEncrypt(default_provider, c.key, c.iv, buf[0..c.msg.len], c.msg);
        try std.testing.expectEqualSlices(u8, c.ct, buf[0..c.msg.len]);
        var back: [64]u8 = undefined;
        try aesCbcDecrypt(default_provider, c.key, c.iv, back[0..c.msg.len], buf[0..c.msg.len]);
        try std.testing.expectEqualSlices(u8, c.msg, back[0..c.msg.len]);
    }
}

test "cbc decrypt propagates a tampered block per chaining" {
    // CBC malleability: a one-bit flip in ciphertext block i garbles
    // plaintext block i and flips that bit in block i+1.
    var key: [16]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i *% 3 +% 1);
    const iv = [16]u8{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 10, 11, 12, 13, 14, 15 };
    const plain = [64]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    };
    var cipher: [64]u8 = undefined;
    try aesCbcEncrypt(default_provider, &key, iv, &cipher, &plain);
    cipher[20] ^= 0x01; // Second ciphertext block, fifth byte.
    var out: [64]u8 = undefined;
    try aesCbcDecrypt(default_provider, &key, iv, &out, &cipher);
    // Blocks before the tamper are untouched.
    try std.testing.expectEqualSlices(u8, plain[0..16], out[0..16]);
    // The tampered block decrypts to garbage.
    try std.testing.expect(!std.mem.eql(u8, plain[16..32], out[16..32]));
    // The next block carries the same bit flip at the same offset.
    try std.testing.expectEqual(plain[36] ^ 0x01, out[36]);
    for ([_]usize{ 32, 33, 34, 35, 37, 38, 39 }) |index| {
        try std.testing.expectEqual(plain[index], out[index]);
    }
    // Blocks after i+1 are untouched.
    try std.testing.expectEqualSlices(u8, plain[48..64], out[48..64]);
}
test "mode glue matches pre-delegation behavior" {
    // These vectors pin the mode glue (counter layout, CBC chaining,
    // AES-192); any behavior change in the dispatch fails here.
    const msg = "The quick brown fox jumps over the lazy dog. PACK!";
    var key16: [16]u8 = undefined;
    for (&key16, 0..) |*b, i| b.* = @intCast(i *% 7 +% 16);
    var dst: [msg.len]u8 = undefined;
    try winzipCtr(default_provider, &key16, &dst, msg);
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
    try aesCbcEncrypt(default_provider, &key, iv, &buf, plain);
    const ciphertext = buf;
    var isolated: [32]u8 = undefined;
    try aesCbcDecrypt(default_provider, &key, iv, &isolated, &ciphertext);
    try aesCbcDecrypt(default_provider, &key, iv, &buf, &buf);
    try std.testing.expectEqualSlices(u8, &isolated, &buf);
    try std.testing.expectEqualSlices(u8, plain, &buf);
}

test "zipcrypto round trips through its own inverse" {
    var keys = ZipCryptoKeys.init("password");
    const msg = "hello world, zip crypto!";
    var cipher: [msg.len]u8 = undefined;
    var keys_enc = keys;
    keys_enc.encrypt(&cipher, msg);
    var plain: [msg.len]u8 = undefined;
    keys.decrypt(&plain, &cipher);
    try std.testing.expectEqualSlices(u8, msg, &plain);
}

test "constant time eql distinguishes inputs" {
    try std.testing.expect(constantTimeEql("abc", "abc"));
    try std.testing.expect(!constantTimeEql("abc", "abd"));
    try std.testing.expect(!constantTimeEql("abc", "abcd"));
    try std.testing.expect(!constantTimeEql("", "a"));
    try std.testing.expect(constantTimeEql("", ""));
}

test "both providers agree on the mode glue when mergeable" {
    const all_mergeable = options.aes_impl == .mergeable and
        options.sha256_impl == .mergeable and
        options.hmac_impl == .mergeable and
        options.pbkdf2_impl == .mergeable;
    if (!all_mergeable) return error.SkipZigTest;
    const msg = "The quick brown fox jumps over the lazy dog. PACK!";
    var key16: [16]u8 = undefined;
    for (&key16, 0..) |*b, i| b.* = @intCast(i *% 7 +% 16);
    var ctr_onprem: [msg.len]u8 = undefined;
    var ctr_offprem: [msg.len]u8 = undefined;
    try winzipCtr(.onprem, &key16, &ctr_onprem, msg);
    try winzipCtr(.offprem, &key16, &ctr_offprem, msg);
    try std.testing.expectEqualSlices(u8, &ctr_onprem, &ctr_offprem);
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i *% 3 +% 1);
    var iv: [16]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @intCast(i *% 5 +% 2);
    const plain = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    var cbc_onprem: [32]u8 = undefined;
    var cbc_offprem: [32]u8 = undefined;
    try aesCbcEncrypt(.onprem, &key, iv, &cbc_onprem, plain);
    try aesCbcEncrypt(.offprem, &key, iv, &cbc_offprem, plain);
    try std.testing.expectEqualSlices(u8, &cbc_onprem, &cbc_offprem);
    var utf16_buf: [32]u16 = undefined;
    const pw_len = std.unicode.utf8ToUtf16Le(&utf16_buf, "password123") catch unreachable;
    var kdf_onprem: [seven_zip_key_length]u8 = undefined;
    var kdf_offprem: [seven_zip_key_length]u8 = undefined;
    sevenZipKdf(.onprem, std.mem.sliceAsBytes(utf16_buf[0..pw_len]), &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, 8, &kdf_onprem);
    sevenZipKdf(.offprem, std.mem.sliceAsBytes(utf16_buf[0..pw_len]), &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, 8, &kdf_offprem);
    try std.testing.expectEqualSlices(u8, &kdf_onprem, &kdf_offprem);
    var mac_onprem: [hmac_sha1_length]u8 = undefined;
    var mac_offprem: [hmac_sha1_length]u8 = undefined;
    hmacSha1(.onprem, &mac_onprem, msg, &key16);
    hmacSha1(.offprem, &mac_offprem, msg, &key16);
    try std.testing.expectEqualSlices(u8, &mac_onprem, &mac_offprem);
    var dk_onprem: [20]u8 = undefined;
    var dk_offprem: [20]u8 = undefined;
    try pbkdf2HmacSha1(.onprem, &dk_onprem, "password", "salt", 7);
    try pbkdf2HmacSha1(.offprem, &dk_offprem, "password", "salt", 7);
    try std.testing.expectEqualSlices(u8, &dk_onprem, &dk_offprem);
    const pt = [16]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const key192 = [24]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    // AES-192 has no stdlib arm, so both tags resolve to the same on-prem schedule.
    const ct192_onprem = try aesEncryptBlock(.onprem, &key192, pt);
    const ct192_offprem = try aesEncryptBlock(.offprem, &key192, pt);
    try std.testing.expectEqualSlices(u8, &ct192_onprem, &ct192_offprem);
}
