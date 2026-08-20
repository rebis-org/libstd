const std = @import("std");

const checksum = @import("checksum");
const crypto = @import("crypto");

const harness = @import("harness.zig");

fn require(ok: bool) !void {
    if (!ok) return error.CheckFailed;
}

fn hexEncode(digest: anytype) [digest.len * 2]u8 {
    const hex_chars = "0123456789abcdef";
    var hex: [digest.len * 2]u8 = undefined;
    for (digest, 0..) |byte, index| {
        hex[2 * index] = hex_chars[byte >> 4];
        hex[2 * index + 1] = hex_chars[byte & 0xf];
    }
    return hex;
}

fn xxh64(input: []const u8) u64 {
    var hasher = checksum.XxHash64.init(0);
    hasher.update(input);
    return hasher.final();
}

fn sha256Hex(input: []const u8) [64]u8 {
    var hasher = crypto.Sha256.init(.{});
    hasher.update(input);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return hexEncode(digest);
}

fn sha1Hex(input: []const u8) [40]u8 {
    var hasher = crypto.Sha1.init(.{});
    hasher.update(input);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    return hexEncode(digest);
}

fn hmacSha1Hex(message: []const u8, key: []const u8) [40]u8 {
    var digest: [20]u8 = undefined;
    crypto.hmacSha1(&digest, message, key);
    return hexEncode(digest);
}

fn pbkdf2Sha1(password: []const u8, salt: []const u8, rounds: u32) [20]u8 {
    var output: [20]u8 = undefined;
    crypto.pbkdf2HmacSha1(&output, password, salt, rounds);
    return output;
}

fn sanityBuffer() [256]u8 {
    var buffer: [256]u8 = undefined;
    var generator: u64 = 0x9e37_79b1;
    for (&buffer) |*byte| {
        byte.* = @truncate(generator >> 56);
        generator *%= 0x9e37_79b1_85eb_ca8d;
    }
    return buffer;
}

fn runChecksums() !void {
    try require(checksum.crc32("") == 0x0000_0000);
    try require(checksum.crc32("abc") == 0x3524_41C2);
    try require(checksum.crc32("123456789") == 0xCBF4_3926);
    try require(xxh64("") == 0xEF46_DB37_51D8_E999);
    try require(xxh64("a") == 0xD24E_C4F1_A98C_6E5B);
    try require(xxh64("abc") == 0x44BC_2CF5_AD77_0999);
    try require(checksum.xxh64("") == 0xEF46_DB37_51D8_E999);
    const lengths = [_]struct { length: usize, expected: u64 }{
        .{ .length = 31, .expected = 0x299B_39A2_90E6_D783 },
        .{ .length = 32, .expected = 0x18B2_1649_2BB4_4B70 },
        .{ .length = 33, .expected = 0x55C8_DC3E_578F_5B59 },
        .{ .length = 63, .expected = 0xA9EF_BE0F_A0F3_F4E7 },
        .{ .length = 64, .expected = 0xEF55_8F8A_CAC2_B5CD },
        .{ .length = 65, .expected = 0xDE0F_20DC_2631_AF7A },
        .{ .length = 256, .expected = 0x5E3F_5BF9_4D57_4981 },
    };
    const buffer = sanityBuffer();
    for (lengths) |entry| {
        try require(xxh64(buffer[0..entry.length]) == entry.expected);
        var hasher = checksum.XxHash64.init(0);
        var offset: usize = 0;
        while (offset < entry.length) {
            const end = @min(offset + 7, entry.length);
            hasher.update(buffer[offset..end]);
            offset = end;
        }
        try require(hasher.final() == entry.expected);
    }
}

fn runSha256() !void {
    try require(std.mem.eql(u8, &sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    try require(std.mem.eql(u8, &sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    try require(std.mem.eql(u8, &sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    const lengths = [_]struct { length: usize, expected: [64]u8 }{
        .{ .length = 55, .expected = "5b39a58741c0585914865dce2e4d3a36464014c084fbd725976ed33cbb482f0f".* },
        .{ .length = 56, .expected = "0882d13811deba21bbb6c5176d22da6db6672fba8c92db7672870d3e0497631d".* },
        .{ .length = 64, .expected = "151818c81c5d18649d637e2c3ad20e393d590a9fe65c6c72eb89f62b1738f940".* },
        .{ .length = 65, .expected = "faec206ffcbf1a972b4b7fe39b3bcedaac1223c2327f83ec43d6ca0f070dbfd6".* },
    };
    const buffer = sanityBuffer();
    for (lengths) |entry| {
        const input = buffer[0..entry.length];
        try require(std.mem.eql(u8, &sha256Hex(input), &entry.expected));
        var hasher = crypto.Sha256.init(.{});
        var offset: usize = 0;
        while (offset < input.len) {
            const end = @min(offset + 11, input.len);
            hasher.update(input[offset..end]);
            offset = end;
        }
        var digest: [32]u8 = undefined;
        hasher.final(&digest);
        try require(std.mem.eql(u8, &hexEncode(digest), &entry.expected));
    }
}

fn runHmac() !void {
    try require(std.mem.eql(u8, &sha1Hex("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d"));
    try require(std.mem.eql(u8, &sha1Hex(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    const short_key = [_]u8{0x0b} ** 20;
    try require(std.mem.eql(u8, &hmacSha1Hex("Hi There", &short_key), "b617318655057264e28bc0b6fb378c8ef146be00"));
    const long_key = [_]u8{0xaa} ** 80;
    try require(std.mem.eql(u8, &hmacSha1Hex("Test Using Larger Than Block-Size Key - Hash Key First", &long_key), "aa4ae5e15272d00e95705637ce8a3b55ed402112"));
    try require(std.mem.eql(u8, &hmacSha1Hex("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", &long_key), "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"));
    try require(std.mem.eql(u8, &pbkdf2Sha1("password", "salt", 1), &.{ 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6 }));
    try require(std.mem.eql(u8, &pbkdf2Sha1("password", "salt", 2), &.{ 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57 }));
    try require(std.mem.eql(u8, &pbkdf2Sha1("password", "salt", 4096), &.{ 0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1 }));
}

fn requireAesBlock(key: []const u8, plaintext: [16]u8, expected: []const u8) !void {
    const encrypted = try crypto.aesEncryptBlock(key, plaintext);
    try require(std.mem.eql(u8, &encrypted, expected));
    const decrypted = try crypto.aesDecryptBlock(key, encrypted);
    try require(std.mem.eql(u8, &decrypted, &plaintext));
}

fn requireCtr(key: []const u8, block_1: []const u8, block_ff: []const u8, block_100: []const u8) !void {
    var source: [16 * 257]u8 = .{0} ** (16 * 257);
    var output: [16 * 257]u8 = undefined;
    try crypto.winzipCtr(key, &output, &source);
    try require(std.mem.eql(u8, output[0..16], block_1));
    try require(std.mem.eql(u8, output[254 * 16 .. 255 * 16], block_ff));
    try require(std.mem.eql(u8, output[255 * 16 .. 256 * 16], block_100));
}

const fips_plaintext = [16]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
const fips_128_key = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
const fips_192_key = [24]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
const fips_256_key = [32]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

fn runAes() !void {
    try requireAesBlock(&fips_128_key, fips_plaintext, &.{ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a });
    try requireAesBlock(&fips_192_key, fips_plaintext, &.{ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 });
    try requireAesBlock(&fips_256_key, fips_plaintext, &.{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 });
    try requireCtr(&fips_128_key, &.{ 0xe3, 0x7c, 0xd3, 0x63, 0xdd, 0x7c, 0x87, 0xa0, 0x9a, 0xff, 0x0e, 0x3e, 0x60, 0xe0, 0x9c, 0x82 }, &.{ 0xe7, 0x03, 0x90, 0x5a, 0xe4, 0x39, 0x87, 0x96, 0xf0, 0x14, 0x95, 0x32, 0x9e, 0x43, 0xda, 0xc7 }, &.{ 0x9e, 0xb1, 0xb6, 0x3c, 0x7e, 0xfe, 0x31, 0xc9, 0xa4, 0x6b, 0xb9, 0x87, 0xba, 0xaf, 0x39, 0x08 });
    try requireCtr(&fips_192_key, &.{ 0x09, 0x4a, 0x72, 0x3c, 0xea, 0xf7, 0xf7, 0xb7, 0x32, 0xe0, 0x5b, 0x90, 0xd3, 0x5b, 0x8c, 0xf1 }, &.{ 0x34, 0x02, 0xc5, 0xd3, 0xf7, 0xb1, 0x61, 0x6e, 0xe7, 0x60, 0xb4, 0xb7, 0x01, 0x85, 0x6d, 0xec }, &.{ 0xf0, 0xf0, 0x78, 0x1f, 0x2a, 0x95, 0x21, 0x8d, 0x73, 0x44, 0x77, 0x0a, 0xd9, 0x5a, 0x91, 0xed });
    try requireCtr(&fips_256_key, &.{ 0xc7, 0xb5, 0x19, 0x84, 0x6a, 0x11, 0x41, 0x1c, 0xd6, 0xac, 0x07, 0xcb, 0x03, 0xf8, 0x01, 0xa8 }, &.{ 0xd9, 0xa3, 0x73, 0x31, 0xc9, 0xc2, 0xda, 0x94, 0x96, 0x17, 0x37, 0xf7, 0xf7, 0x32, 0x2b, 0xd6 }, &.{ 0x05, 0xd9, 0x59, 0x2c, 0xef, 0xc7, 0x83, 0x4b, 0xf6, 0x97, 0x76, 0x61, 0x48, 0x68, 0xa1, 0x51 });
    const cbc_iv = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const cbc_plaintext = [32]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    var cbc_output: [32]u8 = undefined;
    try crypto.aesCbcEncrypt(&fips_256_key, cbc_iv, &cbc_output, &cbc_plaintext);
    try require(std.mem.eql(u8, &cbc_output, &.{ 0x78, 0xe1, 0x6b, 0x06, 0x81, 0x7a, 0x44, 0x53, 0xab, 0xef, 0x8a, 0x23, 0x5f, 0xa9, 0xfa, 0x51, 0x6a, 0xea, 0x1e, 0x89, 0x29, 0xf1, 0xa7, 0xa7, 0xee, 0xb3, 0x45, 0x08, 0x22, 0xe7, 0x66, 0xf8 }));
    var cbc_back: [32]u8 = undefined;
    try crypto.aesCbcDecrypt(&fips_256_key, cbc_iv, &cbc_back, &cbc_output);
    try require(std.mem.eql(u8, &cbc_back, &cbc_plaintext));
    try crypto.aesCbcEncrypt(&fips_256_key, cbc_iv, &cbc_output, &.{});
    const invalid_key = [_]u8{0} ** 15;
    const zeros_16 = [_]u8{0} ** 16;
    var invalid_out: [16]u8 = undefined;
    if (crypto.winzipCtr(&invalid_key, &invalid_out, &zeros_16)) |_| return error.ExpectedInvalidCall else |err| {
        try require(err == error.InvalidCall);
    }
}

pub fn run(_: *harness.Runner) anyerror!void {
    try runChecksums();
    try runSha256();
    try runHmac();
    try runAes();
}

pub const scenario = harness.Scenario{
    .name = "primitives vectors",
    .suite = "primitives",
    .run = run,
    .workspace_size = 256,
    .output_size = 64,
    .encoded_size = 64,
};
