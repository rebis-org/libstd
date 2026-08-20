const std = @import("std");

const Failure = @import("failure.zig").Failure;

pub const block_length = 16;
pub const hmac_sha1_length = 20;
pub const winzip_verify_length = 2;
pub const winzip_hmac_length = 10;
pub const seven_zip_key_length = 32;
pub const winzip_pbkdf2_rounds = 1000;
pub const seven_zip_cycles_max = 24;
pub const seven_zip_default_cycles = 19;
pub const seven_zip_default_rounds: u64 = @as(u64, 1) << seven_zip_default_cycles;

pub const FailureCause = enum {
    none,
    wrong_password,
    kdf_limit,
    password_lifetime,
    unsupported_algorithm,
};

pub const Sha256 = struct {
    state: [8]u32,
    buffer: [64]u8 = undefined,
    buffered: usize = 0,
    total: u64 = 0,

    pub const Options = struct {};

    pub fn init(_: Options) Sha256 {
        return .{ .state = .{
            0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
            0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
        } };
    }

    fn rotr(value: u32, amount: u32) u32 {
        return std.math.rotl(u32, value, 32 - amount);
    }

    fn compress(self: *Sha256, block: *const [64]u8) void {
        var w: [64]u32 = undefined;
        for (0..16) |index| w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
        for (16..64) |index| {
            const lower0 = rotr(w[index - 15], 7) ^ rotr(w[index - 15], 18) ^ (w[index - 15] >> 3);
            const lower1 = rotr(w[index - 2], 17) ^ rotr(w[index - 2], 19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16] +% lower0 +% w[index - 7] +% lower1;
        }
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        var f = self.state[5];
        var g = self.state[6];
        var h = self.state[7];
        for (0..64) |index| {
            const upper1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const choice = (e & f) ^ (~e & g);
            const temp1 = h +% upper1 +% choice +% k[index] +% w[index];
            const upper0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = upper0 +% majority;
            h = g;
            g = f;
            f = e;
            e = d +% temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 +% temp2;
        }
        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
        self.state[5] +%= f;
        self.state[6] +%= g;
        self.state[7] +%= h;
    }

    pub fn update(self: *Sha256, input: []const u8) void {
        self.total +%= input.len;
        var remaining = input;
        if (self.buffered != 0) {
            const take = @min(remaining.len, 64 - self.buffered);
            @memcpy(self.buffer[self.buffered..][0..take], remaining[0..take]);
            self.buffered += take;
            remaining = remaining[take..];
            if (self.buffered == 64) {
                self.compress(&self.buffer);
                self.buffered = 0;
            }
        }
        while (remaining.len >= 64) {
            self.compress(remaining[0..64]);
            remaining = remaining[64..];
        }
        if (remaining.len != 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buffered = remaining.len;
        }
    }

    pub fn final(self: *Sha256, out: []u8) void {
        const bit_length = self.total *% 8;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if (self.buffered > 56) {
            @memset(self.buffer[self.buffered..], 0);
            self.compress(&self.buffer);
            self.buffered = 0;
        }
        @memset(self.buffer[self.buffered..56], 0);
        std.mem.writeInt(u64, self.buffer[56..64], bit_length, .big);
        self.compress(&self.buffer);
        for (self.state, 0..) |word, index| std.mem.writeInt(u32, out[4 * index ..][0..4], word, .big);
    }

    const k = [_]u32{
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
        0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
        0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
        0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
        0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    };
};

pub const Sha1 = struct {
    state: [5]u32,
    buffer: [64]u8 = undefined,
    buffered: usize = 0,
    total: u64 = 0,

    pub const Options = struct {};

    pub fn init(_: Options) Sha1 {
        return .{ .state = .{ 0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0 } };
    }

    fn compress(self: *Sha1, block: *const [64]u8) void {
        var w: [80]u32 = undefined;
        for (0..16) |index| w[index] = std.mem.readInt(u32, block[4 * index ..][0..4], .big);
        for (16..80) |index| {
            w[index] = std.math.rotl(u32, w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16], 1);
        }
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        for (0..80) |index| {
            const f: u32 = if (index < 20)
                (b & c) | (~b & d)
            else if (index < 40)
                b ^ c ^ d
            else if (index < 60)
                (b & c) | (b & d) | (c & d)
            else
                b ^ c ^ d;
            const k: u32 = if (index < 20)
                0x5a82_7999
            else if (index < 40)
                0x6ed9_eba1
            else if (index < 60)
                0x8f1b_bcdc
            else
                0xca62_c1d6;
            const temp = std.math.rotl(u32, a, 5) +% f +% e +% k +% w[index];
            e = d;
            d = c;
            c = std.math.rotl(u32, b, 30);
            b = a;
            a = temp;
        }
        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
    }

    pub fn update(self: *Sha1, input: []const u8) void {
        self.total +%= input.len;
        var remaining = input;
        if (self.buffered != 0) {
            const take = @min(remaining.len, 64 - self.buffered);
            @memcpy(self.buffer[self.buffered..][0..take], remaining[0..take]);
            self.buffered += take;
            remaining = remaining[take..];
            if (self.buffered == 64) {
                self.compress(&self.buffer);
                self.buffered = 0;
            }
        }
        while (remaining.len >= 64) {
            self.compress(remaining[0..64]);
            remaining = remaining[64..];
        }
        if (remaining.len != 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buffered = remaining.len;
        }
    }

    pub fn final(self: *Sha1, out: []u8) void {
        const bit_length = self.total *% 8;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if (self.buffered > 56) {
            @memset(self.buffer[self.buffered..], 0);
            self.compress(&self.buffer);
            self.buffered = 0;
        }
        @memset(self.buffer[self.buffered..56], 0);
        std.mem.writeInt(u64, self.buffer[56..64], bit_length, .big);
        self.compress(&self.buffer);
        for (self.state, 0..) |word, index| std.mem.writeInt(u32, out[4 * index ..][0..4], word, .big);
    }
};

const HmacSha1 = struct {
    inner: Sha1,
    outer: Sha1,

    pub fn init(key: []const u8) HmacSha1 {
        var key_block: [64]u8 = .{0} ** 64;
        if (key.len > 64) {
            const digest = sha1(key);
            @memcpy(key_block[0..20], &digest);
        } else {
            @memcpy(key_block[0..key.len], key);
        }
        var inner_pad: [64]u8 = undefined;
        var outer_pad: [64]u8 = undefined;
        for (key_block, 0..) |byte, index| {
            inner_pad[index] = byte ^ 0x36;
            outer_pad[index] = byte ^ 0x5c;
        }
        var inner = Sha1.init(.{});
        inner.update(&inner_pad);
        var outer = Sha1.init(.{});
        outer.update(&outer_pad);
        return .{ .inner = inner, .outer = outer };
    }

    pub fn update(self: *HmacSha1, input: []const u8) void {
        self.inner.update(input);
    }

    pub fn final(self: *HmacSha1, out: []u8) void {
        var digest: [20]u8 = undefined;
        self.inner.final(&digest);
        self.outer.update(&digest);
        self.outer.final(out);
    }
};

fn sha1(input: []const u8) [20]u8 {
    var hasher = Sha1.init(.{});
    hasher.update(input);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    return digest;
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

const AesKeySchedule = struct {
    rounds: u8,
    words: [60]u32,
};

fn aesKeySchedule(key: []const u8) Failure!AesKeySchedule {
    const nk = key.len / 4;
    if (key.len != nk * 4 or (nk != 4 and nk != 6 and nk != 8)) return error.InvalidCall;
    const rounds: u8 = @intCast(nk + 6);
    var words: [60]u32 = undefined;
    for (0..nk) |index| words[index] = std.mem.readInt(u32, key[4 * index ..][0..4], .big);
    const rcon = [_]u32{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    var index: usize = nk;
    while (index < 4 * (rounds + 1)) : (index += 1) {
        var temp = words[index - 1];
        if (index % nk == 0) {
            temp = subWord(std.math.rotl(u32, temp, 8)) ^ (rcon[index / nk - 1] << 24);
        } else if (nk == 8 and index % nk == 4) {
            temp = subWord(temp);
        }
        words[index] = words[index - nk] ^ temp;
    }
    return .{ .rounds = rounds, .words = words };
}

fn addRoundKey(state: *[block_length]u8, words: []const u32) void {
    for (words, 0..) |word, index| {
        const base = 4 * index;
        state[base] ^= @truncate(word >> 24);
        state[base + 1] ^= @truncate(word >> 16);
        state[base + 2] ^= @truncate(word >> 8);
        state[base + 3] ^= @truncate(word);
    }
}

fn subBytes(state: *[block_length]u8) void {
    for (state) |*byte| byte.* = sbox[byte.*];
}

fn invSubBytes(state: *[block_length]u8) void {
    for (state) |*byte| byte.* = inv_sbox[byte.*];
}

fn shiftRows(state: *[block_length]u8) void {
    var temp: [block_length]u8 = undefined;
    for (0..4) |row| for (0..4) |column| {
        temp[row + 4 * column] = state[row + 4 * ((column + row) % 4)];
    };
    state.* = temp;
}

fn invShiftRows(state: *[block_length]u8) void {
    var temp: [block_length]u8 = undefined;
    for (0..4) |row| for (0..4) |column| {
        temp[row + 4 * column] = state[row + 4 * ((column + 4 - row) % 4)];
    };
    state.* = temp;
}

fn xtime(value: u8) u8 {
    return (value << 1) ^ (@as(u8, value >> 7) *% 0x1b);
}

fn mul2(value: u8) u8 {
    return xtime(value);
}

fn mul3(value: u8) u8 {
    return xtime(value) ^ value;
}

fn mul9(value: u8) u8 {
    return xtime(xtime(xtime(value))) ^ value;
}

fn mul11(value: u8) u8 {
    return xtime(xtime(xtime(value))) ^ xtime(value) ^ value;
}

fn mul13(value: u8) u8 {
    return xtime(xtime(xtime(value))) ^ xtime(xtime(value)) ^ value;
}

fn mul14(value: u8) u8 {
    return xtime(xtime(xtime(value))) ^ xtime(xtime(value)) ^ xtime(value);
}

fn mixColumns(state: *[block_length]u8) void {
    var temp: [block_length]u8 = undefined;
    for (0..4) |column| {
        const a0 = state[0 + 4 * column];
        const a1 = state[1 + 4 * column];
        const a2 = state[2 + 4 * column];
        const a3 = state[3 + 4 * column];
        temp[0 + 4 * column] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
        temp[1 + 4 * column] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
        temp[2 + 4 * column] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
        temp[3 + 4 * column] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
    state.* = temp;
}

fn invMixColumns(state: *[block_length]u8) void {
    var temp: [block_length]u8 = undefined;
    for (0..4) |column| {
        const a0 = state[0 + 4 * column];
        const a1 = state[1 + 4 * column];
        const a2 = state[2 + 4 * column];
        const a3 = state[3 + 4 * column];
        temp[0 + 4 * column] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
        temp[1 + 4 * column] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
        temp[2 + 4 * column] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
        temp[3 + 4 * column] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
    }
    state.* = temp;
}

fn aesEncryptWithSchedule(schedule: *const AesKeySchedule, block: *const [block_length]u8) [block_length]u8 {
    var state = block.*;
    addRoundKey(&state, schedule.words[0..4]);
    var round: usize = 1;
    while (round < schedule.rounds) : (round += 1) {
        subBytes(&state);
        shiftRows(&state);
        mixColumns(&state);
        addRoundKey(&state, schedule.words[4 * round ..][0..4]);
    }
    subBytes(&state);
    shiftRows(&state);
    addRoundKey(&state, schedule.words[4 * schedule.rounds ..][0..4]);
    return state;
}

fn aesDecryptWithSchedule(schedule: *const AesKeySchedule, block: *const [block_length]u8) [block_length]u8 {
    var state = block.*;
    addRoundKey(&state, schedule.words[4 * schedule.rounds ..][0..4]);
    var round: usize = schedule.rounds - 1;
    while (round >= 1) : (round -= 1) {
        invShiftRows(&state);
        invSubBytes(&state);
        addRoundKey(&state, schedule.words[4 * round ..][0..4]);
        invMixColumns(&state);
    }
    invShiftRows(&state);
    invSubBytes(&state);
    addRoundKey(&state, schedule.words[0..4]);
    return state;
}

pub fn aesEncryptBlock(key: []const u8, block: [block_length]u8) Failure![block_length]u8 {
    const schedule = try aesKeySchedule(key);
    return aesEncryptWithSchedule(&schedule, &block);
}

pub fn aesDecryptBlock(key: []const u8, block: [block_length]u8) Failure![block_length]u8 {
    const schedule = try aesKeySchedule(key);
    return aesDecryptWithSchedule(&schedule, &block);
}

pub fn winzipCtr(key: []const u8, dst: []u8, src: []const u8) Failure!void {
    if (dst.len < src.len) return error.InvalidCall;
    const schedule = try aesKeySchedule(key);
    var counter: [block_length]u8 = .{0} ** block_length;
    counter[0] = 1;
    var offset: usize = 0;
    while (offset < src.len) : (offset += block_length) {
        const keystream = aesEncryptWithSchedule(&schedule, &counter);
        const count = @min(block_length, src.len - offset);
        for (0..count) |index| dst[offset + index] = src[offset + index] ^ keystream[index];
        var byte_index: usize = 0;
        while (byte_index < 8) : (byte_index += 1) {
            counter[byte_index] +%= 1;
            if (counter[byte_index] != 0) break;
        }
    }
    return;
}

// AES-256-CBC operates on whole 16-byte blocks; zero padding is the caller's job.
pub fn aesCbcEncrypt(key: []const u8, iv: [block_length]u8, dst: []u8, src: []const u8) Failure!void {
    if (key.len != 32 or src.len % block_length != 0 or dst.len < src.len) return error.InvalidCall;
    const schedule = try aesKeySchedule(key);
    var previous = iv;
    var offset: usize = 0;
    while (offset < src.len) : (offset += block_length) {
        var block: [block_length]u8 = undefined;
        for (0..block_length) |index| block[index] = src[offset + index] ^ previous[index];
        const encrypted = aesEncryptWithSchedule(&schedule, &block);
        @memcpy(dst[offset..][0..block_length], &encrypted);
        previous = encrypted;
    }
    return;
}

pub fn aesCbcDecrypt(key: []const u8, iv: [block_length]u8, dst: []u8, src: []const u8) Failure!void {
    if (key.len != 32 or src.len % block_length != 0 or dst.len < src.len) return error.InvalidCall;
    const schedule = try aesKeySchedule(key);
    var previous = iv;
    var offset: usize = 0;
    while (offset < src.len) : (offset += block_length) {
        const decrypted = aesDecryptWithSchedule(&schedule, src[offset..][0..block_length]);
        for (0..block_length) |index| dst[offset + index] = decrypted[index] ^ previous[index];
        @memcpy(&previous, src[offset..][0..block_length]);
    }
    return;
}

pub fn winzipDeriveKey(password: []const u8, salt: []const u8, key_length: usize, out: []u8) Failure!void {
    const derived_length = std.math.add(usize, 2 * key_length, winzip_verify_length) catch return error.ResourceLimit;
    if (out.len < derived_length) return error.InvalidCall;
    pbkdf2HmacSha1(out[0..derived_length], password, salt, @intCast(winzip_pbkdf2_rounds));
    return;
}

// The 7z AES key derivation hashes salt, UTF-16LE password, and an incrementing
// little-endian u32 counter followed by four zero bytes for 2^num_cycles_power rounds.
pub fn sevenZipKdf(password_utf16: []const u8, salt: []const u8, num_cycles_power: u8, out_key: *[seven_zip_key_length]u8) void {
    var sha = Sha256.init(.{});
    const rounds: u64 = @as(u64, 1) << @intCast(num_cycles_power);
    var counter: [8]u8 = .{0} ** 8;
    var index: u64 = 0;
    while (index < rounds) : (index += 1) {
        sha.update(salt);
        sha.update(password_utf16);
        std.mem.writeInt(u32, counter[0..4], @as(u32, @truncate(index)), .little);
        sha.update(&counter);
    }
    sha.final(out_key);
}

pub fn hmacSha1(out: *[hmac_sha1_length]u8, message: []const u8, key: []const u8) void {
    var hmac = HmacSha1.init(key);
    hmac.update(message);
    hmac.final(out);
}

pub fn pbkdf2HmacSha1(out: []u8, password: []const u8, salt: []const u8, rounds: u32) void {
    var block_index: u32 = 1;
    var offset: usize = 0;
    while (offset < out.len) : (block_index +%= 1) {
        var hmac = HmacSha1.init(password);
        hmac.update(salt);
        var counter_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &counter_bytes, block_index, .big);
        hmac.update(&counter_bytes);
        var u: [20]u8 = undefined;
        hmac.final(&u);
        var t = u;
        var round: u32 = 1;
        while (round < rounds) : (round += 1) {
            var next = HmacSha1.init(password);
            next.update(&u);
            next.final(&u);
            for (0..20) |index| t[index] ^= u[index];
        }
        const count = @min(20, out.len - offset);
        @memcpy(out[offset..][0..count], t[0..count]);
        offset += count;
    }
}

pub fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var accumulator: u8 = 0;
    for (left, right) |l, r| accumulator |= l ^ r;
    return accumulator == 0;
}

// Entropy comes from the platform through the standard library; every shipped
// target exposes one of these sources. The deterministic derivation is only a
// compile-time fallback so unsupported targets still produce per-entry-unique salts.
pub fn fillRandom(bytes: []u8) bool {
    if (comptime @hasDecl(std.posix.system, "arc4random_buf")) {
        std.posix.system.arc4random_buf(bytes.ptr, bytes.len);
        return true;
    }
    if (comptime @hasDecl(std.os.linux, "getrandom")) {
        const count = std.os.linux.getrandom(bytes.ptr, bytes.len, 0);
        return count == bytes.len;
    }
    return false;
}

pub fn deriveDeterministicSalt(password: []const u8, name: []const u8, data: []const u8, out: []u8) Failure!void {
    if (out.len > 32) return error.InvalidCall;
    var sha = Sha256.init(.{});
    sha.update(password);
    sha.update(name);
    sha.update(data);
    var digest: [32]u8 = undefined;
    sha.final(&digest);
    @memcpy(out, digest[0..out.len]);
    return;
}

const zip_crc_table: [256]u32 = blk: {
    @setEvalBranchQuota(10000);
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

    pub fn encrypt(self: *ZipCryptoKeys, dst: []u8, src: []const u8) void {
        for (src, 0..) |plain, index| {
            const cipher = self.encryptByte() ^ plain;
            self.update(plain);
            dst[index] = cipher;
        }
    }

    pub fn decrypt(self: *ZipCryptoKeys, dst: []u8, src: []const u8) void {
        for (src, 0..) |cipher, index| {
            const plain = self.decryptByte() ^ cipher;
            self.update(plain);
            dst[index] = plain;
        }
    }
};

fn subWord(word: u32) u32 {
    var result: u32 = 0;
    for (0..4) |i| {
        const byte: u8 = @truncate(word >> @intCast(8 * i));
        result |= @as(u32, sbox[byte]) << @intCast(8 * i);
    }
    return result;
}

const sbox = blk: {
    @setEvalBranchQuota(10_000);
    var table: [256]u8 = undefined;
    table[0] = 0x63;
    var p: u8 = 1;
    var q: u8 = 1;
    while (true) {
        p = p ^ (p << 1) ^ (if (p & 0x80 != 0) 0x1b else 0);
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if (q & 0x80 != 0) 0x09 else 0;
        table[p] = q ^ std.math.rotl(u8, q, 1) ^ std.math.rotl(u8, q, 2) ^ std.math.rotl(u8, q, 3) ^ std.math.rotl(u8, q, 4) ^ 0x63;
        if (p == 1) break;
    }
    break :blk table;
};

const inv_sbox = blk: {
    var table: [256]u8 = undefined;
    for (sbox, 0..) |value, index| table[value] = @intCast(index);
    break :blk table;
};
