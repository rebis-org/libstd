const std = @import("std");
const builtin = @import("builtin");

// FIPS-197.
// AES-192 needs the classic word expansion because the vectorized schedule requires 16-byte key groups.

pub const block_length = 16;

const Repr = @Vector(2, u64);

const has_arm8 = builtin.cpu.arch == .aarch64 and
    builtin.zig_backend != .stage2_c and
    builtin.cpu.has(.aarch64, .aes);

pub const Block = if (has_arm8) BlockArm8 else BlockSoft;

const BlockArm8 = struct {
    repr: Repr,

    const zero: Repr = .{ 0, 0 };

    pub fn fromBytes(bytes: *const [16]u8) BlockArm8 {
        return .{ .repr = std.mem.bytesToValue(Repr, bytes) };
    }

    pub fn toBytes(block: BlockArm8) [16]u8 {
        return std.mem.toBytes(block.repr);
    }

    fn xorBlocks(first: BlockArm8, second: BlockArm8) BlockArm8 {
        return .{ .repr = first.repr ^ second.repr };
    }

    pub fn encrypt(block: BlockArm8, round_key: BlockArm8) BlockArm8 {
        return .{ .repr = asm (
            \\ mov   %[out].16b, %[in].16b
            \\ aese  %[out].16b, %[zero].16b
            \\ aesmc %[out].16b, %[out].16b
            : [out] "=&x" (-> Repr),
            : [in] "x" (block.repr),
              [zero] "x" (zero),
        ) ^ round_key.repr };
    }

    pub fn encryptLast(block: BlockArm8, round_key: BlockArm8) BlockArm8 {
        return .{ .repr = asm (
            \\ mov   %[out].16b, %[in].16b
            \\ aese  %[out].16b, %[zero].16b
            : [out] "=&x" (-> Repr),
            : [in] "x" (block.repr),
              [zero] "x" (zero),
        ) ^ round_key.repr };
    }

    pub fn decrypt(block: BlockArm8, inv_round_key: BlockArm8) BlockArm8 {
        return .{ .repr = asm (
            \\ mov   %[out].16b, %[in].16b
            \\ aesd  %[out].16b, %[zero].16b
            \\ aesimc %[out].16b, %[out].16b
            : [out] "=&x" (-> Repr),
            : [in] "x" (block.repr),
              [zero] "x" (zero),
        ) ^ inv_round_key.repr };
    }

    pub fn decryptLast(block: BlockArm8, inv_round_key: BlockArm8) BlockArm8 {
        return .{ .repr = asm (
            \\ mov   %[out].16b, %[in].16b
            \\ aesd  %[out].16b, %[zero].16b
            : [out] "=&x" (-> Repr),
            : [in] "x" (block.repr),
              [zero] "x" (zero),
        ) ^ inv_round_key.repr };
    }

    pub fn invMixColumns(block: BlockArm8) BlockArm8 {
        return .{ .repr = asm (
            \\ aesimc %[out].16b, %[in].16b
            : [out] "=x" (-> Repr),
            : [in] "x" (block.repr),
        ) };
    }
};

// The software round mirrors the hardware one so both schedule walkers stay
// identical; the tables and the GF(2^8) ladder below are checked exhaustively
// at comptime.
const BlockSoft = struct {
    repr: Repr,

    pub fn fromBytes(bytes: *const [16]u8) BlockSoft {
        return .{ .repr = std.mem.bytesToValue(Repr, bytes) };
    }

    pub fn toBytes(block: BlockSoft) [16]u8 {
        return std.mem.toBytes(block.repr);
    }

    fn xorBlocks(first: BlockSoft, second: BlockSoft) BlockSoft {
        return .{ .repr = first.repr ^ second.repr };
    }

    pub fn encrypt(block: BlockSoft, round_key: BlockSoft) BlockSoft {
        var bytes = block.toBytes();
        subBytes(&bytes);
        shiftRows(&bytes);
        mixColumns(&bytes);
        const key_bytes = round_key.toBytes();
        addRoundKey(&bytes, &key_bytes);
        return fromBytes(&bytes);
    }

    pub fn encryptLast(block: BlockSoft, round_key: BlockSoft) BlockSoft {
        var bytes = block.toBytes();
        subBytes(&bytes);
        shiftRows(&bytes);
        const key_bytes = round_key.toBytes();
        addRoundKey(&bytes, &key_bytes);
        return fromBytes(&bytes);
    }

    pub fn decrypt(block: BlockSoft, inv_round_key: BlockSoft) BlockSoft {
        var bytes = block.toBytes();
        invMixColumnsBytes(&bytes);
        const key_bytes = inv_round_key.toBytes();
        addRoundKey(&bytes, &key_bytes);
        invShiftRows(&bytes);
        invSubBytes(&bytes);
        return fromBytes(&bytes);
    }

    pub fn decryptLast(block: BlockSoft, inv_round_key: BlockSoft) BlockSoft {
        var bytes = block.toBytes();
        invShiftRows(&bytes);
        invSubBytes(&bytes);
        const key_bytes = inv_round_key.toBytes();
        addRoundKey(&bytes, &key_bytes);
        return fromBytes(&bytes);
    }

    pub fn invMixColumns(block: BlockSoft) BlockSoft {
        var bytes = block.toBytes();
        invMixColumnsBytes(&bytes);
        return fromBytes(&bytes);
    }
};

fn KeySchedule(comptime Aes: type) type {
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();

        const mask1: Repr = @bitCast([16]u8{ 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12 });
        const mask2: Repr = @bitCast([16]u8{ 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15 });

        round_keys: [rounds + 1]Block,

        fn expand128(first: *Block) Self {
            if (comptime !has_arm8) return expandScalar(first, null);
            var round_keys: [11]Block = undefined;
            const rcs = [_]u8{ 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
            inline for (rcs, 0..) |rc, round| {
                round_keys[round] = first.*;
                first.repr = schedule128(rc, first.repr);
            }
            round_keys[rcs.len] = first.*;
            return .{ .round_keys = round_keys };
        }

        fn expand256(first: *Block, second: *Block) Self {
            if (comptime !has_arm8) return expandScalar(first, second);
            var round_keys: [15]Block = undefined;
            const rcs = [_]u8{ 1, 2, 4, 8, 16, 32 };
            round_keys[0] = first.*;
            inline for (rcs, 0..) |rc, round| {
                round_keys[round * 2 + 1] = second.*;
                first.repr = schedule256(false, rc, second.repr, first.repr);
                round_keys[round * 2 + 2] = first.*;
                second.repr = schedule256(true, rc, first.repr, second.repr);
            }
            round_keys[rcs.len * 2 + 1] = second.*;
            first.repr = schedule256(false, 64, second.repr, first.repr);
            round_keys[rcs.len * 2 + 2] = first.*;
            return .{ .round_keys = round_keys };
        }

        // FIPS-197 word expansion covers targets without the crypto
        // extensions; the second half stays null for 128-bit keys.
        fn expandScalar(first: *Block, second: ?*Block) Self {
            var words: [60]u32 = undefined;
            readWords(first, words[0..4]);
            var nk: usize = 4;
            if (second) |part| {
                readWords(part, words[4..8]);
                nk = 8;
            }
            expandWordLoop(words[0 .. 4 * (rounds + 1)], nk);
            var round_keys: [rounds + 1]Block = undefined;
            packRoundKeys(words[0 .. 4 * (rounds + 1)], round_keys[0..]);
            return .{ .round_keys = round_keys };
        }

        fn readWords(block: *const Block, words: []u32) void {
            const bytes = block.toBytes();
            for (words, 0..) |*word, index| {
                word.* = std.mem.readInt(u32, bytes[4 * index ..][0..4], .big);
            }
        }

        pub fn invert(self: Self) Self {
            var round_keys: [rounds + 1]Block = undefined;
            invertSchedule(self.round_keys[0..], round_keys[0..]);
            return .{ .round_keys = round_keys };
        }

        fn schedule128(comptime rc: u8, t: Repr) Repr {
            var v1: Repr = undefined;
            var v2: Repr = undefined;
            var v3: Repr = undefined;
            var v4: Repr = undefined;

            return asm (
                \\ movi %[v2].4s, %[rc]
                \\ tbl  %[v4].16b, {%[t].16b}, %[mask].16b
                \\ ext  %[r].16b, %[zero].16b, %[t].16b, #12
                \\ aese %[v4].16b, %[zero].16b
                \\ eor  %[v2].16b, %[r].16b, %[v2].16b
                \\ ext  %[r].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v2].16b, %[t].16b
                \\ ext  %[v3].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v1].16b, %[r].16b
                \\ eor  %[r].16b, %[v1].16b, %[v3].16b
                \\ eor  %[r].16b, %[r].16b, %[v4].16b
                : [r] "=&x" (-> Repr),
                  [v1] "=&x" (v1),
                  [v2] "=&x" (v2),
                  [v3] "=&x" (v3),
                  [v4] "=&x" (v4),
                : [rc] "N" (rc),
                  [t] "x" (t),
                  [zero] "x" (@as(Repr, .{ 0, 0 })),
                  [mask] "x" (mask1),
            );
        }

        fn schedule256(comptime second: bool, comptime rc: u8, t: Repr, tx: Repr) Repr {
            var v1: Repr = undefined;
            var v2: Repr = undefined;
            var v3: Repr = undefined;
            var v4: Repr = undefined;

            return asm (
                \\ movi %[v2].4s, %[rc]
                \\ tbl  %[v4].16b, {%[t].16b}, %[mask].16b
                \\ ext  %[r].16b, %[zero].16b, %[tx].16b, #12
                \\ aese %[v4].16b, %[zero].16b
                \\ eor  %[v1].16b, %[tx].16b, %[r].16b
                \\ ext  %[r].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v1].16b, %[r].16b
                \\ ext  %[v3].16b, %[zero].16b, %[r].16b, #12
                \\ eor  %[v1].16b, %[v1].16b, %[v2].16b
                \\ eor  %[v1].16b, %[v1].16b, %[v3].16b
                \\ eor  %[r].16b, %[v1].16b, %[v4].16b
                : [r] "=&x" (-> Repr),
                  [v1] "=&x" (v1),
                  [v2] "=&x" (v2),
                  [v3] "=&x" (v3),
                  [v4] "=&x" (v4),
                : [rc] "N" (if (second) @as(u8, 0) else rc),
                  [t] "x" (t),
                  [tx] "x" (tx),
                  [zero] "x" (@as(Repr, .{ 0, 0 })),
                  [mask] "x" (if (second) mask2 else mask1),
            );
        }
    };
}

pub fn AesEncryptCtx(comptime Aes: type) type {
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();

        key_schedule: KeySchedule(Aes),

        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            var first = Block.fromBytes(key[0..16]);
            const key_schedule = if (Aes.key_bits == 128) blk: {
                break :blk KeySchedule(Aes).expand128(&first);
            } else blk: {
                var second = Block.fromBytes(key[16..32]);
                break :blk KeySchedule(Aes).expand256(&first, &second);
            };
            return .{ .key_schedule = key_schedule };
        }

        pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(round_keys[0]);
            inline for (1..rounds) |index| {
                t = t.encrypt(round_keys[index]);
            }
            t = t.encryptLast(round_keys[rounds]);
            dst.* = t.toBytes();
        }

        // Four live blocks hide the aese latency (std modes parallel shape).
        pub fn encryptWide4(ctx: Self, dst: *[64]u8, src: *const [64]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var b0 = Block.fromBytes(src[0..16]).xorBlocks(round_keys[0]);
            var b1 = Block.fromBytes(src[16..32]).xorBlocks(round_keys[0]);
            var b2 = Block.fromBytes(src[32..48]).xorBlocks(round_keys[0]);
            var b3 = Block.fromBytes(src[48..64]).xorBlocks(round_keys[0]);
            inline for (1..rounds) |index| {
                b0 = b0.encrypt(round_keys[index]);
                b1 = b1.encrypt(round_keys[index]);
                b2 = b2.encrypt(round_keys[index]);
                b3 = b3.encrypt(round_keys[index]);
            }
            b0 = b0.encryptLast(round_keys[rounds]);
            b1 = b1.encryptLast(round_keys[rounds]);
            b2 = b2.encryptLast(round_keys[rounds]);
            b3 = b3.encryptLast(round_keys[rounds]);
            dst[0..16].* = b0.toBytes();
            dst[16..32].* = b1.toBytes();
            dst[32..48].* = b2.toBytes();
            dst[48..64].* = b3.toBytes();
        }
    };
}

pub fn AesDecryptCtx(comptime Aes: type) type {
    const rounds = Aes.rounds;

    return struct {
        const Self = @This();

        key_schedule: KeySchedule(Aes),

        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            return .{ .key_schedule = AesEncryptCtx(Aes).init(key).key_schedule.invert() };
        }

        pub fn decrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
            const round_keys = ctx.key_schedule.round_keys;
            var t = Block.fromBytes(src).xorBlocks(round_keys[0]);
            inline for (1..rounds) |index| {
                t = t.decrypt(round_keys[index]);
            }
            t = t.decryptLast(round_keys[rounds]);
            dst.* = t.toBytes();
        }
    };
}

fn AesParams(comptime bits: u16) type {
    return struct {
        pub const key_bits = bits;
        pub const rounds = (bits - 64) / 32 + 8;

        pub fn initEnc(key: [bits / 8]u8) AesEncryptCtx(@This()) {
            return AesEncryptCtx(@This()).init(key);
        }

        pub fn initDec(key: [bits / 8]u8) AesDecryptCtx(@This()) {
            return AesDecryptCtx(@This()).init(key);
        }
    };
}

pub const Aes128 = AesParams(128);
pub const Aes256 = AesParams(256);

// AES-192 fills the same round-key walker from the word expansion; no
// 16-byte key groups exist, so the vectorized schedule cannot apply.
pub const Aes192Hw = struct {
    const rounds = 12;

    round_keys: [rounds + 1]Block,

    pub fn initEnc(key: [24]u8) Aes192Hw {
        var words: [52]u32 = undefined;
        for (0..6) |index| {
            words[index] = std.mem.readInt(u32, key[4 * index ..][0..4], .big);
        }
        expandWordLoop(words[0..], 6);
        var round_keys: [rounds + 1]Block = undefined;
        packRoundKeys(&words, round_keys[0..]);
        return .{ .round_keys = round_keys };
    }

    pub fn initDec(key: [24]u8) Aes192Hw {
        return initEnc(key).invert();
    }

    fn invert(self: Aes192Hw) Aes192Hw {
        var round_keys: [rounds + 1]Block = undefined;
        invertSchedule(self.round_keys[0..], round_keys[0..]);
        return .{ .round_keys = round_keys };
    }

    const BlockDirection = enum { encrypt, decrypt };

    fn cryptBlock(self: Aes192Hw, dst: *[block_length]u8, src: *const [block_length]u8, comptime direction: BlockDirection) void {
        var t = Block.fromBytes(src).xorBlocks(self.round_keys[0]);
        inline for (1..rounds) |index| {
            t = switch (direction) {
                .encrypt => t.encrypt(self.round_keys[index]),
                .decrypt => t.decrypt(self.round_keys[index]),
            };
        }
        t = switch (direction) {
            .encrypt => t.encryptLast(self.round_keys[rounds]),
            .decrypt => t.decryptLast(self.round_keys[rounds]),
        };
        dst.* = t.toBytes();
    }

    pub fn encryptBlock(self: Aes192Hw, dst: *[block_length]u8, src: *const [block_length]u8) void {
        cryptBlock(self, dst, src, .encrypt);
    }

    // Four live blocks hide the aese latency (std modes parallel shape).
    pub fn encryptWide4(self: Aes192Hw, dst: *[64]u8, src: *const [64]u8) void {
        var b0 = Block.fromBytes(src[0..16]).xorBlocks(self.round_keys[0]);
        var b1 = Block.fromBytes(src[16..32]).xorBlocks(self.round_keys[0]);
        var b2 = Block.fromBytes(src[32..48]).xorBlocks(self.round_keys[0]);
        var b3 = Block.fromBytes(src[48..64]).xorBlocks(self.round_keys[0]);
        inline for (1..rounds) |index| {
            b0 = b0.encrypt(self.round_keys[index]);
            b1 = b1.encrypt(self.round_keys[index]);
            b2 = b2.encrypt(self.round_keys[index]);
            b3 = b3.encrypt(self.round_keys[index]);
        }
        b0 = b0.encryptLast(self.round_keys[rounds]);
        b1 = b1.encryptLast(self.round_keys[rounds]);
        b2 = b2.encryptLast(self.round_keys[rounds]);
        b3 = b3.encryptLast(self.round_keys[rounds]);
        dst[0..16].* = b0.toBytes();
        dst[16..32].* = b1.toBytes();
        dst[32..48].* = b2.toBytes();
        dst[48..64].* = b3.toBytes();
    }

    pub fn decryptBlock(self: Aes192Hw, dst: *[block_length]u8, src: *const [block_length]u8) void {
        cryptBlock(self, dst, src, .decrypt);
    }
};

fn expandWordLoop(words: []u32, nk: usize) void {
    var index: usize = nk;
    while (index < words.len) : (index += 1) {
        var temp = words[index - 1];
        if (index % nk == 0) {
            temp = subWord(std.math.rotl(u32, temp, 8)) ^ (rcon[index / nk - 1] << 24);
        } else if (nk == 8 and index % nk == 4) {
            temp = subWord(temp);
        }
        words[index] = words[index - nk] ^ temp;
    }
}

fn packRoundKeys(words: []const u32, round_keys: []Block) void {
    for (round_keys, 0..) |*key, round| {
        var bytes: [16]u8 = undefined;
        for (0..4) |word| {
            std.mem.writeInt(u32, bytes[4 * word ..][0..4], words[4 * round + word], .big);
        }
        key.* = Block.fromBytes(&bytes);
    }
}

fn invertSchedule(round_keys: []const Block, inverted: []Block) void {
    const rounds = inverted.len - 1;
    inverted[0] = round_keys[rounds];
    for (1..rounds) |index| {
        inverted[index] = round_keys[rounds - index].invMixColumns();
    }
    inverted[rounds] = round_keys[0];
}

const rcon = [_]u32{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

fn subWord(word: u32) u32 {
    var result: u32 = 0;
    for (0..4) |index| {
        result |= @as(u32, sbox[@as(u8, @truncate(word >> @intCast(8 * index)))]) << @intCast(8 * index);
    }
    return result;
}

fn addRoundKey(state: *[16]u8, key_bytes: *const [16]u8) void {
    for (0..4) |index| {
        const word = std.mem.readInt(u32, key_bytes[4 * index ..][0..4], .big);
        state[4 * index] ^= @truncate(word >> 24);
        state[4 * index + 1] ^= @truncate(word >> 16);
        state[4 * index + 2] ^= @truncate(word >> 8);
        state[4 * index + 3] ^= @truncate(word);
    }
}

fn subBytesWith(state: *[16]u8, table: *const [256]u8) void {
    for (state) |*byte| byte.* = table[byte.*];
}

fn subBytes(state: *[16]u8) void {
    subBytesWith(state, &sbox);
}

fn invSubBytes(state: *[16]u8) void {
    subBytesWith(state, &inv_sbox);
}

const ShiftDirection = enum { forward, inverse };

fn shiftRowsTo(state: *[16]u8, comptime direction: ShiftDirection) void {
    var temp: [16]u8 = undefined;
    for (0..4) |row| {
        for (0..4) |column| temp[row + 4 * column] = state[
            row + 4 * switch (direction) {
                .forward => (column + row) % 4,
                .inverse => (column + 4 - row) % 4,
            }
        ];
    }
    state.* = temp;
}

fn shiftRows(state: *[16]u8) void {
    shiftRowsTo(state, .forward);
}

fn invShiftRows(state: *[16]u8) void {
    shiftRowsTo(state, .inverse);
}

fn xtime(byte: u8) u8 {
    return (byte << 1) ^ (@as(u8, byte >> 7) *% 0x1b);
}

fn mixColumns(state: *[16]u8) void {
    var temp: [16]u8 = undefined;
    for (0..4) |column| {
        const a0 = state[4 * column];
        const a1 = state[4 * column + 1];
        const a2 = state[4 * column + 2];
        const a3 = state[4 * column + 3];
        temp[4 * column] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        temp[4 * column + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        temp[4 * column + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        temp[4 * column + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
    state.* = temp;
}

fn invMixColumnsBytes(state: *[16]u8) void {
    var temp: [16]u8 = undefined;
    for (0..4) |column| {
        const a0 = state[4 * column];
        const a1 = state[4 * column + 1];
        const a2 = state[4 * column + 2];
        const a3 = state[4 * column + 3];
        temp[4 * column] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
        temp[4 * column + 1] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
        temp[4 * column + 2] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
        temp[4 * column + 3] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
    }
    state.* = temp;
}

fn mul9(byte: u8) u8 {
    return xtime(xtime(xtime(byte))) ^ byte;
}

fn mul11(byte: u8) u8 {
    return xtime(xtime(xtime(byte))) ^ xtime(byte) ^ byte;
}

fn mul13(byte: u8) u8 {
    return xtime(xtime(xtime(byte))) ^ xtime(xtime(byte)) ^ byte;
}

fn mul14(byte: u8) u8 {
    return xtime(xtime(xtime(byte))) ^ xtime(xtime(byte)) ^ xtime(byte);
}

fn gfMulReference(multiplicand_in: u8, multiplier_in: u8) u8 {
    var a = multiplicand_in;
    var b = multiplier_in;
    var result: u8 = 0;
    for (0..8) |_| {
        if (b & 1 != 0) result ^= a;
        const carry = a & 0x80 != 0;
        a <<= 1;
        if (carry) a ^= 0x1b;
        b >>= 1;
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

comptime {
    @setEvalBranchQuota(10_000_000);
    for (0..256) |index| {
        const x: u8 = @intCast(index);
        std.debug.assert(mul9(x) == gfMulReference(9, x));
        std.debug.assert(mul11(x) == gfMulReference(11, x));
        std.debug.assert(mul13(x) == gfMulReference(13, x));
        std.debug.assert(mul14(x) == gfMulReference(14, x));
        std.debug.assert(inv_sbox[sbox[index]] == index);
    }
    std.debug.assert(sbox[0] == 0x63);
    for (0..4) |column| {
        for (0..4) |row| {
            for (0..256) |value| {
                var state: [16]u8 = @splat(0);
                state[4 * column + row] = @intCast(value);
                mixColumns(&state);
                invMixColumnsBytes(&state);
                std.debug.assert(state[4 * column + row] == @as(u8, @intCast(value)));
            }
        }
    }
}

test "aes onprem matches the std oracle" {
    const pt = [16]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const key128 = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const key192 = [24]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    const key256 = [32]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    const ours128 = Aes128.initEnc(key128);
    var std128 = std.crypto.core.aes.Aes128.initEnc(key128);
    var out: [16]u8 = undefined;
    var expected: [16]u8 = undefined;
    ours128.encrypt(&out, &pt);
    std128.encrypt(&expected, &pt);
    try std.testing.expectEqualSlices(u8, &expected, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }, &out);
    const dec128 = Aes128.initDec(key128);
    var back: [16]u8 = undefined;
    dec128.decrypt(&back, &out);
    try std.testing.expectEqualSlices(u8, &pt, &back);

    const ours256 = Aes256.initEnc(key256);
    var std256 = std.crypto.core.aes.Aes256.initEnc(key256);
    ours256.encrypt(&out, &pt);
    std256.encrypt(&expected, &pt);
    try std.testing.expectEqualSlices(u8, &expected, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }, &out);

    const ours192 = Aes192Hw.initEnc(key192);
    ours192.encryptBlock(&out, &pt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }, &out);
    const dec192 = Aes192Hw.initDec(key192);
    dec192.decryptBlock(&back, &out);
    try std.testing.expectEqualSlices(u8, &pt, &back);
}
