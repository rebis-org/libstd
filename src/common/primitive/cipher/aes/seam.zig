const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

// AES-192 stays on-prem because std ships no 192-bit context; either provider
// tag resolves to the on-prem schedule.

const std_aes = std.crypto.core.aes;

const StdDirection = enum { encrypt, decrypt };

fn StdCtx(comptime Params: type, comptime direction: StdDirection) type {
    const Ctx = switch (direction) {
        .encrypt => std_aes.AesEncryptCtx(Params),
        .decrypt => std_aes.AesDecryptCtx(Params),
    };
    return struct {
        inner: Ctx,

        pub fn init(key: [Params.key_bits / 8]u8) @This() {
            return .{ .inner = switch (direction) {
                .encrypt => Params.initEnc(key),
                .decrypt => Params.initDec(key),
            } };
        }

        pub fn encrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
            if (direction != .encrypt) @compileError("a decrypt context cannot encrypt.");
            self.inner.encrypt(dst, src);
        }

        pub fn decrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
            if (direction != .decrypt) @compileError("an encrypt context cannot decrypt.");
            self.inner.decrypt(dst, src);
        }
    };
}

const StdAes128Enc = StdCtx(std_aes.Aes128, .encrypt);
const StdAes128Dec = StdCtx(std_aes.Aes128, .decrypt);
const StdAes256Enc = StdCtx(std_aes.Aes256, .encrypt);
const StdAes256Dec = StdCtx(std_aes.Aes256, .decrypt);

pub const Aes192Hw = struct {
    inner: onprem.Aes192Hw,

    pub fn initEnc(key: [24]u8) Aes192Hw {
        return .{ .inner = onprem.Aes192Hw.initEnc(key) };
    }

    pub fn initDec(key: [24]u8) Aes192Hw {
        return .{ .inner = onprem.Aes192Hw.initDec(key) };
    }

    pub fn bindEnc(_: seam.Provider, key: [24]u8) Aes192Hw {
        return initEnc(key);
    }

    pub fn bindDec(_: seam.Provider, key: [24]u8) Aes192Hw {
        return initDec(key);
    }

    pub fn encryptBlock(self: Aes192Hw, dst: *[16]u8, src: *const [16]u8) void {
        self.inner.encryptBlock(dst, src);
    }

    pub fn decryptBlock(self: Aes192Hw, dst: *[16]u8, src: *const [16]u8) void {
        self.inner.decryptBlock(dst, src);
    }
};

// Mode operations monomorphize over a suite, so block loops never dispatch per block.
pub const suite_onprem = struct {
    pub const Enc128 = onprem.AesEncryptCtx(onprem.Aes128);
    pub const Dec128 = onprem.AesDecryptCtx(onprem.Aes128);
    pub const Enc256 = onprem.AesEncryptCtx(onprem.Aes256);
    pub const Dec256 = onprem.AesDecryptCtx(onprem.Aes256);
};

pub const suite_offprem = struct {
    pub const Enc128 = StdAes128Enc;
    pub const Dec128 = StdAes128Dec;
    pub const Enc256 = StdAes256Enc;
    pub const Dec256 = StdAes256Dec;
};

pub const suite = switch (options.aes_impl) {
    .onprem => suite_onprem,
    .offprem => suite_offprem,
    .mergeable => suite_onprem,
};
