const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

// AES-192 stays on-prem because std ships no 192-bit context; either provider
// tag resolves to the on-prem schedule.

const std_aes = std.crypto.core.aes;

const StdAes128Enc = struct {
    inner: std_aes.AesEncryptCtx(std_aes.Aes128),
    pub fn init(key: [16]u8) @This() {
        return .{ .inner = std_aes.Aes128.initEnc(key) };
    }
    pub fn encrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
        self.inner.encrypt(dst, src);
    }
};

const StdAes128Dec = struct {
    inner: std_aes.AesDecryptCtx(std_aes.Aes128),
    pub fn init(key: [16]u8) @This() {
        return .{ .inner = std_aes.Aes128.initDec(key) };
    }
    pub fn decrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
        self.inner.decrypt(dst, src);
    }
};

const StdAes256Enc = struct {
    inner: std_aes.AesEncryptCtx(std_aes.Aes256),
    pub fn init(key: [32]u8) @This() {
        return .{ .inner = std_aes.Aes256.initEnc(key) };
    }
    pub fn encrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
        self.inner.encrypt(dst, src);
    }
};

const StdAes256Dec = struct {
    inner: std_aes.AesDecryptCtx(std_aes.Aes256),
    pub fn init(key: [32]u8) @This() {
        return .{ .inner = std_aes.Aes256.initDec(key) };
    }
    pub fn decrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
        self.inner.decrypt(dst, src);
    }
};

pub const Aes128EncCtx = seam.CipherCtx(options.aes_impl, onprem.AesEncryptCtx(onprem.Aes128), StdAes128Enc);
pub const Aes128DecCtx = seam.CipherCtx(options.aes_impl, onprem.AesDecryptCtx(onprem.Aes128), StdAes128Dec);
pub const Aes256EncCtx = seam.CipherCtx(options.aes_impl, onprem.AesEncryptCtx(onprem.Aes256), StdAes256Enc);
pub const Aes256DecCtx = seam.CipherCtx(options.aes_impl, onprem.AesDecryptCtx(onprem.Aes256), StdAes256Dec);

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
pub const SuiteOnprem = struct {
    pub const Enc128 = onprem.AesEncryptCtx(onprem.Aes128);
    pub const Dec128 = onprem.AesDecryptCtx(onprem.Aes128);
    pub const Enc256 = onprem.AesEncryptCtx(onprem.Aes256);
    pub const Dec256 = onprem.AesDecryptCtx(onprem.Aes256);
};

pub const SuiteOffprem = struct {
    pub const Enc128 = StdAes128Enc;
    pub const Dec128 = StdAes128Dec;
    pub const Enc256 = StdAes256Enc;
    pub const Dec256 = StdAes256Dec;
};

pub const Suite = switch (options.aes_impl) {
    .onprem => SuiteOnprem,
    .offprem => SuiteOffprem,
    .mergeable => SuiteOnprem,
};
