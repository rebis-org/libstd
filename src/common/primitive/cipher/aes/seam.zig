const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

// AES-192 stays on-prem because std ships no 192-bit context.
pub const Implementation = enum { onprem, offprem };

pub const Block = switch (options.aes_impl) {
    .onprem => onprem.Block,
    .offprem => std.crypto.core.aes.Block,
};

pub const Aes128 = switch (options.aes_impl) {
    .onprem => onprem.Aes128,
    .offprem => std.crypto.core.aes.Aes128,
};

pub const Aes256 = switch (options.aes_impl) {
    .onprem => onprem.Aes256,
    .offprem => std.crypto.core.aes.Aes256,
};

pub const Aes192Hw = onprem.Aes192Hw;

pub const Aes128EncCtx = switch (options.aes_impl) {
    .onprem => onprem.AesEncryptCtx(onprem.Aes128),
    .offprem => std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128),
};

pub const Aes128DecCtx = switch (options.aes_impl) {
    .onprem => onprem.AesDecryptCtx(onprem.Aes128),
    .offprem => std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes128),
};

pub const Aes256EncCtx = switch (options.aes_impl) {
    .onprem => onprem.AesEncryptCtx(onprem.Aes256),
    .offprem => std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256),
};

pub const Aes256DecCtx = switch (options.aes_impl) {
    .onprem => onprem.AesDecryptCtx(onprem.Aes256),
    .offprem => std.crypto.core.aes.AesDecryptCtx(std.crypto.core.aes.Aes256),
};
