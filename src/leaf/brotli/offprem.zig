const std = @import("std");

// No stdlib brotli exists, so the offprem arm is explicit
// UnsupportedFailure. Encode resolves to onprem under every tag (the
// AES-192 precedent), which keeps encoded bytes tag-independent.
pub const DecodeError = error{ UnsupportedFailure, IoFailure, DataFailure, ResourceFailure, CapacityFailure, InternalFailure, CallFailure };
pub const EncodeError = error{ UnsupportedFailure, IoFailure, DataFailure, ResourceFailure, CapacityFailure, InternalFailure, CallFailure };
pub const TrainError = error{UnsupportedFailure};

pub const Options = @import("onprem.zig").Options;

pub fn decode(_: []const u8, _: []u8, _: []u8, _: Options) DecodeError!usize {
    return error.UnsupportedFailure;
}

pub fn encode(_: []const u8, _: []u8, _: []u8, _: Options) EncodeError!usize {
    return error.UnsupportedFailure;
}

pub fn decodedSize(_: []const u8, _: []u8, _: Options) DecodeError!usize {
    return error.UnsupportedFailure;
}

pub fn decodeWorkspaceSize(_: Options) usize {
    _ = _enum_hack;
    return 0;
}

pub fn encodeWorkspaceSize(_: Options) usize {
    return 0;
}

const _enum_hack = 0;
