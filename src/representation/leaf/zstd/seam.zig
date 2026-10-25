const std = @import("std");

const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.leaf_impl;
// One dispatch per call, never per symbol or block; the offprem arm's
// accepted incompleteness is recorded in offprem.zig.
pub const Provider = seam.Provider;

pub fn decodeStream(provider: Provider, input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return seam.dispatch(impl, provider, onprem.decodeStream, offprem.decodeStream, .{ input, output, history, options });
}

pub fn decodeInPlace(provider: Provider, input: *std.Io.Reader, output: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return seam.dispatch(impl, provider, onprem.decodeInPlace, offprem.decodeInPlace, .{ input, output, options });
}

pub fn decodedSize(provider: Provider, input: []const u8, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return seam.dispatch(impl, provider, onprem.decodedSize, offprem.decodedSize, .{ input, history, options });
}
