const std = @import("std");

const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.leaf_impl;
// One dispatch per call, never per symbol or block; fixed builds reject the
// other tag explicitly.
pub const Provider = seam.Provider;
pub const Exception = offprem.Exception;

pub const default_provider: Provider = seam.defaultProvider(impl);

pub fn decode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: onprem.Options) Exception!usize {
    return seam.dispatch(impl, provider, onprem.decode, offprem.decode, .{ input, output, scratch, options });
}

pub fn decodeInPlace(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: onprem.Options) Exception!usize {
    return seam.dispatch(impl, provider, onprem.decodeInPlace, offprem.decode, .{ input, output, scratch, options });
}

pub fn decodedSize(provider: Provider, input: []const u8, scratch: []u8, options: onprem.Options) Exception!usize {
    return seam.dispatch(impl, provider, onprem.decodedSize, offprem.decodedSize, .{ input, scratch, options });
}

pub fn decodeToWriter(provider: Provider, input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: onprem.Options) Exception!void {
    return seam.dispatch(impl, provider, onprem.decodeToWriter, offprem.decodeToWriter, .{ input, writer, scratch, options });
}
