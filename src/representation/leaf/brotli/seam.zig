const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.leaf_impl;
pub const Provider = seam.Provider;
pub const DecodeError = offprem.DecodeError;
pub const EncodeError = offprem.EncodeError;
pub const Options = onprem.Options;

pub fn decode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: Options) DecodeError!usize {
    return seam.dispatchOnprem(impl, provider, onprem.decode, .{ input, output, scratch, options });
}
// Encode stays onprem; no offprem encoder exists.
pub fn encode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: Options) EncodeError!usize {
    try seam.requireServed(provider, .onprem);
    return onprem.encode(input, output, scratch, options);
}
pub fn decodedSize(provider: Provider, input: []const u8, scratch: []u8, options: Options) DecodeError!usize {
    return seam.dispatchOnprem(impl, provider, onprem.decodedSize, .{ input, scratch, options });
}
pub fn decodeWorkspaceSize(provider: Provider, options: Options) usize {
    return if (impl != .offprem and provider == .onprem) onprem.decodeWorkspaceSize(options) else 0;
}
pub fn encodeWorkspaceSize(provider: Provider, options: Options) usize {
    return if (provider == .onprem) onprem.encodeWorkspaceSize(options) else 0;
}
