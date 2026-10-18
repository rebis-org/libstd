const build_options = @import("options");
const seam = @import("seam");

const onprem = @import("onprem.zig");

const impl = build_options.grammar_impl;
pub const Provider = seam.Provider;
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;
pub const Exception = onprem.Exception;
pub const Options = onprem.Options;
pub const scratch_size = onprem.scratch_size;

pub const default_provider: Provider = seam.defaultProvider(impl);
pub fn inspectCount(provider: Provider, archive: []const u8, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.inspectCount, .{ archive, scratch });
}
pub fn archiveSize(provider: Provider, entries: []const Entry, options: Options, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.archiveSize, .{ entries, options, scratch });
}
pub fn encode(provider: Provider, entries: []const Entry, output: []u8, scratch: []u8, options: Options) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.encode, .{ entries, output, scratch, options });
}
pub fn decodedSize(provider: Provider, archive: []const u8, options: Options, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.decodedSize, .{ archive, options, scratch });
}
pub fn inspectOrdinal(provider: Provider, archive: []const u8, ordinal: u64, options: Options, scratch: []u8) Exception!EntryInfo {
    return seam.dispatchOnprem(impl, provider, onprem.inspectOrdinal, .{ archive, ordinal, options, scratch });
}
pub fn decodeOrdinal(provider: Provider, archive: []const u8, ordinal: u64, output: []u8, scratch: []u8, options: Options) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.decodeOrdinal, .{ archive, ordinal, output, scratch, options });
}
