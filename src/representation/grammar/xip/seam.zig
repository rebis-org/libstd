const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.grammar_impl;
pub const Provider = seam.Provider;
pub const Exception = offprem.Exception;
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;
pub const ManifestSink = onprem.ManifestSink;
pub const scratch_size = onprem.scratch_size;
pub const window_capacity = onprem.window_capacity;

pub const default_provider: Provider = seam.defaultProvider(impl);
pub fn inspectCount(provider: Provider, archive: []const u8, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.inspectCount, .{ archive, scratch });
}
pub fn inspectOrdinal(provider: Provider, archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    return seam.dispatchOnprem(impl, provider, onprem.inspectOrdinal, .{ archive, ordinal, scratch });
}
pub fn decodeOrdinal(provider: Provider, archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.decodeOrdinal, .{ archive, ordinal, output, scratch });
}
pub fn inspectAll(provider: Provider, archive: []const u8, scratch: []u8, sink: onprem.ManifestSink) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.inspectAll, .{ archive, scratch, sink });
}
pub fn inspectAllView(comptime Forward: type, provider: Provider, forward: *Forward, scratch: []u8, sink: onprem.ManifestSink) Exception!u64 {
    return seam.dispatchOnpremAs(Exception!u64, impl, provider, onprem.inspectAllView, .{ Forward, forward, scratch, sink });
}
pub fn inspectCountView(comptime Forward: type, provider: Provider, forward: *Forward, scratch: []u8) Exception!u64 {
    return seam.dispatchOnpremAs(Exception!u64, impl, provider, onprem.inspectCountView, .{ Forward, forward, scratch });
}
pub fn inspectOrdinalView(comptime Forward: type, provider: Provider, forward: *Forward, ordinal: u64, scratch: []u8) Exception!onprem.EntryInfo {
    return seam.dispatchOnpremAs(Exception!onprem.EntryInfo, impl, provider, onprem.inspectOrdinalView, .{ Forward, forward, ordinal, scratch });
}
pub fn decodeOrdinalView(comptime Forward: type, provider: Provider, forward: *Forward, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    return seam.dispatchOnpremAs(Exception!usize, impl, provider, onprem.decodeOrdinalView, .{ Forward, forward, ordinal, output, scratch });
}
pub fn archiveSize(provider: Provider, entries: []const Entry, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.archiveSize, .{ entries, scratch });
}
pub fn encode(provider: Provider, entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.encode, .{ entries, output, scratch });
}
