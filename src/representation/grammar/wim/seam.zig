const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.grammar_impl;
pub const Provider = seam.Provider;
pub const Exception = offprem.Exception;
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;
pub const scratch_size = onprem.scratch_size;

pub fn writeScratchLen(entries: []const Entry) Exception!usize {
    return onprem.writeScratchLen(entries);
}
pub fn parseScratchLen(archive: []const u8) Exception!usize {
    return onprem.parseScratchLen(archive);
}
pub fn splitScratchLen(archive: []const u8) Exception!usize {
    return onprem.splitScratchLen(archive);
}

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
pub fn archiveSize(provider: Provider, entries: []const Entry, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.archiveSize, .{ entries, scratch });
}
pub fn encode(provider: Provider, entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.encode, .{ entries, output, scratch });
}
pub fn volumeInspectCount(provider: Provider, parts: []const []const u8, scratch: []u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.volumeInspectCount, .{ parts, scratch });
}
pub fn volumeInspectOrdinal(provider: Provider, parts: []const []const u8, ordinal: u64, scratch: []u8) Exception!onprem.EntryInfo {
    return seam.dispatchOnprem(impl, provider, onprem.volumeInspectOrdinal, .{ parts, ordinal, scratch, onprem.DecodeOptions{} });
}
pub fn volumeDecodeOrdinal(provider: Provider, parts: []const []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.volumeDecodeOrdinal, .{ parts, ordinal, output, scratch, onprem.DecodeOptions{} });
}
pub fn splitPlan(provider: Provider, archive: []const u8, volume_size: u64, scratch: []u8) Exception!onprem.SplitPlan {
    return seam.dispatchOnprem(impl, provider, onprem.wimSplitPlan, .{ archive, volume_size, scratch });
}
pub fn splitEmit(provider: Provider, archive: []const u8, volume_size: u64, output: []u8, lengths: []u64, scratch: []u8) Exception!onprem.SplitPlan {
    return seam.dispatchOnprem(impl, provider, onprem.wimSplitEmit, .{ archive, volume_size, output, lengths, scratch });
}
