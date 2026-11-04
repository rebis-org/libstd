const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.grammar_impl;
// Per-verb faithfulness lives in the offprem file; one dispatch per call.
pub const Provider = seam.Provider;
pub const Exception = offprem.Exception;
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;

pub fn inspectCount(provider: Provider, archive: []const u8) Exception!u64 {
    return seam.dispatch(impl, provider, onprem.inspectCount, offprem.inspectCount, .{archive});
}

pub fn decodeOrdinal(provider: Provider, archive: []const u8, ordinal: u64, output: []u8) Exception!usize {
    return seam.dispatch(impl, provider, onprem.decodeOrdinal, offprem.decodeOrdinal, .{ archive, ordinal, output });
}

pub fn archiveSize(provider: Provider, entries: []const Entry) Exception!u64 {
    return seam.dispatch(impl, provider, onprem.archiveSize, offprem.archiveSize, .{entries});
}

pub fn encode(provider: Provider, entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    return seam.dispatch(impl, provider, onprem.encode, offprem.encode, .{ entries, output, scratch });
}

pub fn inspectOrdinal(provider: Provider, archive: []const u8, ordinal: u64) Exception!EntryInfo {
    // std.tar.Iterator.File carries no mtime/uid/gid/typeflag, so every
    // build resolves ordinal inspect to onprem, keeping the metadata contract.
    _ = provider;
    return onprem.inspectOrdinal(archive, ordinal);
}

// Volume sets resolve to onprem everywhere: the offprem arm has no
// multi-volume reader, and the split write is the first-party GNU layout.
pub fn volumeInspectCount(provider: Provider, volumes: []const []const u8) Exception!u64 {
    return seam.dispatchOnprem(impl, provider, onprem.volumeInspectCount, .{volumes});
}

pub fn volumeInspectOrdinal(provider: Provider, volumes: []const []const u8, ordinal: u64) Exception!EntryInfo {
    return seam.dispatchOnprem(impl, provider, onprem.volumeInspectOrdinal, .{ volumes, ordinal });
}

pub fn volumeDecodeOrdinal(provider: Provider, volumes: []const []const u8, ordinal: u64, output: []u8, segments: []onprem.VolumeSegment) Exception!usize {
    return seam.dispatchOnprem(impl, provider, onprem.volumeDecodeOrdinal, .{ volumes, ordinal, output, segments });
}

pub fn volumeSizeGnu(provider: Provider, entries: []const Entry, volume_size: u64) Exception!onprem.VolumePlan {
    return seam.dispatchOnprem(impl, provider, onprem.volumeSizeGnu, .{ entries, volume_size });
}

pub fn volumeEncodeGnu(provider: Provider, entries: []const Entry, output: []u8, lengths: []u64, volume_size: u64, scratch: []u8) Exception!onprem.VolumePlan {
    return seam.dispatchOnprem(impl, provider, onprem.volumeEncodeGnu, .{ entries, output, lengths, volume_size, scratch });
}
