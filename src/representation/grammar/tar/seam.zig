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
