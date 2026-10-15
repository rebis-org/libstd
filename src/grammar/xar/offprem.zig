const onprem = @import("onprem.zig");
pub const Failure = @import("../../common/primitive/failure.zig").Failure;

pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;

// No stdlib xar exists; the offprem arm is explicit UnsupportedFailure.
// Mergeable builds resolve to onprem.
pub fn inspectCount(_: []const u8, _: []u8) Failure!u64 {
    return error.UnsupportedFailure;
}

pub fn inspectOrdinal(_: []const u8, _: u64, _: []u8) Failure!EntryInfo {
    return error.UnsupportedFailure;
}

pub fn decodeOrdinal(_: []const u8, _: u64, _: []u8, _: []u8) Failure!usize {
    return error.UnsupportedFailure;
}

pub fn archiveSize(_: []const Entry) Failure!u64 {
    return error.UnsupportedFailure;
}

pub fn encode(_: []const Entry, _: []u8, _: []u8) Failure!usize {
    return error.UnsupportedFailure;
}
