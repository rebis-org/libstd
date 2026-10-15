const build_options = @import("options");
// Per-verb faithfulness lives in the offprem file; one dispatch per call.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

pub const Failure = offprem.Failure;
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;

pub const default_provider: Provider = switch (build_options.grammar_impl) {
    .onprem, .mergeable => .onprem,
    .offprem => .offprem,
};

// Fixed builds reject the foreign tag explicitly.
// Mergeable builds bind per call, never per symbol or block.
fn requireServed(provider: Provider, comptime served: Provider) error{UnsupportedFailure}!void {
    if (provider != served) return error.UnsupportedFailure;
}
pub fn inspectCount(provider: Provider, archive: []const u8) Failure!u64 {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.inspectCount(archive);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.inspectCount(archive);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.inspectCount(archive),
            .offprem => offprem.inspectCount(archive),
        },
    };
}
pub fn decodeOrdinal(provider: Provider, archive: []const u8, ordinal: u64, output: []u8) Failure!usize {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeOrdinal(archive, ordinal, output);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeOrdinal(archive, ordinal, output);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeOrdinal(archive, ordinal, output),
            .offprem => offprem.decodeOrdinal(archive, ordinal, output),
        },
    };
}
pub fn archiveSize(provider: Provider, entries: []const Entry) Failure!u64 {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.archiveSize(entries);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.archiveSize(entries);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.archiveSize(entries),
            .offprem => offprem.archiveSize(entries),
        },
    };
}
pub fn encode(provider: Provider, entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.encode(entries, output, scratch);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.encode(entries, output, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.encode(entries, output, scratch),
            .offprem => offprem.encode(entries, output, scratch),
        },
    };
}

pub fn inspectOrdinal(provider: Provider, archive: []const u8, ordinal: u64) Failure!EntryInfo {
    // std.tar.File lacks mtime, uid, gid, and typeflag.
    // Ordinal inspect stays onprem in every build; see offprem.zig.
    _ = provider;
    return onprem.inspectOrdinal(archive, ordinal);
}
