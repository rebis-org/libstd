const build_options = @import("options");
// Per-verb faithfulness lives in the offprem file; one dispatch per call.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

pub const Failure = offprem.Failure;
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;
pub const scratch_size = onprem.scratch_size;

pub const default_provider: Provider = switch (build_options.grammar_impl) {
    .onprem, .mergeable => .onprem,
    .offprem => .offprem,
};

fn requireServed(provider: Provider, comptime served: Provider) error{UnsupportedFailure}!void {
    if (provider != served) return error.UnsupportedFailure;
}

pub fn inspectCount(provider: Provider, archive: []const u8, scratch: []u8) Failure!u64 {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.inspectCount(archive, scratch);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.inspectCount(archive, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.inspectCount(archive, scratch),
            .offprem => offprem.inspectCount(archive, scratch),
        },
    };
}

pub fn inspectOrdinal(provider: Provider, archive: []const u8, ordinal: u64, scratch: []u8) Failure!EntryInfo {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.inspectOrdinal(archive, ordinal, scratch);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.inspectOrdinal(archive, ordinal, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.inspectOrdinal(archive, ordinal, scratch),
            .offprem => offprem.inspectOrdinal(archive, ordinal, scratch),
        },
    };
}

pub fn decodeOrdinal(provider: Provider, archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Failure!usize {
    return switch (build_options.grammar_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeOrdinal(archive, ordinal, output, scratch);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeOrdinal(archive, ordinal, output, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeOrdinal(archive, ordinal, output, scratch),
            .offprem => offprem.decodeOrdinal(archive, ordinal, output, scratch),
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
