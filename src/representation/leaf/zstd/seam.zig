const std = @import("std");

const build_options = @import("options");
// One dispatch per call, never per symbol or block; the offprem arm's
// accepted incompleteness is recorded in offprem.zig.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

fn requireServed(provider: Provider, comptime served: Provider) error{UnsupportedException}!void {
    if (provider != served) return error.UnsupportedException;
}
pub fn decodeStream(provider: Provider, input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeStream(input, output, history, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeStream(input, output, history, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeStream(input, output, history, options),
            .offprem => offprem.decodeStream(input, output, history, options),
        },
    };
}
pub fn decodeInPlace(provider: Provider, input: *std.Io.Reader, output: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeInPlace(input, output, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeInPlace(input, output, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeInPlace(input, output, options),
            .offprem => offprem.decodeInPlace(input, output, options),
        },
    };
}
pub fn decodedSize(provider: Provider, input: []const u8, history: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodedSize(input, history, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodedSize(input, history, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodedSize(input, history, options),
            .offprem => offprem.decodedSize(input, history, options),
        },
    };
}
