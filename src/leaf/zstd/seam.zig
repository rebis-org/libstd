const std = @import("std");

const build_options = @import("options");
// zstd decode seam, the coarse contract shape: one dispatch per call, never
// per symbol or block. The comptime flavor (a fixed leaf_impl build)
// inlines to the arm's own function; the runtime flavor (mergeable) binds
// the provider tag per call. Fixed builds reject the other tag explicitly
// instead of serving it silently.
//
// The offprem arm records the std incompleteness the caller accepts by
// choosing it: frame content checksums are not verified and dictionaries
// are unsupported (see offprem.zig).
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

// Fixed builds reject the other tag explicitly instead of serving it
// silently; the mergeable build binds the tag per call. One dispatch per
// call, never per symbol or block.
fn requireServed(provider: Provider, comptime served: Provider) error{Unsupported}!void {
    if (provider != served) return error.Unsupported;
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
