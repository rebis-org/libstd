const std = @import("std");

const build_options = @import("options");
// One dispatch per call, never per symbol or block; the offprem arm's
// accepted incompleteness is recorded in offprem.zig.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

fn requireServed(provider: Provider, comptime served: Provider) error{UnsupportedFailure}!void {
    if (provider != served) return error.UnsupportedFailure;
}

pub fn decode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decode(input, output, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decode(input, output, scratch, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decode(input, output, scratch, options),
            .offprem => offprem.decode(input, output, scratch, options),
        },
    };
}

pub fn encode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: onprem.Options) onprem.EncodeError!usize {
    // Every tag resolves encode to the onprem arm: no offprem encoder
    // exists, mirroring the deflate seam.
    try requireServed(provider, .onprem);
    return onprem.encode(input, output, scratch, options);
}

pub fn decodedSize(provider: Provider, input: []const u8, scratch: []u8, options: onprem.Options) onprem.DecodeError!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodedSize(input, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodedSize(input, scratch, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodedSize(input, scratch, options),
            .offprem => offprem.decodedSize(input, scratch, options),
        },
    };
}

pub fn decodeWorkspaceSize(provider: Provider, options: onprem.Options) usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            requireServed(provider, .onprem) catch return 0;
            break :blk onprem.decodeWorkspaceSize(options);
        },
        .offprem => blk: {
            requireServed(provider, .offprem) catch return 0;
            break :blk offprem.decodeWorkspaceSize(options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeWorkspaceSize(options),
            .offprem => offprem.decodeWorkspaceSize(options),
        },
    };
}

pub fn encodeWorkspaceSize(provider: Provider, options: onprem.Options) usize {
    // Encode resolves to onprem under every tag.
    if (provider != .onprem) return 0;
    return onprem.encodeWorkspaceSize(options);
}
