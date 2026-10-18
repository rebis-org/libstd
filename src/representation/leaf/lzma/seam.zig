const std = @import("std");

const build_options = @import("options");
// One dispatch per call, never per symbol or block; fixed builds reject the
// other tag explicitly.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

pub const Exception = offprem.Exception;

pub const default_provider: Provider = switch (build_options.leaf_impl) {
    .onprem, .mergeable => .onprem,
    .offprem => .offprem,
};

fn requireServed(provider: Provider, comptime served: Provider) error{UnsupportedException}!void {
    if (provider != served) return error.UnsupportedException;
}
pub fn decode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: onprem.Options) Exception!usize {
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
pub fn decodeInPlace(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: onprem.Options) Exception!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeInPlace(input, output, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decode(input, output, scratch, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeInPlace(input, output, scratch, options),
            .offprem => offprem.decode(input, output, scratch, options),
        },
    };
}
pub fn decodedSize(provider: Provider, input: []const u8, scratch: []u8, options: onprem.Options) Exception!usize {
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
pub fn decodeToWriter(provider: Provider, input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: onprem.Options) Exception!void {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeToWriter(input, writer, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeToWriter(input, writer, scratch, options);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeToWriter(input, writer, scratch, options),
            .offprem => offprem.decodeToWriter(input, writer, scratch, options),
        },
    };
}
