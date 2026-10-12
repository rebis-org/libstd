const std = @import("std");

const build_options = @import("options");
// One dispatch per call, never per chunk or symbol; see offprem.zig for the
// incompleteness choosing std accepts.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

pub const Failure = offprem.Failure;
pub const InPlaceResult = onprem.InPlaceResult;
pub const Options = onprem.Options;

pub const default_provider: Provider = switch (build_options.leaf_impl) {
    .onprem, .mergeable => .onprem,
    .offprem => .offprem,
};

fn requireServed(provider: Provider, comptime served: Provider) error{UnsupportedFailure}!void {
    if (provider != served) return error.UnsupportedFailure;
}
pub fn decode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decode(input, output, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decode(input, output, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decode(input, output, scratch, options),
            .offprem => offprem.decode(input, output, scratch),
        },
    };
}
pub fn decodeInPlace(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!InPlaceResult {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeInPlace(input, output, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeInPlace(input, output, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeInPlace(input, output, scratch, options),
            .offprem => offprem.decodeInPlace(input, output, scratch),
        },
    };
}
pub fn decodeStream(provider: Provider, reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodeStream(reader, writer, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodeStream(reader, writer, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodeStream(reader, writer, scratch, options),
            .offprem => offprem.decodeStream(reader, writer, scratch),
        },
    };
}
pub fn decodedSize(provider: Provider, input: []const u8, scratch: []u8, options: Options) Failure!usize {
    return switch (build_options.leaf_impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk onprem.decodedSize(input, scratch, options);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk offprem.decodedSize(input, scratch);
        },
        .mergeable => switch (provider) {
            .onprem => onprem.decodedSize(input, scratch, options),
            .offprem => offprem.decodedSize(input, scratch),
        },
    };
}
