const std = @import("std");

const build_options = @import("options");
// Codec seam for the deflate decode path, extending the provider model to
// the first leaf: the caller picks onprem (this leaf) or offprem
// (std.compress.flate, decode-only) per call through the same provider tag
// the primitive layer uses, and `portable` keeps governing the onprem arm.
// Encode is onprem-only in every build because no offprem encoder exists;
// an encode under an offprem tag fails explicit `unsupported` at the call
// site, mirroring how an unserved boundary tag fails.
// The seam module supplies the tag type through the build graph (every
// module that compiles this file carries a "seam" import); importing it by
// name keeps module confinement intact.
pub const Provider = @import("seam").Provider;

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

pub const default_provider: Provider = switch (build_options.leaf_impl) {
    .onprem, .mergeable => .onprem,
    .offprem => .offprem,
};

// Whether this build can serve a decode under the tag: fixed builds serve
// their own arm only, mergeable serves both.
pub fn decodeServed(provider: Provider) bool {
    return switch (build_options.leaf_impl) {
        .onprem => provider == .onprem,
        .offprem => provider == .offprem,
        .mergeable => true,
    };
}

// Encode is the onprem arm under every tag: no offprem encoder exists, so
// the seam resolves encode to onprem the way AES-192 resolves to onprem
// under any tag. Encoded bytes are tag-independent
// because every checksum arm is verified byte-identical across providers.
pub fn encodeServed(provider: Provider) bool {
    _ = provider;
    return true;
}

pub const Decode = switch (build_options.leaf_impl) {
    .onprem => onprem.Decompress,
    .offprem => offprem.Decompress,
    .mergeable => Mergeable,
};

const Mergeable = union(Provider) {
    onprem: onprem.Decompress,
    offprem: offprem.Decompress,

    pub fn initBound(provider: Provider, input: *std.Io.Reader, history: []u8) error{Unsupported}!@This() {
        return switch (provider) {
            .onprem => .{ .onprem = onprem.Decompress.init(input, history) },
            .offprem => .{ .offprem = offprem.Decompress.init(input, history) },
        };
    }

    pub fn initSliceBound(provider: Provider, data: []const u8, history: []u8) error{Unsupported}!@This() {
        return switch (provider) {
            .onprem => .{ .onprem = onprem.Decompress.initSlice(data, history) },
            .offprem => .{ .offprem = offprem.Decompress.initSlice(data, history) },
        };
    }

    pub fn inputBitsConsumed(self: *const @This()) usize {
        return switch (self.*) {
            .onprem => |*inner| inner.inputBitsConsumed(),
            .offprem => |*inner| inner.inputBitsConsumed(),
        };
    }

    pub fn setFramePos(self: *@This(), pos: usize) void {
        switch (self.*) {
            .onprem => |*inner| inner.setFramePos(pos),
            .offprem => |*inner| inner.setFramePos(pos),
        }
    }

    // Session-driver surface: framing pokes between steps, dispatched once.
    pub fn streamPosition(self: *const @This()) usize {
        return switch (self.*) {
            .onprem => |*inner| inner.streamPosition(),
            .offprem => |*inner| inner.streamPosition(),
        };
    }

    pub fn restage(self: *@This(), data: []const u8, pos: usize) void {
        switch (self.*) {
            .onprem => |*inner| inner.restage(data, pos),
            .offprem => |*inner| inner.restage(data, pos),
        }
    }

    pub fn atEnd(self: *const @This()) bool {
        return switch (self.*) {
            .onprem => |*inner| inner.atEnd(),
            .offprem => |*inner| inner.atEnd(),
        };
    }

    pub fn clearFailure(self: *@This()) void {
        switch (self.*) {
            .onprem => |*inner| inner.clearFailure(),
            .offprem => |*inner| inner.clearFailure(),
        }
    }

    pub fn readerPtr(self: *@This()) *std.Io.Reader {
        return switch (self.*) {
            .onprem => |*inner| inner.readerPtr(),
            .offprem => |*inner| inner.readerPtr(),
        };
    }
};
