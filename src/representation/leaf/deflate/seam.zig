const std = @import("std");

const build_options = @import("options");
// Encode is onprem-only: no offprem encoder exists, so an offprem encode tag
// fails unsupported at the call site.
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

// Encoded bytes are tag-independent: the onprem encoder serves every
// tag, as with AES-192.
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

    pub fn initBound(provider: Provider, input: *std.Io.Reader, history: []u8) error{UnsupportedException}!@This() {
        return switch (provider) {
            .onprem => .{ .onprem = onprem.Decompress.init(input, history) },
            .offprem => .{ .offprem = offprem.Decompress.init(input, history) },
        };
    }

    pub fn initSliceBoundInPlace(self: *@This(), provider: Provider, data: []const u8, history: []u8) error{UnsupportedException}!void {
        switch (provider) {
            .onprem => {
                self.* = .{ .onprem = undefined };
                self.onprem.initSliceInPlace(data, history);
            },
            .offprem => {
                self.* = .{ .offprem = undefined };
                try self.offprem.initSliceBoundInPlace(provider, data, history);
            },
        }
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

    // The session driver tells starvation from corruption through this:
    // a starved parse stays resumable, a failed one is terminal.
    pub fn isFailed(self: *const @This()) bool {
        return switch (self.*) {
            .onprem => |*inner| inner.isFailed(),
            .offprem => |*inner| inner.isFailed(),
        };
    }

    pub fn readerPtr(self: *@This()) *std.Io.Reader {
        return switch (self.*) {
            .onprem => |*inner| inner.readerPtr(),
            .offprem => |*inner| inner.readerPtr(),
        };
    }

    // Each arm owns how its decoded bytes reach a writer, so this dispatches once.
    pub fn streamTo(self: *@This(), writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        return switch (self.*) {
            .onprem => |*inner| inner.streamTo(writer, limit),
            .offprem => |*inner| inner.streamTo(writer, limit),
        };
    }
};
