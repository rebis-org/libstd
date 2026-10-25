const std = @import("std");

const options = @import("options");

pub const Provider = enum { onprem, offprem };

// The boundary default for non-envelope consumers; the stepped C boundary
// carries no provider parameter.
pub const default_provider: Provider = switch (options.primitives_impl) {
    .onprem, .mergeable => .onprem,
    .offprem => .offprem,
};

const Mode = @TypeOf(options.primitives_impl);

const capability_impls = .{
    options.sha256_impl,  options.sha1_impl,    options.hmac_impl,       options.pbkdf2_impl,
    options.adler32_impl, options.xxh32_impl,   options.xxh64_impl,      options.aes_impl,
    options.crc32_impl,   options.crc64xz_impl, options.bzip2crc32_impl,
};

// A fixed capability keeps its own provider, so the boundary rejects a tag
// only when nothing serves it.
const served = blk: {
    var offprem_served = false;
    var onprem_served = false;
    for (capability_impls) |impl| {
        if (impl != .onprem) offprem_served = true;
        if (impl != .offprem) onprem_served = true;
    }
    break :blk .{ .offprem = offprem_served, .onprem = onprem_served };
};

pub fn isServed(provider: Provider) bool {
    return switch (provider) {
        .onprem => served.onprem,
        .offprem => served.offprem,
    };
}

pub fn Pair(comptime On: type, comptime Off: type) type {
    return union(Provider) {
        onprem: On,
        offprem: Off,
    };
}

// The four families differ only in construction and final shape; one
// comptime core carries the implementation.
const Family = enum { digest, mac, hash, checksum };

fn hashSeed(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.init)).@"fn".param_types[0].?;
}

fn hashFinal(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.final)).@"fn".return_type.?;
}

// A mutable copy keeps `final` pure and matches the stdlib signature
// without forwarding the wrapper's constness.
fn finish(comptime family: Family, inner: anytype, args: anytype) hashFinal(@TypeOf(inner.*)) {
    var copy = inner.*;
    return switch (family) {
        .digest, .mac => blk: {
            if (@TypeOf(args) == void) @compileError("out-style final requires an output pointer");
            copy.final(args);
            break :blk;
        },
        .hash, .checksum => blk: {
            if (@TypeOf(args) != void) @compileError("value-style final takes no arguments");
            break :blk copy.final();
        },
    };
}

fn Core(comptime mode: Mode, comptime family: Family, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => Fixed(.onprem, family, On),
        .offprem => Fixed(.offprem, family, Off),
        .mergeable => Mergeable(family, On, Off),
    };
}

fn Fixed(comptime tag: Provider, comptime family: Family, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const digest_length = Impl.digest_length;
        pub const block_length = Impl.block_length;
        pub const mac_length = Impl.mac_length;
        pub const Options = Impl.Options;
        pub const Seed = hashSeed(Impl);
        pub const Final = hashFinal(Impl);

        pub fn init(args: anytype) @This() {
            const inner = switch (family) {
                .checksum => Impl.init(),
                else => Impl.init(args),
            };
            return .{ .inner = inner };
        }

        // The boundary validated the tag; a mismatch is a caller defect.
        pub fn bind(provider: Provider, args: anytype) @This() {
            std.debug.assert(provider == tag);
            return init(args);
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *const @This(), args: anytype) Final {
            return finish(family, &self.inner, args);
        }

        pub fn finalResult(self: *const @This()) [digest_length]u8 {
            var copy = self.inner;
            return copy.finalResult();
        }
    };
}

fn Mergeable(comptime family: Family, comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const digest_length = On.digest_length;
        pub const block_length = On.block_length;
        pub const mac_length = On.mac_length;
        pub const Options = On.Options;
        pub const Seed = hashSeed(On);
        pub const Final = hashFinal(On);

        pub fn init(args: anytype) @This() {
            return bind(default_provider, args);
        }

        pub fn bind(provider: Provider, args: anytype) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = make(On, args) } },
                .offprem => .{ .state = .{ .offprem = make(Off, args) } },
            };
        }

        fn make(comptime Impl: type, args: anytype) Impl {
            return switch (family) {
                .checksum => Impl.init(),
                // The stdlib Options type is nominally distinct from the on-prem
                // one; both are empty today, so the foreign arm default-constructs.
                .digest => if (Impl.Options == On.Options) Impl.init(args) else Impl.init(.{}),
                .hash, .mac => Impl.init(args),
            };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            switch (self.state) {
                inline else => |*inner| inner.update(input),
            }
        }

        pub fn final(self: *const @This(), args: anytype) Final {
            switch (self.state) {
                inline else => |*inner| return finish(family, inner, args),
            }
        }

        pub fn finalResult(self: *const @This()) [digest_length]u8 {
            switch (self.state) {
                inline else => |*inner| {
                    var copy = inner.*;
                    return copy.finalResult();
                },
            }
        }
    };
}

pub fn Digest(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    const CoreImpl = Core(mode, .digest, On, Off);
    return struct {
        inner: CoreImpl,

        pub const digest_length = CoreImpl.digest_length;
        pub const block_length = CoreImpl.block_length;
        pub const Options = CoreImpl.Options;

        pub fn init(opts: Options) @This() {
            return .{ .inner = CoreImpl.init(opts) };
        }

        pub fn bind(provider: Provider, opts: Options) @This() {
            return .{ .inner = CoreImpl.bind(provider, opts) };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *@This(), out: *[digest_length]u8) void {
            self.inner.final(out);
        }

        pub fn finalResult(self: *@This()) [digest_length]u8 {
            return self.inner.finalResult();
        }
    };
}

pub fn Hash(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    const CoreImpl = Core(mode, .hash, On, Off);
    return struct {
        inner: CoreImpl,

        pub const Seed = CoreImpl.Seed;
        pub const Final = CoreImpl.Final;

        pub fn init(seed: Seed) @This() {
            return .{ .inner = CoreImpl.init(seed) };
        }

        pub fn bind(provider: Provider, seed: Seed) @This() {
            return .{ .inner = CoreImpl.bind(provider, seed) };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *@This()) Final {
            return self.inner.final({});
        }
    };
}

pub fn Checksum(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    const CoreImpl = Core(mode, .checksum, On, Off);
    return struct {
        inner: CoreImpl,

        pub const Final = CoreImpl.Final;

        pub fn init() @This() {
            return .{ .inner = CoreImpl.init({}) };
        }

        pub fn bind(provider: Provider) @This() {
            return .{ .inner = CoreImpl.bind(provider, {}) };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *const @This()) Final {
            return self.inner.final({});
        }
    };
}

pub fn Mac(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    const CoreImpl = Core(mode, .mac, On, Off);
    return struct {
        inner: CoreImpl,

        pub const mac_length = CoreImpl.mac_length;

        pub fn init(key: []const u8) @This() {
            return .{ .inner = CoreImpl.init(key) };
        }

        pub fn bind(provider: Provider, key: []const u8) @This() {
            return .{ .inner = CoreImpl.bind(provider, key) };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *@This(), out: *[mac_length]u8) void {
            self.inner.final(out);
        }

        pub fn finalResult(self: *@This()) [mac_length]u8 {
            return self.inner.finalResult();
        }
    };
}

// Fixed builds reject the foreign tag; mergeable binds per call.
pub fn requireServed(provider: Provider, comptime allowed: Provider) error{UnsupportedException}!void {
    if (provider != allowed) return error.UnsupportedException;
}

pub fn defaultProvider(comptime impl: anytype) Provider {
    return switch (impl) {
        .onprem, .mergeable => .onprem,
        .offprem => .offprem,
    };
}

pub fn dispatchOnprem(comptime impl: anytype, provider: Provider, comptime on: anytype, args: anytype) @typeInfo(@TypeOf(on)).@"fn".return_type.? {
    // No stdlib container exists; the offprem arm returns an explicit
    // UnsupportedException.
    return switch (impl) {
        .onprem => blk: {
            try requireServed(provider, .onprem);
            break :blk @call(.auto, on, args);
        },
        .offprem => blk: {
            try requireServed(provider, .offprem);
            break :blk error.UnsupportedException;
        },
        .mergeable => switch (provider) {
            .onprem => @call(.auto, on, args),
            .offprem => error.UnsupportedException,
        },
    };
}

// Sweep every input width against the paired stdlib implementation,
// splitting updates at each size.
pub fn expectAgreement(pristine_ours: anytype, pristine_theirs: anytype, seed: u64, comptime digest: bool, comptime theirs_field: ?[]const u8) !void {
    var rng = std.Random.DefaultPrng.init(seed);
    var size: usize = 0;
    while (size <= 1024) : (size += 1) {
        const buf = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(buf);
        rng.random().bytes(buf);
        var ours = pristine_ours;
        var theirs = pristine_theirs;
        ours.update(buf[0 .. size / 2]);
        ours.update(buf[size / 2 ..]);
        theirs.update(buf);
        try agree(&ours, &theirs, digest, theirs_field);
    }
    const long = try std.testing.allocator.alloc(u8, 1 << 20);
    defer std.testing.allocator.free(long);
    rng.random().bytes(long);
    var ours = pristine_ours;
    var theirs = pristine_theirs;
    ours.update(long);
    theirs.update(long);
    try agree(&ours, &theirs, digest, theirs_field);
}

fn agree(ours: anytype, theirs: anytype, comptime digest: bool, comptime theirs_field: ?[]const u8) !void {
    if (digest) {
        try std.testing.expectEqual(theirs.finalResult(), ours.finalResult());
    } else if (theirs_field) |field| {
        try std.testing.expectEqual(@field(theirs.*, field), ours.final());
    } else {
        try std.testing.expectEqual(theirs.final(), ours.final());
    }
}
