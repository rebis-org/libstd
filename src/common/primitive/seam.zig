const std = @import("std");

const options = @import("options");

pub const Provider = enum { onprem, offprem };

// Non-envelope consumers bind the boundary default: the fixed provider in
// onprem or offprem builds, onprem in mergeable builds. Session drivers inherit
// it because the stepped C boundary carries no provider parameter.
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

// A fixed capability keeps its own provider regardless of the tag, so the
// boundary rejects a tag only when no capability can serve it at all.
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

pub fn Digest(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => FixedDigest(.onprem, On),
        .offprem => FixedDigest(.offprem, Off),
        .mergeable => MergeableDigest(On, Off),
    };
}

fn FixedDigest(comptime tag: Provider, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const digest_length = Impl.digest_length;
        pub const block_length = Impl.block_length;
        pub const Options = Impl.Options;

        pub fn init(opts: Options) @This() {
            return .{ .inner = Impl.init(opts) };
        }

        // The boundary validated the tag; a mismatch is a caller bug.
        pub fn bind(provider: Provider, opts: Options) @This() {
            std.debug.assert(provider == tag);
            return init(opts);
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

fn MergeableDigest(comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const digest_length = On.digest_length;
        pub const block_length = On.block_length;
        pub const Options = On.Options;

        pub fn init(opts: Options) @This() {
            return bind(default_provider, opts);
        }

        // stdlib's Options is a distinct nominal type; both are empty today, so
        // the offprem arm constructs from defaults.
        pub fn bind(provider: Provider, opts: Options) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = On.init(opts) } },
                .offprem => .{ .state = .{ .offprem = Off.init(.{}) } },
            };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            switch (self.state) {
                inline else => |*inner| inner.update(input),
            }
        }

        pub fn final(self: *@This(), out: *[digest_length]u8) void {
            switch (self.state) {
                inline else => |*inner| inner.final(out),
            }
        }

        pub fn finalResult(self: *@This()) [digest_length]u8 {
            switch (self.state) {
                inline else => |*inner| return inner.finalResult(),
            }
        }
    };
}

pub fn Hash(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => FixedHash(.onprem, On),
        .offprem => FixedHash(.offprem, Off),
        .mergeable => MergeableHash(On, Off),
    };
}

fn hashSeed(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.init)).@"fn".param_types[0].?;
}

fn hashFinal(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.final)).@"fn".return_type.?;
}

fn FixedHash(comptime tag: Provider, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const Seed = hashSeed(Impl);
        pub const Final = hashFinal(Impl);

        pub fn init(seed: Seed) @This() {
            return .{ .inner = Impl.init(seed) };
        }

        pub fn bind(provider: Provider, seed: Seed) @This() {
            std.debug.assert(provider == tag);
            return init(seed);
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *@This()) Final {
            return self.inner.final();
        }
    };
}

fn MergeableHash(comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const Seed = hashSeed(On);
        pub const Final = hashFinal(On);

        pub fn init(seed: Seed) @This() {
            return bind(default_provider, seed);
        }

        pub fn bind(provider: Provider, seed: Seed) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = On.init(seed) } },
                .offprem => .{ .state = .{ .offprem = Off.init(seed) } },
            };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            switch (self.state) {
                inline else => |*inner| inner.update(input),
            }
        }

        pub fn final(self: *@This()) Final {
            switch (self.state) {
                inline else => |*inner| return inner.final(),
            }
        }
    };
}

pub fn Checksum(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => FixedChecksum(.onprem, On),
        .offprem => FixedChecksum(.offprem, Off),
        .mergeable => MergeableChecksum(On, Off),
    };
}

fn FixedChecksum(comptime tag: Provider, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const Final = hashFinal(Impl);

        pub fn init() @This() {
            return .{ .inner = Impl.init() };
        }

        pub fn bind(provider: Provider) @This() {
            std.debug.assert(provider == tag);
            return init();
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn final(self: *const @This()) Final {
            return self.inner.final();
        }
    };
}

fn MergeableChecksum(comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const Final = hashFinal(On);

        pub fn init() @This() {
            return bind(default_provider);
        }

        pub fn bind(provider: Provider) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = On.init() } },
                .offprem => .{ .state = .{ .offprem = Off.init() } },
            };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            switch (self.state) {
                inline else => |*inner| inner.update(input),
            }
        }

        pub fn final(self: *const @This()) Final {
            switch (self.state) {
                inline else => |*inner| return inner.final(),
            }
        }
    };
}

pub fn Mac(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => FixedMac(.onprem, On),
        .offprem => FixedMac(.offprem, Off),
        .mergeable => MergeableMac(On, Off),
    };
}

fn FixedMac(comptime tag: Provider, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const mac_length = Impl.mac_length;

        pub fn init(key: []const u8) @This() {
            return .{ .inner = Impl.init(key) };
        }

        pub fn bind(provider: Provider, key: []const u8) @This() {
            std.debug.assert(provider == tag);
            return init(key);
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

fn MergeableMac(comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const mac_length = On.mac_length;

        pub fn init(key: []const u8) @This() {
            return bind(default_provider, key);
        }

        pub fn bind(provider: Provider, key: []const u8) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = On.init(key) } },
                .offprem => .{ .state = .{ .offprem = Off.init(key) } },
            };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            switch (self.state) {
                inline else => |*inner| inner.update(input),
            }
        }

        pub fn final(self: *@This(), out: *[mac_length]u8) void {
            switch (self.state) {
                inline else => |*inner| inner.final(out),
            }
        }

        pub fn finalResult(self: *@This()) [mac_length]u8 {
            switch (self.state) {
                inline else => |*inner| return inner.finalResult(),
            }
        }
    };
}

// The differential contract the seam stitches together: sweep every input
// width against the paired stdlib implementation, splitting updates at each size.
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
