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
pub fn serves(provider: Provider) bool {
    const sets = comptime blk: {
        var offprem_served = false;
        var onprem_served = false;
        for (capability_impls) |impl| {
            if (impl != .onprem) offprem_served = true;
            if (impl != .offprem) onprem_served = true;
        }
        break :blk .{ .offprem = offprem_served, .onprem = onprem_served };
    };
    return switch (provider) {
        .onprem => sets.onprem,
        .offprem => sets.offprem,
    };
}

// Both providers of one capability contract, bound per context at runtime.
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

        // std's Options is a distinct nominal type; both are empty today, so
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

pub fn ValueHash(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => FixedValueHash(.onprem, On),
        .offprem => FixedValueHash(.offprem, Off),
        .mergeable => MergeableValueHash(On, Off),
    };
}

fn valueHashSeed(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.init)).@"fn".param_types[0].?;
}

fn valueHashFinal(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.final)).@"fn".return_type.?;
}

fn FixedValueHash(comptime tag: Provider, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const Seed = valueHashSeed(Impl);
        pub const Final = valueHashFinal(Impl);

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

fn MergeableValueHash(comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const Seed = valueHashSeed(On);
        pub const Final = valueHashFinal(On);

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

        pub const Final = valueHashFinal(Impl);

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

        pub const Final = valueHashFinal(On);

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
        pub const key_length = Impl.key_length;

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
        pub const key_length = On.key_length;

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

pub fn CipherCtx(comptime mode: Mode, comptime On: type, comptime Off: type) type {
    return switch (mode) {
        .onprem => FixedCipherCtx(.onprem, On),
        .offprem => FixedCipherCtx(.offprem, Off),
        .mergeable => MergeableCipherCtx(On, Off),
    };
}

fn cipherCtxKey(comptime Impl: type) type {
    return @typeInfo(@TypeOf(Impl.init)).@"fn".param_types[0].?;
}

fn FixedCipherCtx(comptime tag: Provider, comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub const Key = cipherCtxKey(Impl);

        pub fn init(key: Key) @This() {
            return .{ .inner = Impl.init(key) };
        }

        pub fn bind(provider: Provider, key: Key) @This() {
            std.debug.assert(provider == tag);
            return init(key);
        }

        pub fn encrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
            self.inner.encrypt(dst, src);
        }

        pub fn decrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
            self.inner.decrypt(dst, src);
        }
    };
}

fn MergeableCipherCtx(comptime On: type, comptime Off: type) type {
    return struct {
        state: Pair(On, Off),

        pub const Key = cipherCtxKey(On);

        pub fn init(key: Key) @This() {
            return bind(default_provider, key);
        }

        pub fn bind(provider: Provider, key: Key) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = On.init(key) } },
                .offprem => .{ .state = .{ .offprem = Off.init(key) } },
            };
        }

        pub fn encrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
            switch (self.state) {
                inline else => |inner| inner.encrypt(dst, src),
            }
        }

        pub fn decrypt(self: @This(), dst: *[16]u8, src: *const [16]u8) void {
            switch (self.state) {
                inline else => |inner| inner.decrypt(dst, src),
            }
        }
    };
}
