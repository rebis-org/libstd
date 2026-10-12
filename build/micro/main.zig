//! Leaf-level micro benchmarks through the time-budgeted runner; a case is a
//! struct with a run method registered in this file.

const std = @import("std");

const checksum = @import("checksum");
const crypto = @import("crypto");

const runner = @import("runner.zig");

const buffer_len = 1 << 20;

const Adler32Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = checksum.Adler32.bind(checksum.default_provider);
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.final());
    }
};

const Crc32Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = checksum.Crc32.bind(checksum.default_provider);
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.final());
    }
};

const XzCrc64Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = checksum.XzCrc64.bind(checksum.default_provider);
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.final());
    }
};

const Bzip2Crc32Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = checksum.Bzip2Crc32.bind(checksum.default_provider);
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.final());
    }
};

const XxHash64Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = checksum.XxHash64.bind(checksum.default_provider, 0);
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.final());
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var config: runner.Config = .{};
    var filter: ?[]const u8 = null;
    var args = init.minimal.args.iterate();
    _ = args.skip();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--shuffle")) {
            config.shuffle = true;
        } else if (std.mem.eql(u8, arg, "--budget-ms")) {
            const value = args.next() orelse return error.MissingOptionValue;
            config.time_budget_ns = try std.fmt.parseInt(u64, value, 10) * std.time.ns_per_ms;
        } else if (std.mem.eql(u8, arg, "--max-iterations")) {
            const value = args.next() orelse return error.MissingOptionValue;
            config.max_iterations = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--filter")) {
            filter = args.next() orelse return error.MissingOptionValue;
        } else {
            return error.UnknownArgument;
        }
    }

    const data = try allocator.alloc(u8, buffer_len);
    defer allocator.free(data);
    var prng = std.Random.DefaultPrng.init(0x5eed);
    prng.random().bytes(data);

    var bench = runner.Benchmark.init(allocator, config);
    defer bench.deinit();

    const adler32_case: Adler32Case = .{ .data = data };
    const crc32_case: Crc32Case = .{ .data = data };
    const xz_crc64_case: XzCrc64Case = .{ .data = data };
    const bzip2_crc32_case: Bzip2Crc32Case = .{ .data = data };
    const xxhash64_case: XxHash64Case = .{ .data = data };

    const xxh32_case: XxHash32Case = .{ .data = data };
    const sha1_case: Sha1Case = .{ .data = data };
    const sha256_case: Sha256Case = .{ .data = data };

    const cases = .{
        .{ "checksum.adler32", &adler32_case },
        .{ "checksum.crc32", &crc32_case },
        .{ "checksum.xz_crc64", &xz_crc64_case },
        .{ "checksum.bzip2_crc32", &bzip2_crc32_case },
        .{ "checksum.xxh32", &xxh32_case },
        .{ "checksum.xxh64", &xxhash64_case },
        .{ "crypto.sha1", &sha1_case },
        .{ "crypto.sha256", &sha256_case },
    };
    inline for (cases) |case| {
        if (filter == null or std.mem.find(u8, case[0], filter.?) != null) {
            try bench.addParam(case[0], case[1]);
        }
    }

    try bench.run(init.io);
}

const XxHash32Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = checksum.XxHash32.bind(checksum.default_provider, 0);
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.final());
    }
};

const Sha1Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = crypto.Sha1.bind(crypto.default_provider, .{});
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.finalResult());
    }
};

const Sha256Case = struct {
    data: []const u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var hash = crypto.Sha256.bind(crypto.default_provider, .{});
        hash.update(self.data);
        std.mem.doNotOptimizeAway(hash.finalResult());
    }
};

test "micro cases stay runnable (smoke)" {
    // Anti-bitrot after TigerBeetle's stdx.benchmark: every case runs in the
    // everyday test pass, so a broken case fails `zig build unit`.
    var prng = std.Random.DefaultPrng.init(0x5eed);
    var buf: [4096]u8 = undefined;
    prng.random().bytes(&buf);

    const adler32_case: Adler32Case = .{ .data = &buf };
    const crc32_case: Crc32Case = .{ .data = &buf };
    const xz_crc64_case: XzCrc64Case = .{ .data = &buf };
    const bzip2_crc32_case: Bzip2Crc32Case = .{ .data = &buf };
    const xxhash64_case: XxHash64Case = .{ .data = &buf };
    const xxh32_case: XxHash32Case = .{ .data = &buf };
    const sha1_case: Sha1Case = .{ .data = &buf };
    const sha256_case: Sha256Case = .{ .data = &buf };

    adler32_case.run(std.testing.allocator);
    crc32_case.run(std.testing.allocator);
    xz_crc64_case.run(std.testing.allocator);
    bzip2_crc32_case.run(std.testing.allocator);
    xxh32_case.run(std.testing.allocator);
    xxhash64_case.run(std.testing.allocator);
    sha1_case.run(std.testing.allocator);
    sha256_case.run(std.testing.allocator);
}
