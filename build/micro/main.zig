const std = @import("std");

const checksum = @import("checksum");
const crypto = @import("crypto");

const runner = @import("runner.zig");

const buffer_len_bytes = 1 << 20;

fn HashCase(comptime Hash: type, comptime mode: enum { simple, seeded, crypto }) type {
    return struct {
        input: []const u8,
        pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            var hash = switch (mode) {
                .simple => Hash.bind(checksum.default_provider),
                .seeded => Hash.bind(checksum.default_provider, 0),
                .crypto => Hash.bind(crypto.default_provider, .{}),
            };
            hash.update(self.input);
            std.mem.doNotOptimizeAway(switch (mode) {
                .simple, .seeded => hash.final(),
                .crypto => hash.finalResult(),
            });
        }
    };
}

const Adler32Case = HashCase(checksum.Adler32, .simple);
const Crc32Case = HashCase(checksum.Crc32, .simple);
const XzCrc64Case = HashCase(checksum.XzCrc64, .simple);
const Bzip2Crc32Case = HashCase(checksum.Bzip2Crc32, .simple);
const XxHash64Case = HashCase(checksum.XxHash64, .seeded);
const XxHash32Case = HashCase(checksum.XxHash32, .seeded);
const Sha1Case = HashCase(crypto.Sha1, .crypto);
const Sha256Case = HashCase(crypto.Sha256, .crypto);

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var config: runner.Config = .{};
    var name_filter: ?[]const u8 = null;
    var args = init.minimal.args.iterate();
    _ = args.skip();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--shuffle")) {
            config.shuffle = true;
        } else if (std.mem.eql(u8, arg, "--budget-ms")) {
            const value = args.next() orelse return error.missing_option_value;
            config.time_budget_ns = try std.fmt.parseInt(u64, value, 10) * std.time.ns_per_ms;
        } else if (std.mem.eql(u8, arg, "--max-iterations")) {
            const value = args.next() orelse return error.missing_option_value;
            config.max_iterations = try std.fmt.parseInt(usize, value, 10);
        } else if (std.mem.eql(u8, arg, "--filter")) {
            name_filter = args.next() orelse return error.missing_option_value;
        } else {
            return error.unknown_argument;
        }
    }

    const input = try allocator.alloc(u8, buffer_len_bytes);
    defer allocator.free(input);
    var random = std.Random.DefaultPrng.init(0x5eed);
    random.random().bytes(input);

    var benchmark = runner.Benchmark.init(allocator, config);
    defer benchmark.deinit();

    const adler32_case: Adler32Case = .{ .input = input };
    const crc32_case: Crc32Case = .{ .input = input };
    const xz_crc64_case: XzCrc64Case = .{ .input = input };
    const bzip2_crc32_case: Bzip2Crc32Case = .{ .input = input };
    const xxhash64_case: XxHash64Case = .{ .input = input };

    const xxh32_case: XxHash32Case = .{ .input = input };
    const sha1_case: Sha1Case = .{ .input = input };
    const sha256_case: Sha256Case = .{ .input = input };

    const registry = .{
        .{ "checksum.adler32", &adler32_case },
        .{ "checksum.crc32", &crc32_case },
        .{ "checksum.xz_crc64", &xz_crc64_case },
        .{ "checksum.bzip2_crc32", &bzip2_crc32_case },
        .{ "checksum.xxh32", &xxh32_case },
        .{ "checksum.xxh64", &xxhash64_case },
        .{ "crypto.sha1", &sha1_case },
        .{ "crypto.sha256", &sha256_case },
    };
    inline for (registry) |entry| {
        if (name_filter == null or std.mem.find(u8, entry[0], name_filter.?) != null) {
            try benchmark.addParam(entry[0], entry[1]);
        }
    }

    try benchmark.run(init.io);
}

test "micro cases stay runnable without runner" {
    // Anti-bitrot after TigerBeetle's stdx.benchmark: every case runs in the
    // everyday test pass, so a broken case fails `zig build unit`.
    var random = std.Random.DefaultPrng.init(0x5eed);
    var scratch: [4096]u8 = undefined;
    random.random().bytes(&scratch);

    const adler32_case: Adler32Case = .{ .input = &scratch };
    const crc32_case: Crc32Case = .{ .input = &scratch };
    const xz_crc64_case: XzCrc64Case = .{ .input = &scratch };
    const bzip2_crc32_case: Bzip2Crc32Case = .{ .input = &scratch };
    const xxhash64_case: XxHash64Case = .{ .input = &scratch };
    const xxh32_case: XxHash32Case = .{ .input = &scratch };
    const sha1_case: Sha1Case = .{ .input = &scratch };
    const sha256_case: Sha256Case = .{ .input = &scratch };

    adler32_case.run(std.testing.allocator);
    crc32_case.run(std.testing.allocator);
    xz_crc64_case.run(std.testing.allocator);
    bzip2_crc32_case.run(std.testing.allocator);
    xxh32_case.run(std.testing.allocator);
    xxhash64_case.run(std.testing.allocator);
    sha1_case.run(std.testing.allocator);
    sha256_case.run(std.testing.allocator);
}
