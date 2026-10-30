const std = @import("std");

const bench_shim = @import("bench_shim");
const checksum = @import("checksum");
const crypto = @import("crypto");

const runner = @import("runner.zig");

const brotli = bench_shim.brotli;
const kernels = bench_shim.kernels;

const buffer_len_bytes = 1 << 20;

fn HashCase(comptime Hash: type, comptime mode: enum { simple, seeded, crypto }) type {
    return struct {
        input: []const u8,
        pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            var hash = switch (mode) {
                .simple => Hash.bind(checksum.default_provider, {}),
                .seeded => Hash.bind(checksum.default_provider, 0),
                .crypto => Hash.bind(crypto.default_provider, .{}),
            };
            hash.update(self.input);
            std.mem.doNotOptimizeAway(switch (mode) {
                .simple, .seeded => hash.final({}),
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

// Drives the shared match-copy ladder across its distance and length
// branches; the distances stay inside the history the window seeds.
const CopyMatchCase = struct {
    window: []u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        const distances = [_]u32{ 1, 2, 3, 4, 5, 8, 15, 16, 17, 64, 4096, 32768 };
        const lengths = [_]u32{ 4, 8, 16, 32, 273, 300 };
        var produced: usize = @min(65536, self.window.len / 2);
        var mix: usize = 0;
        outer: while (produced + 400 < self.window.len) {
            for (distances) |distance| {
                for (lengths) |length| {
                    if (produced + length > self.window.len) break :outer;
                    kernels.copyMatch(self.window, produced, distance, length);
                    produced += length;
                    mix += self.window[produced - 1];
                }
            }
        }
        std.mem.doNotOptimizeAway(mix);
    }
};

// Decodes a fixed system-brotli-shaped fixture produced by our own encoder;
// the literal-heavy random corpus exercises the table decode path.
const BrotliDecodeCase = struct {
    encoded: []const u8,
    output: []u8,
    scratch: []u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        const n = brotli.decode(self.encoded, self.output, self.scratch, .{}) catch
            @panic("brotli decode case failed");
        std.mem.doNotOptimizeAway(n);
    }
};

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
    const window = try allocator.alloc(u8, buffer_len_bytes);
    defer allocator.free(window);
    var random = std.Random.DefaultPrng.init(0x5eed);
    random.random().bytes(input);
    random.random().bytes(window);

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
    const copy_match_case: CopyMatchCase = .{ .window = window };

    // Compressible corpus: repeated sentence plus random chunks, so both the
    // short-code literal path and the match path carry real weight.
    const sentence = "The quick brown fox jumps over the lazy dog. ";
    const compressible = try allocator.alloc(u8, input.len);
    defer allocator.free(compressible);
    var filled: usize = 0;
    while (filled + 65536 <= compressible.len) : (filled += 65536) {
        @memcpy(compressible[filled..][0..sentence.len], sentence);
        var rest = filled + sentence.len;
        while (rest + sentence.len <= filled + 65536) : (rest += sentence.len) {
            @memcpy(compressible[rest..][0..sentence.len], sentence);
        }
        @memcpy(compressible[filled + 32768 ..][0..8192], input[filled .. filled + 8192]);
    }
    @memcpy(compressible[filled..], input[filled..]);
    const compressed = try allocator.alloc(u8, brotli.encodedSizeBound(compressible.len));
    defer allocator.free(compressed);
    const enc_ws = try allocator.alloc(u8, brotli.encode_workspace_size);
    defer allocator.free(enc_ws);
    const brotli_out = try allocator.alloc(u8, compressible.len);
    defer allocator.free(brotli_out);
    const dec_ws = try allocator.alloc(u8, brotli.decode_workspace_size);
    defer allocator.free(dec_ws);
    const enc_len = try brotli.encode(compressible, compressed, enc_ws, .{});
    const brotli_decode_case: BrotliDecodeCase = .{
        .encoded = compressed[0..enc_len],
        .output = brotli_out,
        .scratch = dec_ws,
    };

    const registry = .{
        .{ "checksum.adler32", &adler32_case },
        .{ "checksum.crc32", &crc32_case },
        .{ "checksum.xz_crc64", &xz_crc64_case },
        .{ "checksum.bzip2_crc32", &bzip2_crc32_case },
        .{ "checksum.xxh32", &xxh32_case },
        .{ "checksum.xxh64", &xxhash64_case },
        .{ "crypto.sha1", &sha1_case },
        .{ "crypto.sha256", &sha256_case },
        .{ "kernels.copy_match", &copy_match_case },
        .{ "brotli.decode", &brotli_decode_case },
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
    const original = scratch;

    const adler32_case: Adler32Case = .{ .input = &scratch };
    const crc32_case: Crc32Case = .{ .input = &scratch };
    const xz_crc64_case: XzCrc64Case = .{ .input = &scratch };
    const bzip2_crc32_case: Bzip2Crc32Case = .{ .input = &scratch };
    const xxhash64_case: XxHash64Case = .{ .input = &scratch };
    const xxh32_case: XxHash32Case = .{ .input = &scratch };
    const sha1_case: Sha1Case = .{ .input = &scratch };
    const sha256_case: Sha256Case = .{ .input = &scratch };
    const copy_match_case: CopyMatchCase = .{ .window = &scratch };

    adler32_case.run(std.testing.allocator);
    crc32_case.run(std.testing.allocator);
    xz_crc64_case.run(std.testing.allocator);
    bzip2_crc32_case.run(std.testing.allocator);
    xxh32_case.run(std.testing.allocator);
    xxhash64_case.run(std.testing.allocator);
    sha1_case.run(std.testing.allocator);
    sha256_case.run(std.testing.allocator);
    copy_match_case.run(std.testing.allocator);
    // The copy ladder must have written matches into the window.
    try std.testing.expect(!std.mem.eql(u8, &scratch, &original));

    const fixture = try std.testing.allocator.alloc(u8, 4096);
    defer std.testing.allocator.free(fixture);
    @memcpy(fixture, &original);
    const enc_ws = try std.testing.allocator.alloc(u8, brotli.encode_workspace_size);
    defer std.testing.allocator.free(enc_ws);
    const compressed = try std.testing.allocator.alloc(u8, brotli.encodedSizeBound(fixture.len));
    defer std.testing.allocator.free(compressed);
    const out = try std.testing.allocator.alloc(u8, fixture.len);
    defer std.testing.allocator.free(out);
    const dec_ws = try std.testing.allocator.alloc(u8, brotli.decode_workspace_size);
    defer std.testing.allocator.free(dec_ws);
    const enc_len = try brotli.encode(fixture, compressed, enc_ws, .{});
    const brotli_decode_case: BrotliDecodeCase = .{
        .encoded = compressed[0..enc_len],
        .output = out,
        .scratch = dec_ws,
    };
    brotli_decode_case.run(std.testing.allocator);
    // The case decodes what the encoder produced, byte for byte.
    try std.testing.expectEqualSlices(u8, fixture, out);
}
