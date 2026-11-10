const std = @import("std");

const bench_shim = @import("bench_shim");

const runner = @import("runner.zig");

const bcj = bench_shim.bcj;
const brotli = bench_shim.brotli;
const checksum = bench_shim.checksum;
const crypto = bench_shim.crypto;
const Sha256Mb = crypto.Sha256Mb;
const delta = bench_shim.delta;
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

// Encode plus decode is an in-place involution, so one iteration restores the
// fixture and every iteration sees identical bytes.
const DeltaCase = struct {
    work: []u8,
    distance: u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        delta.encode(self.work, self.distance);
        delta.decode(self.work, self.distance);
        std.mem.doNotOptimizeAway(self.work[self.work.len - 1]);
    }
};

// The arm64 filter is also an encode/decode involution over word-aligned data.
const BcjArm64Case = struct {
    work: []u8,
    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        bcj.encode(.arm64, 0, self.work);
        bcj.decode(.arm64, 0, self.work);
        std.mem.doNotOptimizeAway(self.work[self.work.len - 1]);
    }
};

// Four independent one-megabyte lanes advanced in lockstep, the driving
// pattern the multi-buffer shape exists for.
const Sha256Mb4Case = struct {
    inputs: [4][]const u8,
    digests: [4][32]u8 = undefined,
    pub fn run(self: *@This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var lanes = Sha256Mb(4).init();
        inline for (0..4) |lane| lanes.update(lane, self.inputs[lane]);
        var mix: u32 = 0;
        inline for (0..4) |lane| {
            lanes.final(lane, &self.digests[lane]);
            mix ^= std.mem.readInt(u32, self.digests[lane][0..4], .little);
        }
        std.mem.doNotOptimizeAway(mix);
    }
};

// The driver's own cost: one wave over fixed units whose decode only fills.
const lane_unit_bytes: usize = 4096;

const LaneSource = struct {
    pub const Exception = error{
        CallException,
        UnsupportedException,
        CapacityException,
        ResourceException,
        InternalException,
    };

    total: u32,

    pub fn nextUnit(self: *LaneSource, ordinal: u32, staging: []u8) Exception!?bench_shim.lanes.Unit {
        if (ordinal >= self.total) return null;
        if (staging.len < lane_unit_bytes) return error.CapacityException;
        return .{
            .ordinal = ordinal,
            .input = &.{},
            .output = staging[0..lane_unit_bytes],
            .decoded_size = lane_unit_bytes,
        };
    }

    pub fn decode(_: *LaneSource, unit: bench_shim.lanes.Unit, scratch: []u8) Exception!usize {
        _ = scratch;
        @memset(unit.output, @truncate(unit.ordinal));
        return unit.output.len;
    }
};

const LaneDriverCase = struct {
    staging: [bench_shim.lanes.max_lanes][]u8,
    units: u32,
    threaded: ?*bench_shim.threaded.Threaded = null,
    lanes: u8 = 1,

    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var buffers: [bench_shim.lanes.max_lanes]bench_shim.lanes.Lane = @splat(.{});
        for (&buffers, 0..) |*buffer, index| buffer.staging = self.staging[index];
        var options: bench_shim.lanes.Options = .{ .lanes = self.lanes };
        if (self.threaded) |pool| {
            options.executor = pool.handle();
            options.join = pool.join();
        }
        var decoder = bench_shim.lanes.Decoder(LaneSource).init(
            .{ .total = self.units },
            options,
            buffers,
        ) catch |err| std.debug.panic("lane driver case failed: {s}", .{@errorName(err)});
        var delivered: u32 = 0;
        while (decoder.next() catch |err| std.debug.panic("lane driver case failed: {s}", .{@errorName(err)})) |_| delivered += 1;
        std.mem.doNotOptimizeAway(delivered);
    }
};

var noop_context: u8 = 0;

fn noopWait(_: *anyopaque) callconv(.c) u32 {
    return bench_shim.executor.status.ok;
}

// Inline execution still needs a join when more than one lane is declared.
fn inlineJoin() bench_shim.lanes.Join {
    return .{ .context = &noop_context, .wait = noopWait };
}

const seekable_options: bench_shim.zstd_seekable.Options = .{ .frame_size = 1 << 17, .window_size = 1 << 17 };

// Eight independent frames over one payload, plus the lane scratch.
const SeekableFixture = struct {
    encoded_storage: []u8,
    encoded_len: usize,
    output: []u8,
    workspace: []u8,

    fn init(allocator: std.mem.Allocator, payload: []const u8) !SeekableFixture {
        const frame_options = bench_shim.zstd_seekable.frameOptions(seekable_options);
        const history = try allocator.alloc(u8, @as(usize, frame_options.window_size) + bench_shim.zstd.block_size_max);
        defer allocator.free(history);
        const encoder_workspace = try allocator.alloc(u32, bench_shim.zstd.encoderWorkspaceU32Count(0, seekable_options.frame_size, frame_options));
        defer allocator.free(encoder_workspace);
        const entries = try allocator.alloc(bench_shim.zstd_seekable.FrameEntry, bench_shim.zstd_seekable.frameCountFor(payload.len, seekable_options));
        defer allocator.free(entries);
        const storage = try allocator.alloc(u8, payload.len * 2 + 65536);
        errdefer allocator.free(storage);
        const encoded_len = try bench_shim.zstd_seekable.encode(payload, storage, history, encoder_workspace, entries, seekable_options);
        const output = try allocator.alloc(u8, payload.len);
        errdefer allocator.free(output);
        const workspace = try allocator.alloc(u8, bench_shim.zstd_seekable.workspaceSize(seekable_options, bench_shim.lanes.max_lanes));
        return .{ .encoded_storage = storage, .encoded_len = encoded_len, .output = output, .workspace = workspace };
    }

    fn deinit(self: *SeekableFixture, allocator: std.mem.Allocator) void {
        allocator.free(self.encoded_storage);
        allocator.free(self.output);
        allocator.free(self.workspace);
    }

    fn encoded(self: *const SeekableFixture) []const u8 {
        return self.encoded_storage[0..self.encoded_len];
    }
};

// One frame per lane: the seek table is what proves frames independent.
const SeekableLanesCase = struct {
    fixture: *const SeekableFixture,
    lanes: u8,
    threaded: ?*bench_shim.threaded.Threaded = null,

    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var options: bench_shim.lanes.Options = .{ .lanes = self.lanes, .join = inlineJoin() };
        if (self.threaded) |pool| {
            options.executor = pool.handle();
            options.join = pool.join();
        }
        const total = bench_shim.zstd_seekable.decodeLanes(
            self.fixture.encoded(),
            self.fixture.output,
            self.fixture.workspace,
            seekable_options,
            options,
        ) catch |err| std.debug.panic("seekable lanes case failed: {s}", .{@errorName(err)});
        std.mem.doNotOptimizeAway(total);
    }
};

// One block per lane; the tail index is what proves blocks independent.
const XzFixture = struct {
    encoded_storage: []u8,
    encoded_len: usize,
    output: []u8,
    workspace: []u8,

    fn init(allocator: std.mem.Allocator, payload: []const u8) !XzFixture {
        const scratch = try allocator.alloc(
            u8,
            bench_shim.xz.encodeWorkspaceSizeBt(xz_options.dictionary_size) +
                bench_shim.xz.blockRecordScratchSize(payload.len, xz_options.block_size) + 64,
        );
        defer allocator.free(scratch);
        const storage = try allocator.alloc(u8, try bench_shim.xz.requiredSize(payload, scratch, xz_options));
        errdefer allocator.free(storage);
        const encoded_len = try bench_shim.xz.encode(payload, storage, scratch, xz_options);
        const output = try allocator.alloc(u8, payload.len);
        errdefer allocator.free(output);
        const workspace = try allocator.alloc(u8, bench_shim.xz.workspaceSize(xz_options.dictionary_size, bench_shim.lanes.max_lanes));
        return .{ .encoded_storage = storage, .encoded_len = encoded_len, .output = output, .workspace = workspace };
    }

    fn deinit(self: *XzFixture, allocator: std.mem.Allocator) void {
        allocator.free(self.encoded_storage);
        allocator.free(self.output);
        allocator.free(self.workspace);
    }

    fn encoded(self: *const XzFixture) []const u8 {
        return self.encoded_storage[0..self.encoded_len];
    }
};

const XzLanesCase = struct {
    fixture: *const XzFixture,
    lanes: u8,
    threaded: ?*bench_shim.threaded.Threaded = null,

    pub fn run(self: *const @This(), allocator: std.mem.Allocator) void {
        _ = allocator;
        var options: bench_shim.lanes.Options = .{ .lanes = self.lanes, .join = inlineJoin() };
        if (self.threaded) |pool| {
            options.executor = pool.handle();
            options.join = pool.join();
        }
        const total = bench_shim.xz.decodeLanes(
            self.fixture.encoded(),
            self.fixture.output,
            self.fixture.workspace,
            options,
            bench_shim.checksum.default_provider,
        ) catch |err| std.debug.panic("xz lanes case failed: {s}", .{@errorName(err)});
        std.mem.doNotOptimizeAway(total);
    }
};

const xz_options: bench_shim.xz.Options = .{ .dictionary_size = 1 << 17, .check = .crc64, .block_size = 1 << 17 };

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

    // bcj fixture: random words with a realistic BL/ADRP density so both
    // filter branches carry weight.
    const bcj_work = try allocator.alloc(u8, buffer_len_bytes);
    defer allocator.free(bcj_work);
    {
        var word_index: usize = 0;
        while (word_index + 4 <= bcj_work.len) : (word_index += 4) {
            const word: u32 = switch (word_index % 16) {
                0 => 0x94000000 | (random.random().int(u32) & 0x03FFFFFF),
                8 => 0x90000000 | (random.random().int(u32) & 0x00FFFFFF),
                else => random.random().int(u32),
            };
            std.mem.writeInt(u32, bcj_work[word_index..][0..4], word, .little);
        }
    }
    const delta_work = try allocator.alloc(u8, buffer_len_bytes);
    defer allocator.free(delta_work);
    @memcpy(delta_work, input);

    const delta_d1_case: DeltaCase = .{ .work = delta_work, .distance = 0 };
    const delta_d4_case: DeltaCase = .{ .work = delta_work, .distance = 3 };
    const delta_d32_case: DeltaCase = .{ .work = delta_work, .distance = 31 };
    const bcj_arm64_case: BcjArm64Case = .{ .work = bcj_work };
    var sha256_mb4_case: Sha256Mb4Case = .{ .inputs = .{ input, window, compressible, input } };

    const lane_staging_bytes = try allocator.alloc(u8, bench_shim.lanes.max_lanes * lane_unit_bytes);
    defer allocator.free(lane_staging_bytes);
    var lane_staging: [bench_shim.lanes.max_lanes][]u8 = undefined;
    for (&lane_staging, 0..) |*slice, index| slice.* = lane_staging_bytes[index * lane_unit_bytes ..][0..lane_unit_bytes];
    var threaded = try bench_shim.threaded.Threaded.init(allocator, 8);
    defer threaded.deinit();
    const lane_driver_case: LaneDriverCase = .{
        .staging = lane_staging,
        .units = 64,
        .threaded = &threaded,
        .lanes = 4,
    };

    var seekable_fixture = try SeekableFixture.init(allocator, compressible);
    defer seekable_fixture.deinit(allocator);
    const seekable_1: SeekableLanesCase = .{ .fixture = &seekable_fixture, .lanes = 1 };
    const seekable_2: SeekableLanesCase = .{ .fixture = &seekable_fixture, .lanes = 2, .threaded = &threaded };
    const seekable_4: SeekableLanesCase = .{ .fixture = &seekable_fixture, .lanes = 4, .threaded = &threaded };
    const seekable_8: SeekableLanesCase = .{ .fixture = &seekable_fixture, .lanes = 8, .threaded = &threaded };

    var xz_fixture = try XzFixture.init(allocator, compressible);
    defer xz_fixture.deinit(allocator);
    const xz_1: XzLanesCase = .{ .fixture = &xz_fixture, .lanes = 1 };
    const xz_2: XzLanesCase = .{ .fixture = &xz_fixture, .lanes = 2, .threaded = &threaded };
    const xz_4: XzLanesCase = .{ .fixture = &xz_fixture, .lanes = 4, .threaded = &threaded };
    const xz_8: XzLanesCase = .{ .fixture = &xz_fixture, .lanes = 8, .threaded = &threaded };

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
        .{ "leaf.delta_d1", &delta_d1_case },
        .{ "leaf.delta_d4", &delta_d4_case },
        .{ "leaf.delta_d32", &delta_d32_case },
        .{ "leaf.bcj_arm64", &bcj_arm64_case },
        .{ "crypto.sha256_mb4", &sha256_mb4_case },
        .{ "lanes.driver", &lane_driver_case },
        .{ "lanes.zstd_seekable_1", &seekable_1 },
        .{ "lanes.zstd_seekable_2", &seekable_2 },
        .{ "lanes.zstd_seekable_4", &seekable_4 },
        .{ "lanes.zstd_seekable_8", &seekable_8 },
        .{ "lanes.xz_1", &xz_1 },
        .{ "lanes.xz_2", &xz_2 },
        .{ "lanes.xz_4", &xz_4 },
        .{ "lanes.xz_8", &xz_8 },
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

    // One list drives instantiation and execution; brotli stays separate for
    // its encoder fixture below.
    const cases = .{
        Adler32Case{ .input = &scratch },
        Crc32Case{ .input = &scratch },
        XzCrc64Case{ .input = &scratch },
        Bzip2Crc32Case{ .input = &scratch },
        XxHash32Case{ .input = &scratch },
        XxHash64Case{ .input = &scratch },
        Sha1Case{ .input = &scratch },
        Sha256Case{ .input = &scratch },
        CopyMatchCase{ .window = &scratch },
    };
    inline for (cases) |case_item| case_item.run(std.testing.allocator);
    // The copy ladder must have written matches into the window.
    try std.testing.expect(!std.mem.eql(u8, &scratch, &original));

    // The delta and bcj cases are encode/decode involutions on a fresh
    // snapshot, since the copy ladder above mutated the scratch.
    var filter_scratch: [4096]u8 = undefined;
    @memcpy(&filter_scratch, &scratch);
    const before_filters = filter_scratch;
    inline for (.{ DeltaCase{ .work = &filter_scratch, .distance = 0 }, BcjArm64Case{ .work = &filter_scratch } }) |case_item| {
        case_item.run(std.testing.allocator);
    }
    try std.testing.expectEqualSlices(u8, &before_filters, &filter_scratch);

    var mb4_scratch: [4096]u8 = undefined;
    @memcpy(&mb4_scratch, &original);
    var mb4_case: Sha256Mb4Case = .{ .inputs = .{ &mb4_scratch, &original, &mb4_scratch, &original } };
    mb4_case.run(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(u32, &.{ 0, 0 }, &.{ std.mem.readInt(u32, mb4_case.digests[0][0..4], .little), std.mem.readInt(u32, mb4_case.digests[1][0..4], .little) }));

    var lane_staging_bytes: [bench_shim.lanes.max_lanes * lane_unit_bytes]u8 = undefined;
    var lane_staging: [bench_shim.lanes.max_lanes][]u8 = undefined;
    for (&lane_staging, 0..) |*slice, index| slice.* = lane_staging_bytes[index * lane_unit_bytes ..][0..lane_unit_bytes];
    const lane_case: LaneDriverCase = .{ .staging = lane_staging, .units = 8 };
    lane_case.run(std.testing.allocator);

    var seekable_payload: [1 << 16]u8 = undefined;
    var seekable_prng = std.Random.DefaultPrng.init(0x71);
    seekable_prng.random().bytes(&seekable_payload);
    var seekable_fixture = try SeekableFixture.init(std.testing.allocator, &seekable_payload);
    defer seekable_fixture.deinit(std.testing.allocator);
    const seekable_cases = .{
        SeekableLanesCase{ .fixture = &seekable_fixture, .lanes = 1 },
        SeekableLanesCase{ .fixture = &seekable_fixture, .lanes = 4 },
    };
    inline for (seekable_cases) |case_item| {
        case_item.run(std.testing.allocator);
        // The table says what each frame decodes to; the bytes must match.
        try std.testing.expectEqualSlices(u8, &seekable_payload, seekable_fixture.output);
    }

    var xz_fixture = try XzFixture.init(std.testing.allocator, &seekable_payload);
    defer xz_fixture.deinit(std.testing.allocator);
    const xz_cases = .{
        XzLanesCase{ .fixture = &xz_fixture, .lanes = 1 },
        XzLanesCase{ .fixture = &xz_fixture, .lanes = 4 },
    };
    inline for (xz_cases) |case_item| {
        case_item.run(std.testing.allocator);
        try std.testing.expectEqualSlices(u8, &seekable_payload, xz_fixture.output);
    }

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
