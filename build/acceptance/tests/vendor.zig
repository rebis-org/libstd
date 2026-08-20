const std = @import("std");

const run = @import("run");

const work_dir = "zig-out/benchmark/test";

const Status = enum { pass, fail, skip };

fn writeRandom(init: std.process.Init, name: []const u8, size: usize, seed: u64) !void {
    try std.Io.Dir.cwd().createDirPath(init.io, work_dir);
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}", .{ work_dir, name });
    defer std.heap.page_allocator.free(path);
    const data = try std.heap.page_allocator.alloc(u8, size);
    defer std.heap.page_allocator.free(data);
    var state = seed;
    for (data) |*byte| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        byte.* = @truncate(state >> 33);
    }
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = data });
}

fn libzipBuild(init: std.process.Init, build_dir: []const u8, options: []const []const u8) Status {
    var argv: [16][]const u8 = undefined;
    var count: usize = 0;
    for ([_][]const u8{ "cmake", "-S", "vendor/libzip", "-B", build_dir, "-DCMAKE_BUILD_TYPE=Release" }) |arg| {
        argv[count] = arg;
        count += 1;
    }
    @memcpy(argv[count..][0..options.len], options);
    count += options.len;
    if (run.exitCode(init, argv[0..count]) != 0) return .fail;
    if (run.exitCode(init, &.{ "cmake", "--build", build_dir, "-j4" }) != 0) return .fail;
    return .pass;
}

fn ctest(init: std.process.Init, build_dir: []const u8) Status {
    return if (run.exitCode(init, &.{ "ctest", "--test-dir", build_dir, "--output-on-failure", "-j4" }) == 0) .pass else .fail;
}

fn suiteZstd(init: std.process.Init) !Status {
    if (run.exitCode(init, &.{ "git", "-C", "vendor/zstd", "checkout", "--", "tests/playTests.sh" }) != 0) return .fail;
    if (run.exitCode(init, &.{ "git", "-C", "vendor/zstd", "apply", "../../patch/zstd/playTests.patch" }) != 0) return .fail;
    if (run.exitCode(init, &.{ "make", "-C", "vendor/zstd/tests", "test-zstd", "ZSTD=../programs/zstd" }) != 0) return .fail;
    return .pass;
}

fn suiteXz(init: std.process.Init) !Status {
    const build_dir = "zig-out/benchmark/build/xz";
    std.Io.Dir.cwd().access(init.io, build_dir, .{}) catch {
        std.debug.print("xz tests: build dir missing; run the benchmark step first\n", .{});
        return .skip;
    };
    return ctest(init, build_dir);
}

fn suiteXzOssfuzz(init: std.process.Init) !Status {
    const xz_build = "zig-out/benchmark/build/xz";
    const liblzma = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/liblzma.a", .{xz_build});
    defer std.heap.page_allocator.free(liblzma);

    std.Io.Dir.cwd().access(init.io, liblzma, .{}) catch {
        std.debug.print("xz ossfuzz: building xz cmake first\n", .{});
        if (run.exitCode(init, &.{
            "cmake",                   "-S",              "vendor/xz",           "-B",                    xz_build,
            "-DBUILD_SHARED_LIBS=OFF", "-DXZ_TOOL_XZ=ON", "-DXZ_TOOL_XZDEC=OFF", "-DXZ_TOOL_LZMADEC=OFF", "-DXZ_TOOL_LZMAINFO=OFF",
            "-DXZ_NLS=OFF",            "-DXZ_DOC=OFF",    "-DXZ_DOXYGEN=OFF",
        }) != 0) return .fail;
        if (run.exitCode(init, &.{ "cmake", "--build", xz_build, "-j4" }) != 0) return .fail;
    };

    const fuzz_build = "zig-out/benchmark/test/xz-ossfuzz";
    try std.Io.Dir.cwd().createDirPath(init.io, fuzz_build);

    const seed = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/seed.bin", .{fuzz_build});
    defer std.heap.page_allocator.free(seed);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = seed, .data = "xz fuzz seed payload\n" });

    const fuzzers = [_][]const u8{ "fuzz_decode_alone", "fuzz_decode_stream", "fuzz_decode_stream_mt", "fuzz_encode_stream" };
    for (fuzzers) |fuzzer| {
        const src = try std.fmt.allocPrint(std.heap.page_allocator, "vendor/xz/tests/ossfuzz/{s}.c", .{fuzzer});
        defer std.heap.page_allocator.free(src);
        const obj = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}.o", .{ fuzz_build, fuzzer });
        defer std.heap.page_allocator.free(obj);
        const bin = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}", .{ fuzz_build, fuzzer });
        defer std.heap.page_allocator.free(bin);

        if (run.exitCode(init, &.{
            "clang", "-fsanitize=fuzzer-no-link",
            "-I",    "vendor/xz/src/liblzma/api",
            "-c",    src,
            "-o",    obj,
        }) != 0) return .fail;
        if (run.exitCode(init, &.{
            "clang++", "-fsanitize=fuzzer", obj, liblzma, "-o", bin,
        }) != 0) return .fail;
        if (run.exitCode(init, &.{ bin, "-runs=1", seed }) != 0) return .fail;
    }

    return .pass;
}

fn suiteLibzipRegress(init: std.process.Init) !Status {
    if (libzipBuild(init, "zig-out/benchmark/test/libzip-regress", &.{
        "-DBUILD_REGRESS=ON",
        "-DBUILD_TOOLS=OFF",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_DOC=OFF",
        "-DBUILD_OSSFUZZ=OFF",
        "-DBUILD_SHARED_LIBS=OFF",
    }) != .pass) return .fail;
    return ctest(init, "zig-out/benchmark/test/libzip-regress");
}

fn suiteLibzipOssfuzz(init: std.process.Init) !Status {
    const build_dir = "zig-out/benchmark/test/libzip-ossfuzz";
    if (libzipBuild(init, build_dir, &.{
        "-DBUILD_OSSFUZZ=ON",
        "-DBUILD_REGRESS=OFF",
        "-DBUILD_TOOLS=OFF",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_DOC=OFF",
        "-DBUILD_SHARED_LIBS=OFF",
    }) != .pass) return .fail;
    try std.Io.Dir.cwd().createDirPath(init.io, work_dir);
    const seed = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/input.zip", .{work_dir});
    defer std.heap.page_allocator.free(seed);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = seed, .data = "zip fuzz seed payload\n" });
    const fuzzers = [_][]const u8{ "zip_read_file_fuzzer", "zip_read_fuzzer", "zip_write_encrypt_aes256_file_fuzzer", "zip_write_encrypt_pkware_file_fuzzer" };
    for (fuzzers) |fuzzer| {
        const bin = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/ossfuzz/{s}", .{ build_dir, fuzzer });
        defer std.heap.page_allocator.free(bin);
        if (run.exitCode(init, &.{ bin, seed }) != 0) return .fail;
    }
    return .pass;
}

fn suiteFastLzma2Test(init: std.process.Init) !Status {
    if (run.exitCode(init, &.{ "make", "-C", "vendor/fast-lzma2/test", "-j4", "CFLAGS=-Wall -O1 -pthread -I..", "LIB=../libfast-lzma2.a" }) != 0) return .fail;
    const input = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/fl2-input.bin", .{work_dir});
    defer std.heap.page_allocator.free(input);
    try writeRandom(init, "fl2-input.bin", 1024, 0x12345678);
    return if (run.exitCode(init, &.{ "vendor/fast-lzma2/test/file_test", "-6", input }) == 0) .pass else .fail;
}

fn suiteFastLzma2Fuzzer(init: std.process.Init) !Status {
    if (run.exitCode(init, &.{ "git", "-C", "vendor/fast-lzma2", "checkout", "--", "fuzzer/fuzzer.c" }) != 0) return .fail;
    if (run.exitCode(init, &.{ "git", "-C", "vendor/fast-lzma2", "apply", "../../patch/fast-lzma2/fuzzer.patch" }) != 0) return .fail;
    if (run.exitCode(init, &.{ "make", "-C", "vendor/fast-lzma2/fuzzer", "-j4" }) != 0) return .fail;
    return if (run.exitCode(init, &.{ "vendor/fast-lzma2/fuzzer/fuzzer", "-i1", "-s1" }) == 0) .pass else .fail;
}

fn suiteGzip(init: std.process.Init) !Status {
    if (run.exitCode(init, &.{ "make", "-C", "vendor/gzip", "check" }) != 0) return .fail;
    return .pass;
}

fn suiteTar(init: std.process.Init) !Status {
    if (run.exitCode(init, &.{ "make", "-C", "vendor/tar", "check" }) != 0) return .fail;
    return .pass;
}

fn suiteBzip2Dlltest(init: std.process.Init) !Status {
    try std.Io.Dir.cwd().createDirPath(init.io, work_dir);
    const exe = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/dlltest", .{work_dir});
    defer std.heap.page_allocator.free(exe);
    if (run.exitCode(init, &.{ "cc", "-o", exe, "vendor/bzip2/dlltest.c", "zig-out/benchmark/bin/libbz2.a" }) != 0) return .fail;
    const input = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/bz2-input.bin", .{work_dir});
    defer std.heap.page_allocator.free(input);
    const compressed = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/bz2-input.bz2", .{work_dir});
    defer std.heap.page_allocator.free(compressed);
    const restored = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/bz2-restored.bin", .{work_dir});
    defer std.heap.page_allocator.free(restored);
    try writeRandom(init, "bz2-input.bin", 4096, 0x9e3779b97f4a7c15);
    if (run.exitCode(init, &.{ exe, "-9", input, compressed }) != 0) return .fail;
    if (run.exitCode(init, &.{ exe, "-d", compressed, restored }) != 0) return .fail;
    const original = try std.Io.Dir.cwd().readFileAlloc(init.io, input, std.heap.page_allocator, .limited(1 << 20));
    defer std.heap.page_allocator.free(original);
    const decoded = try std.Io.Dir.cwd().readFileAlloc(init.io, restored, std.heap.page_allocator, .limited(1 << 20));
    defer std.heap.page_allocator.free(decoded);
    return if (std.mem.eql(u8, original, decoded)) .pass else .fail;
}

const suites = [_]struct { name: []const u8, run: *const fn (init: std.process.Init) anyerror!Status }{
    .{ .name = "zstd tests", .run = suiteZstd },
    .{ .name = "xz tests", .run = suiteXz },
    .{ .name = "xz ossfuzz", .run = suiteXzOssfuzz },
    .{ .name = "libzip regress", .run = suiteLibzipRegress },
    .{ .name = "libzip ossfuzz", .run = suiteLibzipOssfuzz },
    .{ .name = "fast-lzma2 test", .run = suiteFastLzma2Test },
    .{ .name = "fast-lzma2 fuzzer", .run = suiteFastLzma2Fuzzer },
    .{ .name = "gzip tests", .run = suiteGzip },
    .{ .name = "tar tests", .run = suiteTar },
    .{ .name = "bzip2 dlltest", .run = suiteBzip2Dlltest },
};

pub fn main(init: std.process.Init) !void {
    var failed: usize = 0;
    for (suites) |suite| {
        const status = suite.run(init) catch .fail;
        switch (status) {
            .pass => std.debug.print("{s}: pass\n", .{suite.name}),
            .skip => std.debug.print("{s}: skip\n", .{suite.name}),
            .fail => {
                std.debug.print("{s}: fail\n", .{suite.name});
                failed += 1;
            },
        }
    }
    if (failed != 0) return error.SuiteFailed;
}
