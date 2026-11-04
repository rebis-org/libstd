// Every decoder must survive arbitrary input without trapping. The smoke
// pass runs the corpus through testing.fuzz; budgeted campaigns live in
// campaign.zig and share the runner table.

const std = @import("std");

const corpus = @import("corpus.zig");
const targets = @import("targets.zig");

const testing = std.testing;

fn drive(smith: *testing.Smith, comptime run: fn (data: []const u8) anyerror!void) anyerror!void {
    var input: [targets.max_input]u8 = undefined;
    const len = smith.slice(&input);
    try run(input[0..len]);
}

// One wrapper keeps the smoke blocks to their runner and seed choice alone.
fn smoke(comptime run: fn (data: []const u8) anyerror!void, comptime seed: ?[]const u8) !void {
    const seeds: []const []const u8 = if (seed) |s| &.{s} else &.{};
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, run);
        }
    }.f, .{ .corpus = seeds });
}

test "fuzz gzip decode" {
    try smoke(targets.runGzip, corpus.gzip_empty[0..]);
}

test "fuzz zlib decode" {
    try smoke(targets.runZlib, corpus.zlib_empty[0..]);
}

test "fuzz deflate decode" {
    try smoke(targets.runDeflate, corpus.deflate_small[0..]);
}

test "fuzz zstd decode" {
    try smoke(targets.runZstd, corpus.zstd_frame[0..]);
}

test "fuzz lz4 decode" {
    try smoke(targets.runLz4, corpus.lz4_frame[0..]);
}

test "fuzz xz decode" {
    try smoke(targets.runXz, corpus.xz_stream[0..]);
}

test "fuzz lzma alone decode" {
    try smoke(targets.runLzmaAlone, corpus.lzma_alone[0..]);
}

test "fuzz bzip2 decode" {
    try smoke(targets.runBzip2, corpus.bzip2_stream[0..]);
}

test "fuzz sevenzip header walk" {
    try smoke(targets.runSevenZip, corpus.ppmd_sevenzip[0..]);
}

test "fuzz zip decode" {
    try smoke(targets.runZip, corpus.zip_one_file[0..]);
}

test "fuzz rar decode" {
    try smoke(targets.runRar, null);
}

test "fuzz tar decode" {
    try smoke(targets.runTar, corpus.tar_one_file[0..]);
}

test "fuzz cpio decode" {
    try smoke(targets.runCpio, null);
}

test "fuzz wim decode" {
    try smoke(targets.runWim, null);
}

test "fuzz xar decode" {
    try smoke(targets.runXar, null);
}

test "fuzz xip decode" {
    try smoke(targets.runXip, null);
}

test "fuzz pkg decode" {
    try smoke(targets.runPkg, null);
}

test "fuzz age decode" {
    try smoke(targets.runAge, null);
}

test "fuzz iso decode" {
    try smoke(targets.runIso, null);
}

test "fuzz squashfs decode" {
    try smoke(targets.runSquashfs, null);
}

test "fuzz dwarfs decode" {
    try smoke(targets.runDwarfs, null);
}

test "fuzz apfs decode" {
    try smoke(targets.runApfs, null);
}
