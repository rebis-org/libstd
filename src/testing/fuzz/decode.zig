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

test "fuzz gzip decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runGzip);
        }
    }.f, .{ .corpus = &.{corpus.gzip_empty[0..]} });
}

test "fuzz zlib decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runZlib);
        }
    }.f, .{ .corpus = &.{corpus.zlib_empty[0..]} });
}

test "fuzz deflate decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runDeflate);
        }
    }.f, .{ .corpus = &.{corpus.deflate_small[0..]} });
}

test "fuzz zstd decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runZstd);
        }
    }.f, .{ .corpus = &.{corpus.zstd_frame[0..]} });
}

test "fuzz lz4 decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runLz4);
        }
    }.f, .{ .corpus = &.{corpus.lz4_frame[0..]} });
}

test "fuzz xz decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runXz);
        }
    }.f, .{ .corpus = &.{corpus.xz_stream[0..]} });
}

test "fuzz lzma alone decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runLzmaAlone);
        }
    }.f, .{ .corpus = &.{corpus.lzma_alone[0..]} });
}

test "fuzz bzip2 decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runBzip2);
        }
    }.f, .{ .corpus = &.{corpus.bzip2_stream[0..]} });
}

test "fuzz sevenzip header walk" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runSevenZip);
        }
    }.f, .{ .corpus = &.{corpus.ppmd_sevenzip[0..]} });
}

test "fuzz zip decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runZip);
        }
    }.f, .{ .corpus = &.{corpus.zip_one_file[0..]} });
}

test "fuzz rar decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runRar);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz tar decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runTar);
        }
    }.f, .{ .corpus = &.{corpus.tar_one_file[0..]} });
}

test "fuzz cpio decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runCpio);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz wim decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runWim);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz xar decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runXar);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz xip decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runXip);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz age decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runAge);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz iso decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runIso);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz squashfs decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runSquashfs);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz dwarfs decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runDwarfs);
        }
    }.f, .{ .corpus = &.{} });
}

test "fuzz apfs decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.runApfs);
        }
    }.f, .{ .corpus = &.{} });
}
