// Every decoder must survive arbitrary input without trapping;
// coverage-guided runs live under the toolchain fuzzer.

const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const crypto = @import("../../common/primitive/crypto.zig");
const io = @import("../../common/primitive/io.zig");
const gzip = @import("../../representation/grammar/gzip/onprem.zig");
const lzma_alone = @import("../../representation/grammar/lzma/onprem.zig");
const rar = @import("../../representation/grammar/rar/onprem.zig");
const sevenzip = @import("../../representation/grammar/sevenzip/onprem.zig");
const tar = @import("../../representation/grammar/tar/onprem.zig");
const xz = @import("../../representation/grammar/xz/onprem.zig");
const zip = @import("../../representation/grammar/zip/onprem.zig");
const zlib = @import("../../representation/grammar/zlib/onprem.zig");
const age = @import("../../representation/grammar/age/onprem.zig");
const cpio = @import("../../representation/grammar/cpio/onprem.zig");
const wim = @import("../../representation/grammar/wim/onprem.zig");
const xar = @import("../../representation/grammar/xar/onprem.zig");
const apfs = @import("../../representation/volume/apfs/onprem.zig");
const dwarfs = @import("../../representation/volume/dwarfs/onprem.zig");
const iso = @import("../../representation/volume/iso/onprem.zig");
const squashfs = @import("../../representation/volume/squashfs/onprem.zig");
const bzip2 = @import("../../representation/leaf/bzip2/onprem.zig");
const deflate = @import("../../representation/leaf/deflate/onprem.zig");
const lz4 = @import("../../representation/leaf/lz4/onprem.zig");
const lzma_seam = @import("../../representation/leaf/lzma/seam.zig");
const zstd = @import("../../representation/leaf/zstd/onprem.zig");
const corpus = @import("corpus.zig");

const testing = std.testing;

// Input stays small so structure-aware mutation stays cheap; the bound sizes
// only fuzz scratch (256 KiB for wrapped windows).
const max_input = 16 * 1024;
const max_output = 256 * 1024;

fn drive(smith: *testing.Smith, comptime run: fn (data: []const u8) anyerror!void) anyerror!void {
    var input: [max_input]u8 = undefined;
    const len = smith.slice(&input);
    try run(input[0..len]);
}

fn runGzip(data: []const u8) anyerror!void {
    var history: [gzip.deflate_history_size]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out);
    _ = gzip.decode(data, &sink, &history, checksum.default_provider) catch {};
}

test "fuzz gzip decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runGzip);
        }
    }.f, .{ .corpus = &.{corpus.gzip_empty[0..]} });
}

fn runZlib(data: []const u8) anyerror!void {
    var history: [32768]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out);
    _ = zlib.decode(data, &sink, &history, checksum.default_provider) catch {};
}

test "fuzz zlib decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runZlib);
        }
    }.f, .{ .corpus = &.{corpus.zlib_empty[0..]} });
}

fn runDeflate(data: []const u8) anyerror!void {
    var history: [deflate.history_size]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var source = std.Io.Reader.fixed(data);
    var sink = std.Io.Writer.fixed(&out);
    var inflater = deflate.Decompress.init(&source, &history);
    _ = inflater.reader.streamRemaining(&sink) catch {};
}

test "fuzz deflate decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runDeflate);
        }
    }.f, .{ .corpus = &.{corpus.deflate_small[0..]} });
}

fn runZstd(data: []const u8) anyerror!void {
    var history: [4096]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var source = std.Io.Reader.fixed(data);
    var sink = std.Io.Writer.fixed(&out);
    _ = zstd.decodeStream(&source, &sink, &history, .{ .window_size = 1 << 20 }) catch {};
}

test "fuzz zstd decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runZstd);
        }
    }.f, .{ .corpus = &.{corpus.zstd_frame[0..]} });
}

fn runLz4(data: []const u8) anyerror!void {
    var scratch: [lz4.decodeWorkspaceSize()]u8 = undefined;
    var out: [max_output]u8 = undefined;
    _ = lz4.decode(data, &out, &scratch, .{}) catch {};
}

test "fuzz lz4 decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runLz4);
        }
    }.f, .{ .corpus = &.{corpus.lz4_frame[0..]} });
}

fn runXz(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, xz.decodeWorkspaceSize(8 << 20));
    defer testing.allocator.free(scratch);
    var out: [max_output]u8 = undefined;
    _ = xz.decode(data, &out, scratch, checksum.default_provider) catch {};
}

test "fuzz xz decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runXz);
        }
    }.f, .{ .corpus = &.{corpus.xz_stream[0..]} });
}

fn runLzmaAlone(data: []const u8) anyerror!void {
    var scratch: [4096]u8 = undefined;
    var out: [max_output]u8 = undefined;
    _ = lzma_alone.decode(data, &out, &scratch, lzma_seam.default_provider) catch {};
}

test "fuzz lzma alone decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runLzmaAlone);
        }
    }.f, .{ .corpus = &.{corpus.lzma_alone[0..]} });
}

fn runBzip2(data: []const u8) anyerror!void {
    var out: [max_output]u8 = undefined;
    const size = bzip2.decodeWorkspaceSizeFor(data) catch return;
    // The BZh9 workspace is ~4.7 MiB; cap fuzz scratch at 8 MiB so every
    // block size stays reachable.
    const scratch = try testing.allocator.alloc(u8, @min(size, 8 << 20));
    defer testing.allocator.free(scratch);
    _ = bzip2.decode(data, &out, scratch, checksum.default_provider) catch {};
}

test "fuzz bzip2 decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runBzip2);
        }
    }.f, .{ .corpus = &.{corpus.bzip2_stream[0..]} });
}

fn runSevenZip(data: []const u8) anyerror!void {
    const backing = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(backing);
    var cause: crypto.FailureCause = .none;
    var workspace = try io.Workspace.init(backing.ptr, backing.len);
    const count = sevenzip.sevenZipInspectCountEx(data, &workspace, .{}, &.{ .failure_cause = &cause }) catch return;
    if (count == 0) return;
    var workspace2 = try io.Workspace.init(backing.ptr, backing.len);
    _ = sevenzip.sevenZipInspectOrdinalEx(data, &workspace2, .{}, 0, &.{ .failure_cause = &cause }) catch {};
}

test "fuzz sevenzip header walk" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runSevenZip);
        }
    }.f, .{ .corpus = &.{corpus.ppmd_sevenzip[0..]} });
}

fn runZip(data: []const u8) anyerror!void {
    const count = zip.zipInspectCount(data) catch return;
    if (count == 0) return;
    const info = zip.zipInspectOrdinal(data, 0) catch return;
    const size: usize = @intCast(@min(info.uncompressed_size, max_output));
    var out: [max_output]u8 = undefined;
    var cause: crypto.FailureCause = .none;
    _ = zip.zipDecodeOrdinal(data, 0, out[0..size], .{ .failure_cause = &cause }) catch {};
}

test "fuzz zip decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runZip);
        }
    }.f, .{ .corpus = &.{corpus.zip_one_file[0..]} });
}

fn runRar(data: []const u8) anyerror!void {
    var header_scratch: [4096]u8 = undefined;
    const count = rar.rarInspectCountOpts(data, 64, .{ .scratch = &header_scratch }) catch return;
    if (count == 0) return;
    var window: [1 << 20]u8 = undefined;
    var table_pool: [rar.table_pool_words]u16 = undefined;
    var state_store: [(rar.max_unpacker_bytes + 7) / 8]u64 = undefined;
    var pending50: [rar.max_pending50]rar.PendingFilter50 = undefined;
    var pending29: [rar.max_pending29]rar.PendingFilter29 = undefined;
    var filter_scratch: [window.len + rar.filter_scratch_extra]u8 = undefined;
    var ppm_heap: [1 << 20]u8 = undefined;
    var out: [8192]u8 = undefined;
    var bufs = rar.DecodeBuffers{
        .state = std.mem.sliceAsBytes(&state_store),
        .window = &window,
        .table_pool = &table_pool,
        .pending50 = &pending50,
        .pending29 = &pending29,
        .filter_scratch = &filter_scratch,
        .ppm_heap = &ppm_heap,
    };
    _ = rar.rarDecodeOrdinal(data, 0, &out, &bufs, .{ .scratch = &header_scratch }) catch {};
}

test "fuzz rar decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runRar);
        }
    }.f, .{ .corpus = &.{} });
}

fn runTar(data: []const u8) anyerror!void {
    const count = tar.inspectCount(data) catch return;
    if (count == 0) return;
    const info = tar.inspectOrdinal(data, 0) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = tar.decodeOrdinal(data, 0, out[0..size]) catch {};
}

test "fuzz tar decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runTar);
        }
    }.f, .{ .corpus = &.{corpus.tar_one_file[0..]} });
}

fn runCpio(data: []const u8) anyerror!void {
    const count = cpio.inspectCount(data) catch return;
    if (count == 0) return;
    const info = cpio.inspectOrdinal(data, 0) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = cpio.decodeOrdinal(data, 0, out[0..size]) catch {};
}

test "fuzz cpio decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runCpio);
        }
    }.f, .{ .corpus = &.{} });
}

fn runWim(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, wim.scratch_size);
    defer testing.allocator.free(scratch);
    const count = wim.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = wim.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = wim.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

test "fuzz wim decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runWim);
        }
    }.f, .{ .corpus = &.{} });
}

fn runXar(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, xar.scratch_size);
    defer testing.allocator.free(scratch);
    const count = xar.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = xar.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = xar.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

test "fuzz xar decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runXar);
        }
    }.f, .{ .corpus = &.{} });
}

fn runAge(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, age.scratch_size);
    defer testing.allocator.free(scratch);
    const count = age.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = age.inspectOrdinal(data, 0, .{}, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = age.decodeOrdinal(data, 0, out[0..size], scratch, .{}) catch {};
}

test "fuzz age decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runAge);
        }
    }.f, .{ .corpus = &.{} });
}

fn runIso(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, iso.scratch_size);
    defer testing.allocator.free(scratch);
    const count = iso.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = iso.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = iso.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

test "fuzz iso decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runIso);
        }
    }.f, .{ .corpus = &.{} });
}

fn runSquashfs(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, squashfs.scratch_size);
    defer testing.allocator.free(scratch);
    const count = squashfs.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = squashfs.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = squashfs.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

test "fuzz squashfs decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runSquashfs);
        }
    }.f, .{ .corpus = &.{} });
}

fn runDwarfs(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, dwarfs.scratch_size);
    defer testing.allocator.free(scratch);
    const count = dwarfs.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = dwarfs.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = dwarfs.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

test "fuzz dwarfs decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runDwarfs);
        }
    }.f, .{ .corpus = &.{} });
}

fn runApfs(data: []const u8) anyerror!void {
    const scratch = try testing.allocator.alloc(u8, apfs.scratch_size);
    defer testing.allocator.free(scratch);
    const count = apfs.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = apfs.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = apfs.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

test "fuzz apfs decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runApfs);
        }
    }.f, .{ .corpus = &.{} });
}
