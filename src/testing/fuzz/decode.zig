// Every decoder must survive arbitrary input without trapping;
// coverage-guided runs live under the toolchain fuzzer.

const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const crypto = @import("../../common/primitive/crypto.zig");
const io = @import("../../common/primitive/io.zig");
const gzip = @import("../../grammar/gzip/onprem.zig");
const lzma_alone = @import("../../grammar/lzma/onprem.zig");
const rar = @import("../../grammar/rar/onprem.zig");
const sevenzip = @import("../../grammar/sevenzip/onprem.zig");
const tar = @import("../../grammar/tar/onprem.zig");
const xz = @import("../../grammar/xz/onprem.zig");
const zip = @import("../../grammar/zip/onprem.zig");
const zlib = @import("../../grammar/zlib/onprem.zig");
const bzip2 = @import("../../leaf/bzip2/onprem.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const lz4 = @import("../../leaf/lz4/onprem.zig");
const zstd = @import("../../leaf/zstd/onprem.zig");

const testing = std.testing;

const max_input = 16 * 1024;
const max_output = 64 * 1024;

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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
}

fn runLzmaAlone(data: []const u8) anyerror!void {
    var scratch: [4096]u8 = undefined;
    var out: [max_output]u8 = undefined;
    _ = lzma_alone.decode(data, &out, &scratch, @import("../../leaf/lzma/seam.zig").default_provider) catch {};
}

test "fuzz lzma alone decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runLzmaAlone);
        }
    }.f, .{ .corpus = &.{} });
}

fn runBzip2(data: []const u8) anyerror!void {
    var out: [max_output]u8 = undefined;
    const size = bzip2.decodeWorkspaceSizeFor(data) catch return;
    const scratch = try testing.allocator.alloc(u8, @min(size, 1 << 20));
    defer testing.allocator.free(scratch);
    _ = bzip2.decode(data, &out, scratch, checksum.default_provider) catch {};
}

test "fuzz bzip2 decode" {
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, runBzip2);
        }
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
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
    }.f, .{ .corpus = &.{} });
}
