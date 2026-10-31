// One runner per decode surface, shared by the fuzz smoke pass and the
// mutation campaign. Nothing here touches std.testing, so the campaign
// binary links the same table the smoke blocks drive.

const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const crypto = @import("../../common/primitive/crypto.zig");
const io = @import("../../common/primitive/io.zig");
const age = @import("../../representation/grammar/age/onprem.zig");
const cpio = @import("../../representation/grammar/cpio/onprem.zig");
const gzip = @import("../../representation/grammar/gzip/onprem.zig");
const lzma_alone = @import("../../representation/grammar/lzma/onprem.zig");
const pkg = @import("../../representation/grammar/pkg/onprem.zig");
const rar = @import("../../representation/grammar/rar/onprem.zig");
const sevenzip = @import("../../representation/grammar/sevenzip/onprem.zig");
const tar = @import("../../representation/grammar/tar/onprem.zig");
const wim = @import("../../representation/grammar/wim/onprem.zig");
const xar = @import("../../representation/grammar/xar/onprem.zig");
const xip = @import("../../representation/grammar/xip/onprem.zig");
const xz = @import("../../representation/grammar/xz/onprem.zig");
const zip = @import("../../representation/grammar/zip/onprem.zig");
const zlib = @import("../../representation/grammar/zlib/onprem.zig");
const bzip2 = @import("../../representation/leaf/bzip2/onprem.zig");
const deflate = @import("../../representation/leaf/deflate/onprem.zig");
const lz4 = @import("../../representation/leaf/lz4/onprem.zig");
const lzma_seam = @import("../../representation/leaf/lzma/seam.zig");
const zstd = @import("../../representation/leaf/zstd/onprem.zig");
const apfs = @import("../../representation/volume/apfs/onprem.zig");
const dwarfs = @import("../../representation/volume/dwarfs/onprem.zig");
const iso = @import("../../representation/volume/iso/onprem.zig");
const squashfs = @import("../../representation/volume/squashfs/onprem.zig");
const corpus = @import("corpus.zig");

// Input stays small so structure-aware mutation stays cheap; the bound sizes
// only fuzz scratch (256 KiB for wrapped windows).
pub const max_input = 16 * 1024;
const max_output = 256 * 1024;

pub fn runGzip(data: []const u8) anyerror!void {
    var history: [gzip.deflate_history_size]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out);
    _ = gzip.decode(data, &sink, &history, checksum.default_provider) catch {};
}

pub fn runZlib(data: []const u8) anyerror!void {
    var history: [32768]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out);
    _ = zlib.decode(data, &sink, &history, checksum.default_provider) catch {};
}

pub fn runDeflate(data: []const u8) anyerror!void {
    var history: [deflate.history_size]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var source = std.Io.Reader.fixed(data);
    var sink = std.Io.Writer.fixed(&out);
    var inflater = deflate.Decompress.init(&source, &history);
    _ = inflater.reader.streamRemaining(&sink) catch {};
}

pub fn runZstd(data: []const u8) anyerror!void {
    var history: [4096]u8 = undefined;
    var out: [max_output]u8 = undefined;
    var source = std.Io.Reader.fixed(data);
    var sink = std.Io.Writer.fixed(&out);
    _ = zstd.decodeStream(&source, &sink, &history, .{ .window_size = 1 << 20 }) catch {};
}

pub fn runLz4(data: []const u8) anyerror!void {
    var scratch: [lz4.decodeWorkspaceSize()]u8 = undefined;
    var out: [max_output]u8 = undefined;
    _ = lz4.decode(data, &out, &scratch, .{}) catch {};
}

pub fn runXz(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, xz.decodeWorkspaceSize(8 << 20));
    defer std.heap.page_allocator.free(scratch);
    var out: [max_output]u8 = undefined;
    _ = xz.decode(data, &out, scratch, checksum.default_provider) catch {};
}

pub fn runLzmaAlone(data: []const u8) anyerror!void {
    var scratch: [4096]u8 = undefined;
    var out: [max_output]u8 = undefined;
    _ = lzma_alone.decode(data, &out, &scratch, lzma_seam.default_provider) catch {};
}

pub fn runBzip2(data: []const u8) anyerror!void {
    var out: [max_output]u8 = undefined;
    const size = bzip2.decodeWorkspaceSizeFor(data) catch return;
    // The BZh9 workspace is ~4.7 MiB; cap fuzz scratch at 8 MiB so every
    // block size stays reachable.
    const scratch = try std.heap.page_allocator.alloc(u8, @min(size, 8 << 20));
    defer std.heap.page_allocator.free(scratch);
    _ = bzip2.decode(data, &out, scratch, checksum.default_provider) catch {};
}

pub fn runSevenZip(data: []const u8) anyerror!void {
    const backing = try std.heap.page_allocator.alloc(u8, 1 << 20);
    defer std.heap.page_allocator.free(backing);
    var cause: crypto.FailureCause = .none;
    var workspace = try io.Workspace.init(backing.ptr, backing.len);
    const count = sevenzip.sevenZipInspectCountEx(data, &workspace, .{}, &.{ .failure_cause = &cause }) catch return;
    if (count == 0) return;
    var workspace2 = try io.Workspace.init(backing.ptr, backing.len);
    _ = sevenzip.sevenZipInspectOrdinalEx(data, &workspace2, .{}, 0, &.{ .failure_cause = &cause }) catch {};
}

pub fn runZip(data: []const u8) anyerror!void {
    const count = zip.zipInspectCount(data) catch return;
    if (count == 0) return;
    const info = zip.zipInspectOrdinal(data, 0) catch return;
    const size: usize = @intCast(@min(info.uncompressed_size, max_output));
    var out: [max_output]u8 = undefined;
    var cause: crypto.FailureCause = .none;
    _ = zip.zipDecodeOrdinal(data, 0, out[0..size], .{ .failure_cause = &cause }) catch {};
}

pub fn runRar(data: []const u8) anyerror!void {
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

pub fn runTar(data: []const u8) anyerror!void {
    const count = tar.inspectCount(data) catch return;
    if (count == 0) return;
    const info = tar.inspectOrdinal(data, 0) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = tar.decodeOrdinal(data, 0, out[0..size]) catch {};
}

pub fn runCpio(data: []const u8) anyerror!void {
    const count = cpio.inspectCount(data) catch return;
    if (count == 0) return;
    const info = cpio.inspectOrdinal(data, 0) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = cpio.decodeOrdinal(data, 0, out[0..size]) catch {};
}

pub fn runWim(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, wim.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = wim.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = wim.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = wim.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runXar(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, xar.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = xar.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = xar.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = xar.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runXip(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, xip.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = xip.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = xip.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = xip.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runPkg(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, pkg.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = pkg.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = pkg.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = pkg.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runAge(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, age.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = age.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = age.inspectOrdinal(data, 0, .{}, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = age.decodeOrdinal(data, 0, out[0..size], scratch, .{}) catch {};
}

pub fn runIso(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, iso.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = iso.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = iso.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = iso.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runSquashfs(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, squashfs.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = squashfs.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = squashfs.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = squashfs.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runDwarfs(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, dwarfs.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = dwarfs.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = dwarfs.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = dwarfs.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

pub fn runApfs(data: []const u8) anyerror!void {
    const scratch = try std.heap.page_allocator.alloc(u8, apfs.scratch_size);
    defer std.heap.page_allocator.free(scratch);
    const count = apfs.inspectCount(data, scratch) catch return;
    if (count == 0) return;
    const info = apfs.inspectOrdinal(data, 0, scratch) catch return;
    const size: usize = @intCast(@min(info.size, max_output));
    var out: [max_output]u8 = undefined;
    _ = apfs.decodeOrdinal(data, 0, out[0..size], scratch) catch {};
}

// One table drives the evidence campaign so a codec cannot be added to the
// smoke pass and forgotten there. Empty-corpus formats seed a signature stub,
// which keeps the mutation inside the header walk instead of byte zero.
pub const Target = struct {
    name: []const u8,
    seed: []const u8,
    run: *const fn ([]const u8) anyerror!void,
};

const rar_magic_seed = "Rar!\x1a\x07\x01\x00";
const cpio_magic_seed = "070701";
const wim_magic_seed = "MSWIM\x00\x00\x00";
const xar_magic_seed = "xar!";
const age_magic_seed = "age-encryption.org/v1\n";
const iso_magic_seed = "\x01CD001\x01\x00";
const squashfs_magic_seed = "hsqs";
const dwarfs_magic_seed = "DWARE01";

pub const targets = [_]Target{
    .{ .name = "gzip", .seed = &corpus.gzip_empty, .run = runGzip },
    .{ .name = "zlib", .seed = &corpus.zlib_empty, .run = runZlib },
    .{ .name = "deflate", .seed = &corpus.deflate_small, .run = runDeflate },
    .{ .name = "zstd", .seed = &corpus.zstd_frame, .run = runZstd },
    .{ .name = "lz4", .seed = &corpus.lz4_frame, .run = runLz4 },
    .{ .name = "xz", .seed = &corpus.xz_stream, .run = runXz },
    .{ .name = "lzma-alone", .seed = &corpus.lzma_alone, .run = runLzmaAlone },
    .{ .name = "bzip2", .seed = &corpus.bzip2_stream, .run = runBzip2 },
    .{ .name = "sevenzip", .seed = &corpus.ppmd_sevenzip, .run = runSevenZip },
    .{ .name = "zip", .seed = &corpus.zip_one_file, .run = runZip },
    .{ .name = "rar", .seed = rar_magic_seed, .run = runRar },
    .{ .name = "tar", .seed = &corpus.tar_one_file, .run = runTar },
    .{ .name = "cpio", .seed = cpio_magic_seed, .run = runCpio },
    .{ .name = "wim", .seed = wim_magic_seed, .run = runWim },
    .{ .name = "xar", .seed = xar_magic_seed, .run = runXar },
    .{ .name = "xip", .seed = xar_magic_seed, .run = runXip },
    .{ .name = "pkg", .seed = xar_magic_seed, .run = runPkg },
    .{ .name = "age", .seed = age_magic_seed, .run = runAge },
    .{ .name = "iso", .seed = iso_magic_seed, .run = runIso },
    .{ .name = "squashfs", .seed = squashfs_magic_seed, .run = runSquashfs },
    .{ .name = "dwarfs", .seed = dwarfs_magic_seed, .run = runDwarfs },
};
