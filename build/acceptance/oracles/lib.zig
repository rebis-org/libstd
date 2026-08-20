const std = @import("std");

const c = @import("c");

const harness = @import("harness.zig");

extern fn ZSTD_compress(dst: [*]u8, dstCapacity: usize, src: [*]const u8, srcSize: usize, level: c_int) usize;
extern fn ZSTD_decompress(dst: [*]u8, dstCapacity: usize, src: [*]const u8, compressedSize: usize) usize;
extern fn ZSTD_isError(code: usize) c_uint;
extern fn ZSTD_compressBound(srcSize: usize) usize;

pub const SystemLibraryStatus = struct {
    name: []const u8,
    available: bool,
};

pub fn requiredStatuses() []const SystemLibraryStatus {
    return &.{
        .{ .name = "z", .available = true },
        .{ .name = "lzma", .available = true },
        .{ .name = "bz2", .available = true },
        .{ .name = "archive", .available = true },
    };
}

fn runStream(stream: anytype, comptime code: anytype, comptime finish: anytype, comptime end: anytype, input: []const u8, output: []u8) ?usize {
    stream.next_in = @ptrCast(@constCast(input.ptr));
    stream.avail_in = @intCast(input.len);
    stream.next_out = output.ptr;
    stream.avail_out = @intCast(output.len);
    const ret = code(stream, finish);
    if (ret != end) return null;
    return output.len - @as(usize, @intCast(stream.avail_out));
}

pub fn gzipValid(compressed: []const u8) bool {
    var stream: c.z_stream = std.mem.zeroes(c.z_stream);
    stream.next_in = @ptrCast(@constCast(compressed.ptr));
    stream.avail_in = @intCast(compressed.len);
    var output: [65536]u8 = undefined;
    stream.next_out = &output;
    stream.avail_out = output.len;
    if (c.inflateInit2_(&stream, 15 + 32, c.ZLIB_VERSION, @sizeOf(c.z_stream)) != c.Z_OK) return false;
    defer _ = c.inflateEnd(&stream);
    return c.inflate(&stream, c.Z_FINISH) == c.Z_STREAM_END;
}

pub fn gzipCompress(input: []const u8, output: []u8) ?usize {
    var stream: c.z_stream = std.mem.zeroes(c.z_stream);
    if (c.deflateInit2_(&stream, 6, c.Z_DEFLATED, 15 + 16, 8, c.Z_DEFAULT_STRATEGY, c.ZLIB_VERSION, @sizeOf(c.z_stream)) != c.Z_OK) return null;
    defer _ = c.deflateEnd(&stream);
    return runStream(&stream, c.deflate, c.Z_FINISH, c.Z_STREAM_END, input, output);
}

pub fn bzip2Valid(compressed: []const u8) bool {
    var output: [65536]u8 = undefined;
    var dest_len: c_uint = @intCast(output.len);
    const ret = c.BZ2_bzBuffToBuffDecompress(
        @ptrCast(&output),
        &dest_len,
        @ptrCast(@constCast(compressed.ptr)),
        @intCast(compressed.len),
        0,
        0,
    );
    return ret == c.BZ_OK and dest_len > 0;
}

pub fn zstdValid(compressed: []const u8) bool {
    var output: [65536]u8 = undefined;
    const len = ZSTD_decompress(&output, output.len, compressed.ptr, compressed.len);
    return ZSTD_isError(len) == 0;
}

pub fn zstdCompress(input: []const u8, output: []u8) ?usize {
    const len = ZSTD_compress(output.ptr, output.len, input.ptr, input.len, 3);
    if (ZSTD_isError(len) != 0) return null;
    return len;
}

pub fn bzip2Compress(input: []const u8, output: []u8) ?usize {
    var dest_len: c_uint = @intCast(output.len);
    const ret = c.BZ2_bzBuffToBuffCompress(
        @ptrCast(output.ptr),
        &dest_len,
        @ptrCast(@constCast(input.ptr)),
        @intCast(input.len),
        9,
        0,
        30,
    );
    if (ret != c.BZ_OK) return null;
    return dest_len;
}

pub fn lzmaRawCompress(input: []const u8, output: []u8) ?usize {
    var stream: c.lzma_stream = std.mem.zeroes(c.lzma_stream);
    var options: c.lzma_options_lzma = std.mem.zeroes(c.lzma_options_lzma);
    if (c.lzma_lzma_preset(&options, 6) != c.LZMA_OK) return null;
    options.dict_size = 1 << 20;
    var filters = [_]c.lzma_filter{
        .{ .id = c.LZMA_FILTER_LZMA1, .options = &options },
        .{ .id = c.LZMA_VLI_UNKNOWN, .options = null },
    };
    if (c.lzma_raw_encoder(&stream, &filters) != c.LZMA_OK) return null;
    defer c.lzma_end(&stream);
    return runStream(&stream, c.lzma_code, c.LZMA_FINISH, c.LZMA_STREAM_END, input, output);
}

pub fn lzmaBufferDecode(bytes: []const u8, output: []u8) ?usize {
    var memlimit: u64 = 1 << 30;
    var in_pos: usize = 0;
    var out_pos: usize = 0;
    const ret = c.lzma_stream_buffer_decode(
        &memlimit,
        0,
        null,
        bytes.ptr,
        &in_pos,
        bytes.len,
        output.ptr,
        &out_pos,
        output.len,
    );
    if (ret != c.LZMA_OK) return null;
    return out_pos;
}

pub fn lzmaAloneDecode(bytes: []const u8, output: []u8) ?usize {
    var stream: c.lzma_stream = std.mem.zeroes(c.lzma_stream);
    if (c.lzma_alone_decoder(&stream, 1 << 30) != c.LZMA_OK) return null;
    defer c.lzma_end(&stream);
    return runStream(&stream, c.lzma_code, c.LZMA_FINISH, c.LZMA_STREAM_END, bytes, output);
}

pub fn xzEncode(input: []const u8, output: []u8, check: u64, delta_dist: ?u32, bcj: ?u32, dict: u32) ?usize {
    var filters: [4]c.lzma_filter = undefined;
    var count: usize = 0;
    var delta_opts: c.lzma_options_delta = .{ .type = c.LZMA_DELTA_TYPE_BYTE, .dist = 1 };
    var lzma_opts: c.lzma_options_lzma = std.mem.zeroes(c.lzma_options_lzma);
    if (c.lzma_lzma_preset(&lzma_opts, 6) != c.LZMA_OK) return null;
    lzma_opts.dict_size = dict;
    if (bcj) |id| {
        filters[count] = .{ .id = id, .options = null };
        count += 1;
    }
    if (delta_dist) |dist| {
        delta_opts.dist = dist;
        filters[count] = .{ .id = c.LZMA_FILTER_DELTA, .options = &delta_opts };
        count += 1;
    }
    filters[count] = .{ .id = c.LZMA_FILTER_LZMA2, .options = &lzma_opts };
    count += 1;
    filters[count] = .{ .id = c.LZMA_VLI_UNKNOWN, .options = null };
    count += 1;
    var stream: c.lzma_stream = std.mem.zeroes(c.lzma_stream);
    if (c.lzma_stream_encoder(&stream, &filters, check) != c.LZMA_OK) return null;
    defer c.lzma_end(&stream);
    return runStream(&stream, c.lzma_code, c.LZMA_FINISH, c.LZMA_STREAM_END, input, output);
}

var temp_counter: usize = 0;

pub fn writeTemp(bytes: []const u8, extension: []const u8) ![:0]u8 {
    const io = harness.io;
    const dir = "zig-out/oracles";
    try std.Io.Dir.cwd().createDirPath(io, dir);
    var index = @atomicRmw(usize, &temp_counter, .Add, 1, .monotonic);
    while (true) : (index += 1) {
        const formatted = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/oracle-{d}.{s}", .{ dir, index, extension });
        defer std.heap.page_allocator.free(formatted);
        const path = try std.heap.page_allocator.dupeZ(u8, formatted);
        const file = std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .truncate = true }) catch |err| {
            if (err == error.PathAlreadyExists) {
                std.heap.page_allocator.free(path);
                continue;
            }
            std.heap.page_allocator.free(path);
            return err;
        };
        errdefer {
            file.close(io);
            _ = std.Io.Dir.cwd().deleteFile(io, path) catch {};
        }
        try file.writeStreamingAll(io, bytes);
        file.close(io);
        return path;
    }
}

pub const ArchiveFormat = enum { tar, zip, seven_zip };

pub const WriteEntry = struct {
    name: []const u8,
    data: []const u8 = &.{},
    filetype: c_uint = 0o100000,
    symlink: ?[]const u8 = null,
    uid: ?i64 = null,
    mtime: ?i64 = null,
};

pub const ExpectedEntry = struct {
    name: []const u8,
    data: ?[]const u8 = null,
    filetype: ?c_uint = null,
    symlink: ?[]const u8 = null,
    hardlink: ?[]const u8 = null,
    uid: ?i64 = null,
};

pub const ArchiveReadResult = enum { ok, unsupported, mismatch };

pub fn archiveReadMatches(bytes: []const u8, expected: []const ExpectedEntry) ArchiveReadResult {
    const io = harness.io;
    const path = writeTemp(bytes, "bin") catch return .unsupported;
    defer {
        _ = std.Io.Dir.cwd().deleteFile(io, path) catch {};
        std.heap.page_allocator.free(path);
    }
    const reader = c.archive_read_new() orelse return .unsupported;
    defer _ = c.archive_read_free(reader);
    if (c.archive_read_support_format_all(reader) != c.ARCHIVE_OK) return .unsupported;
    if (c.archive_read_support_filter_all(reader) != c.ARCHIVE_OK) return .unsupported;
    if (c.archive_read_open_filename(reader, path.ptr, 10240) != c.ARCHIVE_OK) return .unsupported;
    var entry: ?*c.archive_entry = null;
    for (expected, 0..) |exp, expected_index| {
        const r = c.archive_read_next_header(reader, &entry);
        if (r == c.ARCHIVE_EOF) return .mismatch;
        if (r != c.ARCHIVE_OK) return .unsupported;
        const e = entry orelse return .mismatch;
        const name_ptr = c.archive_entry_pathname(e) orelse return .mismatch;
        if (!std.mem.eql(u8, std.mem.span(name_ptr), exp.name)) {
            std.debug.print("archive entry {d}: expected name {s}, got {s}\n", .{ expected_index, exp.name, std.mem.span(name_ptr) });
            return .mismatch;
        }
        if (exp.filetype) |filetype| {
            if (c.archive_entry_filetype(e) != filetype) {
                std.debug.print("archive entry {s}: expected filetype 0o{x}, got 0o{x}\n", .{ exp.name, filetype, c.archive_entry_filetype(e) });
                return .mismatch;
            }
        }
        if (exp.uid) |expected_uid| {
            if (c.archive_entry_uid(e) != expected_uid) return .mismatch;
        }
        if (exp.symlink) |expected_link| {
            const link_ptr = c.archive_entry_symlink(e) orelse return .mismatch;
            if (!std.mem.eql(u8, std.mem.span(link_ptr), expected_link)) {
                std.debug.print("archive entry {s}: expected symlink {s}, got {s}\n", .{ exp.name, expected_link, std.mem.span(link_ptr) });
                return .mismatch;
            }
        }
        if (exp.hardlink) |expected_link| {
            const link_ptr = c.archive_entry_hardlink(e) orelse return .mismatch;
            if (!std.mem.eql(u8, std.mem.span(link_ptr), expected_link)) {
                std.debug.print("archive entry {s}: expected hardlink {s}, got {s}\n", .{ exp.name, expected_link, std.mem.span(link_ptr) });
                return .mismatch;
            }
        }
        if (exp.data) |data| {
            var buffer: [65536]u8 = undefined;
            var got: usize = 0;
            while (got < data.len) {
                const wanted = @min(buffer.len, data.len - got);
                const n = c.archive_read_data(reader, &buffer, wanted);
                if (n < 0) return .unsupported;
                if (n == 0) break;
                const chunk: usize = @intCast(n);
                if (!std.mem.eql(u8, buffer[0..chunk], data[got .. got + chunk])) {
                    std.debug.print("archive entry {s}: data mismatch at {d}\n", .{ exp.name, got });
                    return .mismatch;
                }
                got += chunk;
            }
            if (got != data.len) return .mismatch;
        }
    }
    const r = c.archive_read_next_header(reader, &entry);
    if (r == c.ARCHIVE_OK) return .mismatch;
    if (r != c.ARCHIVE_EOF) return .unsupported;
    return .ok;
}

pub fn archiveWrite(format: ArchiveFormat, entries: []const WriteEntry) ?[]u8 {
    const io = harness.io;
    const extension = switch (format) {
        .tar => "tar",
        .zip => "zip",
        .seven_zip => "7z",
    };
    const path = writeTemp("", extension) catch return null;
    defer {
        _ = std.Io.Dir.cwd().deleteFile(io, path) catch {};
        std.heap.page_allocator.free(path);
    }
    const writer = c.archive_write_new() orelse return null;
    defer _ = c.archive_write_free(writer);
    const set_result = switch (format) {
        .tar => c.archive_write_set_format_pax_restricted(writer),
        .zip => c.archive_write_set_format_zip(writer),
        .seven_zip => c.archive_write_set_format_7zip(writer),
    };
    if (set_result != c.ARCHIVE_OK) return null;
    if (format == .seven_zip) {
        if (c.archive_write_set_format_option(writer, "7zip", "compression", "store") != c.ARCHIVE_OK) return null;
    }
    if (c.archive_write_open_filename(writer, path.ptr) != c.ARCHIVE_OK) return null;
    for (entries) |item| {
        const entry = c.archive_entry_new() orelse return null;
        defer c.archive_entry_free(entry);
        const name_z = std.heap.page_allocator.dupeZ(u8, item.name) catch return null;
        defer std.heap.page_allocator.free(name_z);
        c.archive_entry_set_pathname(entry, name_z.ptr);
        c.archive_entry_set_filetype(entry, item.filetype);
        c.archive_entry_set_perm(entry, 0o644);
        if (item.uid) |value| c.archive_entry_set_uid(entry, value);
        if (item.mtime) |value| c.archive_entry_set_mtime(entry, value, 0);
        if (item.symlink) |link| {
            const link_z = std.heap.page_allocator.dupeZ(u8, link) catch return null;
            defer std.heap.page_allocator.free(link_z);
            c.archive_entry_set_symlink(entry, link_z.ptr);
        }
        if (item.data.len != 0) c.archive_entry_set_size(entry, @intCast(item.data.len));
        if (c.archive_write_header(writer, entry) != c.ARCHIVE_OK) return null;
        if (item.data.len != 0) {
            const written = c.archive_write_data(writer, item.data.ptr, item.data.len);
            if (written != @as(c_long, @intCast(item.data.len))) return null;
        }
        if (c.archive_write_finish_entry(writer) != c.ARCHIVE_OK) return null;
    }
    if (c.archive_write_close(writer) != c.ARCHIVE_OK) return null;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, std.heap.page_allocator, .limited(1 << 24)) catch return null;
    return bytes;
}
