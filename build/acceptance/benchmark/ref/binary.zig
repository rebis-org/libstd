const std = @import("std");

const run = @import("run");

var g_io: std.Io = undefined;

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn parseHex(hex: []const u8, out: []u8) !void {
    if (hex.len != out.len * 2) return error.BadSha256Length;
    for (out, 0..) |*byte, index| {
        const high = hexValue(hex[index * 2]) orelse return error.BadSha256Hex;
        const low = hexValue(hex[index * 2 + 1]) orelse return error.BadSha256Hex;
        byte.* = (high << 4) | low;
    }
}

fn sha256File(path: []const u8) ![32]u8 {
    const data = try std.Io.Dir.cwd().readFileAlloc(g_io, path, std.heap.page_allocator, .limited(1 << 31));
    defer std.heap.page_allocator.free(data);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return digest;
}

fn download(url: []const u8, path: []const u8) !void {
    var client: std.http.Client = .{ .allocator = std.heap.page_allocator, .io = g_io };
    defer client.deinit();
    var file = try std.Io.Dir.cwd().createFile(g_io, path, .{ .truncate = true });
    defer file.close(g_io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = std.Io.File.writer(file, g_io, &buffer);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &writer.interface,
    });
    if (result.status.class() != .success) return error.HttpDownloadFailed;
    try writer.flush();
}

fn extractMember(iterator: *std.tar.Iterator, entry: std.tar.Iterator.File, stage_dir: []const u8, member: []const u8) !void {
    const dest = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}", .{ stage_dir, member });
    defer std.heap.page_allocator.free(dest);
    if (std.mem.lastIndexOfScalar(u8, dest, '/')) |slash| {
        try std.Io.Dir.cwd().createDirPath(g_io, dest[0..slash]);
    }
    var file = try std.Io.Dir.cwd().createFile(g_io, dest, .{ .truncate = true, .permissions = @enumFromInt(0o755) });
    defer file.close(g_io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = std.Io.File.writer(file, g_io, &buffer);
    try iterator.streamRemaining(entry, &writer.interface);
    try writer.flush();
}

fn extract(init: std.process.Init, archive: []const u8, stage_dir: []const u8, members: []const []const u8) !void {
    if (std.mem.endsWith(u8, archive, ".tar.xz")) {
        var argv = std.ArrayList([]const u8).empty;
        defer argv.deinit(std.heap.page_allocator);
        try argv.append(std.heap.page_allocator, "/usr/bin/tar");
        try argv.appendSlice(std.heap.page_allocator, &.{ "-xf", archive, "-C", stage_dir });
        try argv.appendSlice(std.heap.page_allocator, members);
        _ = try run.output(init, argv.items);
        return;
    }
    var file = try std.Io.Dir.cwd().openFile(g_io, archive, .{});
    defer file.close(g_io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = std.Io.File.reader(file, g_io, &buffer);

    var gzip: std.compress.flate.Decompress = undefined;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    if (std.mem.endsWith(u8, archive, ".tar.gz")) {
        gzip = std.compress.flate.Decompress.init(&reader.interface, .gzip, &window);
    } else {
        return error.UnsupportedArchive;
    }

    var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var iterator = std.tar.Iterator.init(&gzip.reader, .{
        .file_name_buffer = &name_buffer,
        .link_name_buffer = &link_buffer,
    });
    var found: usize = 0;
    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        for (members) |member| {
            if (std.mem.eql(u8, entry.name, member)) {
                try extractMember(&iterator, entry, stage_dir, member);
                found += 1;
            }
        }
    }
    if (found != members.len) return error.MissingArchiveMember;
}

pub fn main(init: std.process.Init) !void {
    g_io = init.io;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const url = args.next() orelse return error.MissingUrl;
    const sha256_hex = args.next() orelse return error.MissingSha256;
    const cache_dir = args.next() orelse return error.MissingCacheDir;
    const archive_name = args.next() orelse return error.MissingArchiveName;
    const stage_dir = args.next() orelse return error.MissingStageDir;
    var members = std.ArrayList([]const u8).empty;
    defer members.deinit(std.heap.page_allocator);
    while (args.next()) |member| {
        try members.append(std.heap.page_allocator, member);
    }
    if (members.items.len == 0) return error.MissingMember;

    try std.Io.Dir.cwd().createDirPath(init.io, cache_dir);
    try std.Io.Dir.cwd().createDirPath(init.io, stage_dir);
    const archive_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}", .{ cache_dir, archive_name });
    defer std.heap.page_allocator.free(archive_path);

    var expected: [32]u8 = undefined;
    try parseHex(sha256_hex, &expected);
    var verified = false;
    if (std.Io.Dir.cwd().access(init.io, archive_path, .{})) |_| {
        const digest = try sha256File(archive_path);
        verified = std.mem.eql(u8, &digest, &expected);
    } else |_| {}
    if (!verified) {
        std.debug.print("downloading {s}\n", .{url});
        try download(url, archive_path);
        const digest = try sha256File(archive_path);
        if (!std.mem.eql(u8, &digest, &expected)) {
            std.debug.print("SHA-256 mismatch for {s}\n", .{url});
            return error.Sha256Mismatch;
        }
    }
    try extract(init, archive_path, stage_dir, members.items);
}
