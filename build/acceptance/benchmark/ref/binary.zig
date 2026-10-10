const std = @import("std");

const run = @import("run");

fn hexValue(character: u8) ?u8 {
    return switch (character) {
        '0'...'9' => character - '0',
        'a'...'f' => character - 'a' + 10,
        'A'...'F' => character - 'A' + 10,
        else => null,
    };
}

fn parseHex(hex: []const u8, out: []u8) !void {
    if (hex.len != out.len * 2) return error.bad_sha256_length;
    for (out, 0..) |*byte, index| {
        const high = hexValue(hex[index * 2]) orelse return error.bad_sha256_hex;
        const low = hexValue(hex[index * 2 + 1]) orelse return error.bad_sha256_hex;
        byte.* = (high << 4) | low;
    }
}

fn sha256File(io: std.Io, path: []const u8) ![32]u8 {
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, std.heap.page_allocator, .limited(1 << 31));
    defer std.heap.page_allocator.free(data);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return digest;
}

fn download(io: std.Io, url: []const u8, path: []const u8) !void {
    var client: std.http.Client = .{ .allocator = std.heap.page_allocator, .io = io };
    defer client.deinit();
    var file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = std.Io.File.writer(file, io, &buffer);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &writer.interface,
    });
    if (result.status.class() != .success) return error.http_download_failed;
    try writer.flush();
}

fn extractMember(io: std.Io, iterator: *std.tar.Iterator, entry: std.tar.Iterator.File, stage_dir: []const u8, member: []const u8) !void {
    const dest = try std.heap.page_allocator.print("{s}/{s}", .{ stage_dir, member });
    defer std.heap.page_allocator.free(dest);
    if (std.mem.lastIndexOfScalar(u8, dest, '/')) |slash| {
        try std.Io.Dir.cwd().createDirPath(io, dest[0..slash]);
    }
    var file = try std.Io.Dir.cwd().createFile(io, dest, .{ .truncate = true, .permissions = @fromBackingInt(@intCast(0o755)) });
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var writer = std.Io.File.writer(file, io, &buffer);
    try iterator.streamRemaining(entry, &writer.interface);
    try writer.flush();
}

fn extract(io: std.Io, init: std.process.Init, archive: []const u8, stage_dir: []const u8, members: []const []const u8) !void {
    if (std.mem.endsWith(u8, archive, ".tar.xz")) {
        var argv = std.ArrayList([]const u8).empty;
        defer argv.deinit(std.heap.page_allocator);
        try argv.append(std.heap.page_allocator, "/usr/bin/tar");
        try argv.appendSlice(std.heap.page_allocator, &.{ "-xf", archive, "-C", stage_dir });
        try argv.appendSlice(std.heap.page_allocator, members);
        _ = try run.output(init, argv.items);
        return;
    }
    var file = try std.Io.Dir.cwd().openFile(io, archive, .{});
    defer file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = std.Io.File.reader(file, io, &buffer);

    var gzip: std.compress.flate.Decompress = undefined;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    if (std.mem.endsWith(u8, archive, ".tar.gz")) {
        gzip = std.compress.flate.Decompress.init(&reader.interface, .gzip, &window);
    } else {
        return error.unsupported_archive;
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
                try extractMember(io, &iterator, entry, stage_dir, member);
                found += 1;
            }
        }
    }
    if (found != members.len) return error.missing_archive_member;
}

fn argNext(iterator: *std.process.Args.Iterator, err: anyerror) ![:0]const u8 {
    return iterator.next() orelse err;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const url = try argNext(&args, error.missing_url);
    const sha256_hex = try argNext(&args, error.missing_sha256);
    const cache_dir = try argNext(&args, error.missing_cache_dir);
    const archive_name = try argNext(&args, error.missing_archive_name);
    const stage_dir = try argNext(&args, error.missing_stage_dir);
    var members = std.ArrayList([]const u8).empty;
    defer members.deinit(std.heap.page_allocator);
    while (args.next()) |member| {
        try members.append(std.heap.page_allocator, member);
    }
    if (members.items.len == 0) return error.missing_member;

    try std.Io.Dir.cwd().createDirPath(io, cache_dir);
    try std.Io.Dir.cwd().createDirPath(io, stage_dir);
    const archive_path = try std.heap.page_allocator.print("{s}/{s}", .{ cache_dir, archive_name });
    defer std.heap.page_allocator.free(archive_path);

    var expected: [32]u8 = undefined;
    try parseHex(sha256_hex, &expected);
    var confirmed = false;
    if (std.Io.Dir.cwd().access(io, archive_path, .{})) |_| {
        const digest = try sha256File(io, archive_path);
        confirmed = std.mem.eql(u8, &digest, &expected);
    } else |_| {}
    if (!confirmed) {
        std.debug.print("downloading {s}\n", .{url});
        try download(io, url, archive_path);
        const digest = try sha256File(io, archive_path);
        if (!std.mem.eql(u8, &digest, &expected)) {
            std.debug.print("sha-256 mismatch for {s}\n", .{url});
            return error.sha256_mismatch;
        }
    }
    try extract(io, init, archive_path, stage_dir, members.items);
}
