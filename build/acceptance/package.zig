const std = @import("std");

const manifest = @import("manifest");
const slices = manifest.slices;

const run = @import("run.zig");
const symbols = @import("symbols.zig");

pub fn main(init: std.process.Init) !void {
    var args = run.Args.init(init.minimal.args);
    const host = try args.next(error.MissingArchive);
    const android = try args.next(error.MissingArchive);
    const apple = try args.next(error.MissingArchive);
    const dynamic_library = try args.next(error.MissingArchive);
    try args.done(error.UnexpectedArgument);
    const archive_paths = [_][]const u8{ host, android, apple };
    const distributions = [_]*const manifest.Distribution{ &manifest.host, &manifest.android, &manifest.apple };
    var headers: [archive_paths.len]?[]u8 = .{null} ** archive_paths.len;
    var catalogs: [archive_paths.len]?[]u8 = .{null} ** archive_paths.len;
    defer {
        for (headers) |header| if (header) |bytes| std.heap.page_allocator.free(bytes);
        for (catalogs) |catalog| if (catalog) |bytes| std.heap.page_allocator.free(bytes);
    }
    for (distributions, 0..) |distribution, index| {
        try run.silent(init, &.{ "unzip", "-tq", archive_paths[index] });
        const entries = try run.output(init, &.{ "unzip", "-Z1", archive_paths[index] });
        defer std.heap.page_allocator.free(entries);
        try requireEntries(entries, distribution.entries);
        headers[index] = try extract(init, archive_paths[index], distribution.header);
        catalogs[index] = try extract(init, archive_paths[index], distribution.catalog);
    }
    for (headers[1..]) |header| if (!std.mem.eql(u8, headers[0].?, header.?)) return error.HeaderMismatch;
    for (catalogs[1..]) |catalog| if (!std.mem.eql(u8, catalogs[0].?, catalog.?)) return error.CatalogMismatch;
    for (manifest.android.android.?) |abi| try requireAndroidArchitecture(init, android, abi.library, abi.elf_machine);
    for (manifest.apple.apple.?) |slice| try requireAppleSlice(init, apple, slice);
    try symbols.assertSingleExport(init, dynamic_library);
}

fn print(comptime format: []const u8, args: anytype) ![]u8 {
    return std.fmt.allocPrint(std.heap.page_allocator, format, args);
}

fn extract(init: std.process.Init, archive: []const u8, entry: []const u8) ![]u8 {
    return run.output(init, &.{ "unzip", "-p", archive, entry });
}

fn requireEntries(entries: []const u8, expected: []const []const u8) !void {
    for (expected) |entry| if (!containsEntry(entries, entry)) return error.MissingArchiveEntry;
}

fn containsEntry(entries: []const u8, expected: []const u8) bool {
    var lines = std.mem.splitScalar(u8, entries, '\n');
    while (lines.next()) |entry| if (std.mem.eql(u8, entry, expected)) return true;
    return false;
}

fn requireAndroidArchitecture(init: std.process.Init, archive: []const u8, entry: []const u8, expected_machine: u16) !void {
    const library = try extract(init, archive, entry);
    defer std.heap.page_allocator.free(library);
    if (library.len < 20 or !std.mem.eql(u8, library[0..4], "\x7fELF")) return error.InvalidAndroidLibrary;
    const machine = std.mem.readInt(u16, library[18..20], .little);
    if (machine != expected_machine) return error.InvalidAndroidLibrary;
}

fn requireAppleSlice(init: std.process.Init, archive: []const u8, slice: slices.AppleSlice) !void {
    const temporary_path = try print("zig-out/.package-{s}.dylib", .{slice.id});
    defer std.heap.page_allocator.free(temporary_path);
    defer std.Io.Dir.cwd().deleteFile(init.io, temporary_path) catch {};
    const entry = try print("StdK.xcframework/{s}/{s}", .{ slice.id, slice.library });
    defer std.heap.page_allocator.free(entry);
    const bytes = try extract(init, archive, entry);
    defer std.heap.page_allocator.free(bytes);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = temporary_path, .data = bytes });
    const stdout = try run.output(init, &.{ "vtool", "-show-build", temporary_path });
    defer std.heap.page_allocator.free(stdout);
    const platform_text = try print("platform {s}", .{slice.platform});
    defer std.heap.page_allocator.free(platform_text);
    const minimum_text = try print("minos {s}", .{slice.minimum});
    defer std.heap.page_allocator.free(minimum_text);
    if (std.mem.indexOf(u8, stdout, platform_text) == null or std.mem.indexOf(u8, stdout, minimum_text) == null) return error.InvalidAppleLibrary;
}
