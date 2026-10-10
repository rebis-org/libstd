const std = @import("std");

const manifest = @import("manifest");
const slices = manifest.slices;

const run = @import("run.zig");
const symbols = @import("symbols.zig");

pub fn main(init: std.process.Init) !void {
    var args = run.Args.init(init.minimal.args);
    var archive_paths: [manifest.providers.len * 4][]const u8 = undefined;
    var distributions: [manifest.providers.len * 4]manifest.Distribution = undefined;
    inline for (manifest.providers, 0..) |provider, provider_index| {
        inline for (.{ manifest.hostFor(provider), manifest.androidFor(provider), manifest.appleFor(provider), manifest.cjpmFor(provider) }, 0..) |distribution, form_index| {
            archive_paths[provider_index * 4 + form_index] = try args.next(error.missing_archive);
            distributions[provider_index * 4 + form_index] = distribution;
        }
    }
    const dynamic_library = try args.next(error.missing_archive);
    try args.done(error.unexpected_argument);
    var headers: [archive_paths.len]?[]u8 = @splat(null);
    var catalogs: [archive_paths.len]?[]u8 = @splat(null);
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
    for (headers[1..]) |header| if (!std.mem.eql(u8, headers[0].?, header.?)) return error.header_mismatch;
    for (catalogs[1..]) |catalog| if (!std.mem.eql(u8, catalogs[0].?, catalog.?)) return error.catalog_mismatch;
    inline for (manifest.providers, 0..) |provider, provider_index| {
        for (manifest.androidFor(provider).android.?) |abi| try requireElfMachine(init, archive_paths[provider_index * 4 + 1], abi.zip_path, abi.elf_machine, error.invalid_android_library);
        for (slices.ohos_abis) |abi| try requireOhosEntry(init, archive_paths[provider_index * 4 + 3], abi);
        for (manifest.appleFor(provider).apple.?) |slice| try requireAppleSlice(init, archive_paths[provider_index * 4 + 2], slice);
    }
    try symbols.assertExports(init, dynamic_library);
}

fn requireOhosEntry(init: std.process.Init, archive: []const u8, abi: slices.OhosAbi) !void {
    const entry = try print("stdk/libs/{s}/libstd.so", .{abi.triple});
    defer std.heap.page_allocator.free(entry);
    return requireElfMachine(init, archive, entry, abi.elf_machine, error.invalid_ohos_library);
}

fn print(comptime format: []const u8, args: anytype) ![]u8 {
    return std.heap.page_allocator.print(format, args);
}

fn extract(init: std.process.Init, archive: []const u8, entry: []const u8) ![]u8 {
    return run.output(init, &.{ "unzip", "-p", archive, entry });
}

fn requireEntries(entries: []const u8, expected: []const []const u8) !void {
    for (expected) |entry| if (!hasEntry(entries, entry)) return error.missing_archive_entry;
}

fn hasEntry(entries: []const u8, expected: []const u8) bool {
    var lines = std.mem.splitScalar(u8, entries, '\n');
    while (lines.next()) |entry| if (std.mem.eql(u8, entry, expected)) return true;
    return false;
}

fn requireElfMachine(init: std.process.Init, archive: []const u8, entry: []const u8, expected_machine: u16, err: anyerror) !void {
    const library = try extract(init, archive, entry);
    defer std.heap.page_allocator.free(library);
    if (library.len < 20 or !std.mem.eql(u8, library[0..4], "\x7fELF")) return err;
    const machine = std.mem.readInt(u16, library[18..20], .little);
    if (machine != expected_machine) return err;
}

fn requireAppleSlice(init: std.process.Init, archive: []const u8, slice: slices.AppleSlice) !void {
    const temporary_path = try print("zig-out/.package-{s}.dylib", .{slice.id});
    defer std.heap.page_allocator.free(temporary_path);
    defer std.Io.Dir.cwd().deleteFile(init.io, temporary_path) catch {};
    const entry = try print("StdK.xcframework/{s}/{s}", .{ slice.id, slices.libraryEntry(slice) });
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
    if (std.mem.indexOf(u8, stdout, platform_text) == null or std.mem.indexOf(u8, stdout, minimum_text) == null) return error.invalid_apple_library;
    // App Store validation rejects embedded frameworks whose Info.plist
    // lacks MinimumOSVersion (90530/90360).
    const plist_entry = if (slices.isMacos(slice))
        try print("StdK.xcframework/{s}/{s}/Versions/A/Resources/Info.plist", .{ slice.id, slices.framework_bundle })
    else
        try print("StdK.xcframework/{s}/{s}/Info.plist", .{ slice.id, slices.framework_bundle });
    defer std.heap.page_allocator.free(plist_entry);
    const plist = try extract(init, archive, plist_entry);
    defer std.heap.page_allocator.free(plist);
    if (std.mem.indexOf(u8, plist, "<key>MinimumOSVersion</key>") == null) return error.missing_minimum_os_version;
}
