const std = @import("std");

const manifest = @import("manifest");

const run = @import("run.zig");
const symbols = @import("symbols.zig");

// The argument list is the flat per-provider form list (see
// `manifest.forms`); every check dispatches on the form id.
pub fn main(init: std.process.Init) !void {
    var args = run.CliArgs.init(init.minimal.args);
    const form_count = comptime manifest.forms("onprem").len;
    var archive_paths: [manifest.providers.len * form_count][]const u8 = undefined;
    var arg_index: usize = 0;
    inline for (manifest.providers) |provider| {
        inline for (comptime manifest.forms(provider)) |_| {
            archive_paths[arg_index] = try args.next(error.missing_archive);
            arg_index += 1;
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
    inline for (manifest.providers, 0..) |provider, provider_index| {
        inline for (comptime manifest.forms(provider), 0..) |form, form_index| {
            const index = provider_index * form_count + form_index;
            const archive = archive_paths[index];
            try run.silent(init, &.{ "unzip", "-tq", archive });
            const entries = try run.output(init, &.{ "unzip", "-Z1", archive });
            defer std.heap.page_allocator.free(entries);
            try requireEntries(entries, form.entries);
            headers[index] = try extractEntry(init, archive, form.header);
            catalogs[index] = try extractEntry(init, archive, form.catalog);
            try checkForm(init, archive, form);
        }
    }
    for (headers[1..]) |header| if (!std.mem.eql(u8, headers[0].?, header.?)) return error.header_mismatch;
    for (catalogs[1..]) |catalog| if (!std.mem.eql(u8, catalogs[0].?, catalog.?)) return error.catalog_mismatch;
    try symbols.assertExports(init, dynamic_library);
}

fn checkForm(init: std.process.Init, archive: []const u8, comptime form: manifest.Distribution) !void {
    const id = form.id;
    if (std.mem.startsWith(u8, id, "windows")) {
        for (form.entries) |entry| {
            if (std.mem.indexOf(u8, entry, "/bin/") == null) continue;
            const arch = entry["libstd/bin/".len .. entry.len - "/std.dll".len];
            try requirePeMachine(init, archive, entry, machineOf(arch, true), error.invalid_windows_library);
        }
    } else if (std.mem.startsWith(u8, id, "freebsd") or
        std.mem.startsWith(u8, id, "openbsd") or
        std.mem.startsWith(u8, id, "linux.gnu") or
        std.mem.startsWith(u8, id, "linux.musl"))
    {
        for (form.entries) |entry| {
            if (std.mem.indexOf(u8, entry, "/libstd.so") == null and std.mem.indexOf(u8, entry, "/libstd.dylib") == null) continue;
            const basename = if (std.mem.indexOf(u8, entry, "/libstd.so") != null) "/libstd.so" else "/libstd.dylib";
            const arch = entry["libstd/lib/".len .. entry.len - basename.len];
            try requireElfMachine(init, archive, entry, machineOf(arch, false), error.invalid_elf_library);
        }
    } else if (std.mem.startsWith(u8, id, "darwin")) {
        if (form.apple) |slices| {
            for (slices) |slice| try requireAppleSlice(init, archive, slice);
        }
    } else if (std.mem.eql(u8, id, "linux.android")) {
        for (manifest.android_abis) |abi| try requireElfMachine(init, archive, abi.zip_path, abi.slice.elf_machine, error.invalid_android_library);
    } else if (std.mem.eql(u8, id, "linux.ohos")) {
        for (manifest.ohos_abis) |abi| {
            try requireElfMachine(init, archive, try formatAlloc("stdk/libs/{s}/libstd.so", .{abi.triple}), abi.slice.elf_machine, error.invalid_ohos_library);
        }
    }
}

fn machineOf(arch: []const u8, comptime pe: bool) u16 {
    for (&manifest.slices) |*slice| {
        if (std.mem.eql(u8, @tagName(slice.arch), arch)) return if (pe) slice.pe_machine else slice.elf_machine;
    }
    std.debug.print("unknown arch: {s}\n", .{arch});
    std.process.exit(1);
}

fn formatAlloc(comptime format: []const u8, args: anytype) ![]const u8 {
    return std.heap.page_allocator.print(format, args);
}

fn extractEntry(init: std.process.Init, archive: []const u8, entry: []const u8) ![]u8 {
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
    const library = try extractEntry(init, archive, entry);
    defer std.heap.page_allocator.free(library);
    if (library.len < 20 or !std.mem.eql(u8, library[0..4], "\x7fELF")) return err;
    const machine = std.mem.readInt(u16, library[18..20], .little);
    if (machine != expected_machine) return err;
}

// A DLL carries its machine type in the PE header; the e_lfanew pointer at
// 0x3C names the header's offset past the DOS stub.
fn requirePeMachine(init: std.process.Init, archive: []const u8, entry: []const u8, expected_machine: u16, err: anyerror) !void {
    const library = try extractEntry(init, archive, entry);
    defer std.heap.page_allocator.free(library);
    if (library.len < 0x40 or !std.mem.eql(u8, library[0..2], "MZ")) return err;
    const header_at = std.mem.readInt(u32, library[0x3c..][0..4], .little);
    if (header_at + 6 > library.len or !std.mem.eql(u8, library[header_at..][0..4], "PE\x00\x00")) return err;
    const machine = std.mem.readInt(u16, library[header_at + 4 ..][0..2], .little);
    if (machine != expected_machine) return err;
}

fn requireAppleSlice(init: std.process.Init, archive: []const u8, slice: manifest.AppleSlice) !void {
    const temporary_path = try formatAlloc("zig-out/.package-{s}.dylib", .{slice.id});
    defer std.heap.page_allocator.free(temporary_path);
    defer std.Io.Dir.cwd().deleteFile(init.io, temporary_path) catch {};
    const entry = try formatAlloc("stdk.xcframework/{s}/{s}", .{ slice.id, manifest.libraryEntry(slice) });
    defer std.heap.page_allocator.free(entry);
    const bytes = try extractEntry(init, archive, entry);
    defer std.heap.page_allocator.free(bytes);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = temporary_path, .data = bytes });
    const stdout = try run.output(init, &.{ "vtool", "-show-build", temporary_path });
    defer std.heap.page_allocator.free(stdout);
    const platform_text = try formatAlloc("platform {s}", .{slice.platform});
    defer std.heap.page_allocator.free(platform_text);
    const minimum_text = try formatAlloc("minos {s}", .{slice.minimum});
    defer std.heap.page_allocator.free(minimum_text);
    if (std.mem.find(u8, stdout, platform_text) == null or std.mem.find(u8, stdout, minimum_text) == null) return error.invalid_apple_library;
    // App Store validation rejects embedded frameworks without MinimumOSVersion.
    const plist_entry = if (manifest.isMacos(slice))
        try formatAlloc("stdk.xcframework/{s}/{s}/Versions/A/Resources/Info.plist", .{ slice.id, manifest.framework_bundle })
    else
        try formatAlloc("stdk.xcframework/{s}/{s}/Info.plist", .{ slice.id, manifest.framework_bundle });
    defer std.heap.page_allocator.free(plist_entry);
    const plist = try extractEntry(init, archive, plist_entry);
    defer std.heap.page_allocator.free(plist);
    if (std.mem.find(u8, plist, "<key>MinimumOSVersion</key>") == null) return error.missing_minimum_os_version;
}
