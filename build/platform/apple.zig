const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");
const slices = @import("slices.zig");

pub fn addArchive(b: *std.Build, ctx: *const common.Context) std.Build.LazyPath {
    const headers = b.addWriteFiles();
    _ = headers.addCopyFile(ctx.generated.header, "stdk.h");
    _ = headers.addCopyFile(ctx.generated.framework_module_map, "module.modulemap");
    const plist = b.addWriteFiles();
    const plist_file = plist.add("Info.plist", framework_plist);
    const create = b.addSystemCommand(&.{ "xcodebuild", "-create-xcframework" });
    for (slices.apple_slices) |slice| {
        create.addArg("-framework");
        create.addDirectoryArg(wrapFramework(b, buildSlice(b, ctx, slice), headers.getDirectory(), plist_file, slices.isMacos(slice)));
    }
    create.addArg("-output");
    const framework = create.addOutputDirectoryArg("StdK.xcframework");
    // WriteFile staging resolves symlinks away; the versioned macOS framework
    // keeps its bundle root as symlinks, so stage and zip in one shell step.
    const archive = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\mkdir -p "$1"
        \\cp -R "$2" "$1/StdK.xcframework"
        \\cp "$3" "$1/StdK.xcframework/stdk.catalog.json"
        \\cd "$1"
        \\zip -qry "$4" StdK.xcframework
        ,
        "sh",
    });
    _ = archive.addOutputDirectoryArg("stage");
    archive.addDirectoryArg(framework);
    archive.addFileArg(ctx.generated.catalog);
    return archive.addOutputFileArg(manifest.apple.archive);
}

fn buildSlice(b: *std.Build, ctx: *const common.Context, slice: slices.AppleSlice) std.Build.LazyPath {
    const base = slice.library[0 .. slice.library.len - ".dylib".len];
    // Final leaf name, not a per-arch path: every slice shares one
    // bundle-relative LC_ID_DYLIB for @rpath resolution.
    const install_name = slices.framework_install_name;
    if (slice.arches.len == 1) return buildArch(b, ctx, base, install_name, slice.arches[0]);
    var libraries: [4]std.Build.LazyPath = undefined;
    for (slice.arches, 0..) |arch, index| libraries[index] = buildArch(b, ctx, b.fmt("{s}_{s}", .{ base, archName(arch.arch) }), install_name, arch);
    return universal(b, base, libraries[0..slice.arches.len]);
}

fn buildArch(b: *std.Build, ctx: *const common.Context, name: []const u8, install_name: []const u8, arch: slices.AppleArch) std.Build.LazyPath {
    const target = b.resolveTargetQuery(targetQuery(arch));
    if (arch.zig) {
        const lib = common.addLibrary(b, target, .ReleaseFast, .dynamic, ctx);
        lib.install_name = install_name;
        return lib.getEmittedBin();
    }
    const object = b.addObject(.{
        .name = b.fmt("std-{s}", .{name}),
        .root_module = common.rootModule(b, target, .ReleaseFast, ctx),
    });
    const link = b.addSystemCommand(&.{ "xcrun", "--sdk", arch.sdk, "clang", "-target", arch.triple, "-dynamiclib" });
    link.addFileArg(object.getEmittedBin());
    link.addArgs(&.{ "-install_name", install_name, "-o" });
    return link.addOutputFileArg(b.fmt("{s}.dylib", .{name}));
}

fn universal(b: *std.Build, output_name: []const u8, libraries: []const std.Build.LazyPath) std.Build.LazyPath {
    const lipo = b.addSystemCommand(&.{ "lipo", "-create" });
    for (libraries) |library| lipo.addFileArg(library);
    lipo.addArg("-output");
    return lipo.addOutputFileArg(b.fmt("{s}.dylib", .{output_name}));
}

fn targetQuery(arch: slices.AppleArch) std.Target.Query {
    var query = std.Target.Query{ .cpu_arch = arch.arch, .os_tag = arch.os };
    if (arch.abi) |abi| query.abi = abi;
    if (arch.os_version_min) |version| query.os_version_min = .{ .semver = version };
    return query;
}

fn archName(arch: std.Target.Cpu.Arch) []const u8 {
    return switch (arch) {
        .aarch64 => "arm64",
        .x86_64 => "x86_64",
        else => @tagName(arch),
    };
}

// codesign seals the tree it signs, so the bundle is assembled and signed in
// one step: Zig steps cannot declare an input that a command mutates in place.
fn wrapFramework(b: *std.Build, library: std.Build.LazyPath, headers: std.Build.LazyPath, plist: std.Build.LazyPath, versioned: bool) std.Build.LazyPath {
    const command = b.addSystemCommand(&.{
        "sh", "-c",
        b.fmt(
            \\set -eu
            \\if [ "$5" = versioned ]; then
            \\    mkdir -p "$1/Versions/A/Headers" "$1/Versions/A/Modules" "$1/Versions/A/Resources"
            \\    cp "$2" "$1/Versions/A/{s}"
            \\    cp "$3/stdk.h" "$1/Versions/A/Headers/stdk.h"
            \\    cp "$3/module.modulemap" "$1/Versions/A/Headers/module.modulemap"
            \\    cp "$3/module.modulemap" "$1/Versions/A/Modules/module.modulemap"
            \\    cp "$4" "$1/Versions/A/Resources/Info.plist"
            \\    ln -s A "$1/Versions/Current"
            \\    ln -s Versions/Current/{s} "$1/{s}"
            \\    ln -s Versions/Current/Headers "$1/Headers"
            \\    ln -s Versions/Current/Modules "$1/Modules"
            \\    ln -s Versions/Current/Resources "$1/Resources"
            \\else
            \\    mkdir -p "$1/Headers" "$1/Modules"
            \\    cp "$2" "$1/{s}"
            \\    cp "$3/stdk.h" "$1/Headers/stdk.h"
            \\    cp "$3/module.modulemap" "$1/Headers/module.modulemap"
            \\    cp "$3/module.modulemap" "$1/Modules/module.modulemap"
            \\    cp "$4" "$1/Info.plist"
            \\fi
            \\codesign --force --sign - "$1"
        , .{ slices.framework_binary, slices.framework_binary, slices.framework_binary, slices.framework_binary }),
        "sh",
    });
    const wrapped = command.addOutputDirectoryArg(slices.framework_bundle);
    command.addFileArg(library);
    command.addDirectoryArg(headers);
    command.addFileArg(plist);
    command.addArg(if (versioned) "versioned" else "flat");
    return wrapped;
}

const framework_plist = std.fmt.comptimePrint(
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    \\<plist version="1.0">
    \\<dict>
    \\    <key>CFBundleDevelopmentRegion</key>
    \\    <string>en</string>
    \\    <key>CFBundleExecutable</key>
    \\    <string>{s}</string>
    \\    <key>CFBundleIdentifier</key>
    \\    <string>org.rebis.stdk</string>
    \\    <key>CFBundleInfoDictionaryVersion</key>
    \\    <string>6.0</string>
    \\    <key>CFBundlePackageType</key>
    \\    <string>FMWK</string>
    \\    <key>CFBundleShortVersionString</key>
    \\    <string>1.0</string>
    \\    <key>CFBundleVersion</key>
    \\    <string>1</string>
    \\</dict>
    \\</plist>
    \\
, .{slices.framework_binary});
