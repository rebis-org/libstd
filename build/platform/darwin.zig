const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");

pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Settings,
    distribution: manifest.Distribution,
    output_name: []const u8,
    comptime arch: ?[]const u8,
) std.Build.LazyPath {
    _ = distribution;
    const headers = b.addWriteFiles();
    _ = headers.addCopyFile(ctx.generated.header, "stdk.h");
    _ = headers.addCopyFile(ctx.generated.framework_module_map, "module.modulemap");
    const plist = b.addWriteFiles();
    const xcframework = b.addSystemCommand(&.{ "xcodebuild", "-create-xcframework" });
    const slices = comptime if (arch) |a| manifest.archSlices(a) else &manifest.apple_slices;
    for (slices) |slice| {
        // App Store validation requires MinimumOSVersion on every embedded
        // framework. It follows the slice's own deployment floor.
        const plist_file = plist.add(b.fmt("Info-{s}.plist", .{slice.id}), b.fmt(framework_plist, .{ manifest.framework_binary, ctx.version.major, ctx.version.minor, ctx.version.patch, ctx.version.major, ctx.version.minor, ctx.version.patch, slice.minimum }));
        xcframework.addArg("-framework");
        xcframework.addDirectoryArg(wrapFramework(b, buildSlice(b, ctx, slice), headers.getDirectory(), plist_file, manifest.isMacos(slice)));
    }
    xcframework.addArg("-output");
    const framework = xcframework.addOutputDirectoryArg("stdk.xcframework");
    // WriteFile staging resolves symlinks away, and the macOS framework root
    // is symlinks, so stage and zip in one shell step.
    const archive = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\rm -rf "$1"
        \\mkdir -p "$1"
        \\cp -R "$2" "$1/stdk.xcframework"
        \\cp "$3" "$1/stdk.xcframework/stdk.catalog.json"
        \\out="$(cd "$(dirname "$4")" && pwd)/$(basename "$4")"
        \\cd "$1"
        \\zip -qry "$out" stdk.xcframework
        ,
        "sh",
    });
    _ = archive.addOutputDirectoryArg("stage");
    archive.addDirectoryArg(framework);
    archive.addFileArg2(ctx.generated.catalog, .{});
    return archive.addOutputFileArg(output_name);
}

fn buildSlice(b: *std.Build, ctx: *const common.Settings, slice: manifest.AppleSlice) std.Build.LazyPath {
    if (slice.arches.len > 4) @panic("an Apple slice carries at most four architectures.");
    const base = slice.library[0 .. slice.library.len - ".dylib".len];
    // Final leaf name, not a per-arch path: every slice shares one
    // bundle-relative LC_ID_DYLIB for @rpath resolution.
    const install_name = manifest.framework_install_name;
    if (slice.arches.len == 1) return buildArch(b, ctx, base, install_name, slice.arches[0]);
    var libraries: [4]std.Build.LazyPath = undefined;
    for (slice.arches, 0..) |arch, index| libraries[index] = buildArch(b, ctx, b.fmt("{s}_{s}", .{ base, archName(arch.arch) }), install_name, arch);
    return lipoCombine(b, base, libraries[0..slice.arches.len]);
}

fn buildArch(b: *std.Build, ctx: *const common.Settings, name: []const u8, install_name: []const u8, arch: manifest.AppleArch) std.Build.LazyPath {
    const target = b.resolveTargetQuery(targetQuery(arch));
    if (arch.zig) {
        const lib = common.addLibrary(b, target, .fast, .dynamic, ctx);
        lib.install_name = install_name;
        return lib.getEmittedBin();
    }
    const object = b.addObject(.{
        .name = b.fmt("std-{s}", .{name}),
        .root_module = common.rootModule(b, target, .fast, ctx),
    });
    const link_dylib = b.addSystemCommand(&.{ "xcrun", "--sdk", arch.sdk, "clang", "-target", arch.triple, "-dynamiclib" });
    link_dylib.addFileArg2(object.getEmittedBin(), .{});
    link_dylib.addArgs(&.{ "-install_name", install_name, "-o" });
    return link_dylib.addOutputFileArg(b.fmt("{s}.dylib", .{name}));
}

fn lipoCombine(b: *std.Build, output_name: []const u8, libraries: []const std.Build.LazyPath) std.Build.LazyPath {
    const lipo = b.addSystemCommand(&.{ "lipo", "-create" });
    for (libraries) |library| lipo.addFileArg2(library, .{});
    lipo.addArg("-output");
    return lipo.addOutputFileArg(b.fmt("{s}.dylib", .{output_name}));
}

fn targetQuery(arch: manifest.AppleArch) std.Target.Query {
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

// Codesign seals the tree it signs.
// Assembles and signs in one step because steps cannot mutate inputs in place.
fn wrapFramework(b: *std.Build, library: std.Build.LazyPath, headers: std.Build.LazyPath, plist: std.Build.LazyPath, versioned: bool) std.Build.LazyPath {
    const command = b.addSystemCommand(&.{
        "sh", "-c",
        b.fmt(
            \\set -eu
            \\rm -rf "$1"
            \\if [ "$5" = versioned ]; then
            \\    mkdir -p "$1/Versions/A/Headers" "$1/Versions/A/Modules" "$1/Versions/A/Resources"
            \\    cp "$2" "$1/Versions/A/{s}"
            \\    codesign --remove-signature "$1/Versions/A/{s}" 2>/dev/null || true
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
            \\    codesign --remove-signature "$1/{s}" 2>/dev/null || true
            \\    cp "$3/stdk.h" "$1/Headers/stdk.h"
            \\    cp "$3/module.modulemap" "$1/Headers/module.modulemap"
            \\    cp "$3/module.modulemap" "$1/Modules/module.modulemap"
            \\    cp "$4" "$1/Info.plist"
            \\fi
            \\codesign --force --sign - "$1"
        , .{
            manifest.framework_binary,
            manifest.framework_binary,
            manifest.framework_binary,
            manifest.framework_binary,
            manifest.framework_binary,
            manifest.framework_binary,
        }),
        "sh",
    });
    const wrapped = command.addOutputDirectoryArg(manifest.framework_bundle);
    command.addFileArg2(library, .{});
    command.addDirectoryArg(headers);
    command.addFileArg2(plist, .{});
    command.addArg(if (versioned) "versioned" else "flat");
    return wrapped;
}

const framework_plist =
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
    \\    <string>{d}.{d}.{d}</string>
    \\    <key>CFBundleVersion</key>
    \\    <string>{d}.{d}.{d}</string>
    \\    <key>MinimumOSVersion</key>
    \\    <string>{s}</string>
    \\</dict>
    \\</plist>
    \\
;
