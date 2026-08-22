const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");
const slices = @import("slices.zig");

pub fn addArchive(b: *std.Build, ctx: *const common.Context) std.Build.LazyPath {
    const headers = b.addWriteFiles();
    _ = headers.addCopyFile(ctx.generated.header, "stdk.h");
    _ = headers.addCopyFile(ctx.generated.module_map, "module.modulemap");
    const create = b.addSystemCommand(&.{ "xcodebuild", "-create-xcframework" });
    for (slices.apple_slices) |slice| {
        create.addArg("-library");
        create.addFileArg(buildSlice(b, ctx, slice));
        create.addArg("-headers");
        create.addDirectoryArg(headers.getDirectory());
    }
    create.addArg("-output");
    const framework = create.addOutputDirectoryArg("StdK.xcframework");
    const stage = b.addWriteFiles();
    _ = stage.addCopyDirectory(framework, "StdK.xcframework", .{});
    _ = stage.addCopyFile(ctx.generated.catalog, "StdK.xcframework/stdk.catalog.json");
    return common.addZipArchive(b, manifest.apple, stage);
}

fn buildSlice(b: *std.Build, ctx: *const common.Context, slice: slices.AppleSlice) std.Build.LazyPath {
    const base = slice.library[0 .. slice.library.len - ".dylib".len];
    // The install name must be the final leaf name inside the XCFramework,
    // not a per-arch build path: every arch of a slice shares one LC_ID_DYLIB
    // so the lipo output and any consumer's LC_LOAD_DYLIB resolve via @rpath.
    const install_name = b.fmt("@rpath/{s}", .{slice.library});
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
