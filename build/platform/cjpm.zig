const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");
const slices = @import("slices.zig");

// [ffi.c] entries name the native library each target links.
pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Context,
    distribution: manifest.Distribution,
) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.add("stdk/cjpm.toml", tomlText(b, ctx));
    _ = stage.addCopyFile(b.path("build/templates/cjpm/stdk.cj"), "stdk/src/stdk.cj");
    common.stageHeaderCatalog(stage, ctx, distribution);
    for (slices.ohos_abis) |abi| {
        const resolved = b.resolveTargetQuery(.{
            .cpu_arch = abi.arch,
            .os_tag = .linux,
            .abi = .ohos,
        });
        const static_library = common.addLibrary(b, resolved, ctx.optimize, .static, ctx);
        const dynamic_library = common.addLibrary(b, resolved, ctx.optimize, .dynamic, ctx);
        _ = stage.addCopyFile(static_library.getEmittedBin(), b.fmt("stdk/libs/{s}/libstd.a", .{abi.triple}));
        _ = stage.addCopyFile(dynamic_library.getEmittedBin(), b.fmt("stdk/libs/{s}/libstd.so", .{abi.triple}));
    }
    return common.addZipArchive(b, distribution, stage);
}

fn tomlText(b: *std.Build, ctx: *const common.Context) []const u8 {
    var text: std.ArrayList(u8) = .empty;
    text.appendSlice(b.allocator, b.fmt(
        \\[package]
        \\  cjc-version = "1.2.0"
        \\  name = "stdk"
        \\  description = "Library (for standard) in Zig"
        \\  version = "{d}.{d}.{d}"
        \\  compile-option = ""
        \\  link-option = ""
        \\  output-type = "static"
        \\  src-dir = "src"
        \\
    , .{ ctx.version.major, ctx.version.minor, ctx.version.patch })) catch @panic("the cjpm manifest is out of memory.");
    for (slices.ohos_abis) |abi| {
        text.appendSlice(b.allocator, b.fmt(
            \\
            \\[target.{s}.ffi.c]
            \\  std = {{ path = "libs/{s}" }}
            \\
        , .{ abi.triple, abi.triple })) catch @panic("the cjpm target entry is out of memory.");
    }
    return text.items;
}
