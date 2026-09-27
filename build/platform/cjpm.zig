const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");
const slices = @import("slices.zig");

// Cangjie package (cjpm) archive: a Cangjie module with FFI bindings, the
// generated header and catalog, and prebuilt OHOS libraries per target triple.
// cjpm is the official Cangjie package manager. [ffi.c] entries name the
// native library each target links (libstd.a / libstd.so under libs/<triple>).
pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Context,
) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.add("stdk/cjpm.toml", tomlText(b, ctx));
    _ = stage.addCopyFile(b.path("build/templates/cjpm/stdk.cj"), "stdk/src/stdk.cj");
    _ = stage.addCopyFile(b.path("build/templates/cjpm/session.cj"), "stdk/src/session.cj");
    _ = stage.addCopyFile(ctx.generated.header, "stdk/libs/include/stdk.h");
    _ = stage.addCopyFile(ctx.generated.catalog, "stdk/stdk.catalog.json");
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
    return common.addZipArchive(b, manifest.cjpm, stage);
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
    , .{ ctx.version.major, ctx.version.minor, ctx.version.patch })) catch @panic("OOM");
    for (slices.ohos_abis) |abi| {
        text.appendSlice(b.allocator, b.fmt(
            \\
            \\[target.{s}.ffi.c]
            \\  std = {{ path = "libs/{s}" }}
            \\
        , .{ abi.triple, abi.triple })) catch @panic("OOM");
    }
    return text.items;
}
