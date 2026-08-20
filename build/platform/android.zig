const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");
const slices = @import("slices.zig");

const android_api_level: u32 = 33;

pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Context,
) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.add("AndroidManifest.xml", b.fmt(
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"dev.stdk\" android:versionName=\"{d}.{d}.{d}\" android:versionCode=\"{d}\" />\n",
        .{ ctx.version.major, ctx.version.minor, ctx.version.patch, manifest.versionCode(ctx.version) },
    ));
    _ = stage.addCopyFile(ctx.generated.header, "include/stdk.h");
    _ = stage.addCopyFile(ctx.generated.catalog, "assets/stdk.catalog.json");
    for (slices.android_abis) |abi| {
        const library = common.addLibrary(b, b.resolveTargetQuery(.{
            .cpu_arch = abi.arch,
            .os_tag = .linux,
            .abi = .android,
            .android_api_level = android_api_level,
        }), ctx.optimize, .dynamic, ctx);
        _ = stage.addCopyFile(library.getEmittedBin(), abi.library);
    }
    return common.addZipArchive(b, manifest.android, stage);
}
