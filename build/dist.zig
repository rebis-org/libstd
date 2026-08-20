const std = @import("std");

const android = @import("platform/android.zig");
const apple = @import("platform/apple.zig");
const common = @import("platform/common.zig");
const manifest = @import("platform/manifest.zig");

pub const Unit = struct {
    name: []const u8,
    kind: Kind,
};

pub const Kind = enum { host, android, apple };

pub const units = [_]Unit{
    .{ .name = "libstd.zip", .kind = .host },
    .{ .name = "stdk.aar", .kind = .android },
    .{ .name = "StdK.XCFramework.zip", .kind = .apple },
};

pub fn expand(b: *std.Build, ctx: *common.Context) void {
    const archives = common.Archives{
        .host = addHostArchive(b, ctx),
        .android = android.addArchive(b, ctx),
        .apple = apple.addArchive(b, ctx),
    };
    ctx.archives = archives;
    const dist = b.step("dist", "Build distribution archives");
    dist.dependOn(&b.addInstallFile(archives.host, manifest.host.archive).step);
    dist.dependOn(&b.addInstallFile(archives.android, manifest.android.archive).step);
    dist.dependOn(&b.addInstallFile(archives.apple, manifest.apple.archive).step);
}

fn addHostArchive(b: *std.Build, ctx: *common.Context) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.addCopyFile(ctx.generated.header, manifest.host.header);
    _ = stage.addCopyFile(ctx.generated.module_map, "libstd/include/module.modulemap");
    _ = stage.addCopyFile(ctx.generated.catalog, manifest.host.catalog);
    _ = stage.addCopyFile(ctx.host.static_library.getEmittedBin(), "libstd/lib/libstd.a");
    _ = stage.addCopyFile(ctx.host.dynamic_library.getEmittedBin(), "libstd/lib/libstd.dylib");
    return common.addZipArchive(b, manifest.host, stage);
}
