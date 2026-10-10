const std = @import("std");

const android = @import("platform/android.zig");
const apple = @import("platform/apple.zig");
const cjpm = @import("platform/cjpm.zig");
const common = @import("platform/common.zig");
const manifest = @import("platform/manifest.zig");

pub const Unit = struct {
    name: []const u8,
    kind: Kind,
};

pub const Kind = enum { host, android, apple, cjpm };

pub const units = blk: {
    var list: [manifest.providers.len * 4]Unit = undefined;
    for (manifest.providers, 0..) |provider, index| {
        list[index * 4] = .{ .name = "libstd." ++ provider ++ ".zip", .kind = .host };
        list[index * 4 + 1] = .{ .name = "stdk." ++ provider ++ ".android.aar", .kind = .android };
        list[index * 4 + 2] = .{ .name = "StdK." ++ provider ++ ".apple.zip", .kind = .apple };
        list[index * 4 + 3] = .{ .name = "stdk." ++ provider ++ ".oh.zip", .kind = .cjpm };
    }
    break :blk list;
};

pub fn expand(b: *std.Build, ctx: *common.Context) void {
    if (ctx.dist_providers.len != manifest.providers.len) @panic("The distribution needs one provider context per manifest provider.");
    const archives = b.allocator.alloc(common.ProviderArchives, manifest.providers.len) catch @panic("The distribution registry is out of memory.");
    const dist = b.step("dist", "Build distribution archives");
    inline for (manifest.providers, 0..) |provider, index| {
        var pctx = ctx.*;
        pctx.options = ctx.dist_providers[index].options;
        pctx.host = ctx.dist_providers[index].host;
        archives[index] = .{
            .name = provider,
            .host = addHostArchive(b, &pctx, manifest.hostFor(provider)),
            .android = android.addArchive(b, &pctx, manifest.androidFor(provider)),
            .apple = apple.addArchive(b, &pctx, manifest.appleFor(provider)),
            .cjpm = cjpm.addArchive(b, &pctx, manifest.cjpmFor(provider)),
        };
        inline for (@typeInfo(common.ProviderArchives).@"struct".field_names) |field_name| {
            if (comptime std.mem.eql(u8, field_name, "name")) continue;
            const form = switch (comptime std.meta.stringToEnum(Kind, field_name) orelse .host) {
                .host => manifest.hostFor(provider),
                .android => manifest.androidFor(provider),
                .apple => manifest.appleFor(provider),
                .cjpm => manifest.cjpmFor(provider),
            };
            dist.dependOn(&b.addInstallFile(@field(archives[index], field_name), form.archive).step);
        }
    }
    ctx.archives = archives;
}

fn addHostArchive(b: *std.Build, ctx: *const common.Context, distribution: manifest.Distribution) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    common.stageHeaderCatalog(stage, ctx, distribution);
    _ = stage.addCopyFile(ctx.generated.module_map, "libstd/include/module.modulemap");
    _ = stage.addCopyFile(ctx.host.static_library.getEmittedBin(), "libstd/lib/libstd.a");
    _ = stage.addCopyFile(ctx.host.dynamic_library.getEmittedBin(), "libstd/lib/libstd.dylib");
    return common.addZipArchive(b, distribution, stage);
}
