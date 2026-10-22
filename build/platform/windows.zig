const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");

// The gnu flavor links the MinGW-w64 libc Zig ships; the msvc flavor stays
// free of any C runtime so consumers bring their own. Both build on any host.
pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Settings,
    distribution: manifest.Distribution,
    output_name: []const u8,
    comptime abi: std.Target.Abi,
    comptime arch: ?[]const u8,
) std.Build.LazyPath {
    const stage = common.beginLibstdStage(b, ctx, distribution);
    const import_name = if (abi == .msvc) "std.lib" else "std.dll.a";
    inline for (comptime manifest.pickSlices(.windows, null, arch)) |slice| {
        const target = b.resolveTargetQuery(.{ .cpu_arch = slice.arch, .os_tag = .windows, .abi = abi });
        const static_library = common.addLibrary(b, target, ctx.optimize, .static, ctx);
        _ = stage.addCopyFile(static_library.getEmittedBin(), b.fmt("libstd/lib/{s}/std.lib", .{@tagName(slice.arch)}));
        const dynamic_library = common.addLibrary(b, target, ctx.optimize, .dynamic, ctx);
        _ = stage.addCopyFile(dynamic_library.getEmittedBin(), b.fmt("libstd/bin/{s}/std.dll", .{@tagName(slice.arch)}));
        _ = stage.addCopyFile(dynamic_library.getEmittedImplib(), b.fmt("libstd/import/{s}/{s}", .{ @tagName(slice.arch), import_name }));
    }
    return common.addZipArchive(b, distribution, stage, output_name);
}
