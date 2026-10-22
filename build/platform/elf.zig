const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");

// One engine serves every form whose per-arch content is a static/dynamic
// pair under libstd/lib/<arch>/; only the target query and extensions vary.
pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Settings,
    distribution: manifest.Distribution,
    output_name: []const u8,
    comptime os_tag: std.Target.Os.Tag,
    comptime abi: ?std.Target.Abi,
    comptime arch: ?[]const u8,
) std.Build.LazyPath {
    const stage = common.beginLibstdStage(b, ctx, distribution);
    const arches = comptime pick(manifest.slices[0..], os_tag, abi, arch);
    inline for (arches) |slice| {
        var query = std.Target.Query{ .cpu_arch = slice.arch, .os_tag = os_tag };
        if (comptime abi) |a| query.abi = a;
        if (comptime os_tag == .macos) query.os_version_min = .{ .semver = .{ .major = 13, .minor = 0, .patch = 0 } };
        const target = b.resolveTargetQuery(query);
        inline for (comptime linkages(os_tag)) |linkage| {
            const library = common.addLibrary(b, target, ctx.optimize, linkage, ctx);
            _ = stage.addCopyFile(library.getEmittedBin(), b.fmt("libstd/lib/{s}/{s}", .{ @tagName(slice.arch), libName(os_tag, linkage) }));
        }
    }
    return common.addZipArchive(b, distribution, stage, output_name);
}

fn libName(comptime os_tag: std.Target.Os.Tag, comptime linkage: std.lang.LinkMode) []const u8 {
    if (linkage == .static) return "libstd.a";
    return switch (os_tag) {
        .macos => "libstd.dylib",
        else => "libstd.so",
    };
}

fn linkages(comptime os_tag: std.Target.Os.Tag) []const std.lang.LinkMode {
    // WASI has no shared-library model.
    return if (os_tag == .wasi) &.{.static} else &.{ .static, .dynamic };
}

fn pick(comptime table: []const manifest.TargetSlice, comptime os_tag: std.Target.Os.Tag, comptime abi: ?std.Target.Abi, comptime arch: ?[]const u8) []const manifest.TargetSlice {
    comptime {
        const os_arches: []const []const u8 = switch (os_tag) {
            .linux => if (abi == .musl) &.{ "x86_64", "aarch64", "riscv64" } else if (abi == .ohos) &.{ "x86_64", "aarch64" } else &.{ "x86_64", "aarch64", "riscv64", "loongarch64" },
            .freebsd, .openbsd, .macos => &.{ "x86_64", "aarch64" },
            .wasi => &.{"wasm32"},
            else => @compileError("no elf table for " ++ @tagName(os_tag)),
        };
        var chosen: [table.len]manifest.TargetSlice = undefined;
        var n: usize = 0;
        for (table) |slice| {
            for (os_arches) |name| {
                if (std.mem.eql(u8, @tagName(slice.arch), name)) {
                    chosen[n] = slice;
                    n += 1;
                }
            }
        }
        if (arch) |a| {
            for (chosen[0..n]) |slice| {
                if (std.mem.eql(u8, @tagName(slice.arch), a)) return &.{slice};
            }
            @compileError("unknown arch: " ++ a);
        }
        return chosen[0..n];
    }
}
