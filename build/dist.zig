const std = @import("std");

const common = @import("platform/common.zig");
const darwin = @import("platform/darwin.zig");
const elf = @import("platform/elf.zig");
const linux = @import("platform/linux.zig");
const manifest = @import("platform/manifest.zig");
const windows = @import("platform/windows.zig");

// Kinds name the artifact shape that routes to a builder: one ELF
// engine serves macos, linux, the BSDs, and WASI.
pub const Kind = enum { elf, pe, xcframework, aar, cjpm };

pub const Unit = common.KindedUnit(Kind);

pub fn kindFor(id: []const u8) Kind {
    comptime {
        @setEvalBranchQuota(100_000);
    }
    if (std.mem.startsWith(u8, id, "windows")) return .pe;
    if (std.mem.startsWith(u8, id, "darwin")) return .xcframework;
    if (std.mem.eql(u8, id, "linux.android")) return .aar;
    if (std.mem.eql(u8, id, "linux.ohos")) return .cjpm;
    return .elf;
}

// The listing shows the form names; the installed archives carry the
// version-sha tag computed at configure time.
pub const units = blk: {
    var list: [manifest.providers.len * manifest.forms("onprem").len]Unit = undefined;
    for (manifest.providers, 0..) |provider, index| {
        for (manifest.forms(provider), 0..) |form, form_index| {
            list[index * manifest.forms("onprem").len + form_index] = .{ .name = form.archive, .kind = kindFor(form.id) };
        }
    }
    break :blk list;
};

fn archFilter(id: []const u8) ?[]const u8 {
    // Per-arch ids carry the arch in the last segment; `windows.gnu` and
    // `windows.msvc` are universal forms, not arch names.
    if (std.mem.lastIndexOfScalar(u8, id, '.')) |last| {
        const segment = id[last + 1 ..];
        const non_arches = [_][]const u8{ "gnu", "msvc", "musl", "android", "ohos", "universal" };
        for (non_arches) |name| if (std.mem.eql(u8, segment, name)) return null;
        return segment;
    }
    return null;
}

pub fn expand(b: *std.Build, ctx: *common.Settings) void {
    if (ctx.dist_providers.len != manifest.providers.len) @panic("the distribution needs one provider context per manifest provider.");
    const dist = b.step("dist", "Build distribution archives");
    const form_count = manifest.forms("onprem").len;
    const form_archives = b.allocator.alloc(std.Build.LazyPath, manifest.providers.len * form_count) catch @panic("the distribution registry is out of memory.");
    var form_index: usize = 0;
    inline for (manifest.providers, 0..) |provider, index| {
        var provider_ctx = ctx.*;
        provider_ctx.options = ctx.dist_providers[index].options;
        provider_ctx.host = ctx.dist_providers[index].host;
        inline for (comptime manifest.forms(provider)) |form| {
            const file_name = b.fmt("{s}-{s}.{s}", .{ form.archive, ctx.dist_tag, if (comptime kindFor(form.id) == .aar) "aar" else "zip" });
            const archive = switch (comptime kindFor(form.id)) {
                .elf => elf.addArchive(b, &provider_ctx, form, file_name, comptime osTag(form.id), comptime abiTag(form.id), comptime archFilter(form.id)),
                .pe => windows.addArchive(b, &provider_ctx, form, file_name, if (std.mem.startsWith(u8, form.id, "windows.msvc")) .msvc else .gnu, comptime archFilter(form.id)),
                .xcframework => darwin.addArchive(b, &provider_ctx, form, file_name, comptime archFilter(form.id)),
                .aar => linux.addAar(b, &provider_ctx, form, file_name),
                .cjpm => linux.addArchive(b, &provider_ctx, form, file_name),
            };
            dist.dependOn(&b.addInstallFile(archive, file_name).step);
            form_archives[form_index] = archive;
            form_index += 1;
        }
    }
    ctx.dist_forms = form_archives;
}

fn osTag(comptime id: []const u8) std.Target.Os.Tag {
    comptime {
        if (std.mem.startsWith(u8, id, "macos")) return .macos;
        if (std.mem.startsWith(u8, id, "freebsd")) return .freebsd;
        if (std.mem.startsWith(u8, id, "openbsd")) return .openbsd;
        if (std.mem.startsWith(u8, id, "wasi")) return .wasi;
        return .linux;
    }
}

fn abiTag(comptime id: []const u8) ?std.Target.Abi {
    comptime {
        if (std.mem.startsWith(u8, id, "linux.musl")) return .musl;
        if (std.mem.startsWith(u8, id, "linux")) return .gnu;
        return null;
    }
}
