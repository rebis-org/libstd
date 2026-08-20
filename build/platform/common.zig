const std = @import("std");

const render = @import("../../src/catalog/render.zig");
const cmd = @import("../acceptance/benchmark/command.zig");
const modules = @import("../modules.zig");
const manifest = @import("manifest.zig");

pub fn refTarget(b: *std.Build, target: std.Build.ResolvedTarget) std.Build.ResolvedTarget {
    return b.resolveTargetQuery(.{
        .cpu_arch = target.result.cpu.arch,
        .os_tag = target.result.os.tag,
    });
}

pub const Generated = struct {
    step: *std.Build.Step,
    header: std.Build.LazyPath,
    catalog: std.Build.LazyPath,
    module_map: std.Build.LazyPath,
};

pub const HostLibraries = struct {
    static_library: *std.Build.Step.Compile,
    dynamic_library: *std.Build.Step.Compile,
};

pub const Archives = struct {
    host: std.Build.LazyPath,
    android: std.Build.LazyPath,
    apple: std.Build.LazyPath,
};

pub const Context = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    version: std.SemanticVersion,
    generated: Generated,
    host: HostLibraries,
    refs: ?cmd.Refs = null,
    archives: ?Archives = null,
    force_fallback: bool = false,
    options: *std.Build.Module = undefined,
};

pub fn addLibrary(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    linkage: std.builtin.LinkMode,
    ctx: *const Context,
) *std.Build.Step.Compile {
    return addLibraryFromModule(b, rootModule(b, target, optimize, ctx), linkage);
}

pub fn rootModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, ctx: *const Context) *std.Build.Module {
    return modules.createFor(b, modules.library, target, optimize, ctx);
}

fn addLibraryFromModule(b: *std.Build, module: *std.Build.Module, linkage: std.builtin.LinkMode) *std.Build.Step.Compile {
    return b.addLibrary(.{
        .name = "std",
        .root_module = module,
        .linkage = linkage,
    });
}

pub fn addGenerated(b: *std.Build) Generated {
    const files = b.addWriteFiles();
    return .{
        .step = &files.step,
        .header = files.add("stdk.h", render.header),
        .catalog = files.add("stdk.catalog.json", render.catalog),
        .module_map = files.add("module.modulemap", render.module_map),
    };
}

pub fn addHostLibraries(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    force_fallback: bool,
    options: *std.Build.Module,
) HostLibraries {
    var ctx = Context{
        .target = target,
        .optimize = optimize,
        .version = undefined,
        .generated = undefined,
        .host = undefined,
        .force_fallback = force_fallback,
        .options = options,
    };
    const module = rootModule(b, target, optimize, &ctx);
    const static_library = addLibraryFromModule(b, module, .static);
    const dynamic_library = addLibraryFromModule(b, module, .dynamic);
    return .{ .static_library = static_library, .dynamic_library = dynamic_library };
}

pub fn installGenerated(b: *std.Build, generated: Generated) void {
    b.getInstallStep().dependOn(&b.addInstallHeaderFile(generated.header, "stdk.h").step);
    b.getInstallStep().dependOn(&b.addInstallFile(generated.catalog, "stdk.catalog.json").step);
    b.getInstallStep().dependOn(&b.addInstallFile(generated.module_map, "module.modulemap").step);
}

pub fn addZipArchive(b: *std.Build, comptime distribution: manifest.Distribution, stage: *std.Build.Step.WriteFile) std.Build.LazyPath {
    const zip = b.addSystemCommand(&.{ "zip", "-qry" });
    const archive = zip.addOutputFileArg(distribution.archive);
    zip.addArg(archiveRoot(distribution));
    zip.setCwd(stage.getDirectory());
    return archive;
}

fn archiveRoot(comptime distribution: manifest.Distribution) []const u8 {
    return comptime blk: {
        const entries = distribution.entries;
        const first = entries[0];
        const slash = std.mem.indexOfScalar(u8, first, '/') orelse break :blk ".";
        const prefix = first[0 .. slash + 1];
        for (entries[1..]) |entry| {
            if (!std.mem.startsWith(u8, entry, prefix)) break :blk ".";
        }
        break :blk prefix[0 .. prefix.len - 1];
    };
}
