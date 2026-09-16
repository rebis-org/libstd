const std = @import("std");

const render = @import("../../src/kernel/render.zig");
const cmd = @import("../acceptance/benchmark/command.zig");
const modules = @import("../modules.zig");
const manifest = @import("manifest.zig");

pub fn refTarget(b: *std.Build, target: std.Build.ResolvedTarget) std.Build.ResolvedTarget {
    return b.resolveTargetQuery(.{
        .cpu_arch = target.result.cpu.arch,
        .os_tag = target.result.os.tag,
    });
}

// Explicit file args keep the scan's cache key honest in both directions: a directory arg is unfingerprinted.
pub fn descriptorPaths(b: *std.Build) [][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var dir = std.Io.Dir.cwd().openDir(b.graph.io, "src", .{ .iterate = true }) catch @panic("component scan: open src");
    defer dir.close(b.graph.io);
    var walker = dir.walk(b.allocator) catch @panic("component scan: walk src");
    while (walker.next(b.graph.io) catch @panic("component scan: walk src")) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".descriptor.zon")) continue;
        const rel = std.fmt.allocPrint(b.allocator, "src/{s}", .{entry.path}) catch @panic("component scan: oom");
        list.append(b.allocator, rel) catch @panic("component scan: oom");
    }
    std.mem.sort([]const u8, list.items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return std.mem.order(u8, lhs, rhs) == .lt;
        }
    }.lessThan);
    return list.items;
}

pub fn descriptorScan(b: *std.Build, ctx: *const Context) std.Build.LazyPath {
    const module = modules.create(b, modules.component, ctx);
    const exe = b.addExecutable(.{ .name = "component", .root_module = module });
    const run = b.addRunArtifact(exe);
    for (descriptorPaths(b)) |path| run.addFileArg(b.path(path));
    return run.addOutputFileArg("components.generated.zig");
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
    portable: bool = false,
    options: *std.Build.Module,
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
    const module = modules.createFor(b, modules.library, target, optimize, ctx);
    // Discovery expects the generated table plus the nucleus import.
    const generated_components = descriptorScan(b, ctx);
    const components_module = b.createModule(.{
        .root_source_file = generated_components,
        .target = target,
        .optimize = optimize,
    });
    const nucleus_module = modules.createFor(b, modules.nucleus, target, optimize, ctx);
    components_module.addImport("nucleus", nucleus_module);
    module.addImport("components", components_module);
    module.addImport("nucleus", nucleus_module);
    return module;
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
    // Catalog derives from the same comptime source the discovery call serves.
    // Scan path reads only options and portable; version/generated/host go unread.
    var scan_ctx = Context{
        .target = b.graph.host,
        .optimize = .Debug,
        .version = undefined,
        .generated = undefined,
        .host = undefined,
        .options = b.addOptions().createModule(),
    };
    const generated_components = descriptorScan(b, &scan_ctx);
    const components_module = b.createModule(.{
        .root_source_file = generated_components,
        .target = b.graph.host,
        .optimize = .Debug,
    });
    const nucleus_module = modules.createFor(b, modules.nucleus, b.graph.host, .Debug, &scan_ctx);
    components_module.addImport("nucleus", nucleus_module);
    const gen_module = b.createModule(.{
        .root_source_file = b.path("src/catalog_gen.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    gen_module.addImport("components", components_module);
    gen_module.addImport("nucleus", nucleus_module);
    const gen_exe = b.addExecutable(.{ .name = "catalog_gen", .root_module = gen_module });
    const gen_run = b.addRunArtifact(gen_exe);
    return .{
        .step = &files.step,
        .header = files.add("stdk.h", render.header),
        .catalog = gen_run.addOutputFileArg("stdk.catalog.json"),
        .module_map = files.add("module.modulemap", render.module_map),
    };
}

pub fn addHostLibraries(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    portable: bool,
    options: *std.Build.Module,
) HostLibraries {
    return addHostLibrariesWithOptions(b, target, optimize, portable, options);
}

pub fn addHostLibrariesWithOptions(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    portable: bool,
    options: *std.Build.Module,
) HostLibraries {
    // Module construction reads only portable; version/generated/host go unread here.
    var ctx = Context{
        .target = target,
        .optimize = optimize,
        .version = undefined,
        .generated = undefined,
        .host = undefined,
        .portable = portable,
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
