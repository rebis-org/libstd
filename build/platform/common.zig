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

// Each descriptor is a file argument, because a directory argument is unfingerprinted.
pub fn descriptorPaths(b: *std.Build) [][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var dir = std.Io.Dir.cwd().openDir(b.graph.io, "src", .{ .iterate = true }) catch @panic("The component scan cannot open src.");
    defer dir.close(b.graph.io);
    var walker = dir.walk(b.allocator) catch @panic("The component scan cannot start a walk of src.");
    while (walker.next(b.graph.io) catch @panic("The component scan cannot continue the walk of src.")) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".descriptor.zon")) continue;
        const rel = b.allocator.print("src/{s}", .{entry.path}) catch @panic("The component scan is out of memory.");
        list.append(b.allocator, rel) catch @panic("The component scan is out of memory.");
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
    header_dir: std.Build.LazyPath,
    catalog: std.Build.LazyPath,
    module_map: std.Build.LazyPath,
    framework_module_map: std.Build.LazyPath,
};

pub const HostLibraries = struct {
    static_library: *std.Build.Step.Compile,
    dynamic_library: *std.Build.Step.Compile,
};

pub const Context = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    version: std.SemanticVersion,
    generated: Generated,
    host: HostLibraries,
    refs: ?cmd.Refs = null,
    archives: ?[]const ProviderArchives = null,
    portable: bool = false,
    options: *std.Build.Module,
    sanitize_c: ?std.zig.SanitizeC = null,
    dist_providers: []const DistProvider = &.{},
};

pub const DistProvider = struct {
    name: []const u8,
    options: *std.Build.Module,
    host: HostLibraries,
};

pub const ProviderArchives = struct {
    name: []const u8,
    host: std.Build.LazyPath,
    android: std.Build.LazyPath,
    apple: std.Build.LazyPath,
    cjpm: std.Build.LazyPath,
};

pub fn addLibrary(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    linkage: std.builtin.LinkMode,
    ctx: *const Context,
) *std.Build.Step.Compile {
    return addLibraryFromModule(b, rootModule(b, target, optimize, ctx), linkage);
}

pub fn rootModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, ctx: *const Context) *std.Build.Module {
    const module = modules.createFor(b, modules.library, target, optimize, ctx);
    // Discovery needs the generated table plus the interface import.
    const modules_pair = modules.componentsWithInterface(b, ctx, target, target, optimize);
    module.addImport("components", modules_pair.components);
    module.addImport("interface", modules_pair.interface);
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
    // The catalog comes from the same comptime source that the discovery call serves.
    // The scan path reads only options and portable; version, generated, and host go unread.
    var scan_ctx = Context{
        .target = b.graph.host,
        .optimize = .Debug,
        .version = undefined,
        .generated = undefined,
        .host = undefined,
        .options = b.addOptions().createModule(),
    };
    const modules_pair = modules.componentsWithInterface(b, &scan_ctx, b.graph.host, b.graph.host, .Debug);
    const components_module = modules_pair.components;
    const interface_module = modules_pair.interface;
    const gen_module = b.createModule(.{
        .root_source_file = b.path("src/catalog_gen.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    gen_module.addImport("components", components_module);
    gen_module.addImport("interface", interface_module);
    const gen_exe = b.addExecutable(.{ .name = "catalog_gen", .root_module = gen_module });
    const gen_run = b.addRunArtifact(gen_exe);
    return .{
        .step = &files.step,
        .header = files.add("stdk.h", render.header),
        .header_dir = files.getDirectory(),
        .catalog = gen_run.addOutputFileArg("stdk.catalog.json"),
        .module_map = files.add("module.modulemap", render.module_map),
        .framework_module_map = files.add("module.framework.modulemap", render.framework_module_map),
    };
}

pub fn addHostLibraries(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    portable: bool,
    options: *std.Build.Module,
) HostLibraries {
    return addHostLibrariesWithOptions(b, target, optimize, portable, options, null);
}

pub fn addHostLibrariesWithOptions(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    portable: bool,
    options: *std.Build.Module,
    sanitize_c: ?std.zig.SanitizeC,
) HostLibraries {
    // Module construction reads only portable; version, generated, and host go unread.
    var ctx = Context{
        .target = target,
        .optimize = optimize,
        .version = undefined,
        .generated = undefined,
        .host = undefined,
        .portable = portable,
        .options = options,
        .sanitize_c = sanitize_c,
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

pub fn addZipArchive(b: *std.Build, distribution: manifest.Distribution, stage: *std.Build.Step.WriteFile) std.Build.LazyPath {
    const zip = b.addSystemCommand(&.{ "zip", "-qry" });
    const archive = zip.addOutputFileArg(distribution.archive);
    zip.addArg(archiveRoot(distribution));
    zip.setCwd(stage.getDirectory());
    return archive;
}

fn archiveRoot(distribution: manifest.Distribution) []const u8 {
    const entries = distribution.entries;
    const first = entries[0];
    const slash = std.mem.indexOfScalar(u8, first, '/') orelse return ".";
    const prefix = first[0 .. slash + 1];
    for (entries[1..]) |entry| {
        if (!std.mem.startsWith(u8, entry, prefix)) return ".";
    }
    return prefix[0 .. prefix.len - 1];
}
