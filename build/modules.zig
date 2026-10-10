const std = @import("std");

const common = @import("platform/common.zig");

pub const Import = struct {
    name: []const u8,
    module: []const u8,
};

pub const Module = struct {
    name: []const u8,
    root: []const u8,
    imports: []const Import = &.{},
    crc_kernel: bool = false,
};

pub const seam = Module{ .name = "seam", .root = "src/common/primitive/seam.zig" };
pub const checksum = Module{ .name = "checksum", .root = "src/common/primitive/checksum.zig", .imports = &.{.{ .name = "seam", .module = "seam" }}, .crc_kernel = true };
pub const crypto = Module{ .name = "crypto", .root = "src/common/primitive/crypto.zig", .imports = &.{.{ .name = "seam", .module = "seam" }} };

pub const library = Module{ .name = "library", .root = "src/root.zig", .imports = &.{.{ .name = "seam", .module = "seam" }}, .crc_kernel = true };
pub const manifest = Module{ .name = "manifest", .root = "build/platform/manifest.zig" };
pub const package = Module{
    .name = "package",
    .root = "build/acceptance/package.zig",
    .imports = &.{
        .{ .name = "manifest", .module = "manifest" },
    },
};
pub const abi_exports = Module{ .name = "abi_exports", .root = "build/acceptance/abi.zig" };
pub const harness = Module{ .name = "harness", .root = "build/acceptance/oracles/harness.zig" };
pub const run = Module{ .name = "run", .root = "build/acceptance/run.zig" };
pub const oracles = Module{
    .name = "oracles",
    .root = "build/acceptance/oracles/oracles.zig",
    .imports = &.{
        .{ .name = "checksum", .module = "checksum" },
        .{ .name = "crypto", .module = "crypto" },
    },
};
pub const interface = Module{ .name = "interface", .root = "src/interface/root.zig" };
pub const grammar = Module{ .name = "grammar", .root = "src/grammar.zig", .imports = &.{.{ .name = "seam", .module = "seam" }}, .crc_kernel = true };
pub const trap = Module{
    .name = "trap",
    .root = "build/acceptance/oracles/trap.zig",
    .imports = &.{
        .{ .name = "interface", .module = "interface" },
    },
};
pub const component = Module{ .name = "component", .root = "build/component.zig" };
pub const benchmark = Module{
    .name = "benchmark",
    .root = "build/acceptance/benchmark/benchmark.zig",
    .imports = &.{
        .{ .name = "harness", .module = "harness" },
        .{ .name = "run", .module = "run" },
    },
};

const importable = [_]Module{ seam, checksum, crypto, library, manifest, harness, run, interface, grammar, trap, component };

fn byName(name: []const u8) Module {
    for (importable) |module| {
        if (std.mem.eql(u8, module.name, name)) return module;
    }
    @compileError("unknown module: " ++ name ++ ".");
}

pub fn create(b: *std.Build, comptime spec: Module, ctx: *const common.Context) *std.Build.Module {
    return createFor(b, spec, b.graph.host, .Debug, ctx);
}

pub const Components = struct {
    interface: *std.Build.Module,
    components: *std.Build.Module,
};

pub fn componentsWithInterface(
    b: *std.Build,
    ctx: *const common.Context,
    components_target: std.Build.ResolvedTarget,
    interface_target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
) Components {
    const generated = common.descriptorScan(b, ctx);
    const interface_module = createFor(b, interface, interface_target, optimize, ctx);
    const components_module = b.createModule(.{
        .root_source_file = generated,
        .target = components_target,
        .optimize = optimize,
    });
    if (ctx.sanitize_c) |sc| components_module.sanitize_c = sc;
    components_module.addImport("interface", interface_module);
    return .{ .interface = interface_module, .components = components_module };
}

pub fn withKernelFeatures(target: std.Build.ResolvedTarget) std.Build.ResolvedTarget {
    var adjusted = target;
    if (adjusted.result.cpu.arch == .aarch64) {
        const crc_feature = @backingInt(std.Target.aarch64.Feature.crc);
        adjusted.query.cpu_features_add.addFeature(crc_feature);
        adjusted.result.cpu.features.addFeature(crc_feature);
        const crypto_feature = @backingInt(std.Target.aarch64.Feature.crypto);
        adjusted.query.cpu_features_add.addFeature(crypto_feature);
        adjusted.result.cpu.features.addFeature(crypto_feature);
        // The crypto feature implies aes (std.Target.aarch64), and LLVM's aes implies
        // pmull, which the CRC32 fold kernel multiplies with.
    }
    return adjusted;
}

pub fn createFor(
    b: *std.Build,
    comptime spec: Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    ctx: *const common.Context,
) *std.Build.Module {
    var adjusted = target;
    if (!ctx.portable and spec.crc_kernel and adjusted.result.cpu.arch == .aarch64) {
        adjusted = withKernelFeatures(adjusted);
    }
    const module = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = adjusted,
        .optimize = optimize,
    });
    if (ctx.sanitize_c) |sc| module.sanitize_c = sc;
    module.addImport("options", ctx.options);
    inline for (spec.imports) |import| {
        module.addImport(import.name, createShared(b, byName(import.module), target, optimize, ctx));
    }
    return module;
}

// Imported modules must be single instances per (name, target, optimize): the
// compiler rejects a file rooted in two instances of one module.
var shared_modules: ?std.StringHashMap(*std.Build.Module) = null;

fn createShared(
    b: *std.Build,
    comptime spec: Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    ctx: *const common.Context,
) *std.Build.Module {
    if (shared_modules == null) shared_modules = std.StringHashMap(*std.Build.Module).init(b.allocator);
    const key = std.fmt.allocPrint(b.allocator, "{s}|{s}|{s}|{d}", .{
        spec.name,
        target.result.zigTriple(b.allocator) catch @panic("The shared module key cannot allocate the target triple."),
        @tagName(optimize),
        @intFromPtr(ctx.options),
    }) catch @panic("The shared module key is out of memory.");
    if (shared_modules.?.get(key)) |module| return module;
    const module = createFor(b, spec, target, optimize, ctx);
    shared_modules.?.put(key, module) catch @panic("The shared module registry is out of memory.");
    return module;
}
