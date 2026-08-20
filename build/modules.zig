const std = @import("std");

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

pub const checksum = Module{ .name = "checksum", .root = "src/common/primitive/checksum.zig", .crc_kernel = true };
pub const crypto = Module{ .name = "crypto", .root = "src/common/primitive/crypto.zig" };
pub const registry = Module{ .name = "registry", .root = "src/registry.zig" };
pub const library = Module{ .name = "library", .root = "src/root.zig", .crc_kernel = true };
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
pub const benchmark = Module{
    .name = "benchmark",
    .root = "build/acceptance/benchmark/benchmark.zig",
    .imports = &.{
        .{ .name = "harness", .module = "harness" },
        .{ .name = "run", .module = "run" },
    },
};

const importable = [_]Module{ checksum, crypto, registry, library, manifest, harness, run };

fn byName(name: []const u8) Module {
    for (importable) |module| {
        if (std.mem.eql(u8, module.name, name)) return module;
    }
    @compileError("unknown module: " ++ name);
}

const common = @import("platform/common.zig");

pub fn create(b: *std.Build, comptime spec: Module, ctx: *const common.Context) *std.Build.Module {
    return createFor(b, spec, b.graph.host, .Debug, ctx);
}

pub fn createFor(
    b: *std.Build,
    comptime spec: Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    ctx: *const common.Context,
) *std.Build.Module {
    var adjusted = target;
    if (!ctx.force_fallback and spec.crc_kernel and adjusted.result.cpu.arch == .aarch64) {
        const feature = @intFromEnum(std.Target.aarch64.Feature.crc);
        adjusted.query.cpu_features_add.addFeature(feature);
        adjusted.result.cpu.features.addFeature(feature);
    }
    const module = b.createModule(.{
        .root_source_file = b.path(spec.root),
        .target = adjusted,
        .optimize = optimize,
    });
    if (!ctx.force_fallback and spec.crc_kernel and target.result.cpu.arch == .aarch64) {
        module.addAssemblyFile(b.path("src/common/primitive/checksum/aarch64.S"));
    }
    module.addImport("options", ctx.options);
    inline for (spec.imports) |import| {
        module.addImport(import.name, createFor(b, byName(import.module), target, optimize, ctx));
    }
    return module;
}
