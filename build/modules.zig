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
pub const kernels = Module{ .name = "kernels", .root = "src/common/kernels.zig" };

pub const library = Module{ .name = "library", .root = "src/root.zig", .imports = &.{.{ .name = "seam", .module = "seam" }}, .crc_kernel = true };
// Package-manager entry: the same import closure as the
// library module, rooted at the package door instead of the boundary file.
pub const package_entry = Module{ .name = "libstd", .root = "main.zig", .imports = &.{.{ .name = "seam", .module = "seam" }}, .crc_kernel = true };
pub const manifest = Module{ .name = "manifest", .root = "build/platform/manifest.zig" };
pub const package_check = Module{
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
pub const implementations = Module{ .name = "implementations", .root = "src/impls.zig", .imports = &.{.{ .name = "seam", .module = "seam" }}, .crc_kernel = true };
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
pub const micro = Module{
    .name = "micro",
    .root = "build/micro/main.zig",
    .imports = &.{
        .{ .name = "checksum", .module = "checksum" },
        .{ .name = "crypto", .module = "crypto" },
        .{ .name = "kernels", .module = "kernels" },
    },
};

const importable = [_]Module{ seam, checksum, crypto, kernels, library, manifest, package_check, abi_exports, harness, run, oracles, interface, implementations, trap, component, benchmark, micro };

fn moduleForName(name: []const u8) Module {
    for (importable) |module| {
        if (std.mem.eql(u8, module.name, name)) return module;
    }
    @compileError("unknown module: " ++ name ++ ".");
}

pub fn create(b: *std.Build, comptime module_spec: Module, ctx: *const common.Settings) *std.Build.Module {
    return createFor(b, module_spec, b.graph.host, .debug, ctx);
}

pub const Components = struct {
    interface: *std.Build.Module,
    components: *std.Build.Module,
};

pub fn componentsWithInterface(
    b: *std.Build,
    ctx: *const common.Settings,
    components_target: std.Build.ResolvedTarget,
    interface_target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
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

pub fn withKernelFeatures(target: std.Build.ResolvedTarget, kernel_isa: common.KernelIsa) std.Build.ResolvedTarget {
    if (kernel_isa == .detected) return target;
    var adjusted = target;
    const arch = adjusted.result.cpu.arch;
    const aarch64_features = [_]std.Target.aarch64.Feature{ .crc, .crypto };
    const x86_features = [_]std.Target.x86.Feature{ .sha, .avx2, .aes };
    if (arch == .aarch64) for (aarch64_features) |feature| {
        const bit = @backingInt(feature);
        adjusted.query.cpu_features_add.addFeature(bit);
        adjusted.result.cpu.features.addFeature(bit);
    };
    if (arch == .x86_64) for (x86_features) |feature| {
        const bit = @backingInt(feature);
        adjusted.query.cpu_features_add.addFeature(bit);
        adjusted.result.cpu.features.addFeature(bit);
    };
    // 'extended' builds hard-require SHA-NI, AVX2, and AES-NI on x86_64 and
    // crc+crypto on aarch64 at runtime; 'detected' keeps whatever the
    // resolved target already carries.
    return adjusted;
}

pub fn createFor(
    b: *std.Build,
    comptime module_spec: Module,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    ctx: *const common.Settings,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(module_spec.root),
        .target = kernelAdjustedTarget(module_spec, target, ctx.portable, ctx.kernel_isa),
        .optimize = optimize,
    });
    if (ctx.sanitize_c) |sanitize| module.sanitize_c = sanitize;
    module.addImport("options", ctx.options);
    inline for (module_spec.imports) |import| {
        module.addImport(import.name, createShared(b, moduleForName(import.module), target, optimize, ctx));
    }
    return module;
}

// crc_kernel specs ask for the hardware feature set the optimized paths need.
// Portable builds stay on the unadjusted target with software arms only.
pub fn kernelAdjustedTarget(comptime module_spec: Module, target: std.Build.ResolvedTarget, portable: bool, kernel_isa: common.KernelIsa) std.Build.ResolvedTarget {
    if (!portable and kernel_isa == .extended and module_spec.crc_kernel and (target.result.cpu.arch == .aarch64 or target.result.cpu.arch == .x86_64)) {
        return withKernelFeatures(target, kernel_isa);
    }
    return target;
}

// Imported modules stay single instances per (name, target, optimize).
// The compiler rejects a file rooted in two instances of one module.
var shared_modules: ?std.StringHashMap(*std.Build.Module) = null;

pub fn createShared(
    b: *std.Build,
    comptime module_spec: Module,
    target: std.Build.ResolvedTarget,
    optimize: std.lang.Optimize,
    ctx: *const common.Settings,
) *std.Build.Module {
    if (shared_modules == null) shared_modules = std.StringHashMap(*std.Build.Module).init(b.allocator);
    const key = b.allocator.print("{s}|{s}|{s}|{d}", .{
        module_spec.name,
        target.result.zigTriple(b.allocator) catch @panic("the shared module key cannot allocate the target triple."),
        @tagName(optimize),
        @intFromPtr(ctx.options),
    }) catch @panic("the shared module key is out of memory.");
    if (shared_modules.?.get(key)) |module| return module;
    const module = createFor(b, module_spec, target, optimize, ctx);
    shared_modules.?.put(key, module) catch @panic("the shared module registry is out of memory.");
    return module;
}
