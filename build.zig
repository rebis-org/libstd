const std = @import("std");

const package = @import("build.zig.zon");

const units = @import("build/units.zig");
const common = @import("build/platform/common.zig");
const modules = @import("build/modules.zig");

const version = std.SemanticVersion.parse(package.version) catch @compileError("version must be semantic");

const Implementation = enum { onprem, offprem, mergeable };
const capabilities = .{ "sha256", "sha1", "hmac", "pbkdf2", "adler32", "xxh32", "xxh64", "aes", "crc32", "crc64xz", "bzip2crc32" };

fn putCapability(options: *std.Build.Step.Options, comptime capability: []const u8, selected: Implementation, portable_flag: bool) void {
    options.addOption(Implementation, capability ++ "_impl", selected);
    options.addOption(bool, capability ++ "_portable", portable_flag);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const portable = b.option(bool, "portable", "Compatible implementation for primitive seam") orelse false;
    const primitives_impl = b.option(Implementation, "primitives_impl", "Default implementation for primitive seam") orelse .onprem;
    const options = b.addOptions();
    options.addOption(bool, "portable", portable);
    options.addOption(Implementation, "primitives_impl", primitives_impl);
    inline for (capabilities) |capability| {
        const selected = b.option(Implementation, capability ++ "_impl", "Implementation for the " ++ capability ++ " capability") orelse primitives_impl;
        const capability_portable = b.option(bool, capability ++ "_portable", "Portable-only paths for the " ++ capability ++ " capability") orelse portable;
        putCapability(options, capability, selected, capability_portable);
        if (selected == .offprem and capability_portable) {
            std.debug.print("invalid configuration: the " ++ capability ++ " capability is offprem while its portable flag is set; portable governs onprem paths only. use -D" ++ capability ++ "_portable=false or an onprem or mergeable provider.\n", .{});
            std.process.exit(1);
        }
    }
    const options_module = options.createModule();
    var dist_providers: [3]common.DistProvider = undefined;
    inline for ([_]Implementation{ .onprem, .offprem, .mergeable }, 0..) |impl, index| {
        const provider_options = b.addOptions();
        provider_options.addOption(bool, "portable", false);
        provider_options.addOption(Implementation, "primitives_impl", impl);
        inline for (capabilities) |capability| {
            putCapability(provider_options, capability, impl, false);
        }
        const provider_options_module = provider_options.createModule();
        dist_providers[index] = .{
            .name = @tagName(impl),
            .options = provider_options_module,
            .host = common.addHostLibrariesWithOptions(b, target, optimize, false, provider_options_module, null),
        };
    }
    const generated = common.addGenerated(b);
    const host = common.addHostLibraries(b, target, optimize, portable, options_module);
    var ctx = common.Settings{
        .target = target,
        .optimize = optimize,
        .version = version,
        .generated = generated,
        .host = host,
        .portable = portable,
        .options = options_module,
        .dist_providers = &dist_providers,
    };
    // Package-manager exposure for Zig consumers:
    // b.dependency("libstd", .{}).module("libstd") compiles the boundary and
    // the bypass facade with the selected provider options; in this build
    // the module stays inert because nothing imports it.
    const package_module = b.addModule("libstd", .{
        .root_source_file = b.path("main.zig"),
        .target = modules.kernelAdjustedTarget(modules.pkg, target, portable),
        .optimize = optimize,
    });
    common.attachPackageImports(b, package_module, target, optimize, &ctx);
    units.expand(b, &ctx);
    _ = units.addListingStep(b);

    // Unit-level test blocks: fast in-process invariants at the substrate
    // and primitive layer. System-level interop and contract pins stay in
    // the oracle suite.
    const unit_step = b.step("unit", "Run unit-level test blocks");
    inline for (&.{ modules.interface, modules.checksum, modules.grammar }) |spec| {
        const test_module = modules.createFor(b, spec, ctx.target, ctx.optimize, &ctx);
        const unit_tests = b.addTest(.{ .root_module = test_module });
        const run_unit = b.addRunArtifact(unit_tests);
        unit_step.dependOn(&run_unit.step);
    }
}
