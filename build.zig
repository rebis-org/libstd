const std = @import("std");

const package = @import("build.zig.zon");

const modules = @import("build/modules.zig");
const common = @import("build/platform/common.zig");
const units = @import("build/units.zig");

const Implementation = common.Implementation;
const capabilities = common.capabilities;

const version = std.SemanticVersion.parse(package.version) catch @compileError("version must be semantic");

fn putCapability(options: *std.Build.Step.Options, comptime capability: []const u8, selected: Implementation, portable_flag: bool) void {
    common.putCapability(options, capability, selected, portable_flag);
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
    const leaf_impl = b.option(Implementation, "leaf_impl", "Implementation for the leaf codec layer") orelse primitives_impl;
    const grammar_impl = b.option(Implementation, "grammar_impl", "Implementation for the grammar container layer") orelse primitives_impl;
    options.addOption(Implementation, "leaf_impl", leaf_impl);
    options.addOption(Implementation, "grammar_impl", grammar_impl);
    if (leaf_impl == .offprem and portable) {
        std.debug.print("invalid configuration: the leaf layer is offprem while the portable flag is set; portable governs onprem paths only. use -Dportable=false or an onprem or mergeable provider.\n", .{});
        std.process.exit(1);
    }
    if (grammar_impl == .offprem and portable) {
        std.debug.print("invalid configuration: the grammar layer is offprem while the portable flag is set; portable governs onprem paths only. use -Dportable=false or an onprem or mergeable provider.\n", .{});
        std.process.exit(1);
    }
    const options_module = options.createModule();
    var dist_providers: [3]common.DistProvider = undefined;
    inline for ([_]Implementation{ .onprem, .offprem, .mergeable }, 0..) |impl, index| {
        const provider_options = b.addOptions();
        common.putUniformOptions(provider_options, impl, false);
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
    inline for (&.{ modules.interface, modules.checksum, modules.implementations }) |spec| {
        const test_module = modules.createFor(b, spec, ctx.target, ctx.optimize, &ctx);
        const unit_tests = b.addTest(.{ .root_module = test_module });
        const run_unit = b.addRunArtifact(unit_tests);
        unit_step.dependOn(&run_unit.step);
    }
    // The micro runner's own invariants (calibration clamp, percentile rank,
    // allocation counting) ride the unit step next to the library blocks.
    const micro_tests = b.addTest(.{ .root_module = modules.createFor(b, modules.micro, ctx.target, .debug, &ctx) });
    unit_step.dependOn(&b.addRunArtifact(micro_tests).step);

    // Leaf-level micro benchmarks through the time-budgeted runner in
    // build/micro. Defaults to fast because debug numbers carry no evidence.
    const micro_optimize = b.option(std.lang.Optimize, "micro_optimize", "Optimization mode for zig build micro") orelse .fast;
    const micro_module = modules.createFor(b, modules.micro, ctx.target, micro_optimize, &ctx);
    const micro_exe = b.addExecutable(.{ .name = "micro", .root_module = micro_module });
    const run_micro = b.addRunArtifact(micro_exe);
    run_micro.addPassthruArgs();
    b.step("micro", "Run leaf-level micro benchmarks (time budget, p75/p99, allocation counts)").dependOn(&run_micro.step);
}
