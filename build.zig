const std = @import("std");

const package = @import("build.zig.zon");

const modules = @import("build/modules.zig");
const common = @import("build/platform/common.zig");
const units = @import("build/units.zig");

const Implementation = common.Implementation;
const capabilities = common.capabilities;

const version = std.SemanticVersion.parse(package.version) catch @compileError("version must be semantic");

fn rejectOffpremPortable(comptime subject: []const u8, comptime flag: []const u8) void {
    std.debug.print("invalid configuration: " ++ subject ++ " is offprem while " ++ flag ++ " is set.\n", .{});
    std.process.exit(1);
}

pub fn build(b: *std.Build) void {
    const dist_sha = b.graph.environ_map.get("STDK_GIT_SHA") orelse blk: {
        const result = std.process.run(b.allocator, b.graph.io, .{ .argv = &.{ "git", "rev-parse", "--short=8", "HEAD" } }) catch break :blk "nogit";
        if (result.term == .exited and result.term.exited == 0) break :blk std.mem.trim(u8, result.stdout, "\n");
        break :blk "nogit";
    };
    const target = blk: {
        var resolved = b.standardTargetOptions(.{});
        // Rosetta CPUID reports SHA-NI but the instructions fault; strip
        // 'sha' so std's Sha256 skips its SHA-NI arm.
        if (resolved.query.isNative() and resolved.result.cpu.arch == .x86_64 and resolved.result.os.tag == .macos) {
            const sha_bit = @backingInt(std.Target.x86.Feature.sha);
            resolved.query.cpu_features_sub.addFeature(sha_bit);
            resolved.result.cpu.features.removeFeature(sha_bit);
        }
        break :blk resolved;
    };
    const optimize = b.standardOptimizeOption(.{});
    const portable = b.option(bool, "portable", "Compatible implementation for primitive seam") orelse false;
    const kernel_isa = b.option(common.KernelIsa, "kernel_isa", "Hardware ISA the crc kernels may assume; 'extended' hard-requires sha/avx2/aes on x86_64 and crc/crypto on aarch64 at runtime") orelse .detected;
    const primitives_impl = b.option(Implementation, "primitives_impl", "Default implementation for primitive seam") orelse .onprem;
    const options = b.addOptions();
    options.addOption(bool, "portable", portable);
    options.addOption(Implementation, "primitives_impl", primitives_impl);
    inline for (capabilities) |capability| {
        const selected = b.option(Implementation, capability ++ "_impl", "Implementation for the " ++ capability ++ " capability") orelse primitives_impl;
        const capability_portable = b.option(bool, capability ++ "_portable", "Portable-only paths for the " ++ capability ++ " capability") orelse portable;
        common.putCapability(options, capability, selected, capability_portable);
        if (selected == .offprem and capability_portable) rejectOffpremPortable(capability ++ " capability", capability ++ "_portable");
    }
    const leaf_impl = b.option(Implementation, "leaf_impl", "Implementation for the leaf codec layer") orelse primitives_impl;
    const grammar_impl = b.option(Implementation, "grammar_impl", "Implementation for the grammar container layer") orelse primitives_impl;
    options.addOption(Implementation, "leaf_impl", leaf_impl);
    options.addOption(Implementation, "grammar_impl", grammar_impl);
    if (leaf_impl == .offprem and portable) rejectOffpremPortable("leaf layer", "portable");
    if (grammar_impl == .offprem and portable) rejectOffpremPortable("grammar layer", "portable");
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
        .kernel_isa = kernel_isa,
        .options = options_module,
        .dist_providers = &dist_providers,
        .dist_tag = b.fmt("{d}.{d}.{d}-{s}", .{ version.major, version.minor, version.patch, dist_sha }),
    };
    // Exposes the boundary to package-manager consumers.
    // Stays inert here because nothing imports it.
    const package_module = b.addModule("libstd", .{
        .root_source_file = b.path("main.zig"),
        .target = modules.kernelAdjustedTarget(modules.package_entry, target, portable, kernel_isa),
        .optimize = optimize,
    });
    common.attachPackageImports(b, package_module, target, optimize, &ctx);
    units.expand(b, &ctx);
    _ = units.addListingStep(b);

    // Unit blocks pin in-process invariants; system pins stay in oracles.
    // Zig 0.17 test filters are inert; selection is per binary.
    const test_filter = b.option([]const u8, "test_filter", "Only run unit test binaries whose module name contains the substring");
    const unit_step = b.step("unit", "Run unit-level test blocks");
    inline for ([_]modules.Module{ modules.interface, modules.checksum, modules.implementations }) |spec| {
        const selected = test_filter == null or std.mem.find(u8, spec.name, test_filter.?) != null;
        if (selected) {
            const test_module = modules.createFor(b, spec, ctx.target, ctx.optimize, &ctx);
            const unit_tests = b.addTest(.{ .root_module = test_module });
            const run_unit = b.addRunArtifact(unit_tests);
            unit_step.dependOn(&run_unit.step);
        }
    }
    // Runner invariants ride the unit step with library blocks.
    if (test_filter == null or std.mem.find(u8, modules.micro.name, test_filter.?) != null) {
        const micro_tests = b.addTest(.{ .root_module = modules.createFor(b, modules.micro, ctx.target, .debug, &ctx) });
        unit_step.dependOn(&b.addRunArtifact(micro_tests).step);
    }
    {
        const dudect_module = b.createModule(.{
            .root_source_file = b.path("src/dudect.zig"),
            .target = modules.kernelAdjustedTarget(modules.package_entry, ctx.target, portable, ctx.kernel_isa),
            .optimize = optimize,
        });
        dudect_module.addImport("options", ctx.options);
        dudect_module.addImport("seam", modules.createShared(b, modules.seam, ctx.target, optimize, &ctx));
        const dudect_exe = b.addExecutable(.{ .name = "dudect", .root_module = dudect_module });
        const dudect_step = b.step("dudect", "Run the constant-time timing evidence session");
        dudect_step.dependOn(&b.addRunArtifact(dudect_exe).step);
    }
    {
        const analyze_module = b.createModule(.{
            .root_source_file = b.path("src/analysis.zig"),
            .target = modules.kernelAdjustedTarget(modules.package_entry, ctx.target, ctx.portable, ctx.kernel_isa),
            .optimize = optimize,
        });
        common.attachPackageImports(b, analyze_module, ctx.target, optimize, &ctx);
        const analyze_exe = b.addExecutable(.{ .name = "analyze", .root_module = analyze_module });
        b.step("analyze", "Compile-check the audit-touched modules").dependOn(&b.addRunArtifact(analyze_exe).step);
    }
    // Package consumers see only the libstd module; the acceptance test
    // proves real operations run through that one import.
    if (test_filter == null or std.mem.find(u8, "consumer", test_filter.?) != null) {
        const consumer_module = b.createModule(.{
            .root_source_file = b.path("build/acceptance/consumer.zig"),
            .target = modules.kernelAdjustedTarget(modules.package_entry, target, portable, kernel_isa),
            .optimize = optimize,
        });
        consumer_module.addImport("libstd", package_module);
        const consumer_tests = b.addTest(.{ .root_module = consumer_module });
        unit_step.dependOn(&b.addRunArtifact(consumer_tests).step);
    }

    // The module roots at src/fuzz.zig so cross-directory imports stay
    // legal; the step is a smoke gate, not a campaign.
    const fuzz_module = modules.createFor(b, modules.fuzz, ctx.target, ctx.optimize, &ctx);
    const fuzz_tests = b.addTest(.{ .root_module = fuzz_module });
    const fuzz_step = b.step("fuzz", "Build the decode-surface fuzz harness and run its non-campaign pass");
    fuzz_step.dependOn(&b.addRunArtifact(fuzz_tests).step);

    // Campaigns are evidence sessions with an operator-set budget; keeping
    // them out of `unit` stops an unbudgeted run from reading as a pass.
    const campaign_module = modules.createFor(b, modules.fuzz_campaign, ctx.target, ctx.optimize, &ctx);
    const campaign_exe = b.addExecutable(.{ .name = "campaign", .root_module = campaign_module });
    const run_campaign = b.addRunArtifact(campaign_exe);
    run_campaign.addPassthruArgs();
    b.step("campaign", "Run mutation campaigns (--iterations N, --format name)").dependOn(&run_campaign.step);

    // Debug numbers carry no evidence, so micro defaults to fast.
    const micro_optimize = b.option(std.lang.Optimize, "micro_optimize", "Optimization mode for zig build micro") orelse .fast;
    const micro_module = modules.createFor(b, modules.micro, ctx.target, micro_optimize, &ctx);
    const micro_exe = b.addExecutable(.{ .name = "micro", .root_module = micro_module });
    const run_micro = b.addRunArtifact(micro_exe);
    run_micro.addPassthruArgs();
    b.step("micro", "Run micro benchmarks (time budget, p75/p99, allocation counts)").dependOn(&run_micro.step);
}
