const std = @import("std");

const package = @import("build.zig.zon");

const units = @import("build/units.zig");
const common = @import("build/platform/common.zig");
const modules = @import("build/modules.zig");

const version = std.SemanticVersion.parse(package.version) catch @compileError("version must be semantic");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const portable = b.option(bool, "portable", "Disable arch-gated kernels and use portable fallbacks") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "portable", portable);
    const options_module = options.createModule();
    const generated = common.addGenerated(b);
    const host = common.addHostLibraries(b, target, optimize, portable, options_module);
    var ctx = common.Context{
        .target = target,
        .optimize = optimize,
        .version = version,
        .generated = generated,
        .host = host,
        .portable = portable,
        .options = options_module,
    };
    units.expand(b, &ctx);
    _ = units.addListingStep(b);

    // Unit-level test blocks: fast in-process invariants at the substrate
    // and primitive layer. System-level interop and contract pins stay in
    // the oracle suite.
    const unit_step = b.step("unit", "Run unit-level test blocks");
    inline for (&.{ modules.nucleus, modules.checksum }) |spec| {
        const test_module = modules.createFor(b, spec, ctx.target, ctx.optimize, &ctx);
        const unit_tests = b.addTest(.{ .root_module = test_module });
        const run_unit = b.addRunArtifact(unit_tests);
        unit_step.dependOn(&run_unit.step);
    }
}
