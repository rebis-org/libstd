const std = @import("std");

const package = @import("build.zig.zon");

const units = @import("build/units.zig");
const common = @import("build/platform/common.zig");

const version = std.SemanticVersion.parse(package.version) catch @compileError("version must be semantic");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const force_fallback = b.option(bool, "force_fallback", "Disable arch-gated kernels and use portable fallbacks") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "force_fallback", force_fallback);
    const options_module = options.createModule();
    const generated = common.addGenerated(b);
    const host = common.addHostLibraries(b, target, optimize, force_fallback, options_module);
    var ctx = common.Context{
        .target = target,
        .optimize = optimize,
        .version = version,
        .generated = generated,
        .host = host,
        .force_fallback = force_fallback,
        .options = options_module,
    };
    units.expand(b, &ctx);
    _ = units.addListingStep(b);
}
