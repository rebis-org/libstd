const std = @import("std");

const cmd = @import("acceptance/benchmark/command.zig");
const sevenzip = @import("acceptance/benchmark/ref/sevenzip.zig");
const modules = @import("modules.zig");
const common = @import("platform/common.zig");

pub const Unit = struct {
    name: []const u8,
    kind: Kind,
};

pub const Kind = enum { oracles, benchmark };

pub const units = [_]Unit{
    .{ .name = "oracles", .kind = .oracles },
    .{ .name = "benchmark", .kind = .benchmark },
};

pub fn expand(b: *std.Build, ctx: *common.Context) void {
    const refs = ctx.refs orelse @panic("vendor units must expand before acceptance units");
    inline for (units) |unit| switch (unit.kind) {
        .oracles => addOracles(b, ctx),
        .benchmark => addBenchmark(b, ctx, refs),
    };
}

const AcceptanceApp = struct {
    exe: *std.Build.Step.Compile,
    run: *std.Build.Step.Run,
};

fn addAcceptanceApp(
    b: *std.Build,
    ctx: *common.Context,
    name: []const u8,
    comptime spec: modules.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    extra_imports: []const std.Build.Module.Import,
    host: common.HostLibraries,
    step_name: []const u8,
    step_description: []const u8,
) AcceptanceApp {
    const module = modules.createFor(b, spec, target, optimize, ctx);
    for (extra_imports) |import| module.addImport(import.name, import.module);
    const exe = b.addExecutable(.{ .name = name, .root_module = module });
    exe.root_module.linkLibrary(host.dynamic_library);
    const run = b.addRunArtifact(exe);
    b.step(step_name, step_description).dependOn(&run.step);
    return .{ .exe = exe, .run = run };
}

fn addOracles(b: *std.Build, ctx: *common.Context) void {
    const c_module = blk: {
        const translate_c = b.addTranslateC(.{
            .root_source_file = b.path("build/acceptance/oracles/c/c.h"),
            .target = ctx.target,
            .optimize = ctx.optimize,
        });
        break :blk translate_c.createModule();
    };

    const ab_variant_baseline = b.addOptions();
    ab_variant_baseline.addOption([]const u8, "name", "baseline");
    const ab_variant_baseline_module = ab_variant_baseline.createModule();

    const app = addAcceptanceApp(b, ctx, "oracles", modules.oracles, ctx.target, ctx.optimize, &.{
        .{ .name = "c", .module = c_module },
        .{ .name = "ab_variant", .module = ab_variant_baseline_module },
    }, ctx.host, "oracles", "Run the oracle suite against the system libraries");
    app.exe.root_module.linkSystemLibrary("z", .{});
    app.exe.root_module.linkSystemLibrary("lzma", .{});
    app.exe.root_module.linkSystemLibrary("bz2", .{});
    app.exe.root_module.linkSystemLibrary("archive", .{});
    app.exe.root_module.addObjectFile(ctx.refs.?.zstd_lib);
    app.run.addFileArg(ctx.generated.catalog);

    const skip_options = b.addOptions();
    skip_options.addOption(bool, "force_fallback", ctx.force_fallback);
    const skip_options_module = skip_options.createModule();
    const skip_host = common.addHostLibrariesWithOptions(b, ctx.target, ctx.optimize, ctx.force_fallback, skip_options_module);

    const ab_variant_skip = b.addOptions();
    ab_variant_skip.addOption([]const u8, "name", "skip");
    const ab_variant_skip_module = ab_variant_skip.createModule();

    const skip_app = addAcceptanceApp(b, ctx, "oracles_skip", modules.oracles, ctx.target, ctx.optimize, &.{
        .{ .name = "c", .module = c_module },
        .{ .name = "ab_variant", .module = ab_variant_skip_module },
    }, skip_host, "oracles_skip", "Run the oracle suite against the encode A/B variant slot (currently identical to baseline)");
    skip_app.exe.root_module.linkSystemLibrary("z", .{});
    skip_app.exe.root_module.linkSystemLibrary("lzma", .{});
    skip_app.exe.root_module.linkSystemLibrary("bz2", .{});
    skip_app.exe.root_module.linkSystemLibrary("archive", .{});
    skip_app.exe.root_module.addObjectFile(ctx.refs.?.zstd_lib);
    skip_app.run.addFileArg(ctx.generated.catalog);

    const baseline_ab_run = b.addRunArtifact(app.exe);
    baseline_ab_run.addFileArg(ctx.generated.catalog);
    baseline_ab_run.addArg("--suite");
    baseline_ab_run.addArg("lzma_ab");
    baseline_ab_run.step.dependOn(&app.exe.step);

    const skip_ab_run = b.addRunArtifact(skip_app.exe);
    skip_ab_run.addFileArg(ctx.generated.catalog);
    skip_ab_run.addArg("--suite");
    skip_ab_run.addArg("lzma_ab");
    skip_ab_run.step.dependOn(&skip_app.exe.step);

    const diff = b.addSystemCommand(&.{ "diff", "-rq", "zig-out/oracles/ab/baseline", "zig-out/oracles/ab/skip" });
    diff.step.dependOn(&baseline_ab_run.step);
    diff.step.dependOn(&skip_ab_run.step);
    b.step("oracles_ab", "Compare LZMA encode output between baseline and skip-on variants").dependOn(&diff.step);
}

fn addBenchmark(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    const ref_target = common.refTarget(b, ctx.target);
    const app = addAcceptanceApp(b, ctx, "benchmark", modules.benchmark, ref_target, ctx.optimize, &.{}, ctx.host, "benchmark", "Run the Silesia codec benchmark against official implementations and write the report");
    _ = sevenzip.addReference(b, ref_target, ctx.optimize, app.exe);
    refs.link(b, app.exe.root_module);
    app.exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/libzip.c") });
    app.exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/unrar.c") });
    // Expansion runs for every -Dtarget; the SDK path only exists when the
    // benchmark app itself targets Darwin, so look it up only there.
    const macos_sdk_usr_lib: ?[]const u8 = if (ref_target.result.os.tag.isDarwin())
        macosSdkUsrLib(b, ctx) orelse
            @panic("benchmark build needs the macOS SDK: run `xcode-select` to point at an Xcode install")
    else
        null;
    if (macos_sdk_usr_lib) |sdk_usr_lib| app.exe.root_module.addLibraryPath(.{ .cwd_relative = sdk_usr_lib });
    app.exe.root_module.linkSystemLibrary("c++", .{});
    app.exe.root_module.linkSystemLibrary("z", .{});
    app.exe.step.dependOn(&refs.libzip_build.step);
    refs.dependOnTools(&app.run.step);
    refs.dependOnBins(&app.run.step);
    app.run.addFileArg(ctx.generated.catalog);

    const skip_options = b.addOptions();
    skip_options.addOption(bool, "force_fallback", ctx.force_fallback);
    const skip_options_module = skip_options.createModule();
    const skip_host = common.addHostLibrariesWithOptions(b, ctx.target, ctx.optimize, ctx.force_fallback, skip_options_module);

    const skip_app = addAcceptanceApp(b, ctx, "benchmark_skip", modules.benchmark, ref_target, ctx.optimize, &.{}, skip_host, "benchmark_skip", "Run the Silesia codec benchmark against the encode A/B variant slot (currently identical to baseline)");
    _ = sevenzip.addReference(b, ref_target, ctx.optimize, skip_app.exe);
    refs.link(b, skip_app.exe.root_module);
    skip_app.exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/libzip.c") });
    skip_app.exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/unrar.c") });
    if (macos_sdk_usr_lib) |sdk_usr_lib| skip_app.exe.root_module.addLibraryPath(.{ .cwd_relative = sdk_usr_lib });
    skip_app.exe.root_module.linkSystemLibrary("c++", .{});
    skip_app.exe.root_module.linkSystemLibrary("z", .{});
    skip_app.exe.step.dependOn(&refs.libzip_build.step);
    refs.dependOnTools(&skip_app.run.step);
    refs.dependOnBins(&skip_app.run.step);
    skip_app.run.addFileArg(ctx.generated.catalog);
}

fn macosSdkUsrLib(b: *std.Build, ctx: *common.Context) ?[]const u8 {
    const sdk = std.zig.system.darwin.getSdk(b.allocator, b.graph.io, &ctx.target.result) orelse return null;
    defer b.allocator.free(sdk);
    return b.fmt("{s}/usr/lib", .{sdk});
}
