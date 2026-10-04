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
    const refs = ctx.refs orelse @panic("Vendor units must expand before acceptance units.");
    inline for (units) |unit| switch (unit.kind) {
        .oracles => addOracles(b, ctx, refs),
        .benchmark => addBenchmark(b, ctx, refs),
    };
    addOraclesUbsan(b, ctx, refs);
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
    optimize: std.builtin.Optimize,
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

const Translator = @import("translate_c").Translator;

fn translateCModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize) *std.Build.Module {
    // C translation moved out of the toolchain in 0.17.0: the ZSF translate-c
    // package is the same implementation with an independent release cadence.
    const translate_c = b.dependency("translate_c", .{});
    const translator: Translator = .init(translate_c, .{
        .c_source_file = b.path("build/acceptance/oracles/c/c.h"),
        .target = target,
        .optimize = optimize,
    });
    return translator.mod;
}

fn abVariantModule(b: *std.Build, name: []const u8) *std.Build.Module {
    const variant = b.addOptions();
    variant.addOption([]const u8, "name", name);
    return variant.createModule();
}

fn skipHostLibs(b: *std.Build, ctx: *const common.Context) common.HostLibraries {
    const skip_options = b.addOptions();
    skip_options.addOption(bool, "portable", ctx.portable);
    return common.addHostLibrariesWithOptions(b, ctx.target, ctx.optimize, ctx.portable, skip_options.createModule(), ctx.sanitize_c);
}

fn linkOracleRefs(app: AcceptanceApp, refs: cmd.Refs, catalog: std.Build.LazyPath) void {
    app.exe.root_module.linkSystemLibrary("z", .{});
    app.exe.root_module.linkSystemLibrary("lzma", .{});
    app.exe.root_module.linkSystemLibrary("bz2", .{});
    app.exe.root_module.linkSystemLibrary("archive", .{});
    app.exe.root_module.addObjectFile(refs.zstd_lib);
    app.exe.root_module.addObjectFile(refs.lz4_lib);
    app.run.addFileArg(catalog);
}

fn addTrapRun(b: *std.Build, ctx: *const common.Context, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, exe_name: []const u8) *std.Build.Step.Run {
    const trap_module = modules.createFor(b, modules.trap, target, optimize, ctx);
    const trap_exe = b.addExecutable(.{ .name = exe_name, .root_module = trap_module });
    return b.addRunArtifact(trap_exe);
}

fn addContractCheck(b: *std.Build, nucleus: *std.Build.Module, components: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, sanitize_c: ?std.zig.SanitizeC, exe_name: []const u8, catalog: std.Build.LazyPath) *std.Build.Step.Run {
    const kernel_module = b.createModule(.{
        .root_source_file = b.path("src/kernel/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (sanitize_c) |sc| kernel_module.sanitize_c = sc;
    kernel_module.addImport("nucleus", nucleus);
    kernel_module.addImport("components", components);
    const contract_module = b.createModule(.{
        .root_source_file = b.path("build/acceptance/oracles/contract.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (sanitize_c) |sc| contract_module.sanitize_c = sc;
    contract_module.addImport("nucleus", nucleus);
    contract_module.addImport("kernel", kernel_module);
    const contract_exe = b.addExecutable(.{ .name = exe_name, .root_module = contract_module });
    const contract_run = b.addRunArtifact(contract_exe);
    contract_run.addFileArg(catalog);
    return contract_run;
}

fn linkBenchmarkExe(b: *std.Build, exe: *std.Build.Step.Compile, run: *std.Build.Step.Run, refs: cmd.Refs, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, catalog: std.Build.LazyPath, sdk_usr_lib: ?[]const u8) void {
    _ = sevenzip.addReference(b, target, optimize, exe);
    refs.link(b, exe.root_module);
    exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/libzip.c") });
    exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/unrar.c") });
    if (sdk_usr_lib) |lib| exe.root_module.addLibraryPath(.{ .cwd_relative = lib });
    exe.root_module.linkSystemLibrary("c++", .{});
    exe.root_module.linkSystemLibrary("z", .{});
    exe.step.dependOn(&refs.libzip_build.step);
    refs.dependOnTools(&run.step);
    refs.dependOnBins(&run.step);
    run.addFileArg(catalog);
}

fn addOracles(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    const pair = modules.componentsWithNucleus(b, ctx, ctx.target, ctx.target, ctx.optimize);
    const c_module = translateCModule(b, ctx.target, ctx.optimize);
    const ab_variant_baseline_module = abVariantModule(b, "baseline");

    const app = addAcceptanceApp(b, ctx, "oracles", modules.oracles, ctx.target, ctx.optimize, &.{
        .{ .name = "c", .module = c_module },
        .{ .name = "ab_variant", .module = ab_variant_baseline_module },
        .{ .name = "components", .module = pair.components },
    }, ctx.host, "oracles", "Run the oracle suite against the system libraries");
    linkOracleRefs(app, refs, ctx.generated.catalog);

    const skip_host = skipHostLibs(b, ctx);
    const ab_variant_skip_module = abVariantModule(b, "skip");

    const skip_app = addAcceptanceApp(b, ctx, "oracles_skip", modules.oracles, ctx.target, ctx.optimize, &.{
        .{ .name = "c", .module = c_module },
        .{ .name = "ab_variant", .module = ab_variant_skip_module },
        .{ .name = "components", .module = pair.components },
    }, skip_host, "oracles_skip", "Run the oracle suite against the encode A/B variant slot");
    linkOracleRefs(skip_app, refs, ctx.generated.catalog);

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

    // Re-executes per scenario: contract violations trap the process, so driver and scenarios cannot share an address space.
    app.run.step.dependOn(&addTrapRun(b, ctx, ctx.target, ctx.optimize, "oracles_trap").step);
    app.run.step.dependOn(&addContractCheck(b, pair.nucleus, pair.components, ctx.target, ctx.optimize, ctx.sanitize_c, "contract_check", ctx.generated.catalog).step);

    const compose_ab_module = b.createModule(.{
        .root_source_file = b.path("src/compose_ab.zig"),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    compose_ab_module.addImport("options", ctx.options);
    modules.maybeAddCrcAsm(b, compose_ab_module, ctx.target, ctx.portable);
    const compose_ab_exe = b.addExecutable(.{ .name = "compose_ab", .root_module = compose_ab_module });
    const compose_ab_run = b.addRunArtifact(compose_ab_exe);
    app.run.step.dependOn(&compose_ab_run.step);
}

fn addOraclesUbsan(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    // Zig 0.16 ships no ASan runtime, so UBSan is the only implementable sanitizer step.
    var ubsan_ctx = ctx.*;
    ubsan_ctx.sanitize_c = .full;
    ubsan_ctx.host = common.addHostLibrariesWithOptions(b, ctx.target, ctx.optimize, ctx.portable, ctx.options, .full);

    const pair = modules.componentsWithNucleus(b, &ubsan_ctx, ctx.target, ctx.target, ctx.optimize);
    const c_module = translateCModule(b, ctx.target, ctx.optimize);
    const ab_variant_baseline_module = abVariantModule(b, "baseline");

    const app = addAcceptanceApp(b, &ubsan_ctx, "oracles_ubsan", modules.oracles, ctx.target, ctx.optimize, &.{
        .{ .name = "c", .module = c_module },
        .{ .name = "ab_variant", .module = ab_variant_baseline_module },
        .{ .name = "components", .module = pair.components },
    }, ubsan_ctx.host, "oracles_ubsan", "Run the oracle suite with UBSan");
    linkOracleRefs(app, refs, ctx.generated.catalog);
    app.run.step.dependOn(&addTrapRun(b, &ubsan_ctx, ctx.target, ctx.optimize, "oracles_trap_ubsan").step);
    app.run.step.dependOn(&addContractCheck(b, pair.nucleus, pair.components, ctx.target, ctx.optimize, .full, "contract_check_ubsan", ctx.generated.catalog).step);

    // compose_ab is a throughput gate that flakes under contention; sanitizer slowdown would fault it, so it stays out.
    b.step("oracles_san", "Run all sanitizer suites (ASan absent: Zig 0.16 ships no ASan runtime)").dependOn(&app.run.step);
}

fn addBenchmark(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    const ref_target = common.refTarget(b, ctx.target);
    // Components target intentionally stays on ctx.target while nucleus uses refTarget (reference parity codegen).
    const pair = modules.componentsWithNucleus(b, ctx, ctx.target, ref_target, ctx.optimize);
    const bench_components_module = pair.components;
    const bench_nucleus = pair.nucleus;
    // Links the zstd leaf directly: the bypass row wires substrate spans without kernel or dylib.
    const bypass_module = b.createModule(.{
        .root_source_file = b.path("src/bypass.zig"),
        .target = ref_target,
        .optimize = ctx.optimize,
    });
    bypass_module.addImport("options", ctx.options);
    bypass_module.addImport("nucleus", bench_nucleus);
    modules.maybeAddCrcAsm(b, bypass_module, ref_target, ctx.portable);
    const app = addAcceptanceApp(b, ctx, "benchmark", modules.benchmark, ref_target, ctx.optimize, &.{
        .{ .name = "components", .module = bench_components_module },
        .{ .name = "bypass", .module = bypass_module },
    }, ctx.host, "benchmark", "Run the Silesia codec benchmark against reference implementations and write the report");
    // SDK path exists only for Darwin targets. Expansion runs for every -Dtarget.
    const macos_sdk_usr_lib: ?[]const u8 = if (ref_target.result.os.tag.isDarwin())
        macosSdkUsrLib(b, ctx) orelse
            @panic("benchmark build needs the macOS SDK: run `xcode-select` to point at an Xcode install")
    else
        null;
    linkBenchmarkExe(b, app.exe, app.run, refs, ref_target, ctx.optimize, ctx.generated.catalog, macos_sdk_usr_lib);

    const skip_host = skipHostLibs(b, ctx);

    const skip_app = addAcceptanceApp(b, ctx, "benchmark_skip", modules.benchmark, ref_target, ctx.optimize, &.{}, skip_host, "benchmark_skip", "Run the Silesia codec benchmark against the encode A/B variant slot");
    linkBenchmarkExe(b, skip_app.exe, skip_app.run, refs, ref_target, ctx.optimize, ctx.generated.catalog, macos_sdk_usr_lib);
}

fn macosSdkUsrLib(b: *std.Build, ctx: *common.Context) ?[]const u8 {
    const sdk = std.zig.system.darwin.getSdk(b.allocator, b.graph.io, &ctx.target.result) orelse return null;
    defer b.allocator.free(sdk);
    return b.fmt("{s}/usr/lib", .{sdk});
}
