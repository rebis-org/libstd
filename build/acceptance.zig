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
    const refs = ctx.refs orelse @panic("The vendor units must expand before the acceptance units.");
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

fn skipVariantHostLibraries(b: *std.Build, ctx: *const common.Context) common.HostLibraries {
    const skip_options = b.addOptions();
    skip_options.addOption(bool, "portable", ctx.portable);
    return common.addHostLibrariesWithOptions(b, ctx.target, ctx.optimize, ctx.portable, skip_options.createModule(), ctx.sanitize_c);
}

fn linkOracleRefs(app: AcceptanceApp, refs: cmd.Refs, catalog: std.Build.LazyPath) void {
    inline for ([_][]const u8{ "z", "lzma", "bz2", "archive" }) |name| {
        app.exe.root_module.linkSystemLibrary(name, .{});
    }
    inline for ([_]std.Build.LazyPath{ refs.zstd_lib, refs.lz4_lib }) |object| {
        app.exe.root_module.addObjectFile(object);
    }
    app.run.addFileArg(catalog);
}

fn addTrapRun(b: *std.Build, ctx: *const common.Context, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, exe_name: []const u8) *std.Build.Step.Run {
    const trap_module = modules.createFor(b, modules.trap, target, optimize, ctx);
    const trap_exe = b.addExecutable(.{ .name = exe_name, .root_module = trap_module });
    return b.addRunArtifact(trap_exe);
}

fn addContractCheck(b: *std.Build, interface: *std.Build.Module, components: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize, sanitize_c: ?std.zig.SanitizeC, exe_name: []const u8, catalog: std.Build.LazyPath) *std.Build.Step.Run {
    const kernel_module = b.createModule(.{
        .root_source_file = b.path("src/kernel/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (sanitize_c) |sc| kernel_module.sanitize_c = sc;
    kernel_module.addImport("interface", interface);
    kernel_module.addImport("components", components);
    const contract_module = b.createModule(.{
        .root_source_file = b.path("build/acceptance/oracles/contract.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (sanitize_c) |sc| contract_module.sanitize_c = sc;
    contract_module.addImport("interface", interface);
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

fn addOracleApp(
    b: *std.Build,
    ctx: *common.Context,
    refs: cmd.Refs,
    exe_name: []const u8,
    variant_name: []const u8,
    modules_pair: modules.Components,
    c_module: *std.Build.Module,
    host: common.HostLibraries,
    step_name: []const u8,
    step_description: []const u8,
) AcceptanceApp {
    const variant_module = abVariantModule(b, variant_name);
    const app = addAcceptanceApp(b, ctx, exe_name, modules.oracles, ctx.target, ctx.optimize, &.{
        .{ .name = "c", .module = c_module },
        .{ .name = "ab_variant", .module = variant_module },
        .{ .name = "components", .module = modules_pair.components },
    }, host, step_name, step_description);
    linkOracleRefs(app, refs, ctx.generated.catalog);
    return app;
}

fn addAbComparison(b: *std.Build, baseline_exe: *std.Build.Step.Compile, skip_exe: *std.Build.Step.Compile, catalog: std.Build.LazyPath) void {
    var runs: [2]*std.Build.Step.Run = undefined;
    const exes = [_]*std.Build.Step.Compile{ baseline_exe, skip_exe };
    inline for (exes, 0..) |exe, index| {
        const ab_run = b.addRunArtifact(exe);
        ab_run.addFileArg(catalog);
        ab_run.addArg("--suite");
        ab_run.addArg("lzma_ab");
        ab_run.step.dependOn(&exe.step);
        runs[index] = ab_run;
    }
    const diff = b.addSystemCommand(&.{ "diff", "-rq", "zig-out/oracles/ab/baseline", "zig-out/oracles/ab/skip" });
    diff.step.dependOn(&runs[0].step);
    diff.step.dependOn(&runs[1].step);
    b.step("oracles_ab", "Compare LZMA encode output between the baseline and skip variants").dependOn(&diff.step);
}

fn addOracles(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    const modules_pair = modules.componentsWithInterface(b, ctx, ctx.target, ctx.target, ctx.optimize);
    const c_module = translateCModule(b, ctx.target, ctx.optimize);

    const app = addOracleApp(b, ctx, refs, "oracles", "baseline", modules_pair, c_module, ctx.host, "oracles", "Run the oracle suite against the system libraries");

    const skip_host = skipVariantHostLibraries(b, ctx);
    const skip_app = addOracleApp(b, ctx, refs, "oracles_skip", "skip", modules_pair, c_module, skip_host, "oracles_skip", "Run the oracle suite against the encode A/B variant slot");

    addAbComparison(b, app.exe, skip_app.exe, ctx.generated.catalog);

    // Each scenario runs in its own process: a contract violation traps, so the
    // driver and the scenarios cannot share one address space.
    app.run.step.dependOn(&addTrapRun(b, ctx, ctx.target, ctx.optimize, "oracles_trap").step);
    app.run.step.dependOn(&addContractCheck(b, modules_pair.interface, modules_pair.components, ctx.target, ctx.optimize, ctx.sanitize_c, "contract_check", ctx.generated.catalog).step);

    const compose_ab_module = b.createModule(.{
        .root_source_file = b.path("src/compose_ab.zig"),
        .target = modules.withKernelFeatures(ctx.target),
        .optimize = ctx.optimize,
    });
    compose_ab_module.addImport("options", ctx.options);
    compose_ab_module.addImport("seam", modules.create(b, modules.seam, ctx));
    const compose_ab_exe = b.addExecutable(.{ .name = "compose_ab", .root_module = compose_ab_module });
    const compose_ab_run = b.addRunArtifact(compose_ab_exe);
    app.run.step.dependOn(&compose_ab_run.step);
}

fn addOraclesUbsan(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    // Zig 0.16 ships no ASan runtime, so UBSan is the only implementable sanitizer step.
    var ubsan_ctx = ctx.*;
    ubsan_ctx.sanitize_c = .full;
    ubsan_ctx.host = common.addHostLibrariesWithOptions(b, ctx.target, ctx.optimize, ctx.portable, ctx.options, .full);

    const modules_pair = modules.componentsWithInterface(b, &ubsan_ctx, ctx.target, ctx.target, ctx.optimize);
    const c_module = translateCModule(b, ctx.target, ctx.optimize);

    const app = addOracleApp(b, &ubsan_ctx, refs, "oracles_ubsan", "baseline", modules_pair, c_module, ubsan_ctx.host, "oracles_ubsan", "Run the oracle suite with UBSan");
    app.run.step.dependOn(&addTrapRun(b, &ubsan_ctx, ctx.target, ctx.optimize, "oracles_trap_ubsan").step);
    app.run.step.dependOn(&addContractCheck(b, modules_pair.interface, modules_pair.components, ctx.target, ctx.optimize, .full, "contract_check_ubsan", ctx.generated.catalog).step);

    // compose_ab is a throughput gate that flakes under contention, and the
    // sanitizer slowdown would fault it, so this step leaves it out.
    b.step("oracles_san", "Run all sanitizer suites (ASan is absent: Zig ships no ASan runtime)").dependOn(&app.run.step);
}

fn addBenchmarkApp(
    b: *std.Build,
    ctx: *common.Context,
    refs: cmd.Refs,
    exe_name: []const u8,
    host: common.HostLibraries,
    step_name: []const u8,
    step_description: []const u8,
    target: std.Build.ResolvedTarget,
    components_module: *std.Build.Module,
    bypass_module: ?*std.Build.Module,
    sdk_usr_lib: ?[]const u8,
    catalog: std.Build.LazyPath,
) AcceptanceApp {
    var extra: [2]std.Build.Module.Import = undefined;
    var extra_count: usize = 0;
    extra[extra_count] = .{ .name = "components", .module = components_module };
    extra_count += 1;
    if (bypass_module) |bypass| {
        extra[extra_count] = .{ .name = "bypass", .module = bypass };
        extra_count += 1;
    }
    const app = addAcceptanceApp(b, ctx, exe_name, modules.benchmark, target, ctx.optimize, extra[0..extra_count], host, step_name, step_description);
    linkBenchmarkExe(b, app.exe, app.run, refs, target, ctx.optimize, catalog, sdk_usr_lib);
    return app;
}

fn addBenchmark(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    const ref_target = common.refTarget(b, ctx.target);
    // The components target stays on ctx.target while the interface uses ref_target,
    // because the reference binaries need the parity code generation.
    const modules_pair = modules.componentsWithInterface(b, ctx, ctx.target, ref_target, ctx.optimize);
    const bench_components_module = modules_pair.components;
    const bench_interface = modules_pair.interface;
    // The zstd leaf links directly: the bypass row wires substrate spans with no
    // kernel and no dylib.
    const bypass_module = b.createModule(.{
        .root_source_file = b.path("src/bypass.zig"),
        .target = modules.withKernelFeatures(ref_target),
        .optimize = ctx.optimize,
    });
    bypass_module.addImport("options", ctx.options);
    bypass_module.addImport("interface", bench_interface);
    // The SDK path exists only for a Darwin target, and the expansion runs for every -Dtarget.
    const macos_sdk_usr_lib: ?[]const u8 = if (ref_target.result.os.tag.isDarwin())
        macosSdkUsrLib(b, ctx) orelse
            @panic("The benchmark build needs the macOS SDK. Run xcode-select to select an Xcode install.")
    else
        null;
    _ = addBenchmarkApp(b, ctx, refs, "benchmark", ctx.host, "benchmark", "Run the Silesia codec benchmark against reference implementations and write the report", ref_target, bench_components_module, bypass_module, macos_sdk_usr_lib, ctx.generated.catalog);

    const skip_host = skipVariantHostLibraries(b, ctx);
    _ = addBenchmarkApp(b, ctx, refs, "benchmark_skip", skip_host, "benchmark_skip", "Run the Silesia codec benchmark against the encode A/B variant slot", ref_target, bench_components_module, null, macos_sdk_usr_lib, ctx.generated.catalog);
}

fn macosSdkUsrLib(b: *std.Build, ctx: *common.Context) ?[]const u8 {
    const sdk = std.zig.system.darwin.getSdk(b.allocator, b.graph.io, &ctx.target.result) orelse return null;
    defer b.allocator.free(sdk);
    return b.fmt("{s}/usr/lib", .{sdk});
}
