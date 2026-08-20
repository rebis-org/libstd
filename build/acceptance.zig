const std = @import("std");

const clang = @import("clang.zig");
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
    addChecks(b, &refs);
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
    const app = addAcceptanceApp(b, ctx, "oracles", modules.oracles, ctx.target, ctx.optimize, &.{.{ .name = "c", .module = c_module }}, ctx.host, "oracles", "Run the oracle suite against the system libraries");
    app.exe.root_module.linkSystemLibrary("z", .{});
    app.exe.root_module.linkSystemLibrary("lzma", .{});
    app.exe.root_module.linkSystemLibrary("bz2", .{});
    app.exe.root_module.linkSystemLibrary("archive", .{});
    app.exe.root_module.addObjectFile(ctx.refs.?.zstd_lib);
    app.run.addFileArg(ctx.generated.catalog);
}

fn addBenchmark(b: *std.Build, ctx: *common.Context, refs: cmd.Refs) void {
    const ref_target = common.refTarget(b, ctx.target);
    const app = addAcceptanceApp(b, ctx, "benchmark", modules.benchmark, ref_target, ctx.optimize, &.{}, ctx.host, "benchmark", "Run the Silesia codec benchmark against official implementations and write the report");
    _ = sevenzip.addReference(b, ref_target, ctx.optimize, app.exe);
    refs.link(b, app.exe.root_module);
    app.exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/libzip.c") });
    app.exe.root_module.addCSourceFile(.{ .file = b.path("build/acceptance/benchmark/ref/unrar.c") });
    const macos_sdk_usr_lib = macosSdkUsrLib(b, ctx) orelse
        @panic("benchmark build needs the macOS SDK: run `xcode-select` to point at an Xcode install");
    app.exe.root_module.addLibraryPath(.{ .cwd_relative = macos_sdk_usr_lib });
    app.exe.root_module.linkSystemLibrary("c++", .{});
    app.exe.root_module.linkSystemLibrary("z", .{});
    app.exe.step.dependOn(&refs.libzip_build.step);
    refs.dependOnTools(&app.run.step);
    refs.dependOnBins(&app.run.step);
    app.run.addFileArg(ctx.generated.catalog);
}

fn macosSdkUsrLib(b: *std.Build, ctx: *common.Context) ?[]const u8 {
    const sdk = std.zig.system.darwin.getSdk(b.allocator, b.graph.io, &ctx.target.result) orelse return null;
    defer b.allocator.free(sdk);
    return b.fmt("{s}/usr/lib", .{sdk});
}

fn addChecks(b: *std.Build, refs: *const cmd.Refs) void {
    const sources = [_][]const u8{
        "build/acceptance/abi.h",
        "build/acceptance/header.c",
        "build/acceptance/header.cpp",
        "build/acceptance/benchmark/ref/benchmark.cpp",
        "build/acceptance/benchmark/ref/libzip.c",
        "build/acceptance/benchmark/ref/unrar.c",
        "build/acceptance/benchmark/ref/ref.h",
        "build/acceptance/oracles/c/c.h",
        "build/acceptance/oracles/c/archive.h",
        "build/acceptance/oracles/c/lzma.h",
    };

    const format_step = b.step("format", "Check clang-format compliance of acceptance C/C++ sources");
    format_step.dependOn(clang.format(b, &sources, false));

    const fmt = b.step("fmt", "Apply clang-format to acceptance C/C++ sources");
    fmt.dependOn(clang.format(b, &sources, true));

    const include_dir = b.getInstallPath(.header, "");
    const lint = b.step("lint", "Run clang-tidy with strict checks on acceptance C/C++ sources");
    lint.dependOn(clang.tidy(b, &.{"build/acceptance/header.c"}, &.{ "-std=c23", "-I", include_dir }));
    lint.dependOn(clang.tidy(b, &.{"build/acceptance/header.cpp"}, &.{ "-std=c++26", "-I", include_dir }));
    const libzip_tidy = clang.tidy(b, &.{"build/acceptance/benchmark/ref/libzip.c"}, &.{ "-std=c23", "-I", "vendor/libzip/lib", "-I", cmd.libzip_build_dir });
    libzip_tidy.dependOn(&refs.libzip_configure.step);
    lint.dependOn(libzip_tidy);
    lint.dependOn(clang.tidy(b, &.{"build/acceptance/benchmark/ref/unrar.c"}, &.{ "-std=c23", "-I", "vendor/unrar" }));
    lint.dependOn(clang.tidy(b, &.{"build/acceptance/benchmark/ref/benchmark.cpp"}, &.{ "-std=c++26", "-DZ7_EXTERNAL_CODECS", "-fno-sanitize=alignment", "-I", "vendor/7zip/CPP", "-I", "build/acceptance/benchmark/ref" }));
    lint.dependOn(clang.tidy(b, &.{
        "build/acceptance/oracles/c/c.h",
        "build/acceptance/oracles/c/archive.h",
        "build/acceptance/oracles/c/lzma.h",
    }, &.{"-std=c23"}));
}
