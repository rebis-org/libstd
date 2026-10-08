const std = @import("std");
const builtin = @import("builtin");

const modules = @import("modules.zig");
const common = @import("platform/common.zig");

pub const Unit = struct {
    name: []const u8,
    kind: Kind,
};

pub const Kind = enum { abi, exe, render, package };

pub const units = [_]Unit{
    .{ .name = "abi", .kind = .abi },
    .{ .name = "exe", .kind = .exe },
    .{ .name = "render", .kind = .render },
    .{ .name = "package", .kind = .package },
};

pub fn expand(b: *std.Build, ctx: *common.Context) void {
    inline for (units) |unit| switch (unit.kind) {
        .abi => addAbi(b, ctx),
        .exe => addExe(b, ctx),
        .render => addRender(b, ctx),
        .package => addPackage(b, ctx),
    };
}

fn addHeaderProbe(b: *std.Build, zig: []const u8, driver: []const u8, std_flag: []const u8, source: std.Build.LazyPath, header_dir: std.Build.LazyPath) *std.Build.Step.Run {
    const probe = b.addSystemCommand(&.{ zig, driver, std_flag });
    probe.addDirectoryArg2(header_dir, .{ .prefix = "-I" });
    probe.addFileArg(source);
    probe.addArgs(&.{ "-o", if (builtin.os.tag == .windows) "NUL" else "/dev/null" });
    probe.step.dependOn(b.getInstallStep());
    return probe;
}

fn addAbi(b: *std.Build, ctx: *common.Context) void {
    const zig = b.graph.zig_exe;
    // There is no -fsyntax-only mode: objecting to /dev/null proves that the header
    // parses as C23 and C++26 without linking.
    const c_header = addHeaderProbe(b, zig, "cc", "-std=c23", b.path("build/acceptance/header.c"), ctx.generated.header_dir);
    const cpp_header = addHeaderProbe(b, zig, "c++", "-std=c++2c", b.path("build/acceptance/header.cpp"), ctx.generated.header_dir);
    const abi = b.step("abi", "Check the ABI contract of the generated header and library");
    abi.dependOn(&c_header.step);
    abi.dependOn(&cpp_header.step);
    abi.dependOn(&ctx.host.dynamic_library.step);
    const abi_exports = b.addExecutable(.{
        .name = "abi_exports",
        .root_module = modules.create(b, modules.abi_exports, ctx),
    });
    const abi_exports_run = b.addRunArtifact(abi_exports);
    abi_exports_run.addFileArg(ctx.host.dynamic_library.getEmittedBin());
    abi.dependOn(&abi_exports_run.step);
}

fn addExe(b: *std.Build, ctx: *common.Context) void {
    const exe = b.step("exe", "Build the host static and dynamic libraries");
    exe.dependOn(&ctx.host.static_library.step);
    exe.dependOn(&ctx.host.dynamic_library.step);
    b.installArtifact(ctx.host.static_library);
    b.installArtifact(ctx.host.dynamic_library);
}

fn addRender(b: *std.Build, ctx: *common.Context) void {
    b.step("render", "Generate the catalog, header, and module map").dependOn(ctx.generated.step);
    common.installGenerated(b, ctx.generated);
}

fn addPackage(b: *std.Build, ctx: *common.Context) void {
    const archives = ctx.archives orelse @panic("The distribution units must expand before the checks units.");
    const package_exe = b.addExecutable(.{ .name = "package", .root_module = modules.create(b, modules.package, ctx) });
    const package_run = b.addRunArtifact(package_exe);
    package_run.addFileArg(archives.host);
    package_run.addFileArg(archives.android);
    package_run.addFileArg(archives.apple);
    package_run.addFileArg(archives.cjpm);
    package_run.addFileArg(ctx.host.dynamic_library.getEmittedBin());
    b.step("package", "Check the distribution archives").dependOn(&package_run.step);
}
