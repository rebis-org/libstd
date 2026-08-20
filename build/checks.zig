const std = @import("std");

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

fn addAbi(b: *std.Build, ctx: *common.Context) void {
    const include = b.getInstallPath(.header, "");
    const include_flag = b.fmt("-I{s}", .{include});
    const c_header = b.addSystemCommand(&.{ "cc", "-std=c23", "-fsyntax-only", include_flag });
    c_header.addFileArg(b.path("build/acceptance/header.c"));
    c_header.step.dependOn(b.getInstallStep());
    const cpp_header = b.addSystemCommand(&.{ "c++", "-std=c++2c", "-fsyntax-only", include_flag });
    cpp_header.addFileArg(b.path("build/acceptance/header.cpp"));
    cpp_header.step.dependOn(b.getInstallStep());
    const abi = b.step("abi", "Verify the ABI contract of the generated header and library");
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
    const archives = ctx.archives orelse @panic("dist units must expand before checks units");
    const package_exe = b.addExecutable(.{ .name = "package", .root_module = modules.create(b, modules.package, ctx) });
    const package_run = b.addRunArtifact(package_exe);
    package_run.addFileArg(archives.host);
    package_run.addFileArg(archives.android);
    package_run.addFileArg(archives.apple);
    package_run.addFileArg(ctx.host.dynamic_library.getEmittedBin());
    b.step("package", "Validate distribution archives").dependOn(&package_run.step);
}
