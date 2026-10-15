const builtin = @import("builtin");
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

pub fn expand(b: *std.Build, ctx: *common.Settings) void {
    inline for (units) |unit| switch (unit.kind) {
        .abi => addAbi(b, ctx),
        .exe => addExe(b, ctx),
        .render => addRender(b, ctx),
        .package => addPackage(b, ctx),
    };
}

fn addHeaderProbe(
    b: *std.Build,
    abi: *std.Build.Step,
    probe_tool: *std.Build.Step.Compile,
    command: []const []const u8,
    std_flag: []const u8,
    source: std.Build.LazyPath,
    header_dir: std.Build.LazyPath,
) void {
    const probe = std.Build.Step.Run.create(b, b.fmt("abi {s} {s}", .{ command[command.len - 1], std_flag }));
    probe.addArtifactArg(probe_tool);
    probe.addArgs(command);
    probe.addArg("--");
    probe.addArg(std_flag);
    probe.addDirectoryArg2(header_dir, .{ .prefix = "-I" });
    probe.addFileArg2(source, .{});
    probe.addArgs(&.{ "-o", if (builtin.target.os.tag == .windows) "NUL" else "/dev/null" });
    probe.step.dependOn(b.getInstallStep());
    abi.dependOn(&probe.step);
}

fn addAbi(b: *std.Build, ctx: *common.Settings) void {
    const zig = b.graph.zig_exe;
    const abi = b.step("abi", "Check the ABI contract of the generated header and library");
    const probe_tool = b.addExecutable(.{
        .name = "abi_probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/platform/probe.zig"),
            .target = b.graph.host,
        }),
    });
    const header_c = b.path("build/acceptance/header.c");
    const header_cpp = b.path("build/acceptance/header.cpp");
    const c_stds = .{ "-std=c11", "-std=c17", "-std=c23" };
    const cxx_stds = .{ "-std=c++20", "-std=c++23", "-std=c++2c" };
    inline for (c_stds) |std_flag| {
        addHeaderProbe(b, abi, probe_tool, &.{ zig, "cc" }, std_flag, header_c, ctx.generated.header_dir);
    }
    inline for (cxx_stds) |std_flag| {
        addHeaderProbe(b, abi, probe_tool, &.{ zig, "c++" }, std_flag, header_cpp, ctx.generated.header_dir);
    }
    abi.dependOn(&ctx.host.dynamic_library.step);
    const abi_exports = b.addExecutable(.{
        .name = "abi_exports",
        .root_module = modules.create(b, modules.abi_exports, ctx),
    });
    const abi_exports_run = b.addRunArtifact(abi_exports);
    abi_exports_run.addFileArg2(ctx.host.dynamic_library.getEmittedBin(), .{});
    abi.dependOn(&abi_exports_run.step);
}

fn addExe(b: *std.Build, ctx: *common.Settings) void {
    const exe = b.step("exe", "Build the host static and dynamic libraries");
    exe.dependOn(&ctx.host.static_library.step);
    exe.dependOn(&ctx.host.dynamic_library.step);
    b.installArtifact(ctx.host.static_library);
    b.installArtifact(ctx.host.dynamic_library);
}

fn addRender(b: *std.Build, ctx: *common.Settings) void {
    b.step("render", "Generate the catalog, header, and module map").dependOn(ctx.generated.step);
    common.installGenerated(b, ctx.generated);
}

fn addPackage(b: *std.Build, ctx: *common.Settings) void {
    const archives = ctx.archives orelse @panic("The distribution units must expand before the checks units.");
    const package_exe = b.addExecutable(.{ .name = "package", .root_module = modules.create(b, modules.package, ctx) });
    const package_run = b.addRunArtifact(package_exe);
    for (archives) |provider| {
        inline for (@typeInfo(common.ProviderArchives).@"struct".field_names) |field_name| {
            if (comptime std.mem.eql(u8, field_name, "name")) continue;
            package_run.addFileArg2(@field(provider, field_name), .{});
        }
    }
    package_run.addFileArg2(ctx.host.dynamic_library.getEmittedBin(), .{});
    b.step("package", "Check the distribution archives").dependOn(&package_run.step);
}
