const std = @import("std");

const cmd = @import("acceptance/benchmark/command.zig");
const modules = @import("modules.zig");
const common = @import("platform/common.zig");

pub const Unit = struct {
    name: []const u8,
};

pub const units = [_]Unit{
    .{ .name = "vendor" },
};

pub fn expand(b: *std.Build, ctx: *common.Context) void {
    const refs = cmd.add(b, ctx);
    ctx.refs = refs;
    addVendorTests(b, refs, ctx);
}

fn addVendorTests(b: *std.Build, refs: cmd.Refs, ctx: *common.Context) void {
    const test_exe = b.addExecutable(.{
        .name = "vendor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/acceptance/tests/vendor.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .imports = &.{.{ .name = "run", .module = modules.create(b, modules.run, ctx) }},
        }),
    });
    const run = b.addRunArtifact(test_exe);
    refs.dependOnTools(&run.step);
    b.step("test", "Build and run each vendored test and fuzz suite").dependOn(&run.step);
}
