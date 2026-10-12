const std = @import("std");

const reference = @import("acceptance/benchmark/refs.zig");
const modules = @import("modules.zig");
const common = @import("platform/common.zig");

pub const Unit = struct {
    name: []const u8,
};

pub const units = [_]Unit{
    .{ .name = "vendor" },
};

pub fn expand(b: *std.Build, ctx: *common.Settings) void {
    const refs = reference.add(b, ctx);
    ctx.refs = refs;
    addVendorTests(b, refs, ctx);
}

fn addVendorTests(b: *std.Build, refs: reference.Refs, ctx: *common.Settings) void {
    const test_exe = b.addExecutable(.{
        .name = "vendor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/acceptance/tests/vendor.zig"),
            .target = b.graph.host,
            .optimize = .debug,
            .imports = &.{.{ .name = "run", .module = modules.create(b, modules.run, ctx) }},
        }),
    });
    const run = b.addRunArtifact(test_exe);
    refs.dependOnTools(&run.step);
    b.step("test", "Build and run each vendored test and fuzz suite").dependOn(&run.step);
}
