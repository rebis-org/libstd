const std = @import("std");

fn addFiles(run: *std.Build.Step.Run, b: *std.Build, files: []const []const u8) void {
    for (files) |path| run.addFileArg(b.path(path));
}

pub fn format(b: *std.Build, files: []const []const u8, apply: bool) *std.Build.Step {
    const run = if (apply)
        b.addSystemCommand(&.{ "clang-format", "-i" })
    else
        b.addSystemCommand(&.{ "clang-format", "--dry-run", "--Werror", "--fail-on-incomplete-format" });
    addFiles(run, b, files);
    return &run.step;
}

pub fn tidy(b: *std.Build, files: []const []const u8, args: []const []const u8) *std.Build.Step {
    const run = b.addSystemCommand(&.{ "clang-tidy", "-quiet", "-config-file=.clang-tidy", "-header-filter=build/acceptance/.*" });
    addFiles(run, b, files);
    run.addArgs(&.{"--"});
    run.addArgs(args);
    run.step.dependOn(b.getInstallStep());
    return &run.step;
}
