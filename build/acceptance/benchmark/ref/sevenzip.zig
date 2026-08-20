const std = @import("std");

const sources_file = @embedFile("sevenzip.txt");

const flags = [_][]const u8{
    "-DZ7_EXTERNAL_CODECS",
    "-fno-sanitize=alignment",
};

pub fn addReference(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    exe: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libcpp = true,
    });
    var files = std.ArrayList([]const u8).empty;
    var lines = std.mem.splitScalar(u8, sources_file, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        files.append(b.allocator, line) catch @panic("oom");
    }
    module.addCSourceFiles(.{
        .root = b.path("vendor/7zip"),
        .files = files.items,
        .flags = &flags,
    });
    module.addCSourceFile(.{
        .file = b.path("build/acceptance/benchmark/ref/benchmark.cpp"),
        .flags = &flags,
    });
    module.addIncludePath(b.path("vendor/7zip/CPP"));
    module.addIncludePath(b.path("build/acceptance/benchmark/ref"));
    const lib = b.addLibrary(.{
        .name = "sevenzip",
        .root_module = module,
        .linkage = .dynamic,
    });
    b.installArtifact(lib);
    exe.root_module.linkLibrary(lib);
    return lib;
}
