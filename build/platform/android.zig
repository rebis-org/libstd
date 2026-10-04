const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");
const slices = @import("slices.zig");

const android_api_level: u32 = 33;

fn versionCode(version: std.SemanticVersion) u32 {
    return @intCast(version.major * 1_000_000 + version.minor * 1_000 + version.patch);
}

// The JNI bridge builds into the Android libraries only, never the host
// library, so the C ABI export surface stays the enumerated set.
fn addClassesJar(b: *std.Build) std.Build.LazyPath {
    const compile = b.addSystemCommand(&.{
        "sh", "-c",
        \\case "$3" in *.jar) ;; *) echo "classes.jar output argument is $3" && exit 1 ;; esac
        \\out_dir=$(dirname "$3")
        \\mkdir -p "$out_dir/classes"
        \\javac -Xlint:all -Werror -encoding UTF-8 -d "$out_dir/classes" "$2"
        \\jar cf "$3" -C "$out_dir/classes" .
        ,
        "_",  "unused",
    });
    compile.addFileArg(b.path("build/templates/android/dev/stdk/StdK.java"));
    return compile.addOutputFileArg("classes.jar");
}

fn addJniBridge(b: *std.Build, library: *std.Build.Step.Compile) void {
    const java_home = b.graph.environ_map.get("JAVA_HOME") orelse
        @panic("android archive needs JAVA_HOME for jni.h");
    library.root_module.addIncludePath(b.path("build/templates/android/jni/shim"));
    library.root_module.addCSourceFile(.{
        .file = b.path("build/templates/android/jni/stdk.c"),
        .flags = &.{
            b.fmt("-I{s}", .{b.pathJoin(&.{ java_home, "include" })}),
            b.fmt("-I{s}", .{b.pathJoin(&.{ java_home, "include", "darwin" })}),
        },
    });
}

pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Context,
) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.add("AndroidManifest.xml", b.fmt(
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"dev.stdk\" android:versionName=\"{d}.{d}.{d}\" android:versionCode=\"{d}\" />\n",
        .{ ctx.version.major, ctx.version.minor, ctx.version.patch, versionCode(ctx.version) },
    ));
    _ = stage.addCopyFile(ctx.generated.header, manifest.android.header);
    _ = stage.addCopyFile(ctx.generated.catalog, manifest.android.catalog);
    _ = stage.addCopyFile(addClassesJar(b), "classes.jar");
    for (slices.android_abis) |abi| {
        const library = common.addLibrary(b, b.resolveTargetQuery(.{
            .cpu_arch = abi.arch,
            .os_tag = .linux,
            .abi = .android,
            .android_api_level = android_api_level,
        }), ctx.optimize, .dynamic, ctx);
        addJniBridge(b, library);
        _ = stage.addCopyFile(library.getEmittedBin(), abi.library);
    }
    return common.addZipArchive(b, manifest.android, stage);
}
