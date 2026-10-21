const std = @import("std");

const common = @import("common.zig");
const manifest = @import("manifest.zig");

const android_api_level: u32 = 33;

fn versionCode(version: std.SemanticVersion) u32 {
    return @intCast(version.major * 1_000_000 + version.minor * 1_000 + version.patch);
}

// The bridge links into Android libraries only.
// Keeps the host export surface to the enumerated set.
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
    compile.addFileArg2(b.path("build/templates/android/dev/stdk/stdk.java"), .{});
    return compile.addOutputFileArg("classes.jar");
}

fn addJniBridge(b: *std.Build, library: *std.Build.Step.Compile) void {
    const java_home = b.graph.environ_map.get("JAVA_HOME") orelse
        @panic("the Android archive needs JAVA_HOME to find jni.h.");
    const jni_platform = switch (b.graph.host.result.os.tag) {
        .macos => "darwin",
        .linux => "linux",
        .windows => "win32",
        else => "linux",
    };
    library.root_module.addIncludePath(b.path("build/templates/android/jni/shim"));
    library.root_module.addCSourceFile(.{
        .file = b.path("build/templates/android/jni/stdk.c"),
        .flags = &.{
            b.fmt("-I{s}", .{b.pathJoin(&.{ java_home, "include" })}),
            b.fmt("-I{s}", .{b.pathJoin(&.{ java_home, "include", jni_platform })}),
        },
    });
}

pub fn addAar(
    b: *std.Build,
    ctx: *const common.Settings,
    distribution: manifest.Distribution,
    output_name: []const u8,
) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.add("AndroidManifest.xml", b.fmt(
        "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"dev.stdk\" android:versionName=\"{d}.{d}.{d}\" android:versionCode=\"{d}\" />\n",
        .{ ctx.version.major, ctx.version.minor, ctx.version.patch, versionCode(ctx.version) },
    ));
    common.stageHeaderCatalog(stage, ctx, distribution);
    _ = stage.addCopyFile(addClassesJar(b), "classes.jar");
    for (manifest.android_abis) |abi| {
        // 32-bit arm rides the softfp ABI; the others use the plain android ABI.
        const library = common.addLibrary(b, b.resolveTargetQuery(.{
            .cpu_arch = abi.slice.arch,
            .os_tag = .linux,
            .abi = abi.abi,
            .android_api_level = android_api_level,
        }), ctx.optimize, .dynamic, ctx);
        addJniBridge(b, library);
        _ = stage.addCopyFile(library.getEmittedBin(), abi.zip_path);
    }
    return common.addZipArchive(b, distribution, stage, output_name);
}

// [ffi.c] entries name the native library each target links.
pub fn addArchive(
    b: *std.Build,
    ctx: *const common.Settings,
    distribution: manifest.Distribution,
    output_name: []const u8,
) std.Build.LazyPath {
    const stage = b.addWriteFiles();
    _ = stage.add("stdk/cjpm.toml", tomlManifest(b, ctx));
    _ = stage.addCopyFile(b.path("build/templates/cjpm/stdk.cj"), "stdk/src/stdk.cj");
    common.stageHeaderCatalog(stage, ctx, distribution);
    for (manifest.ohos_abis) |abi| {
        const target = b.resolveTargetQuery(.{
            .cpu_arch = abi.slice.arch,
            .os_tag = .linux,
            .abi = .ohos,
        });
        inline for ([_]std.lang.LinkMode{ .static, .dynamic }) |linkage| {
            const library = common.addLibrary(b, target, ctx.optimize, linkage, ctx);
            const extension = if (linkage == .static) "a" else "so";
            _ = stage.addCopyFile(library.getEmittedBin(), b.fmt("stdk/libs/{s}/libstd.{s}", .{ abi.triple, extension }));
        }
    }
    return common.addZipArchive(b, distribution, stage, output_name);
}

fn tomlManifest(b: *std.Build, ctx: *const common.Settings) []const u8 {
    var text: std.ArrayList(u8) = .empty;
    text.appendSlice(b.allocator, b.fmt(
        \\[package]
        \\  cjc-version = "1.2.0"
        \\  name = "stdk"
        \\  description = "Library (for standard) in Zig"
        \\  version = "{d}.{d}.{d}"
        \\  compile-option = ""
        \\  link-option = ""
        \\  output-type = "static"
        \\  src-dir = "src"
        \\
    , .{ ctx.version.major, ctx.version.minor, ctx.version.patch })) catch @panic("the cjpm manifest is out of memory.");
    for (manifest.ohos_abis) |abi| {
        text.appendSlice(b.allocator, b.fmt(
            \\
            \\[target.{s}.ffi.c]
            \\  std = {{ path = "libs/{s}" }}
            \\
        , .{ abi.triple, abi.triple })) catch @panic("the cjpm target entry is out of memory.");
    }
    return text.items;
}
