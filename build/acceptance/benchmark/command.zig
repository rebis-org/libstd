const std = @import("std");

const common = @import("../../platform/common.zig");
const modules = @import("../../modules.zig");

pub const Refs = struct {
    sevenzz: *std.Build.Step.InstallFile,
    zstd_cmd: *std.Build.Step.InstallFile,
    zstd_lib: std.Build.LazyPath,
    xz_cmd: *std.Build.Step.InstallFile,
    xz_lib: std.Build.LazyPath,
    bzip2_cmd: *std.Build.Step.InstallFile,
    bzip2_lib: std.Build.LazyPath,
    bzip2_lib_install: *std.Build.Step.InstallFile,
    gzip_cmd: *std.Build.Step.InstallFile,
    lzma_cmd: *std.Build.Step.InstallFile,
    lz4_cmd: *std.Build.Step.InstallFile,
    lz4_lib: std.Build.LazyPath,
    tar_cmd: *std.Build.Step.InstallFile,
    ziptool_cmd: *std.Build.Step.InstallFile,
    libzip_lib: std.Build.LazyPath,
    libzip_configure: *std.Build.Step.Run,
    libzip_build: *std.Build.Step.Run,
    unrar_cmd: *std.Build.Step.InstallFile,
    libunrar_lib: std.Build.LazyPath,
    fast_lzma2_lib: std.Build.LazyPath,
    fast_lzma2_test: *std.Build.Step.Run,
    sevenzz_bin: *std.Build.Step.InstallFile,
    rar_bin: *std.Build.Step.InstallFile,
    unrar_bin: *std.Build.Step.InstallFile,

    pub fn link(self: Refs, b: *std.Build, module: *std.Build.Module) void {
        module.addObjectFile(self.zstd_lib);
        module.addObjectFile(self.xz_lib);
        module.addObjectFile(self.bzip2_lib);
        module.addObjectFile(self.libzip_lib);
        module.addObjectFile(self.libunrar_lib);
        module.addObjectFile(self.fast_lzma2_lib);
        module.addObjectFile(self.lz4_lib);
        module.addIncludePath(b.path("vendor/libzip/lib"));
        module.addIncludePath(b.path(libzip_build_dir));
        module.addIncludePath(b.path("vendor/unrar"));
    }

    pub fn dependOnTools(self: Refs, step: *std.Build.Step) void {
        step.dependOn(&self.sevenzz.step);
        step.dependOn(&self.zstd_cmd.step);
        step.dependOn(&self.xz_cmd.step);
        step.dependOn(&self.bzip2_cmd.step);
        step.dependOn(&self.bzip2_lib_install.step);
        step.dependOn(&self.gzip_cmd.step);
        step.dependOn(&self.lzma_cmd.step);
        step.dependOn(&self.lz4_cmd.step);
        step.dependOn(&self.tar_cmd.step);
        step.dependOn(&self.ziptool_cmd.step);
        step.dependOn(&self.unrar_cmd.step);
        step.dependOn(&self.fast_lzma2_test.step);
        step.dependOn(&self.libzip_build.step);
    }

    pub fn dependOnBins(self: Refs, step: *std.Build.Step) void {
        step.dependOn(&self.sevenzz_bin.step);
        step.dependOn(&self.rar_bin.step);
        step.dependOn(&self.unrar_bin.step);
    }
};

pub const Binary = enum { sevenzz, rar, unrar };

pub const BinaryRef = struct {
    version: []const u8,
    url: []const u8,
    sha256: []const u8,
    installs: []const struct { member: []const u8, binary: Binary },
};

pub const binary_refs = [_]BinaryRef{
    .{
        .version = "26.02",
        .url = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-mac.tar.xz",
        .sha256 = "1cf6760579502f87e591ff5c73a005ec50b3e4d6f507e8b038382d563c3175b9",
        .installs = &.{.{ .member = "7zz", .binary = .sevenzz }},
    },
    .{
        .version = "7.23",
        .url = "https://www.rarlab.com/rar/rarmacos-arm-723.tar.gz",
        .sha256 = "68b393c000758d477fde43c955ff7542f12f76f3f5e87cdda923152fc791bd4d",
        .installs = &.{
            .{ .member = "rar/rar", .binary = .rar },
            .{ .member = "rar/unrar", .binary = .unrar },
        },
    },
};

const bin_pkgs_dir = "zig-out/benchmark/bin/pkgs";

pub const libzip_build_dir = "zig-out/benchmark/build/libzip";

fn binaryName(binary: Binary) []const u8 {
    return switch (binary) {
        .sevenzz => "7zz",
        .rar => "rar",
        .unrar => "unrar",
    };
}

fn make(b: *std.Build, cwd: []const u8, argv: []const []const u8) *std.Build.Step.Run {
    const step = b.addSystemCommand(argv);
    step.setCwd(b.path(cwd));
    return step;
}

fn cmake(b: *std.Build, source: []const u8, build_dir: []const u8, options: []const []const u8) struct { configure: *std.Build.Step.Run, build: *std.Build.Step.Run } {
    var argv = std.ArrayList([]const u8).empty;
    argv.appendSlice(b.allocator, &.{ "cmake", "-S", source, "-B", build_dir, "-DCMAKE_BUILD_TYPE=Release" }) catch @panic("oom");
    argv.appendSlice(b.allocator, options) catch @panic("oom");
    const configure = b.addSystemCommand(argv.items);
    const build = b.addSystemCommand(&.{ "cmake", "--build", build_dir, "-j4" });
    build.step.dependOn(&configure.step);
    return .{ .configure = configure, .build = build };
}

fn copyOut(b: *std.Build, dep: *std.Build.Step, source: []const u8, name: []const u8) std.Build.LazyPath {
    const copy = b.addSystemCommand(&.{"cp"});
    copy.addFileArg(b.path(source));
    copy.step.dependOn(dep);
    return copy.addOutputFileArg(name);
}

fn installOut(b: *std.Build, dep: *std.Build.Step, source: []const u8, name: []const u8) *std.Build.Step.InstallFile {
    return b.addInstallFileWithDir(copyOut(b, dep, source, name), .{ .custom = "benchmark/bin" }, name);
}

fn gnu(b: *std.Build, cwd: []const u8, argv: []const []const u8, dummy_dir: std.Build.LazyPath) *std.Build.Step.Run {
    // The vendor autotools builds only probe $MAKEINFO/$TEXI2PDF for --version;
    // the generated scripts answer that and the real work stays disabled. The
    // paths must be absolute single words: gnulib's get_version splits its
    // argument unquoted, and recursive makes resolve MAKEINFO from subdirs.
    const step = b.addSystemCommand(&.{
        "sh", "-c",
        \\dummy="$(cd "$1" && pwd)"
        \\export MAKEINFO="$dummy/makeinfo" TEXI2PDF="$dummy/texi2pdf"
        \\shift
        \\exec "$@"
        ,
        "sh",
    });
    step.addDirectoryArg2(dummy_dir, .{});
    step.addArgs(argv);
    step.setCwd(b.path(cwd));
    return step;
}

fn archiveFileName(url: []const u8) []const u8 {
    return url[std.mem.lastIndexOfScalar(u8, url, '/').? + 1 ..];
}

fn addBinaryFetch(b: *std.Build, ctx: *const common.Context, ref: BinaryRef) *std.Build.Step.Run {
    const stage = b.fmt("{s}/{s}.d", .{ bin_pkgs_dir, archiveFileName(ref.url) });
    const fetch_exe = b.addExecutable(.{
        .name = "binary_fetch",
        .root_module = b.createModule(.{
            .root_source_file = b.path("build/acceptance/benchmark/ref/binary.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .imports = &.{.{ .name = "run", .module = modules.create(b, modules.run, ctx) }},
        }),
    });
    const fetch = b.addRunArtifact(fetch_exe);
    fetch.addArgs(&.{ ref.url, ref.sha256, bin_pkgs_dir, archiveFileName(ref.url), stage });
    for (ref.installs) |install| {
        fetch.addArg(install.member);
    }
    return fetch;
}

fn addBinaryRefs(b: *std.Build, ctx: *const common.Context) struct { sevenzz: *std.Build.Step.InstallFile, rar: *std.Build.Step.InstallFile, unrar: *std.Build.Step.InstallFile } {
    var fetches: [binary_refs.len]?*std.Build.Step.Run = @splat(null);
    var installs: [3]?*std.Build.Step.InstallFile = .{ null, null, null };
    for (binary_refs, 0..) |ref, i| {
        const fetch = blk: {
            for (0..i) |j| {
                if (std.mem.eql(u8, binary_refs[j].url, ref.url)) break :blk fetches[j].?;
            }
            const created = addBinaryFetch(b, ctx, ref);
            fetches[i] = created;
            break :blk created;
        };
        for (ref.installs) |install| {
            const slot = @backingInt(install.binary);
            if (installs[slot] != null) continue;
            const source = b.path(b.fmt("{s}/{s}.d/{s}", .{ bin_pkgs_dir, archiveFileName(ref.url), install.member }));
            const target = b.addInstallFileWithDir(source, .{ .custom = "benchmark/bin/bins" }, binaryName(install.binary));
            target.step.dependOn(&fetch.step);
            installs[slot] = target;
        }
    }
    return .{ .sevenzz = installs[0].?, .rar = installs[1].?, .unrar = installs[2].? };
}

fn addSevenZz(b: *std.Build) struct { sevenzz: *std.Build.Step.InstallFile, lzma: *std.Build.Step.InstallFile } {
    // ip7z/7zip 26.03 trips clang/LLVM 22's lifetime-safety-intra-TU suggestion on
    // MyStpCpy under the makefile's -Weverything -Werror; the makefile composes
    // flags from CFLAGS_WARN_WALL, so the warning is disabled there.
    const make_7zz = make(b, "vendor/7zip/CPP/7zip/Bundles/Alone2", &.{ "make", "-f", "../../cmpl_mac_arm64.mak", "DISABLE_RAR_COMPRESS=1", "CFLAGS_WARN_WALL=-Werror -Wall -Wextra -Wno-lifetime-safety-intra-tu-suggestions" });
    const make_lzma = make(b, "vendor/7zip/CPP/7zip/Bundles/LzmaCon", &.{ "make", "-f", "makefile.gcc", "-j4" });
    return .{
        .sevenzz = installOut(b, &make_7zz.step, "vendor/7zip/CPP/7zip/Bundles/Alone2/b/m_arm64/7zz", "7zz"),
        .lzma = installOut(b, &make_lzma.step, "vendor/7zip/CPP/7zip/Bundles/LzmaCon/_o/lzma", "lzma"),
    };
}

fn addZstd(b: *std.Build) struct { cmd: *std.Build.Step.InstallFile, lib: std.Build.LazyPath } {
    const make_zstd_cmd = make(b, "vendor/zstd", &.{ "make", "zstd-release" });
    const make_zstd_lib = make(b, "vendor/zstd", &.{ "make", "lib-release" });
    return .{
        .cmd = installOut(b, &make_zstd_cmd.step, "vendor/zstd/programs/zstd", "zstd"),
        .lib = copyOut(b, &make_zstd_lib.step, "vendor/zstd/lib/libzstd.a", "libzstd.a"),
    };
}

fn addXz(b: *std.Build) struct { cmd: *std.Build.Step.InstallFile, lib: std.Build.LazyPath } {
    const xz = cmake(b, "vendor/xz", "zig-out/benchmark/build/xz", &.{
        "-DBUILD_SHARED_LIBS=OFF",
        "-DXZ_TOOL_XZ=ON",
        "-DXZ_TOOL_XZDEC=OFF",
        "-DXZ_TOOL_LZMADEC=OFF",
        "-DXZ_TOOL_LZMAINFO=OFF",
        "-DXZ_NLS=OFF",
        "-DXZ_DOC=OFF",
        "-DXZ_DOXYGEN=OFF",
    });
    return .{
        .cmd = installOut(b, &xz.build.step, "zig-out/benchmark/build/xz/xz", "xz"),
        .lib = copyOut(b, &xz.build.step, "zig-out/benchmark/build/xz/liblzma.a", "liblzma.a"),
    };
}

fn addBzip2(b: *std.Build) struct { cmd: *std.Build.Step.InstallFile, lib: std.Build.LazyPath, lib_install: *std.Build.Step.InstallFile } {
    const bzip2 = cmake(b, "vendor/bzip2", "zig-out/benchmark/build/bzip2", &.{
        "-DENABLE_STATIC_LIB=ON",
        "-DENABLE_SHARED_LIB=OFF",
    });
    const lib = copyOut(b, &bzip2.build.step, "zig-out/benchmark/build/bzip2/libbz2_static.a", "libbz2.a");
    return .{
        .cmd = installOut(b, &bzip2.build.step, "zig-out/benchmark/build/bzip2/bzip2", "bzip2"),
        .lib = lib,
        // Vendor dlltest suite links the static lib from this path.
        .lib_install = b.addInstallFileWithDir(lib, .{ .custom = "benchmark/bin" }, "libbz2.a"),
    };
}

fn addTexinfoDummy(b: *std.Build) std.Build.LazyPath {
    // Texinfo doc tools are only version-probed by the vendor autotools builds;
    // dummy scripts answer --version and the real doc work stays disabled.
    const texinfo = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\mkdir -p "$1"
        \\printf '%s\n' '#!/bin/sh' 'if [ "$1" = "--version" ]; then echo "makeinfo (GNU texinfo) 7.1"; fi' 'exit 0' > "$1/makeinfo"
        \\printf '%s\n' '#!/bin/sh' 'if [ "$1" = "--version" ]; then echo "texi2pdf (GNU texinfo) 7.1"; fi' 'exit 0' > "$1/texi2pdf"
        \\chmod +x "$1/makeinfo" "$1/texi2pdf"
        ,
        "sh",
    });
    return texinfo.addOutputDirectoryArg("texinfo-dummy");
}

fn addGzip(b: *std.Build, dummy_dir: std.Build.LazyPath) *std.Build.Step.InstallFile {
    const bootstrap = gnu(b, "vendor/gzip", &.{ "./bootstrap", "--skip-po" }, dummy_dir);
    const configure = gnu(b, "vendor/gzip", &.{"./configure"}, dummy_dir);
    configure.step.dependOn(&bootstrap.step);
    const make_gzip = gnu(b, "vendor/gzip", &.{ "make", "-j4" }, dummy_dir);
    make_gzip.step.dependOn(&configure.step);
    return installOut(b, &make_gzip.step, "vendor/gzip/gzip", "gzip");
}

fn addTar(b: *std.Build, dummy_dir: std.Build.LazyPath) *std.Build.Step.InstallFile {
    const check_bison = b.addSystemCommand(&.{ "sh", "-c", "if [ ! -x /opt/homebrew/opt/bison/bin/bison ]; then echo 'GNU tar build requires bison >= 2.4 (for example Homebrew bison); install it and retry' >&2; exit 1; fi" });
    const bootstrap = gnu(b, "vendor/tar", &.{ "sh", "-c", "export PATH=\"/opt/homebrew/opt/bison/bin:$PATH\"; exec ./bootstrap --skip-po" }, dummy_dir);
    bootstrap.step.dependOn(&check_bison.step);
    const configure = gnu(b, "vendor/tar", &.{ "sh", "-c", "export PATH=\"/opt/homebrew/opt/bison/bin:$PATH\"; exec ./configure --disable-nls" }, dummy_dir);
    configure.step.dependOn(&bootstrap.step);
    const make_tar = gnu(b, "vendor/tar", &.{ "sh", "-c", "export PATH=\"/opt/homebrew/opt/bison/bin:$PATH\"; exec make -j4 LIBS=-liconv" }, dummy_dir);
    make_tar.step.dependOn(&configure.step);
    return installOut(b, &make_tar.step, "vendor/tar/src/tar", "tar");
}

fn addLibzip(b: *std.Build) struct { cmd: *std.Build.Step.InstallFile, lib: std.Build.LazyPath, configure: *std.Build.Step.Run, build: *std.Build.Step.Run } {
    const libzip = cmake(b, "vendor/libzip", libzip_build_dir, &.{
        "-DBUILD_TOOLS=ON",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_DOC=OFF",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_REGRESS=OFF",
        "-DBUILD_OSSFUZZ=OFF",
    });
    return .{
        .cmd = installOut(b, &libzip.build.step, libzip_build_dir ++ "/src/ziptool", "ziptool"),
        .lib = copyOut(b, &libzip.build.step, libzip_build_dir ++ "/lib/libzip.a", "liblibzip_a.a"),
        .configure = libzip.configure,
        .build = libzip.build,
    };
}

fn addUnrar(b: *std.Build) struct { cmd: *std.Build.Step.InstallFile, lib: std.Build.LazyPath } {
    const make_lib = b.addSystemCommand(&.{ "sh", "-c", "make clean && make -j4 lib" });
    make_lib.setCwd(b.path("vendor/unrar"));
    const copy = b.addSystemCommand(&.{"cp"});
    copy.addFileArg(b.path("vendor/unrar/libunrar.a"));
    copy.step.dependOn(&make_lib.step);
    const lib = copy.addOutputFileArg("libunrar.a");
    const make_cmd = b.addSystemCommand(&.{ "sh", "-c", "make clean && make -j4" });
    make_cmd.setCwd(b.path("vendor/unrar"));
    make_cmd.step.dependOn(&copy.step);
    return .{
        .cmd = installOut(b, &make_cmd.step, "vendor/unrar/unrar", "unrar"),
        .lib = lib,
    };
}

fn addFastLzma2(b: *std.Build) struct { lib: std.Build.LazyPath, test_run: *std.Build.Step.Run } {
    const make_lib = b.addSystemCommand(&.{ "sh", "-c", "make -j4 $(ls *.c | sed 's/\\.c$/.o/')" });
    make_lib.setCwd(b.path("vendor/fast-lzma2"));
    const archive = b.addSystemCommand(&.{ "sh", "-c", "ar rcs \"$1\" vendor/fast-lzma2/*.o", "sh" });
    const lib = archive.addOutputFileArg("libfast-lzma2.a");
    archive.step.dependOn(&make_lib.step);
    const make_test = b.addSystemCommand(&.{ "make", "-j4", "CFLAGS=-Wall -O1 -pthread -I.." });
    make_test.addFileArg2(lib, .{ .prefix = "LIB=" });
    make_test.setCwd(b.path("vendor/fast-lzma2/test"));
    make_test.step.dependOn(&archive.step);
    return .{ .lib = lib, .test_run = make_test };
}

fn addLz4(b: *std.Build) struct { cmd: *std.Build.Step.InstallFile, lib: std.Build.LazyPath } {
    const make_cmd = make(b, "vendor/lz4", &.{ "make", "lz4-release" });
    const make_lib = make(b, "vendor/lz4", &.{ "make", "lib-release" });
    return .{
        .cmd = installOut(b, &make_cmd.step, "vendor/lz4/programs/lz4", "lz4"),
        .lib = copyOut(b, &make_lib.step, "vendor/lz4/lib/liblz4.a", "liblz4.a"),
    };
}

pub fn add(b: *std.Build, ctx: *const common.Context) Refs {
    const seven = addSevenZz(b);
    const zstd = addZstd(b);
    const xz = addXz(b);
    const bzip2 = addBzip2(b);
    const dummy_dir = addTexinfoDummy(b);
    const gzip_cmd = addGzip(b, dummy_dir);
    const tar_cmd = addTar(b, dummy_dir);
    const libzip = addLibzip(b);
    const unrar = addUnrar(b);
    const fast_lzma2 = addFastLzma2(b);
    const lz4 = addLz4(b);
    const bin_refs = addBinaryRefs(b, ctx);

    return .{
        .sevenzz = seven.sevenzz,
        .zstd_cmd = zstd.cmd,
        .zstd_lib = zstd.lib,
        .xz_cmd = xz.cmd,
        .xz_lib = xz.lib,
        .bzip2_cmd = bzip2.cmd,
        .bzip2_lib = bzip2.lib,
        .bzip2_lib_install = bzip2.lib_install,
        .gzip_cmd = gzip_cmd,
        .lzma_cmd = seven.lzma,
        .lz4_cmd = lz4.cmd,
        .lz4_lib = lz4.lib,
        .tar_cmd = tar_cmd,
        .ziptool_cmd = libzip.cmd,
        .libzip_lib = libzip.lib,
        .libzip_configure = libzip.configure,
        .libzip_build = libzip.build,
        .unrar_cmd = unrar.cmd,
        .libunrar_lib = unrar.lib,
        .fast_lzma2_lib = fast_lzma2.lib,
        .fast_lzma2_test = fast_lzma2.test_run,
        .sevenzz_bin = bin_refs.sevenzz,
        .rar_bin = bin_refs.rar,
        .unrar_bin = bin_refs.unrar,
    };
}
