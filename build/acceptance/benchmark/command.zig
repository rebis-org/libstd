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

pub const Bin = enum { sevenzz, rar, unrar };

pub const BinaryRef = struct {
    version: []const u8,
    url: []const u8,
    sha256: []const u8,
    installs: []const struct { member: []const u8, bin: Bin },
};

pub const binary_refs = [_]BinaryRef{
    .{
        .version = "26.02",
        .url = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-mac.tar.xz",
        .sha256 = "1cf6760579502f87e591ff5c73a005ec50b3e4d6f507e8b038382d563c3175b9",
        .installs = &.{.{ .member = "7zz", .bin = .sevenzz }},
    },
    .{
        .version = "7.23",
        .url = "https://www.rarlab.com/rar/rarmacos-arm-723.tar.gz",
        .sha256 = "68b393c000758d477fde43c955ff7542f12f76f3f5e87cdda923152fc791bd4d",
        .installs = &.{
            .{ .member = "rar/rar", .bin = .rar },
            .{ .member = "rar/unrar", .bin = .unrar },
        },
    },
};

const bin_pkgs_dir = "zig-out/benchmark/bin/pkgs";

pub const libzip_build_dir = "zig-out/benchmark/build/libzip";

fn binName(bin: Bin) []const u8 {
    return switch (bin) {
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

fn gnu(b: *std.Build, cwd: []const u8, argv: []const []const u8, makeinfo: []const u8, texi2pdf: []const u8) *std.Build.Step.Run {
    const step = b.addSystemCommand(argv);
    step.setCwd(b.path(cwd));
    step.setEnvironmentVariable("MAKEINFO", makeinfo);
    step.setEnvironmentVariable("TEXI2PDF", texi2pdf);
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
    var fetches: [binary_refs.len]?*std.Build.Step.Run = .{null} ** binary_refs.len;
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
            const slot = @intFromEnum(install.bin);
            if (installs[slot] != null) continue;
            const source = b.path(b.fmt("{s}/{s}.d/{s}", .{ bin_pkgs_dir, archiveFileName(ref.url), install.member }));
            const target = b.addInstallFileWithDir(source, .{ .custom = "benchmark/bin/bins" }, binName(install.bin));
            target.step.dependOn(&fetch.step);
            installs[slot] = target;
        }
    }
    return .{ .sevenzz = installs[0].?, .rar = installs[1].?, .unrar = installs[2].? };
}

pub fn add(b: *std.Build, ctx: *const common.Context) Refs {
    const make_7zz = make(b, "vendor/7zip/CPP/7zip/Bundles/Alone2", &.{ "make", "-f", "../../cmpl_mac_arm64.mak", "DISABLE_RAR_COMPRESS=1" });
    const sevenzz = installOut(b, &make_7zz.step, "vendor/7zip/CPP/7zip/Bundles/Alone2/b/m_arm64/7zz", "7zz");

    const make_zstd_cmd = make(b, "vendor/zstd", &.{ "make", "zstd-release" });
    const zstd_cmd = installOut(b, &make_zstd_cmd.step, "vendor/zstd/programs/zstd", "zstd");
    const make_zstd_lib = make(b, "vendor/zstd", &.{ "make", "lib-release" });
    const zstd_lib = copyOut(b, &make_zstd_lib.step, "vendor/zstd/lib/libzstd.a", "libzstd.a");

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
    const xz_cmd = installOut(b, &xz.build.step, "zig-out/benchmark/build/xz/xz", "xz");
    const xz_lib = copyOut(b, &xz.build.step, "zig-out/benchmark/build/xz/liblzma.a", "liblzma.a");

    const bzip2 = cmake(b, "vendor/bzip2", "zig-out/benchmark/build/bzip2", &.{
        "-DENABLE_STATIC_LIB=ON",
        "-DENABLE_SHARED_LIB=OFF",
    });
    const bzip2_cmd = installOut(b, &bzip2.build.step, "zig-out/benchmark/build/bzip2/bzip2", "bzip2");
    const bzip2_lib = copyOut(b, &bzip2.build.step, "zig-out/benchmark/build/bzip2/libbz2_static.a", "libbz2.a");
    // The bzip2 dlltest vendor suite links the static lib from this path.
    const bzip2_lib_install = b.addInstallFileWithDir(bzip2_lib, .{ .custom = "benchmark/bin" }, "libbz2.a");

    const mkdir_dummy = b.addSystemCommand(&.{ "mkdir", "-p", "zig-out/benchmark/build/dummy" });
    const write_dummy = b.addSystemCommand(&.{ "sh", "-c", "printf '%s\\n' '#!/bin/sh' 'if [ \"$1\" = \"--version\" ]; then echo \"makeinfo (GNU texinfo) 7.1\"; fi' 'exit 0' > zig-out/benchmark/build/dummy/makeinfo && chmod +x zig-out/benchmark/build/dummy/makeinfo && printf '%s\\n' '#!/bin/sh' 'if [ \"$1\" = \"--version\" ]; then echo \"texi2pdf (GNU texinfo) 7.1\"; fi' 'exit 0' > zig-out/benchmark/build/dummy/texi2pdf && chmod +x zig-out/benchmark/build/dummy/texi2pdf" });
    write_dummy.step.dependOn(&mkdir_dummy.step);
    const makeinfo = b.pathFromRoot("zig-out/benchmark/build/dummy/makeinfo");
    const texi2pdf = b.pathFromRoot("zig-out/benchmark/build/dummy/texi2pdf");

    const bootstrap_gzip = gnu(b, "vendor/gzip", &.{ "./bootstrap", "--skip-po" }, makeinfo, texi2pdf);
    bootstrap_gzip.step.dependOn(&write_dummy.step);
    const configure_gzip = gnu(b, "vendor/gzip", &.{"./configure"}, makeinfo, texi2pdf);
    configure_gzip.step.dependOn(&bootstrap_gzip.step);
    const make_gzip = gnu(b, "vendor/gzip", &.{ "make", "-j4" }, makeinfo, texi2pdf);
    make_gzip.step.dependOn(&configure_gzip.step);
    const gzip_cmd = installOut(b, &make_gzip.step, "vendor/gzip/gzip", "gzip");

    const tar_check_bison = b.addSystemCommand(&.{ "sh", "-c", "if [ ! -x /opt/homebrew/opt/bison/bin/bison ]; then echo 'GNU tar build requires bison >= 2.4 (for example Homebrew bison); install it and retry' >&2; exit 1; fi" });
    const bootstrap_tar = gnu(b, "vendor/tar", &.{ "sh", "-c", "export PATH=\"/opt/homebrew/opt/bison/bin:$PATH\"; exec ./bootstrap --skip-po" }, makeinfo, texi2pdf);
    bootstrap_tar.step.dependOn(&write_dummy.step);
    bootstrap_tar.step.dependOn(&tar_check_bison.step);
    const configure_tar = gnu(b, "vendor/tar", &.{ "sh", "-c", "export PATH=\"/opt/homebrew/opt/bison/bin:$PATH\"; exec ./configure --disable-nls" }, makeinfo, texi2pdf);
    configure_tar.step.dependOn(&bootstrap_tar.step);
    const make_tar = gnu(b, "vendor/tar", &.{ "sh", "-c", "export PATH=\"/opt/homebrew/opt/bison/bin:$PATH\"; exec make -j4 LIBS=-liconv" }, makeinfo, texi2pdf);
    make_tar.step.dependOn(&configure_tar.step);
    const tar_cmd = installOut(b, &make_tar.step, "vendor/tar/src/tar", "tar");

    const libzip = cmake(b, "vendor/libzip", libzip_build_dir, &.{
        "-DBUILD_TOOLS=ON",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_DOC=OFF",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_REGRESS=OFF",
        "-DBUILD_OSSFUZZ=OFF",
    });
    const ziptool_cmd = installOut(b, &libzip.build.step, libzip_build_dir ++ "/src/ziptool", "ziptool");
    const libzip_lib = copyOut(b, &libzip.build.step, libzip_build_dir ++ "/lib/libzip.a", "liblibzip_a.a");

    const make_unrar_lib = b.addSystemCommand(&.{ "sh", "-c", "make clean && make -j4 lib" });
    make_unrar_lib.setCwd(b.path("vendor/unrar"));
    const copy_libunrar = b.addSystemCommand(&.{"cp"});
    copy_libunrar.addFileArg(b.path("vendor/unrar/libunrar.a"));
    copy_libunrar.step.dependOn(&make_unrar_lib.step);
    const libunrar_lib = copy_libunrar.addOutputFileArg("libunrar.a");
    const make_unrar_cmd = b.addSystemCommand(&.{ "sh", "-c", "make clean && make -j4" });
    make_unrar_cmd.setCwd(b.path("vendor/unrar"));
    make_unrar_cmd.step.dependOn(&copy_libunrar.step);
    const unrar_cmd = installOut(b, &make_unrar_cmd.step, "vendor/unrar/unrar", "unrar");

    const make_fl2 = b.addSystemCommand(&.{ "sh", "-c", "make -j4 $(ls *.c | sed 's/\\.c$/.o/')" });
    make_fl2.setCwd(b.path("vendor/fast-lzma2"));
    const archive_fl2 = b.addSystemCommand(&.{ "sh", "-c", "ar rcs \"$1\" vendor/fast-lzma2/*.o", "sh" });
    const fast_lzma2_lib = archive_fl2.addOutputFileArg("libfast-lzma2.a");
    archive_fl2.step.dependOn(&make_fl2.step);
    const install_fl2_lib = b.addInstallFileWithDir(fast_lzma2_lib, .{ .custom = "benchmark/build/fast-lzma2" }, "libfast-lzma2.a");
    const make_fl2_test = b.addSystemCommand(&.{ "make", "-j4", "CFLAGS=-Wall -O1 -pthread -I..", b.fmt("LIB={s}", .{b.pathFromRoot("zig-out/benchmark/build/fast-lzma2/libfast-lzma2.a")}) });
    make_fl2_test.setCwd(b.path("vendor/fast-lzma2/test"));
    make_fl2_test.step.dependOn(&install_fl2_lib.step);

    const make_lzma = make(b, "vendor/7zip/CPP/7zip/Bundles/LzmaCon", &.{ "make", "-f", "makefile.gcc", "-j4" });
    const lzma_cmd = installOut(b, &make_lzma.step, "vendor/7zip/CPP/7zip/Bundles/LzmaCon/_o/lzma", "lzma");

    const bin_refs = addBinaryRefs(b, ctx);

    return .{
        .sevenzz = sevenzz,
        .zstd_cmd = zstd_cmd,
        .zstd_lib = zstd_lib,
        .xz_cmd = xz_cmd,
        .xz_lib = xz_lib,
        .bzip2_cmd = bzip2_cmd,
        .bzip2_lib = bzip2_lib,
        .bzip2_lib_install = bzip2_lib_install,
        .gzip_cmd = gzip_cmd,
        .lzma_cmd = lzma_cmd,
        .tar_cmd = tar_cmd,
        .ziptool_cmd = ziptool_cmd,
        .libzip_lib = libzip_lib,
        .libzip_configure = libzip.configure,
        .libzip_build = libzip.build,
        .unrar_cmd = unrar_cmd,
        .libunrar_lib = libunrar_lib,
        .fast_lzma2_lib = fast_lzma2_lib,
        .fast_lzma2_test = make_fl2_test,
        .sevenzz_bin = bin_refs.sevenzz,
        .rar_bin = bin_refs.rar,
        .unrar_bin = bin_refs.unrar,
    };
}
