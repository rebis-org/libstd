const std = @import("std");

// The naming rule: `libstd` names the C ABI library archives; `stdk` names
// bundles. Segments are the std.Target tag names, hyphen-separated; the abi
// segment drops only when the form has one legal value (none), and the arch
// segment never drops — `universal` names every architecture of a form.
// `darwin` is the one family name: an XCFramework spans macos, ios, and
// maccatalyst, which no single Os.Tag names.
pub const Layout = enum { pe, elf, dylib, wasi, aar, cjpm, apple };

pub const FormSpec = struct {
    stem: []const u8,
    os: []const u8,
    abi: ?[]const u8 = null,
    layout: Layout,
    // Empty means the form is one bundle carrying every architecture.
    arches: []const []const u8 = &.{},
};

pub const specs = [_]FormSpec{
    .{ .stem = "libstd", .os = "macos", .layout = .dylib, .arches = &.{ "aarch64", "x86_64" } },
    .{ .stem = "libstd", .os = "linux", .abi = "gnu", .layout = .elf, .arches = &.{ "x86_64", "aarch64", "riscv64", "loongarch64" } },
    .{ .stem = "libstd", .os = "linux", .abi = "musl", .layout = .elf, .arches = &.{ "x86_64", "aarch64", "riscv64" } },
    .{ .stem = "libstd", .os = "windows", .abi = "gnu", .layout = .pe, .arches = &.{ "x86_64", "aarch64" } },
    .{ .stem = "libstd", .os = "windows", .abi = "msvc", .layout = .pe, .arches = &.{ "x86_64", "aarch64" } },
    .{ .stem = "libstd", .os = "freebsd", .layout = .elf, .arches = &.{ "x86_64", "aarch64" } },
    .{ .stem = "libstd", .os = "openbsd", .layout = .elf, .arches = &.{ "x86_64", "aarch64" } },
    .{ .stem = "libstd", .os = "wasi", .layout = .wasi, .arches = &.{"wasm32"} },
    .{ .stem = "stdk", .os = "darwin", .layout = .apple, .arches = &.{ "aarch64", "x86_64" } },
    .{ .stem = "stdk", .os = "linux", .abi = "android", .layout = .aar },
    .{ .stem = "stdk", .os = "linux", .abi = "ohos", .layout = .cjpm },
};

pub const TargetSlice = struct {
    arch: std.Target.Cpu.Arch,
    elf_machine: u16,
    pe_machine: u16,
};

pub const elf_x86_64: u16 = 62;
pub const elf_aarch64: u16 = 183;
pub const elf_riscv64: u16 = 243;
pub const elf_loongarch64: u16 = 258;
pub const elf_arm: u16 = 40;
pub const elf_x86: u16 = 3;

pub const slices = [_]TargetSlice{
    .{ .arch = .x86_64, .elf_machine = elf_x86_64, .pe_machine = 0x8664 },
    .{ .arch = .aarch64, .elf_machine = elf_aarch64, .pe_machine = 0xAA64 },
    .{ .arch = .riscv64, .elf_machine = elf_riscv64, .pe_machine = 0 },
    .{ .arch = .loongarch64, .elf_machine = elf_loongarch64, .pe_machine = 0 },
    .{ .arch = .arm, .elf_machine = elf_arm, .pe_machine = 0 },
    .{ .arch = .x86, .elf_machine = elf_x86, .pe_machine = 0 },
    .{ .arch = .wasm32, .elf_machine = 0, .pe_machine = 0 },
};

pub fn pickSlices(comptime os_tag: std.Target.Os.Tag, comptime abi: ?std.Target.Abi, comptime arch: ?[]const u8) []const TargetSlice {
    comptime {
        const os_arches: []const []const u8 = switch (os_tag) {
            .linux => if (abi == .musl) &.{ "x86_64", "aarch64", "riscv64" } else if (abi == .ohos) &.{ "x86_64", "aarch64" } else &.{ "x86_64", "aarch64", "riscv64", "loongarch64" },
            .windows, .freebsd, .openbsd, .macos => &.{ "x86_64", "aarch64" },
            .wasi => &.{"wasm32"},
            else => @compileError("no slice table for " ++ @tagName(os_tag)),
        };
        var chosen: [slices.len]TargetSlice = undefined;
        var n: usize = 0;
        for (&slices) |*slice| {
            for (os_arches) |name| {
                if (std.mem.eql(u8, @tagName(slice.arch), name)) {
                    chosen[n] = slice.*;
                    n += 1;
                }
            }
        }
        if (arch) |a| {
            for (chosen[0..n]) |slice| {
                if (std.mem.eql(u8, @tagName(slice.arch), a)) return &.{slice};
            }
            @compileError("unknown arch: " ++ a);
        }
        return chosen[0..n];
    }
}

pub fn sliceFor(comptime arch: []const u8) *const TargetSlice {
    comptime {
        for (&slices) |*entry| {
            if (std.mem.eql(u8, @tagName(entry.arch), arch)) return entry;
        }
        @compileError("unknown arch: " ++ arch);
    }
}

// android's zip paths follow NDK branding; the library targets use the strict
// abi tags (32-bit arm rides softfp).
pub const AndroidAbi = struct { zip_path: []const u8, slice: *const TargetSlice, abi: std.Target.Abi };
pub const android_abis = [_]AndroidAbi{
    .{ .zip_path = "jni/arm64-v8a/libstd.so", .slice = sliceFor("aarch64"), .abi = .android },
    .{ .zip_path = "jni/x86_64/libstd.so", .slice = sliceFor("x86_64"), .abi = .android },
    .{ .zip_path = "jni/armeabi-v7a/libstd.so", .slice = sliceFor("arm"), .abi = .androideabi },
    .{ .zip_path = "jni/x86/libstd.so", .slice = sliceFor("x86"), .abi = .android },
};

pub const OhosAbi = struct { triple: []const u8, slice: *const TargetSlice };
pub const ohos_abis = [_]OhosAbi{
    .{ .triple = "aarch64-linux-ohos", .slice = sliceFor("aarch64") },
    .{ .triple = "x86_64-linux-ohos", .slice = sliceFor("x86_64") },
};

pub const AppleArch = struct {
    arch: std.Target.Cpu.Arch,
    os: std.Target.Os.Tag,
    abi: ?std.Target.Abi = null,
    os_version_min: ?std.SemanticVersion = null,
    zig: bool = false,
    sdk: []const u8 = "",
    triple: []const u8 = "",
};

pub const AppleSlice = struct {
    id: []const u8,
    library: []const u8,
    platform: []const u8,
    minimum: []const u8,
    arches: []const AppleArch,
};

pub const apple_slices = [_]AppleSlice{
    .{ .id = "ios-arm64", .library = "ios.dylib", .platform = "IOS", .minimum = "16.0", .arches = &.{
        .{ .arch = .aarch64, .os = .ios, .os_version_min = .{ .major = 16, .minor = 0, .patch = 0 }, .sdk = "iphoneos", .triple = "arm64-apple-ios16.0" },
    } },
    .{ .id = "ios-arm64_x86_64-simulator", .library = "ios_sim.dylib", .platform = "IOSSIMULATOR", .minimum = "16.0", .arches = &.{
        .{ .arch = .aarch64, .os = .ios, .abi = .simulator, .os_version_min = .{ .major = 16, .minor = 0, .patch = 0 }, .sdk = "iphonesimulator", .triple = "arm64-apple-ios16.0-simulator" },
        .{ .arch = .x86_64, .os = .ios, .abi = .simulator, .os_version_min = .{ .major = 16, .minor = 0, .patch = 0 }, .sdk = "iphonesimulator", .triple = "x86_64-apple-ios16.0-simulator" },
    } },
    .{ .id = "macos-arm64_x86_64", .library = "macos.dylib", .platform = "MACOS", .minimum = "13.0", .arches = &.{
        .{ .arch = .aarch64, .os = .macos, .os_version_min = .{ .major = 13, .minor = 0, .patch = 0 }, .sdk = "macosx", .triple = "arm64-apple-macos13.0" },
        .{ .arch = .x86_64, .os = .macos, .os_version_min = .{ .major = 13, .minor = 0, .patch = 0 }, .sdk = "macosx", .triple = "x86_64-apple-macos13.0" },
    } },
    .{ .id = "ios-arm64_x86_64-maccatalyst", .library = "catalyst.dylib", .platform = "MACCATALYST", .minimum = "16.0", .arches = &.{
        .{ .arch = .aarch64, .os = .maccatalyst, .os_version_min = .{ .major = 16, .minor = 0, .patch = 0 }, .zig = true },
        .{ .arch = .x86_64, .os = .maccatalyst, .os_version_min = .{ .major = 16, .minor = 0, .patch = 0 }, .zig = true },
    } },
};

// watchOS is blocked: arm64_32 has no 0.17 backend, and aarch64-watchos
// clamps floors to 26.0, failing the package gate.

pub const framework_bundle = "stdk.framework";
pub const framework_binary = "StdK";
pub const framework_install_name = "@rpath/stdk.framework/StdK";

pub fn isMacos(slice: AppleSlice) bool {
    return std.mem.eql(u8, slice.platform, "MACOS");
}

pub fn libraryEntry(slice: AppleSlice) []const u8 {
    // macOS frameworks are versioned bundles: the binary lives under
    // Versions/A and the bundle root holds symlinks only.
    if (isMacos(slice)) return framework_bundle ++ "/Versions/A/" ++ framework_binary;
    return framework_bundle ++ "/" ++ framework_binary;
}

pub fn archSlices(comptime arch: []const u8) []const AppleSlice {
    if (comptime std.mem.eql(u8, arch, "aarch64")) return aarch64_slices.items[0..aarch64_slices.len];
    if (comptime std.mem.eql(u8, arch, "x86_64")) return x86_64_slices.items[0..x86_64_slices.len];
    @compileError("unknown darwin arch: " ++ arch);
}

const aarch64_slices = filterSlices(.aarch64);
const x86_64_slices = filterSlices(.x86_64);

const SliceSet = struct { items: [apple_slices.len]AppleSlice, len: usize };

fn filterSlices(comptime arch: std.Target.Cpu.Arch) SliceSet {
    comptime {
        @setEvalBranchQuota(200_000);
        var list: [apple_slices.len]AppleSlice = undefined;
        var n: usize = 0;
        for (apple_slices) |slice| {
            var has = false;
            for (slice.arches) |a| {
                if (a.arch == arch) has = true;
            }
            if (has) {
                list[n] = slice;
                n += 1;
            }
        }
        return .{ .items = list, .len = n };
    }
}

pub const Distribution = struct {
    id: []const u8,
    archive: []const u8,
    header: []const u8,
    catalog: []const u8,
    entries: []const []const u8,
    apple: ?[]const AppleSlice = null,
};

pub const providers = [_][]const u8{ "onprem", "offprem", "mergeable" };

pub fn forms(comptime provider: []const u8) []const Distribution {
    if (comptime std.mem.eql(u8, provider, "onprem")) return &onprem_forms;
    if (comptime std.mem.eql(u8, provider, "offprem")) return &offprem_forms;
    if (comptime std.mem.eql(u8, provider, "mergeable")) return &mergeable_forms;
    @compileError("unknown provider: " ++ provider);
}

const onprem_forms = buildForms("onprem");
const offprem_forms = buildForms("offprem");
const mergeable_forms = buildForms("mergeable");

fn buildForms(comptime provider: []const u8) [countForms()]Distribution {
    comptime {
        @setEvalBranchQuota(1_000_000);
        var list: [countForms()]Distribution = undefined;
        var n: usize = 0;
        for (&specs) |*spec| {
            list[n] = makeForm(provider, spec, null);
            n += 1;
            // A single-architecture form has no per-arch twin: universal is
            // already the exact archive.
            if (spec.arches.len > 1) {
                for (spec.arches) |arch| {
                    list[n] = makeForm(provider, spec, arch);
                    n += 1;
                }
            }
        }
        return list;
    }
}

fn countForms() usize {
    comptime {
        var n: usize = 0;
        for (specs) |spec| n += 1 + (if (spec.arches.len > 1) spec.arches.len else 0);
        return n;
    }
}

fn makeForm(comptime provider: []const u8, comptime spec: *const FormSpec, comptime arch: ?[]const u8) Distribution {
    const id = if (arch) |a|
        spec.os ++ (if (spec.abi) |abi| "." ++ abi else "") ++ "." ++ a
    else if (spec.arches.len == 0)
        spec.os ++ (if (spec.abi) |abi| "." ++ abi else "")
    else
        spec.os ++ (if (spec.abi) |abi| "." ++ abi else "") ++ ".universal";
    const arch_segment = if (arch) |a| a else "universal";
    return .{
        .id = id,
        .archive = spec.stem ++ "-" ++ provider ++ "-" ++ spec.os ++ (if (spec.abi) |abi| "-" ++ abi else "") ++ "-" ++ arch_segment,
        .header = switch (spec.layout) {
            .apple => comptime std.fmt.comptimePrint("stdk.xcframework/{s}/{s}/Headers/stdk.h", .{ (if (arch) |a| archSlices(a) else &apple_slices)[0].id, framework_bundle }),
            .aar => "include/stdk.h",
            .cjpm => "stdk/libs/include/stdk.h",
            else => "libstd/include/stdk.h",
        },
        .catalog = switch (spec.layout) {
            .apple => "stdk.xcframework/stdk.catalog.json",
            .aar => "assets/stdk.catalog.json",
            .cjpm => "stdk/stdk.catalog.json",
            else => "libstd/stdk.catalog.json",
        },
        .entries = makeEntries(spec, arch),
        .apple = if (spec.layout == .apple) (if (arch) |a| archSlices(a) else &apple_slices) else null,
    };
}

fn makeEntries(comptime spec: *const FormSpec, comptime arch: ?[]const u8) []const []const u8 {
    const arch_list: []const []const u8 = if (arch) |a| &.{a} else if (spec.arches.len == 0) &.{"universal"} else spec.arches;
    return switch (spec.layout) {
        .pe => libstdEntries(arch_list, &.{
            "libstd/lib/{s}/std.lib",
            "libstd/bin/{s}/std.dll",
            "libstd/import/{s}/" ++ (if (std.mem.eql(u8, spec.abi.?, "msvc")) "std.lib" else "std.dll.a"),
        }),
        .elf => libstdEntries(arch_list, &.{ "libstd/lib/{s}/libstd.a", "libstd/lib/{s}/libstd.so" }),
        .dylib => libstdEntries(arch_list, &.{ "libstd/lib/{s}/libstd.a", "libstd/lib/{s}/libstd.dylib" }),
        .wasi => wasiEntries(),
        .aar => aarEntries(),
        .cjpm => cjpmEntries(),
        .apple => appleEntries(if (arch) |a| archSlices(a) else &apple_slices),
    };
}

const libstd_tree = [_][]const u8{
    "libstd/include/stdk.h",
    "libstd/include/module.modulemap",
    "libstd/lib/pkgconfig/libstd.pc",
    "libstd/stdk.catalog.json",
};

// Every libstd layout appends per-arch files from one template list.
fn libstdEntries(comptime arch_ids: []const []const u8, comptime per_arch: []const []const u8) []const []const u8 {
    comptime {
        const entries = blk: {
            var list: [libstd_tree.len + per_arch.len * arch_ids.len][]const u8 = undefined;
            for (libstd_tree, 0..) |entry, index| list[index] = entry;
            for (arch_ids, 0..) |arch_id, index| {
                for (per_arch, 0..) |template, offset| {
                    list[libstd_tree.len + index * per_arch.len + offset] = std.fmt.comptimePrint(template, .{arch_id});
                }
            }
            break :blk list;
        };
        return &entries;
    }
}

fn wasiEntries() []const []const u8 {
    const entries: [libstd_tree.len + 1][]const u8 = blk: {
        var list: [libstd_tree.len + 1][]const u8 = undefined;
        for (libstd_tree, 0..) |entry, i| list[i] = entry;
        list[libstd_tree.len] = "libstd/lib/wasm32/libstd.a";
        break :blk list;
    };
    return &entries;
}

fn aarEntries() []const []const u8 {
    const count = 4 + android_abis.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "AndroidManifest.xml";
        tmp[1] = "include/stdk.h";
        tmp[2] = "assets/stdk.catalog.json";
        tmp[3] = "classes.jar";
        inline for (android_abis, 0..) |abi, index| tmp[4 + index] = abi.zip_path;
        break :blk tmp;
    };
    return &entries;
}

const apple_entries_per_slice = 5;

fn appleEntries(comptime slices_list: []const AppleSlice) []const []const u8 {
    const count = 2 + apple_entries_per_slice * slices_list.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "stdk.xcframework/Info.plist";
        tmp[1] = "stdk.xcframework/stdk.catalog.json";
        inline for (slices_list, 0..) |slice, index| {
            const root = comptime "stdk.xcframework/" ++ slice.id ++ "/" ++ framework_bundle;
            const prefix = comptime if (isMacos(slice)) "Versions/A/" else "";
            tmp[2 + apple_entries_per_slice * index] = root ++ "/" ++ prefix ++ framework_binary;
            tmp[2 + apple_entries_per_slice * index + 1] = root ++ "/" ++ prefix ++ "Headers/stdk.h";
            tmp[2 + apple_entries_per_slice * index + 2] = root ++ "/" ++ prefix ++ "Headers/module.modulemap";
            tmp[2 + apple_entries_per_slice * index + 3] = root ++ "/" ++ prefix ++ "Modules/module.modulemap";
            tmp[2 + apple_entries_per_slice * index + 4] = if (isMacos(slice)) root ++ "/Versions/A/Resources/Info.plist" else root ++ "/Info.plist";
        }
        break :blk tmp;
    };
    return &entries;
}

const cjpm_entries_per_abi = 2;

fn cjpmEntries() []const []const u8 {
    const count = 4 + cjpm_entries_per_abi * ohos_abis.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "stdk/cjpm.toml";
        tmp[1] = "stdk/src/stdk.cj";
        tmp[2] = "stdk/libs/include/stdk.h";
        tmp[3] = "stdk/stdk.catalog.json";
        inline for (ohos_abis, 0..) |abi, index| {
            tmp[4 + cjpm_entries_per_abi * index] = "stdk/libs/" ++ abi.triple ++ "/libstd.a";
            tmp[4 + cjpm_entries_per_abi * index + 1] = "stdk/libs/" ++ abi.triple ++ "/libstd.so";
        }
        break :blk tmp;
    };
    return &entries;
}
