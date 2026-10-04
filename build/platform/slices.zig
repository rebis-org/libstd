const std = @import("std");

pub const AppleSlice = struct {
    id: []const u8,
    library: []const u8,
    platform: []const u8,
    minimum: []const u8,
    arches: []const AppleArch,
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

// Only iOS, iOS Simulator, macOS, and Mac Catalyst ship. tvOS and visionOS
// are omitted for now. watchOS is blocked: its device slice needs arm64_32, which Zig
// 0.17 has no backend for, and aarch64-watchos clamps any floor below 26.0
// up to minos 26.0, so no v9 slice can pass the package gate.

pub const framework_bundle = "StdK.framework";
pub const framework_binary = "StdK";
pub const framework_install_name = "@rpath/StdK.framework/StdK";

// Every Apple slice ships as a framework bundle: App Store validation rejects
// loose dylibs inside an iOS/tvOS/Catalyst app bundle, and create-xcframework
// refuses an XCFramework that mixes frameworks with bare libraries.
pub fn isMacos(slice: AppleSlice) bool {
    return std.mem.eql(u8, slice.platform, "MACOS");
}

pub fn libraryEntry(slice: AppleSlice) []const u8 {
    // macOS frameworks are versioned bundles: the binary lives under
    // Versions/A and the bundle root holds symlinks only.
    if (isMacos(slice)) return framework_bundle ++ "/Versions/A/" ++ framework_binary;
    return framework_bundle ++ "/" ++ framework_binary;
}

pub const AndroidAbi = struct {
    library: []const u8,
    arch: std.Target.Cpu.Arch,
    elf_machine: u16,
};

pub const android_abis = [_]AndroidAbi{
    .{ .library = "jni/arm64-v8a/libstd.so", .arch = .aarch64, .elf_machine = 183 },
    .{ .library = "jni/x86_64/libstd.so", .arch = .x86_64, .elf_machine = 62 },
};

// HarmonyOS (OHOS) targets for the cjpm package: cjc names these
// aarch64-linux-ohos / x86_64-linux-ohos (see cjc cross-compilation docs).
pub const OhosAbi = struct {
    triple: []const u8,
    arch: std.Target.Cpu.Arch,
    elf_machine: u16,
};

pub const ohos_abis = [_]OhosAbi{
    .{ .triple = "aarch64-linux-ohos", .arch = .aarch64, .elf_machine = 183 },
    .{ .triple = "x86_64-linux-ohos", .arch = .x86_64, .elf_machine = 62 },
};
