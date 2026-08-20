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
    .{ .id = "ios-arm64", .library = "ios.dylib", .platform = "IOS", .minimum = "15.0", .arches = &.{
        .{ .arch = .aarch64, .os = .ios, .sdk = "iphoneos", .triple = "arm64-apple-ios15.0" },
    } },
    .{ .id = "ios-arm64_x86_64-simulator", .library = "ios_sim.dylib", .platform = "IOSSIMULATOR", .minimum = "15.0", .arches = &.{
        .{ .arch = .aarch64, .os = .ios, .abi = .simulator, .sdk = "iphonesimulator", .triple = "arm64-apple-ios15.0-simulator" },
        .{ .arch = .x86_64, .os = .ios, .abi = .simulator, .sdk = "iphonesimulator", .triple = "x86_64-apple-ios15.0-simulator" },
    } },
    .{ .id = "macos-arm64_x86_64", .library = "macos.dylib", .platform = "MACOS", .minimum = "12.0", .arches = &.{
        .{ .arch = .aarch64, .os = .macos, .os_version_min = .{ .major = 12, .minor = 0, .patch = 0 }, .sdk = "macosx", .triple = "arm64-apple-macos12.0" },
        .{ .arch = .x86_64, .os = .macos, .os_version_min = .{ .major = 12, .minor = 0, .patch = 0 }, .sdk = "macosx", .triple = "x86_64-apple-macos12.0" },
    } },
    .{ .id = "ios-arm64_x86_64-maccatalyst", .library = "catalyst.dylib", .platform = "MACCATALYST", .minimum = "15.0", .arches = &.{
        .{ .arch = .aarch64, .os = .maccatalyst, .os_version_min = .{ .major = 15, .minor = 0, .patch = 0 }, .zig = true },
        .{ .arch = .x86_64, .os = .maccatalyst, .os_version_min = .{ .major = 15, .minor = 0, .patch = 0 }, .zig = true },
    } },
    .{ .id = "tvos-arm64", .library = "tvos.dylib", .platform = "TVOS", .minimum = "15.0", .arches = &.{
        .{ .arch = .aarch64, .os = .tvos, .sdk = "appletvos", .triple = "arm64-apple-tvos15.0" },
    } },
    .{ .id = "tvos-arm64_x86_64-simulator", .library = "tvos_sim.dylib", .platform = "TVOSSIMULATOR", .minimum = "15.0", .arches = &.{
        .{ .arch = .aarch64, .os = .tvos, .abi = .simulator, .sdk = "appletvsimulator", .triple = "arm64-apple-tvos15.0-simulator" },
        .{ .arch = .x86_64, .os = .tvos, .abi = .simulator, .sdk = "appletvsimulator", .triple = "x86_64-apple-tvos15.0-simulator" },
    } },
};

pub const AndroidAbi = struct {
    library: []const u8,
    arch: std.Target.Cpu.Arch,
    elf_machine: u16,
};

pub const android_abis = [_]AndroidAbi{
    .{ .library = "jni/arm64-v8a/libstd.so", .arch = .aarch64, .elf_machine = 183 },
    .{ .library = "jni/x86_64/libstd.so", .arch = .x86_64, .elf_machine = 62 },
};
