const std = @import("std");

pub const slices = @import("slices.zig");

pub const Distribution = struct {
    id: []const u8,
    archive: []const u8,
    header: []const u8,
    catalog: []const u8,
    entries: []const []const u8,
    apple: ?[]const slices.AppleSlice = null,
    android: ?[]const slices.AndroidAbi = null,
};

pub const host: Distribution = .{
    .id = "host",
    .archive = "libstd.zip",
    .header = "libstd/include/stdk.h",
    .catalog = "libstd/stdk.catalog.json",
    .entries = hostEntries(),
};

pub const android: Distribution = .{
    .id = "android",
    .archive = "stdk.aar",
    .header = "include/stdk.h",
    .catalog = "assets/stdk.catalog.json",
    .entries = androidEntries(),
    .android = &slices.android_abis,
};

pub const apple: Distribution = .{
    .id = "apple",
    .archive = "StdK.XCFramework.zip",
    .header = std.fmt.comptimePrint("StdK.xcframework/{s}/{s}/Headers/stdk.h", .{ slices.apple_slices[0].id, slices.framework_bundle }),
    .catalog = "StdK.xcframework/stdk.catalog.json",
    .entries = appleEntries(),
    .apple = &slices.apple_slices,
};

pub fn versionCode(version: std.SemanticVersion) u32 {
    return @intCast(version.major * 1_000_000 + version.minor * 1_000 + version.patch);
}

fn hostEntries() []const []const u8 {
    const entries: [5][]const u8 = .{
        "libstd/include/stdk.h",
        "libstd/include/module.modulemap",
        "libstd/lib/libstd.a",
        "libstd/lib/libstd.dylib",
        "libstd/stdk.catalog.json",
    };
    return &entries;
}

fn androidEntries() []const []const u8 {
    const count = 3 + slices.android_abis.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "AndroidManifest.xml";
        tmp[1] = "include/stdk.h";
        tmp[2] = "assets/stdk.catalog.json";
        inline for (slices.android_abis, 0..) |abi, index| tmp[3 + index] = abi.library;
        break :blk tmp;
    };
    return &entries;
}

fn appleEntries() []const []const u8 {
    const count = 2 + 5 * slices.apple_slices.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "StdK.xcframework/Info.plist";
        tmp[1] = "StdK.xcframework/stdk.catalog.json";
        inline for (slices.apple_slices, 0..) |slice, index| {
            const root = std.fmt.comptimePrint("StdK.xcframework/{s}/{s}", .{ slice.id, slices.framework_bundle });
            if (slices.isMacos(slice)) {
                tmp[2 + 5 * index] = root ++ "/Versions/A/" ++ slices.framework_binary;
                tmp[2 + 5 * index + 1] = root ++ "/Versions/A/Headers/stdk.h";
                tmp[2 + 5 * index + 2] = root ++ "/Versions/A/Headers/module.modulemap";
                tmp[2 + 5 * index + 3] = root ++ "/Versions/A/Modules/module.modulemap";
                tmp[2 + 5 * index + 4] = root ++ "/Versions/A/Resources/Info.plist";
            } else {
                tmp[2 + 5 * index] = root ++ "/" ++ slices.framework_binary;
                tmp[2 + 5 * index + 1] = root ++ "/Headers/stdk.h";
                tmp[2 + 5 * index + 2] = root ++ "/Headers/module.modulemap";
                tmp[2 + 5 * index + 3] = root ++ "/Modules/module.modulemap";
                tmp[2 + 5 * index + 4] = root ++ "/Info.plist";
            }
        }
        break :blk tmp;
    };
    return &entries;
}
