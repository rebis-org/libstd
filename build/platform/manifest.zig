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

pub const providers = [_][]const u8{ "onprem", "offprem", "mergeable" };

const host_entries = hostEntries();
const android_entries = androidEntries();
const apple_entries = appleEntries();
const cjpm_entries = cjpmEntries();

pub fn hostFor(comptime provider: []const u8) Distribution {
    return .{
        .id = "host",
        .archive = "libstd." ++ provider ++ ".zip",
        .header = "libstd/include/stdk.h",
        .catalog = "libstd/stdk.catalog.json",
        .entries = host_entries,
    };
}

pub fn androidFor(comptime provider: []const u8) Distribution {
    return .{
        .id = "android",
        .archive = "stdk." ++ provider ++ ".android.aar",
        .header = "include/stdk.h",
        .catalog = "assets/stdk.catalog.json",
        .entries = android_entries,
        .android = &slices.android_abis,
    };
}

pub fn appleFor(comptime provider: []const u8) Distribution {
    return .{
        .id = "apple",
        .archive = "StdK." ++ provider ++ ".apple.zip",
        .header = std.fmt.comptimePrint("StdK.xcframework/{s}/{s}/Headers/stdk.h", .{ slices.apple_slices[0].id, slices.framework_bundle }),
        .catalog = "StdK.xcframework/stdk.catalog.json",
        .entries = apple_entries,
        .apple = &slices.apple_slices,
    };
}

pub fn cjpmFor(comptime provider: []const u8) Distribution {
    return .{
        .id = "cjpm",
        .archive = "stdk." ++ provider ++ ".oh.zip",
        .header = "stdk/libs/include/stdk.h",
        .catalog = "stdk/stdk.catalog.json",
        .entries = cjpm_entries,
    };
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
    const count = 4 + slices.android_abis.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "AndroidManifest.xml";
        tmp[1] = "include/stdk.h";
        tmp[2] = "assets/stdk.catalog.json";
        tmp[3] = "classes.jar";
        inline for (slices.android_abis, 0..) |abi, index| tmp[4 + index] = abi.library;
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

fn cjpmEntries() []const []const u8 {
    const count = 4 + 2 * slices.ohos_abis.len;
    const entries: [count][]const u8 = blk: {
        var tmp: [count][]const u8 = undefined;
        tmp[0] = "stdk/cjpm.toml";
        tmp[1] = "stdk/src/stdk.cj";
        tmp[2] = "stdk/libs/include/stdk.h";
        tmp[3] = "stdk/stdk.catalog.json";
        inline for (slices.ohos_abis, 0..) |abi, index| {
            tmp[4 + 2 * index] = std.fmt.comptimePrint("stdk/libs/{s}/libstd.a", .{abi.triple});
            tmp[4 + 2 * index + 1] = std.fmt.comptimePrint("stdk/libs/{s}/libstd.so", .{abi.triple});
        }
        break :blk tmp;
    };
    return &entries;
}
