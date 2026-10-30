const std = @import("std");

fn forceAllDecls(comptime module: type) void {
    inline for (comptime std.meta.declarations(module)) |name| {
        _ = @field(module, name);
    }
}

const forced_modules = [_][]const u8{
    "compose/api.zig",
    "compose/archive.zig",
    "compose/call.zig",
    "compose/drivers.zig",
    "compose/transform.zig",
    "kernel/node.zig",
};

comptime {
    forceAllDecls(@import("compose/api.zig"));
    forceAllDecls(@import("compose/archive.zig"));
    forceAllDecls(@import("compose/call.zig"));
    forceAllDecls(@import("compose/drivers.zig"));
    forceAllDecls(@import("compose/transform.zig"));
    forceAllDecls(@import("interface").lease);
    forceAllDecls(@import("kernel/node.zig"));
}

pub fn main(init: std.process.Init) !void {
    if (forced_modules.len == 0) return error.EmptyAnalysisSet;
    var buffer: [160]u8 = undefined;
    var writer: std.Io.Writer = std.Io.Writer.fixed(&buffer);
    try writer.print("analyze: {d} modules forced.\n", .{forced_modules.len});
    try std.Io.File.stdout().writeStreamingAll(init.io, writer.buffered());
}
