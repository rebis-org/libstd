const std = @import("std");

fn forceAllDecls(comptime module: type) void {
    inline for (comptime std.meta.declarations(module)) |name| {
        _ = @field(module, name);
    }
}

// Module types, not path strings: @import takes literals only, so the
// list drives both the comptime forcing and the printed count. interface.lease
// stays forced separately, outside the counted set.
const forced_modules = .{
    @import("compose/api.zig"),
    @import("compose/archive.zig"),
    @import("compose/call.zig"),
    @import("compose/drivers.zig"),
    @import("compose/transform.zig"),
    @import("kernel/node.zig"),
};

comptime {
    for (forced_modules) |module| forceAllDecls(module);
    forceAllDecls(@import("interface").lease);
}

pub fn main(init: std.process.Init) !void {
    if (forced_modules.len == 0) return error.EmptyAnalysisSet;
    var buffer: [160]u8 = undefined;
    var writer: std.Io.Writer = std.Io.Writer.fixed(&buffer);
    try writer.print("analyze: {d} modules forced.\n", .{forced_modules.len});
    try std.Io.File.stdout().writeStreamingAll(init.io, writer.buffered());
}
