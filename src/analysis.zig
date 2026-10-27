const std = @import("std");

fn forceAllDecls(comptime module: type) void {
    inline for (comptime std.meta.declarations(module)) |name| {
        _ = @field(module, name);
    }
}

test "force-analyze the compose and kernel audit-touched modules" {
    comptime {
        forceAllDecls(@import("compose/api.zig"));
        forceAllDecls(@import("compose/archive.zig"));
        forceAllDecls(@import("compose/call.zig"));
        forceAllDecls(@import("compose/drivers.zig"));
        forceAllDecls(@import("compose/transform.zig"));
        forceAllDecls(@import("interface").lease);
        forceAllDecls(@import("kernel/node.zig"));
    }
}
