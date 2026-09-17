const std = @import("std");

const abi = @import("envelope.zig");

// Rendered from frozen ABI and assembled descriptors, so header, artifact, and kernel always agree.

pub const header = renderHeader();
pub const module_map = renderModuleMap();
// A module map sealed in a framework bundle's Modules/ directory must declare
// a framework module or clang skips the umbrella header.
pub const framework_module_map = renderFrameworkModuleMap();

fn renderHeader() []const u8 {
    comptime {
        var statuses: []const u8 = "#define STDK_ABI_EPOCH UINT32_C(7)\n";
        for (abi.Status.definitions) |status| statuses = statuses ++ std.fmt.comptimePrint("#define STDK_STATUS_{s} UINT32_C({d})\n", .{ status.name, status.value });
        const layouts = std.fmt.comptimePrint("#define STDK_SIZEOF_ID UINT32_C({d})\n#define STDK_SIZEOF_NODE UINT32_C({d})\n#define STDK_SIZEOF_CALL UINT32_C({d})\n", .{ @sizeOf(abi.Id), @sizeOf(abi.Node), @sizeOf(abi.Call) });
        const assertions = std.fmt.comptimePrint("STDK_STATIC_ASSERT(sizeof(stdk_id) == {d}, \"stdk_id size mismatch\");\nSTDK_STATIC_ASSERT(offsetof(stdk_call_envelope, operation) == {d}, \"stdk_call operation offset mismatch\");\nSTDK_STATIC_ASSERT(offsetof(stdk_node, id) == {d}, \"stdk_node ID offset mismatch\");\n", .{ @sizeOf(abi.Id), @offsetOf(abi.Call, "operation"), @offsetOf(abi.Node, "id") });
        const call = "uint32_t stdk_call(stdk_call_envelope* call);";
        return renderTemplate(@embedFile("stdk.h.in"), &.{
            .{ .marker = "@STDK_STATUS@", .value = statuses },
            .{ .marker = "@STDK_LAYOUT@", .value = layouts },
            .{ .marker = "@STDK_ASSERT@", .value = assertions },
            .{ .marker = "@STDK_CALL@", .value = call },
        });
    }
}

fn renderModuleMap() []const u8 {
    return renderTemplate(@embedFile("../../build/templates/module.modulemap.in"), &.{
        .{ .marker = "@STDK_MODULE_NAME@", .value = "StdK" },
    });
}

fn renderFrameworkModuleMap() []const u8 {
    return renderTemplate(@embedFile("../../build/templates/module.framework.modulemap.in"), &.{
        .{ .marker = "@STDK_MODULE_NAME@", .value = "StdK" },
    });
}

const TemplateValue = struct { marker: []const u8, value: []const u8 };

fn renderTemplate(comptime template: []const u8, comptime values: []const TemplateValue) []const u8 {
    var output = template;
    inline for (values) |replacement| {
        const index = std.mem.indexOf(u8, output, replacement.marker) orelse @compileError("Header template marker is missing.");
        if (std.mem.indexOfPos(u8, output, index + replacement.marker.len, replacement.marker) != null) @compileError("Header template marker must be unique.");
        output = output[0..index] ++ replacement.value ++ output[index + replacement.marker.len ..];
    }
    if (std.mem.indexOf(u8, output, "@STDK_") != null) @compileError("template has an unresolved standard-kit marker");
    return output;
}
