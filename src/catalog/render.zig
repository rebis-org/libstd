const std = @import("std");

const abi = @import("../abi/contract.zig");
const registry = @import("registry.zig");

pub const catalog = renderCatalog();
pub const header = renderHeader();
pub const module_map = renderModuleMap();

fn renderCatalog() []const u8 {
    comptime {
        var descriptors: []const u8 = "";
        for (registry.sorted_descriptors, 0..) |descriptor, index| {
            descriptors = descriptors ++ std.fmt.comptimePrint(
                "    {{" ++
                    "\"id\":{{\"low\":\"0x{x:0>16}\",\"high\":\"0x{x:0>16}\"}}," ++
                    "\"name\":\"{s}\"," ++
                    "\"kind\":\"{s}\"," ++
                    "\"representation\":\"{s}\"," ++
                    "\"cardinality\":\"{s}\"," ++
                    "\"direction\":\"{s}\"," ++
                    "\"command_mask\":{d}," ++
                    "\"capability\":\"{s}\"," ++
                    "\"capability_mask\":{d}," ++
                    "\"planning\":\"{s}\"," ++
                    "\"delivery\":\"{s}\"}}{s}\n",
                .{
                    descriptor.id.low,
                    descriptor.id.high,
                    descriptor.name,
                    @tagName(descriptor.kind),
                    @tagName(descriptor.representation),
                    @tagName(descriptor.cardinality),
                    @tagName(descriptor.direction),
                    descriptor.command_mask,
                    @tagName(descriptor.capability),
                    descriptor.capability_mask,
                    @tagName(descriptor.planning),
                    @tagName(descriptor.delivery),
                    if (index + 1 == registry.sorted_descriptors.len) "" else ",",
                },
            );
        }
        return "{\n" ++ "  \"epoch\": 3,\n" ++ "  \"parameter_selector\": \"value_high: family(16)|ordinal(32)|attrs(8)|flags(8); value_low: scalar value\",\n" ++ "  \"descriptors\": [\n" ++ descriptors ++ "  ]\n}\n";
    }
}

fn renderHeader() []const u8 {
    comptime {
        var statuses: []const u8 = "#define STDK_ABI_EPOCH UINT32_C(3)\n";
        for (abi.Status.definitions) |status| statuses = statuses ++ std.fmt.comptimePrint("#define STDK_STATUS_{s} UINT32_C({d})\n", .{ status.name, status.value });
        const layouts = std.fmt.comptimePrint("#define STDK_SIZEOF_ID UINT32_C({d})\n#define STDK_SIZEOF_NODE UINT32_C({d})\n#define STDK_SIZEOF_CALL UINT32_C({d})\n", .{ @sizeOf(abi.Id), @sizeOf(abi.Node), @sizeOf(abi.Call) });
        const assertions = std.fmt.comptimePrint("STDK_STATIC_ASSERT(sizeof(stdk_id) == {d}, \"stdk_id size\");\nSTDK_STATIC_ASSERT(offsetof(stdk_call_envelope, operation) == {d}, \"stdk_call operation offset\");\nSTDK_STATIC_ASSERT(offsetof(stdk_node, id) == {d}, \"stdk_node ID offset\");\n", .{ @sizeOf(abi.Id), @offsetOf(abi.Call, "operation"), @offsetOf(abi.Node, "id") });
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

const TemplateValue = struct { marker: []const u8, value: []const u8 };

fn renderTemplate(comptime template: []const u8, comptime values: []const TemplateValue) []const u8 {
    var output = template;
    inline for (values) |replacement| {
        const index = std.mem.indexOf(u8, output, replacement.marker) orelse @compileError("template marker is missing");
        if (std.mem.indexOfPos(u8, output, index + replacement.marker.len, replacement.marker) != null) @compileError("template marker must be unique");
        output = output[0..index] ++ replacement.value ++ output[index + replacement.marker.len ..];
    }
    if (std.mem.indexOf(u8, output, "@STDK_") != null) @compileError("template has an unresolved standard-kit marker");
    return output;
}
