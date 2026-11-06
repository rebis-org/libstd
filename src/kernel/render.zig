const std = @import("std");

const abi = @import("envelope.zig");

// Rendered from frozen ABI and assembled descriptors, so header, artifact, and kernel always agree.

pub const header = renderHeader();
pub const module_map = renderModuleMap();
// A Modules/ module map must declare a framework module, or clang skips
// the umbrella header.
pub const framework_module_map = renderFrameworkModuleMap();

fn renderHeader() []const u8 {
    comptime {
        var statuses: []const u8 = "#define STDK_ABI_EPOCH UINT32_C(9)\n";
        for (abi.Status.definitions) |status| statuses = statuses ++ std.fmt.comptimePrint("#define STDK_STATUS_{s} UINT32_C({d})\n", .{ status.name, status.value });
        const layouts = std.fmt.comptimePrint("#define STDK_SIZEOF_ID UINT32_C({d})\n#define STDK_SIZEOF_NODE UINT32_C({d})\n#define STDK_SIZEOF_CALL UINT32_C({d})\n", .{ @sizeOf(abi.Id), @sizeOf(abi.Node), @sizeOf(abi.Call) });
        const assertions = std.fmt.comptimePrint("STDK_STATIC_ASSERT(sizeof(stdk_id) == {d}, \"stdk_id size mismatch: the ABI fixes 16 bytes\");\nSTDK_STATIC_ASSERT(offsetof(stdk_call_envelope, operation) == {d}, \"stdk_call operation offset mismatch: the ABI fixes offset 8\");\nSTDK_STATIC_ASSERT(offsetof(stdk_node, id) == {d}, \"stdk_node id offset mismatch: the ABI fixes offset 8\");\n", .{ @sizeOf(abi.Id), @offsetOf(abi.Call, "operation"), @offsetOf(abi.Node, "id") });
        const call = "uint32_t stdk_call(stdk_call_envelope* call);";
        return substitute(@embedFile("stdk.h.in"), &.{
            .{ .marker = "@STDK_STATUS@", .value = statuses },
            .{ .marker = "@STDK_LAYOUT@", .value = layouts },
            .{ .marker = "@STDK_ASSERT@", .value = assertions },
            .{ .marker = "@STDK_CALL@", .value = call },
        });
    }
}

fn renderModuleMap() []const u8 {
    return substitute(@embedFile("../../build/templates/module.modulemap.in"), &.{
        .{ .marker = "@STDK_MODULE_NAME@", .value = "StdK" },
    });
}

fn renderFrameworkModuleMap() []const u8 {
    return substitute(@embedFile("../../build/templates/module.framework.modulemap.in"), &.{
        .{ .marker = "@STDK_MODULE_NAME@", .value = "StdK" },
    });
}

const Replacement = struct { marker: []const u8, value: []const u8 };

fn substitute(comptime template: []const u8, comptime values: []const Replacement) []const u8 {
    // A Windows checkout carries CRLF in text files the attributes do not
    // pin; normalization keeps the artifact byte-identical on every host.
    const output = comptime blk: {
        var normalized: []const u8 = &.{};
        for (template) |byte| {
            if (byte != '\r') normalized = normalized ++ [1]u8{byte};
        }
        for (values) |replacement| {
            const index = std.mem.find(u8, normalized, replacement.marker) orelse @compileError("header template marker is missing.");
            if (std.mem.findPos(u8, normalized, index + replacement.marker.len, replacement.marker) != null) @compileError("header template marker must be unique.");
            normalized = normalized[0..index] ++ replacement.value ++ normalized[index + replacement.marker.len ..];
        }
        if (std.mem.find(u8, normalized, "@STDK_") != null) @compileError("template has an unresolved standard-kit marker.");
        break :blk normalized;
    };
    return output;
}

test "render header pins the abi epoch and every status define" {
    // The pinned lines are the frozen wire contract: the epoch and all ten status values, in definitions-table order.
    const pins = [_][]const u8{
        "#define STDK_ABI_EPOCH UINT32_C(9)",
        "#define STDK_STATUS_OK UINT32_C(0)",
        "#define STDK_STATUS_INVALID_CALL UINT32_C(1)",
        "#define STDK_STATUS_UNSUPPORTED UINT32_C(2)",
        "#define STDK_STATUS_INSUFFICIENT_CAPACITY UINT32_C(3)",
        "#define STDK_STATUS_INVALID_DATA UINT32_C(4)",
        "#define STDK_STATUS_INTEGRITY_FAILURE UINT32_C(5)",
        "#define STDK_STATUS_IO_FAILURE UINT32_C(6)",
        "#define STDK_STATUS_RESOURCE_LIMIT UINT32_C(7)",
        "#define STDK_STATUS_INTERNAL_FAILURE UINT32_C(8)",
        "#define STDK_STATUS_CANCELLED UINT32_C(9)",
    };
    for (pins) |pin| {
        try std.testing.expect(std.mem.find(u8, header, pin) != null);
    }
}

test "render header pins structure sizes layout assertions and the entry point" {
    const pins = [_][]const u8{
        "#define STDK_SIZEOF_ID UINT32_C(16)",
        "#define STDK_SIZEOF_NODE UINT32_C(96)",
        "#define STDK_SIZEOF_CALL UINT32_C(112)",
        "STDK_STATIC_ASSERT(sizeof(stdk_id) == 16, \"stdk_id size mismatch: the ABI fixes 16 bytes\");",
        "STDK_STATIC_ASSERT(offsetof(stdk_call_envelope, operation) == 8, \"stdk_call operation offset mismatch: the ABI fixes offset 8\");",
        "STDK_STATIC_ASSERT(offsetof(stdk_node, id) == 8, \"stdk_node id offset mismatch: the ABI fixes offset 8\");",
        "uint32_t stdk_call(stdk_call_envelope* call);",
    };
    for (pins) |pin| {
        try std.testing.expect(std.mem.find(u8, header, pin) != null);
    }
}

test "render header keeps the async and session surface free of template markers" {
    const pins = [_][]const u8{
        "#define STDK_COMPLETION_IN_PROGRESS UINT32_C(0)",
        "#define STDK_COMPLETION_DONE UINT32_C(1)",
        "#define STDK_COMPLETION_PENDING UINT32_C(4294967295)",
        "STDK_STATIC_ASSERT(sizeof(struct stdk_completion) == 16,",
        "uint32_t stdk_submit(stdk_call_envelope *call, struct stdk_completion *completion);",
        "uint32_t stdk_group(struct stdk_submission *submissions, uint64_t count,",
        "uint32_t stdk_poll(struct stdk_completion *completion);",
        "uint32_t stdk_cancel(struct stdk_completion *completion);",
        "uint64_t stdk_session_storage(const char *component, const char *verb);",
        "const char *stdk_session_catalog(void);",
        "uint32_t stdk_session_destroy(void *session);",
    };
    for (pins) |pin| {
        try std.testing.expect(std.mem.find(u8, header, pin) != null);
    }
    // No template marker survives rendering, and the guard closes.
    try std.testing.expect(std.mem.find(u8, header, "@STDK") == null);
    try std.testing.expect(std.mem.endsWith(u8, header, "#endif\n"));
}

test "substitute normalizes windows line endings in the template" {
    const rendered = substitute("#define A\r\n@STDK_MARKER@\r\n#endif\r\n", &.{.{ .marker = "@STDK_MARKER@", .value = "1\n" }});
    // Every CR is gone, so the artifact ends the same way on every host.
    try std.testing.expect(std.mem.findScalar(u8, rendered, '\r') == null);
    try std.testing.expect(std.mem.endsWith(u8, rendered, "#endif\n"));
}
