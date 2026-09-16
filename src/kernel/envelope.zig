const std = @import("std");

pub const Id = extern struct { low: u64, high: u64 };

pub const Status = struct {
    pub const ok: u32 = 0;
    pub const invalid_call: u32 = 1;
    pub const unsupported: u32 = 2;
    pub const insufficient_capacity: u32 = 3;
    pub const invalid_data: u32 = 4;
    pub const integrity_failure: u32 = 5;
    pub const io_failure: u32 = 6;
    pub const resource_limit: u32 = 7;
    pub const internal_failure: u32 = 8;

    pub const definitions = [_]struct { name: []const u8, value: u32 }{
        .{ .name = "OK", .value = ok },
        .{ .name = "INVALID_CALL", .value = invalid_call },
        .{ .name = "UNSUPPORTED", .value = unsupported },
        .{ .name = "INSUFFICIENT_CAPACITY", .value = insufficient_capacity },
        .{ .name = "INVALID_DATA", .value = invalid_data },
        .{ .name = "INTEGRITY_FAILURE", .value = integrity_failure },
        .{ .name = "IO_FAILURE", .value = io_failure },
        .{ .name = "RESOURCE_LIMIT", .value = resource_limit },
        .{ .name = "INTERNAL_FAILURE", .value = internal_failure },
    };
};

pub const node_flag_optional: u32 = 1;
pub const node_flag_callback_resource: u32 = 2;

pub const Node = extern struct {
    structure_size: u32,
    flags: u32,
    id: Id,
    value_low: u64,
    value_high: u64,
    bytes: ?[*]u8,
    byte_capacity: u64,
    byte_length: u64,
    child: ?*Node,
    next: ?*Node,
    reserved: [2]u64,

    pub fn init() Node {
        return .{
            .structure_size = @sizeOf(Node),
            .flags = 0,
            .id = .{ .low = 0, .high = 0 },
            .value_low = 0,
            .value_high = 0,
            .bytes = null,
            .byte_capacity = 0,
            .byte_length = 0,
            .child = null,
            .next = null,
            .reserved = .{ 0, 0 },
        };
    }

    pub fn valid(self: *const Node) bool {
        return self.structure_size >= @sizeOf(Node) and self.flags & ~(node_flag_optional | node_flag_callback_resource) == 0 and std.mem.allEqual(u64, &self.reserved, 0);
    }
};

pub const Callback = *const fn (call: *Call) callconv(.c) u32;

pub const Call = extern struct {
    structure_size: u32,
    flags: u32,
    operation: Id,
    request: ?*Node,
    response: ?*Node,
    diagnostic: ?*Node,
    workspace: ?[*]u8,
    workspace_capacity: u64,
    callback: ?Callback,
    callback_context: ?*anyopaque,
    reserved: [4]u64,

    pub fn init() Call {
        return .{
            .structure_size = @sizeOf(Call),
            .flags = 0,
            .operation = .{ .low = 0, .high = 0 },
            .request = null,
            .response = null,
            .diagnostic = null,
            .workspace = null,
            .workspace_capacity = 0,
            .callback = null,
            .callback_context = null,
            .reserved = .{ 0, 0, 0, 0 },
        };
    }

    pub fn valid(self: *const Call) bool {
        return self.structure_size >= @sizeOf(Call) and self.flags == 0 and std.mem.allEqual(u64, &self.reserved, 0);
    }
};

comptime {
    if (@sizeOf(Id) != 16 or @alignOf(Id) != 8) @compileError("stdk_id layout changed");
    if (@offsetOf(Call, "operation") != 8) @compileError("stdk_call operation offset changed");
    if (@offsetOf(Node, "id") != 8) @compileError("stdk_node ID offset changed");
}
