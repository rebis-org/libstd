const std = @import("std");

pub const Id = extern struct {
    low: u64,
    high: u64,
};

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
    pub const cancelled: u32 = 9;
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
};

pub extern fn stdk_call(call: *Call) callconv(.c) u32;

// The async submission boundary: the completion record is caller-owned
// storage and the ticket is its pointer. The submission descriptor and the
// executor vtable are C-representable shapes for host thread pools.
pub const Completion = extern struct {
    structure_size: u32,
    state: u32,
    status: u32,
    reserved: u32,

    pub const in_progress: u32 = 0;
    pub const done: u32 = 1;
    pub const pending: u32 = std.math.maxInt(u32);

    pub fn init() Completion {
        return .{ .structure_size = @sizeOf(Completion), .state = in_progress, .status = 0, .reserved = 0 };
    }
};

pub const Submission = extern struct {
    call: ?*Call,
    completion: ?*Completion,
};

pub const Task = extern struct {
    context: *anyopaque,
    invoke: *const fn (context: *anyopaque) callconv(.c) u32,
};

pub const ExecutorVtable = extern struct {
    run: *const fn (ptr: *anyopaque, task: Task) callconv(.c) u32,
};

pub const Executor = extern struct {
    ptr: *anyopaque,
    vtable: *const ExecutorVtable,
};

pub extern fn stdk_submit(call: ?*Call, completion: ?*Completion) callconv(.c) u32;
pub extern fn stdk_group(submissions: ?[*]Submission, count: u64, executor: ?*const Executor) callconv(.c) u32;
pub extern fn stdk_poll(completion: ?*Completion) callconv(.c) u32;
pub extern fn stdk_cancel(completion: ?*Completion) callconv(.c) u32;

pub fn isIdEqual(left: Id, right: Id) bool {
    return left.low == right.low and left.high == right.high;
}

comptime {
    if (@sizeOf(Completion) != 16) @compileError("stdk_completion layout drifted: the ABI fixes 16 bytes.");
}

comptime {
    if (@sizeOf(Id) != 16) @compileError("stdk_id layout drifted: the ABI fixes 16 bytes.");
    if (@sizeOf(Node) != 96) @compileError("stdk_node layout drifted: the ABI fixes 96 bytes.");
    if (@sizeOf(Call) != 112) @compileError("stdk_call layout drifted: the ABI fixes 112 bytes.");
    if (@offsetOf(Call, "operation") != 8) @compileError("stdk_call operation offset drifted: the ABI fixes offset 8.");
    if (@offsetOf(Node, "id") != 8) @compileError("stdk_node id offset drifted: the ABI fixes offset 8.");
}
