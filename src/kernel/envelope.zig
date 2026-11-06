const std = @import("std");

// The C ABI fixes 16 bytes at 8-byte alignment; explicit alignment holds
// it where u64 aligns to 4.
pub const Id = extern struct { low: u64 align(8), high: u64 align(8) };

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
        .{ .name = "CANCELLED", .value = cancelled },
    };
};

pub const node_flag_optional: u32 = 1;
pub const node_flag_callback_resource: u32 = 2;

fn hasValidSizeAndReserved(structure_size: u32, expected: usize, reserved: []const u64) bool {
    return structure_size >= expected and std.mem.allEqual(u64, reserved, 0);
}

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
        var self = std.mem.zeroes(Node);
        self.structure_size = @sizeOf(Node);
        return self;
    }

    pub fn isValid(self: *const Node) bool {
        return hasValidSizeAndReserved(self.structure_size, @sizeOf(Node), &self.reserved) and self.flags & ~(node_flag_optional | node_flag_callback_resource) == 0;
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
        var self = std.mem.zeroes(Call);
        self.structure_size = @sizeOf(Call);
        return self;
    }

    pub fn isValid(self: *const Call) bool {
        return hasValidSizeAndReserved(self.structure_size, @sizeOf(Call), &self.reserved) and self.flags == 0;
    }
};

comptime {
    // The C ABI fixes these offsets; a drift here is a silent host miscompile.
    if (@sizeOf(Id) != 16 or @alignOf(Id) != 8) @compileError("stdk_id layout drifted: the ABI fixes 16 bytes at 8-byte alignment.");
    if (@offsetOf(Call, "operation") != 8) @compileError("stdk_call layout drifted: the ABI fixes the operation id at offset 8.");
    if (@offsetOf(Node, "id") != 8) @compileError("stdk_node layout drifted: the ABI fixes the id at offset 8.");
}

test "envelope status codes and definitions pin the wire vocabulary" {
    const expected = [_]struct { name: []const u8, value: u32 }{
        .{ .name = "OK", .value = 0 },
        .{ .name = "INVALID_CALL", .value = 1 },
        .{ .name = "UNSUPPORTED", .value = 2 },
        .{ .name = "INSUFFICIENT_CAPACITY", .value = 3 },
        .{ .name = "INVALID_DATA", .value = 4 },
        .{ .name = "INTEGRITY_FAILURE", .value = 5 },
        .{ .name = "IO_FAILURE", .value = 6 },
        .{ .name = "RESOURCE_LIMIT", .value = 7 },
        .{ .name = "INTERNAL_FAILURE", .value = 8 },
        .{ .name = "CANCELLED", .value = 9 },
    };
    try std.testing.expectEqual(@as(usize, 10), Status.definitions.len);
    for (Status.definitions, expected) |definition, pin| {
        try std.testing.expectEqualStrings(pin.name, definition.name);
        try std.testing.expectEqual(pin.value, definition.value);
    }
    try std.testing.expectEqual(@as(u32, 0), Status.ok);
    try std.testing.expectEqual(@as(u32, 1), Status.invalid_call);
    try std.testing.expectEqual(@as(u32, 2), Status.unsupported);
    try std.testing.expectEqual(@as(u32, 3), Status.insufficient_capacity);
    try std.testing.expectEqual(@as(u32, 4), Status.invalid_data);
    try std.testing.expectEqual(@as(u32, 5), Status.integrity_failure);
    try std.testing.expectEqual(@as(u32, 6), Status.io_failure);
    try std.testing.expectEqual(@as(u32, 7), Status.resource_limit);
    try std.testing.expectEqual(@as(u32, 8), Status.internal_failure);
    try std.testing.expectEqual(@as(u32, 9), Status.cancelled);
    // Every status value is distinct: a host must never conflate two.
    for (Status.definitions, 0..) |outer, outer_index| {
        for (Status.definitions[outer_index + 1 ..]) |inner| {
            try std.testing.expect(outer.value != inner.value);
        }
    }
}

test "envelope id fixes sixteen bytes at eight byte alignment" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Id));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(Id));
    const id = Id{ .low = 0x0123_4567_89ab_cdef, .high = 0xfedc_ba98_7654_3210 };
    try std.testing.expectEqual(@as(u64, 0x0123_4567_89ab_cdef), id.low);
    try std.testing.expectEqual(@as(u64, 0xfedc_ba98_7654_3210), id.high);
    const zeroed = std.mem.zeroes(Id);
    try std.testing.expectEqual(@as(u64, 0), zeroed.low);
    try std.testing.expectEqual(@as(u64, 0), zeroed.high);
}

test "envelope node flags occupy disjoint low bits" {
    try std.testing.expectEqual(@as(u32, 1), node_flag_optional);
    try std.testing.expectEqual(@as(u32, 2), node_flag_callback_resource);
    try std.testing.expectEqual(@as(u32, 0), node_flag_optional & node_flag_callback_resource);

    var optional_node = Node.init();
    optional_node.flags = node_flag_optional;
    try std.testing.expect(optional_node.isValid());

    var callback_node = Node.init();
    callback_node.flags = node_flag_callback_resource;
    try std.testing.expect(callback_node.isValid());

    var both_flags = Node.init();
    both_flags.flags = node_flag_optional | node_flag_callback_resource;
    try std.testing.expect(both_flags.isValid());
}

test "envelope node init zeroes the frame and validity accepts the pinned layout" {
    const node = Node.init();
    try std.testing.expectEqual(@as(u32, 96), node.structure_size);
    try std.testing.expectEqual(@as(usize, 96), @sizeOf(Node));
    try std.testing.expectEqual(@as(u32, 0), node.flags);
    try std.testing.expectEqual(@as(u64, 0), node.id.low);
    try std.testing.expectEqual(@as(u64, 0), node.id.high);
    try std.testing.expectEqual(@as(u64, 0), node.value_low);
    try std.testing.expectEqual(@as(u64, 0), node.value_high);
    try std.testing.expect(node.bytes == null);
    try std.testing.expectEqual(@as(u64, 0), node.byte_capacity);
    try std.testing.expectEqual(@as(u64, 0), node.byte_length);
    try std.testing.expect(node.child == null);
    try std.testing.expect(node.next == null);
    try std.testing.expectEqual(@as(u64, 0), node.reserved[0]);
    try std.testing.expectEqual(@as(u64, 0), node.reserved[1]);
    try std.testing.expect(node.isValid());

    // Hosts may hand over a larger structure; the envelope accepts it.
    var oversized = Node.init();
    oversized.structure_size += 1;
    try std.testing.expect(oversized.isValid());
}

test "envelope node validity rejects undersized unknown flag and reserved frames" {
    var undersized = Node.init();
    undersized.structure_size -= 1;
    try std.testing.expect(!undersized.isValid());

    var unknown_flag = Node.init();
    unknown_flag.flags = node_flag_optional | 4;
    try std.testing.expect(!unknown_flag.isValid());

    var high_flag = Node.init();
    high_flag.flags = 0x8000_0000;
    try std.testing.expect(!high_flag.isValid());

    var reserved_set = Node.init();
    reserved_set.reserved[0] = 1;
    try std.testing.expect(!reserved_set.isValid());

    var reserved_tail = Node.init();
    reserved_tail.reserved[1] = 7;
    try std.testing.expect(!reserved_tail.isValid());
}

test "envelope call init pins the dispatch frame layout and validity" {
    const call = Call.init();
    try std.testing.expectEqual(@as(u32, 112), call.structure_size);
    try std.testing.expectEqual(@as(usize, 112), @sizeOf(Call));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(Call, "operation"));
    try std.testing.expectEqual(@as(u32, 0), call.flags);
    try std.testing.expectEqual(@as(u64, 0), call.operation.low);
    try std.testing.expectEqual(@as(u64, 0), call.operation.high);
    try std.testing.expect(call.request == null);
    try std.testing.expect(call.response == null);
    try std.testing.expect(call.diagnostic == null);
    try std.testing.expect(call.workspace == null);
    try std.testing.expectEqual(@as(u64, 0), call.workspace_capacity);
    try std.testing.expect(call.callback == null);
    try std.testing.expect(call.callback_context == null);
    try std.testing.expectEqual(@as(u64, 0), call.reserved[0]);
    try std.testing.expectEqual(@as(u64, 0), call.reserved[3]);
    try std.testing.expect(call.isValid());

    var undersized = Call.init();
    undersized.structure_size -= 1;
    try std.testing.expect(!undersized.isValid());

    var flagged = Call.init();
    flagged.flags = 1;
    try std.testing.expect(!flagged.isValid());

    var reserved_set = Call.init();
    reserved_set.reserved[3] = 1;
    try std.testing.expect(!reserved_set.isValid());

    var oversized = Call.init();
    oversized.structure_size += 1;
    try std.testing.expect(oversized.isValid());
}
