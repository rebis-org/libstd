const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");

const Resource = resource.Resource;
const Workspace = resource.Workspace;
const Exception = vocabulary.Exception;

// The materialized head first, then the parameter tail.
pub fn list(head: []const u8, tail: []const []const u8, workspace: *Workspace) Exception![]const []const u8 {
    const parts = try workspace.take([]const u8, 1 + tail.len);
    parts[0] = head;
    for (tail, 0..) |part, index| parts[1 + index] = part;
    return parts;
}

// Header staging is capped by the largest part.
pub fn largest(head: []const u8, tail: []const []const u8) usize {
    var widest = head.len;
    for (tail) |part| {
        if (part.len > widest) widest = part.len;
    }
    return widest;
}

// A gather concatenates disjoint parts, so it cannot exceed the set.
pub fn setBytes(head: []const u8, tail: []const []const u8) Exception!usize {
    var total = head.len;
    for (tail) |part| total = try bounds.addUsize(total, part.len);
    return total;
}

pub fn totalBytes(parts: []const []const u8) Exception!usize {
    var total: usize = 0;
    for (parts) |part| total = try bounds.addUsize(total, part.len);
    return total;
}

// Parts ride request nodes, so the boundary checks never see them.
pub fn checkOverlap(workspace: *Workspace, sink: ?*Resource, parts: []const []const u8) Exception!void {
    for (parts) |part| {
        if (part.len == 0) continue;
        if (try common.spanOverlap(@intFromPtr(workspace.bytes.ptr), workspace.bytes.len, @intFromPtr(part.ptr), part.len)) return error.CallException;
        const sink_resource = sink orelse continue;
        switch (sink_resource.kind) {
            .direct_write => |destination| {
                if (try common.spanOverlap(@intFromPtr(destination.ptr), destination.len, @intFromPtr(part.ptr), part.len)) return error.CallException;
            },
            else => {},
        }
    }
}

// Every part but the last is exactly the granularity (zip, 7z).
pub fn byChunk(set: []const u8, volume_size: u64, workspace: *Workspace) Exception![]const []const u8 {
    const width = std.math.cast(usize, volume_size) orelse return error.ResourceException;
    const count = if (set.len == 0) 1 else 1 + (set.len - 1) / width;
    const parts = try workspace.take([]const u8, count);
    var at: usize = 0;
    for (0..count) |index| {
        const take = @min(width, set.len - at);
        parts[index] = set[at..][0..take];
        at += take;
    }
    return parts;
}

// GNU tar's volumes vary with their members, so lengths differ.
pub fn byLength(set: []const u8, lengths: []const u64, workspace: *Workspace) Exception![]const []const u8 {
    const parts = try workspace.take([]const u8, lengths.len);
    var at: usize = 0;
    for (lengths, 0..) |len, index| {
        const take = std.math.cast(usize, len) orelse return error.ResourceException;
        if ((bounds.addUsize(at, take) catch return error.InternalException) > set.len) return error.InternalException;
        parts[index] = set[at..][0..take];
        at += take;
    }
    if (at != set.len) return error.InternalException;
    return parts;
}

test "volume set algebra orders the head first and sizes from the widest part" {
    var arena: [256]u8 align(@alignOf([]const u8)) = undefined;
    var workspace = try Workspace.init(&arena, arena.len);
    const head = [_]u8{ 1, 2, 3 };
    const tail = [_][]const u8{ &[_]u8{ 4, 5 }, &[_]u8{ 6, 7, 8, 9 } };
    const parts = try list(&head, &tail, &workspace);
    // The materialized set keeps the head first, then the tail in order.
    try std.testing.expectEqualSlices(u8, &head, parts[0]);
    try std.testing.expectEqualSlices(u8, tail[0], parts[1]);
    try std.testing.expectEqualSlices(u8, tail[1], parts[2]);
    // The widest part comes from the tail, and both sums agree.
    try std.testing.expectEqual(@as(usize, 4), largest(&head, &tail));
    try std.testing.expectEqual(@as(usize, 9), try setBytes(&head, &tail));
    try std.testing.expectEqual(try setBytes(&head, &tail), try totalBytes(parts));
    // An empty tail leaves the head alone as the whole set.
    const solo = try list(&head, &.{}, &workspace);
    try std.testing.expectEqual(@as(usize, 1), solo.len);
    try std.testing.expectEqual(@as(usize, 3), try totalBytes(solo));
}

test "volume chunking cuts every set shape at the fixed width" {
    var arena: [256]u8 align(@alignOf([]const u8)) = undefined;
    var workspace = try Workspace.init(&arena, arena.len);
    const set = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    // An exact multiple cuts count = len/width with no partial part.
    const exact = try byChunk(&set, 5, &workspace);
    try std.testing.expectEqual(@as(usize, 2), exact.len);
    try std.testing.expectEqualSlices(u8, set[0..5], exact[0]);
    try std.testing.expectEqualSlices(u8, set[5..10], exact[1]);
    // A width past the set keeps one part: the whole set.
    const whole = try byChunk(&set, 32, &workspace);
    try std.testing.expectEqual(@as(usize, 1), whole.len);
    try std.testing.expectEqualSlices(u8, &set, whole[0]);
    // A ragged cut lands the remainder in the last part only.
    const ragged = try byChunk(&set, 4, &workspace);
    try std.testing.expectEqual(@as(usize, 3), ragged.len);
    try std.testing.expectEqualSlices(u8, set[4..8], ragged[1]);
    try std.testing.expectEqualSlices(u8, set[8..10], ragged[2]);
    // An empty set still yields exactly one empty part.
    const empty = try byChunk(&.{}, 4, &workspace);
    try std.testing.expectEqual(@as(usize, 1), empty.len);
    try std.testing.expectEqual(@as(usize, 0), empty[0].len);
    // A workspace too small for the part table reports capacity, not a cut.
    var tiny: [16]u8 align(@alignOf([]const u8)) = undefined;
    var small_workspace = try Workspace.init(&tiny, tiny.len);
    try std.testing.expectError(error.CapacityException, byChunk(&set, 4, &small_workspace));
}

test "volume length cutting walks the plan and rejects both miss classes" {
    var arena: [256]u8 align(@alignOf([]const u8)) = undefined;
    var workspace = try Workspace.init(&arena, arena.len);
    const set = [_]u8{ 0, 1, 2, 3, 4, 5 };
    // Zero-length entries hold their place in the plan.
    const plan = [_]u64{ 2, 0, 4 };
    const parts = try byLength(&set, &plan, &workspace);
    try std.testing.expectEqual(@as(usize, 3), parts.len);
    try std.testing.expectEqualSlices(u8, set[0..2], parts[0]);
    try std.testing.expectEqual(@as(usize, 0), parts[1].len);
    try std.testing.expectEqualSlices(u8, set[2..6], parts[2]);
    // An undershoot stops short of the set end.
    try std.testing.expectError(error.InternalException, byLength(&set, &[_]u64{ 2, 3 }, &workspace));
    // An overshoot runs past the set end.
    try std.testing.expectError(error.InternalException, byLength(&set, &[_]u64{ 3, 4 }, &workspace));
    // An empty plan and an empty set agree on zero parts.
    try std.testing.expectEqual(@as(usize, 0), (try byLength(&.{}, &.{}, &workspace)).len);
}

test "volume overlap checks refuse parts that share memory with the staging" {
    var arena: [256]u8 align(@alignOf([]const u8)) = undefined;
    var workspace = try Workspace.init(&arena, arena.len);
    var destination: [8]u8 = undefined;
    var sink: Resource = .{
        .call = undefined,
        .token_low = 0,
        .token_high = 0,
        .capabilities = 0,
        .kind = .{ .direct_write = &destination },
    };
    const outside = [_]u8{ 1, 2, 3 };
    // A disjoint part passes with a sink and without one.
    try checkOverlap(&workspace, &sink, &.{&outside});
    try checkOverlap(&workspace, null, &.{&outside});
    // A part inside the workspace or the write destination is refused.
    try std.testing.expectError(error.CallException, checkOverlap(&workspace, &sink, &.{arena[0..4]}));
    try std.testing.expectError(error.CallException, checkOverlap(&workspace, &sink, &.{destination[2..6]}));
    // An empty part rides along even inside the staging.
    try checkOverlap(&workspace, &sink, &.{ arena[0..0], &outside });
    // Sinks that are not direct writes check nothing of their own.
    var callback_sink: Resource = .{
        .call = undefined,
        .token_low = 0,
        .token_high = 0,
        .capabilities = 0,
        .kind = .callback_write,
    };
    try checkOverlap(&workspace, &callback_sink, &.{destination[2..6]});
}
