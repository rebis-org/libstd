const std = @import("std");

const entry_prim = @import("../../common/entry.zig");
const bounds = @import("../../common/primitive/bounds.zig");
const exception_prim = @import("../../common/primitive/exception.zig");

const Exception = exception_prim.Exception;

// Shared volume-tree machinery: the walk path stack, the name rule, and
// the children-linking pass.

// One directory level, whether written or read back: NUL-free,
// separator-free, neither dot nor dot-dot, and clear of the shared
// escape rules, within the per-segment byte cap.
fn componentSafe(name: []const u8) bool {
    if (name.len > 256) return false;
    return entry_prim.isSafeComponent(name);
}

// A joined-path stack: pop rewinds to a depth span; joined borrows the
// path without committing it.
pub fn WalkState(comptime max_dir_depth: u32) type {
    return struct {
        const Self = @This();

        ordinal: u64 = 0,
        path_len: usize = 0,
        spans: [max_dir_depth]usize = undefined,
        path: []u8 = &.{},

        pub fn push(self: *Self, name: []const u8, depth: usize) Exception!void {
            // Components come from the image, so hostile names fail as
            // data, not as caller error.
            if (!componentSafe(name)) return error.DataException;
            if (depth >= max_dir_depth) return error.DataException;
            self.spans[depth] = self.path_len;
            const extra = if (self.path_len == 0) name.len else name.len + 1;
            if (self.path_len + extra > self.path.len) return error.DataException;
            if (self.path_len != 0) {
                self.path[self.path_len] = '/';
                self.path_len += 1;
            }
            @memcpy(self.path[self.path_len..][0..name.len], name);
            self.path_len += name.len;
        }

        pub fn pop(self: *Self, depth: usize) void {
            self.path_len = self.spans[depth];
        }

        // The joined name outlives the walk: found unwinds before any mutation.
        pub fn joined(self: *Self, name: []const u8) Exception![]const u8 {
            if (!componentSafe(name)) return error.DataException;
            const extra = if (self.path_len == 0) name.len else name.len + 1;
            if (self.path_len + extra > self.path.len) return error.DataException;
            var end = self.path_len;
            if (end != 0) {
                self.path[end] = '/';
                end += 1;
            }
            @memcpy(self.path[end..][0..name.len], name);
            return self.path[0 .. end + name.len];
        }
    };
}

// Volume-tree names reject empty and dot segments at every level and cap
// the whole path and each segment.
pub fn validateName(name: []const u8) Exception!void {
    if (name.len == 0 or name.len > 512) return error.CallException;
    // The same escape rules as every other writer: backslash and Windows
    // drive prefixes refuse here, not at extraction time.
    if (bounds.isAbsoluteOrTraversal(name)) return error.CallException;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |part| {
        if (!componentSafe(part)) return error.CallException;
    }
}

// Links parents to children by index and sorts each run by name; the
// returned adjacency feeds the ordering pass.
pub fn linkChildren(comptime Node: type, nodes: *std.ArrayList(Node), counts: []const u32, alloc: std.mem.Allocator) Exception![]u32 {
    const starts = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    var acc: u32 = 0;
    for (counts, 0..) |c, i| {
        starts[i] = acc;
        acc += c;
    }
    const kids = alloc.alloc(u32, acc) catch return error.ResourceException;
    const fill = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    @memcpy(fill, starts);
    for (nodes.items, 0..) |node, i| {
        if (i == 0) continue;
        kids[fill[node.parent]] = @intCast(i);
        fill[node.parent] += 1;
    }
    for (nodes.items, 0..) |*node, i| {
        node.first_child = starts[i];
        const slice = kids[node.first_child .. node.first_child + counts[i]];
        std.mem.sort(u32, slice, nodes, struct {
            fn less(ns: *std.ArrayList(Node), a: u32, b: u32) bool {
                return std.mem.order(u8, ns.items[a].name, ns.items[b].name) == .lt;
            }
        }.less);
    }
    return kids;
}

test "walk state rejects hostile image components" {
    const testing = std.testing;
    const State = WalkState(4);
    var path: [64]u8 = undefined;
    var state: State = .{ .path = &path };
    try state.push("dir", 0);
    const hostile = [_][]const u8{
        "..", ".", "", "a\\b", "C:/x", "a\x00b", "a/b",
    };
    for (hostile) |name| {
        try testing.expectError(error.DataException, state.push(name, 1));
        try testing.expectError(error.DataException, state.joined(name));
    }
    // A rejected push leaves the committed path untouched.
    try testing.expectEqualStrings("dir", state.path[0..state.path_len]);
    const joined = try state.joined("file.txt");
    try testing.expectEqualStrings("dir/file.txt", joined);
}

test "volume tree rejects NUL in written names" {
    const testing = std.testing;
    try testing.expectError(error.CallException, validateName("a\x00b.txt"));
    try validateName("a/b/c.txt");
}
