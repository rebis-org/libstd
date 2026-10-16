const std = @import("std");

const exception_prim = @import("exception.zig");

const Exception = exception_prim.Exception;

// Iterative preorder over an archive directory tree, so entry nesting
// depth can never exhaust the call stack.
const Frame = struct { next: usize, end: usize };

pub fn orderTree(comptime Node: type, nodes: *std.ArrayList(Node), kids: []const u32, root: u32, trunk: *std.ArrayList(u32), files: ?*std.ArrayList(u32), alloc: std.mem.Allocator) Exception!void {
    const sink = files orelse trunk;
    var stack: std.ArrayList(Frame) = .empty;
    // Depth never exceeds the node count; reserve it up front.
    stack.ensureTotalCapacity(alloc, nodes.items.len) catch return error.ResourceException;
    defer stack.deinit(alloc);
    stack.append(alloc, try visit(Node, nodes, kids, root, trunk, alloc)) catch return error.ResourceException;
    while (stack.items.len > 0) {
        const top = &stack.items[stack.items.len - 1];
        if (top.next >= top.end) {
            _ = stack.pop();
            continue;
        }
        const child = kids[top.next];
        top.next += 1;
        if (nodes.items[child].kind == .dir) {
            stack.append(alloc, try visit(Node, nodes, kids, child, trunk, alloc)) catch return error.ResourceException;
        } else {
            sink.append(alloc, child) catch return error.ResourceException;
        }
    }
}

fn visit(comptime Node: type, nodes: *std.ArrayList(Node), kids: []const u32, dir: u32, trunk: *std.ArrayList(u32), alloc: std.mem.Allocator) Exception!Frame {
    trunk.append(alloc, dir) catch return error.ResourceException;
    const start = nodes.items[dir].first_child;
    const end = start + nodes.items[dir].child_count;
    if (@hasField(Node, "subdir_count")) {
        var subdirs: u32 = 0;
        for (kids[start..end]) |child| {
            if (nodes.items[child].kind == .dir) subdirs += 1;
        }
        nodes.items[dir].subdir_count = subdirs;
    }
    return .{ .next = start, .end = end };
}
