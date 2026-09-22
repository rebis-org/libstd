const std = @import("std");

const run = @import("run.zig");

// Enumerated public boundary: the gate fails on extra or missing exports.
pub const exports = [_][]const u8{
    "_stdk_call",
    "_stdk_session_storage",
    "_stdk_session_create",
    "_stdk_session_bounded",
    "_stdk_session_step",
    "_stdk_session_failure",
    "_stdk_session_catalog",
    "_stdk_session_destroy",
};

pub fn assertExports(init: std.process.Init, library: []const u8) !void {
    const stdout = try run.output(init, &.{ "nm", "-gU", library });
    defer std.heap.page_allocator.free(stdout);
    var found = [_]bool{false} ** exports.len;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        const index = std.mem.indexOf(u8, line, " T ") orelse continue;
        const name = std.mem.trim(u8, line[index + 3 ..], " \t\r");
        const known = for (exports, 0..) |expected, i| {
            if (std.mem.eql(u8, name, expected)) {
                found[i] = true;
                break true;
            }
        } else false;
        if (!known) return error.UnexpectedExport;
        count += 1;
    }
    if (count != exports.len) return error.MissingExport;
    for (found) |present| {
        if (!present) return error.MissingExport;
    }
}

pub const assertSingleExport = assertExports;
