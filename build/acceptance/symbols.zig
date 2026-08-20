const std = @import("std");

const run = @import("run.zig");

pub fn assertSingleExport(init: std.process.Init, library: []const u8) !void {
    const stdout = try run.output(init, &.{ "nm", "-gU", library });
    defer std.heap.page_allocator.free(stdout);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |line| {
        const index = std.mem.indexOf(u8, line, " T ") orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[index + 3 ..], " \t\r"), "_stdk_call")) return error.UnexpectedExport;
        count += 1;
    }
    if (count != 1) return error.MissingExport;
}
