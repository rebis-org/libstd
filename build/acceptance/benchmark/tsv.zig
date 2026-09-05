const std = @import("std");

pub fn cell(buf: *[16]u8, comptime fmt: []const u8, value: f64, show: bool) []const u8 {
    if (!show) return "missing";
    return std.fmt.bufPrint(buf, fmt, .{value}) catch "missing";
}

pub fn gap(buf: *[16]u8, gap_value: ?f64) []const u8 {
    const g = gap_value orelse return "missing";
    return std.fmt.bufPrint(buf, "{d:.1}", .{g * 100.0}) catch "missing";
}

pub fn emitRow(report: *std.ArrayList(u8), allocator: std.mem.Allocator, first: []const []const u8, values: []const []const u8) !void {
    for (first, 0..) |column, index| {
        if (index > 0) try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, column);
    }
    for (values) |value| {
        try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, value);
    }
    try report.appendSlice(allocator, "\n");
}
