const std = @import("std");

const missing = "missing";

fn formatCell(buffer: *[16]u8, comptime format: []const u8, value: f64) []const u8 {
    return std.fmt.bufPrint(buffer, format, .{value}) catch missing;
}

pub fn cell(buffer: *[16]u8, comptime format: []const u8, value: f64, show: bool) []const u8 {
    if (!show) return missing;
    return formatCell(buffer, format, value);
}

pub fn gap(buffer: *[16]u8, gap_value: ?f64) []const u8 {
    const value = gap_value orelse return missing;
    return formatCell(buffer, "{d:.1}", value * 100.0);
}

fn appendTabbed(report: *std.ArrayList(u8), allocator: std.mem.Allocator, columns: []const []const u8) !void {
    for (columns) |column| {
        try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, column);
    }
}

pub fn emitRow(report: *std.ArrayList(u8), allocator: std.mem.Allocator, first: []const []const u8, values: []const []const u8) !void {
    for (first, 0..) |column, index| {
        if (index > 0) try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, column);
    }
    try appendTabbed(report, allocator, values);
    try report.appendSlice(allocator, "\n");
}
