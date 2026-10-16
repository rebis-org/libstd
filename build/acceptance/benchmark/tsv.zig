const std = @import("std");

const missing_cell = "missing";

fn formatValue(buffer: *[16]u8, comptime format: []const u8, value: f64) []const u8 {
    var writer: std.Io.Writer = std.Io.Writer.fixed(buffer);
    writer.print(format, .{value}) catch return missing_cell;
    return writer.buffered();
}

pub fn formattedCell(buffer: *[16]u8, comptime format: []const u8, value: f64, show: bool) []const u8 {
    if (!show) return missing_cell;
    return formatValue(buffer, format, value);
}

pub fn formatGap(buffer: *[16]u8, gap_value: ?f64) []const u8 {
    const value = gap_value orelse return missing_cell;
    return formatValue(buffer, "{d:.1}", value * 100.0);
}

pub fn emitRow(report: *std.ArrayList(u8), allocator: std.mem.Allocator, leading: []const []const u8, cells: []const []const u8) !void {
    for (leading, 0..) |column, index| {
        if (index > 0) try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, column);
    }
    for (cells) |column| {
        try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, column);
    }
    try report.appendSlice(allocator, "\n");
}
