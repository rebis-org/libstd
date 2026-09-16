const std = @import("std");

const kernel_catalog = @import("kernel/catalog.zig");

// Same comptime source as discovery, so the shipped artifact cannot drift.
//
// Rooted at src/: module confinement requires it to reach kernel/catalog.
pub fn main(init: std.process.Init) !void {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const output_path = args.next() orelse return error.MissingArgument;
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = output_path, .data = kernel_catalog.catalog_json });
}
