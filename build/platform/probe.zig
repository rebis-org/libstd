const builtin = @import("builtin");
const std = @import("std");

pub fn main(init: std.process.Init) !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = arena.allocator();

    var collected: std.ArrayList([]const u8) = .empty;
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, alloc);
    defer args.deinit();
    while (args.next()) |arg| try collected.append(alloc, arg);
    if (collected.items.len < 2) return error.usage;
    const tail = collected.items[1..];
    var split_at: ?usize = null;
    for (tail, 0..) |arg, i| {
        if (std.mem.eql(u8, arg, "--")) {
            split_at = i;
            break;
        }
    }
    const split = split_at orelse return error.usage;
    const command = tail[0..split];
    const command_args = tail[split + 1 ..];
    if (command.len == 0 or command_args.len == 0) return error.usage;

    const program = (try findProgram(alloc, init.io, init.minimal.environ, command[0])) orelse {
        std.debug.print("abi: skip {s} (not found).\n", .{command[0]});
        return 0;
    };

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(alloc, program);
    try argv.appendSlice(alloc, command[1..]);
    try argv.appendSlice(alloc, command_args);

    const io = init.io;
    var child = try std.process.spawn(io, .{ .argv = argv.items });
    switch (try child.wait(io)) {
        .exited => |code| return code,
        .signal => |sig| return @intCast(128 + @backingInt(sig)),
        else => return 1,
    }
}

fn findProgram(alloc: std.mem.Allocator, io: std.Io, environ: std.process.Environ, name: []const u8) !?[]const u8 {
    const has_separator = std.mem.findScalar(u8, name, '/') != null or
        (builtin.os.tag == .windows and std.mem.findScalar(u8, name, '\\') != null);
    if (std.Io.Dir.path.isAbsolute(name) or has_separator) {
        std.Io.Dir.cwd().access(io, name, .{}) catch return null;
        return name;
    }
    if (builtin.os.tag == .windows) return null;
    const path_env = std.process.Environ.getPosix(environ, "PATH") orelse return null;
    var entries = std.mem.splitScalar(u8, path_env, ':');
    while (entries.next()) |dir| {
        const joined = try std.Io.Dir.path.join(alloc, &.{ dir, name });
        std.Io.Dir.cwd().access(io, joined, .{}) catch continue;
        return joined;
    }
    return null;
}
