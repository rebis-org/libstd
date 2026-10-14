const std = @import("std");
const builtin = @import("builtin");

pub fn main(init: std.process.Init) !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = arena.allocator();

    var all: std.ArrayList([]const u8) = .empty;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    while (args.next()) |arg| try all.append(alloc, arg);
    if (all.items.len < 2) return error.Usage;
    const rest = all.items[1..];
    var cut: ?usize = null;
    for (rest, 0..) |arg, i| {
        if (std.mem.eql(u8, arg, "--")) {
            cut = i;
            break;
        }
    }
    const sep = cut orelse return error.Usage;
    const command = rest[0..sep];
    const command_args = rest[sep + 1 ..];
    if (command.len == 0 or command_args.len == 0) return error.Usage;

    const program = (try findProgram(alloc, init.io, init.minimal.environ, command[0])) orelse {
        std.debug.print("abi: skip {s} (not found)\n", .{command[0]});
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
        .signal => |sig| return @intCast(128 + @intFromEnum(sig)),
        else => return 1,
    }
}

fn findProgram(alloc: std.mem.Allocator, io: std.Io, environ: std.process.Environ, name: []const u8) !?[]const u8 {
    const has_separator = std.mem.indexOfScalar(u8, name, '/') != null or
        (builtin.os.tag == .windows and std.mem.indexOfScalar(u8, name, '\\') != null);
    if (std.fs.path.isAbsolute(name) or has_separator) {
        std.Io.Dir.cwd().access(io, name, .{}) catch return null;
        return name;
    }
    if (builtin.os.tag == .windows) return null;
    const path_env = std.process.Environ.getPosix(environ, "PATH") orelse return null;
    var it = std.mem.splitScalar(u8, path_env, ':');
    while (it.next()) |dir| {
        const joined = try std.fs.path.join(alloc, &.{ dir, name });
        std.Io.Dir.cwd().access(io, joined, .{}) catch continue;
        return joined;
    }
    return null;
}
