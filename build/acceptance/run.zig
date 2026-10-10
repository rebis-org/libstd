const std = @import("std");

pub const Args = struct {
    iterator: std.process.Args.Iterator,

    pub fn init(arguments: std.process.Args) Args {
        var iterator = std.process.Args.Iterator.init(arguments);
        _ = iterator.next();
        return .{ .iterator = iterator };
    }

    pub fn next(self: *Args, comptime missing: anyerror) ![:0]const u8 {
        return self.iterator.next() orelse missing;
    }

    pub fn done(self: *Args, comptime unexpected: anyerror) !void {
        if (self.iterator.next() != null) return unexpected;
    }
};

const Result = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn success(self: *const Result) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    fn detach(self: *Result) []u8 {
        const stdout = self.stdout;
        std.heap.page_allocator.free(self.stderr);
        return stdout;
    }

    fn deinit(self: *Result) void {
        std.heap.page_allocator.free(self.stdout);
        std.heap.page_allocator.free(self.stderr);
    }
};

fn spawn(init: std.process.Init, argv: []const []const u8, cwd: ?[]const u8) !Result {
    const options = std.process.RunOptions{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
    };
    const result = try std.process.run(std.heap.page_allocator, init.io, options);
    return .{ .term = result.term, .stdout = result.stdout, .stderr = result.stderr };
}

pub fn output(init: std.process.Init, argv: []const []const u8) ![]u8 {
    return outputCwd(init, null, argv);
}

pub fn outputCwd(init: std.process.Init, cwd: ?[]const u8, argv: []const []const u8) ![]u8 {
    var result = spawn(init, argv, cwd) catch return error.spawn_failed;
    if (!result.success()) {
        std.debug.print("command failed: {s}\n{s}\n", .{ argv[0], result.stderr });
        result.deinit();
        return error.command_failed;
    }
    return result.detach();
}

pub fn silent(init: std.process.Init, argv: []const []const u8) !void {
    const stdout = try output(init, argv);
    std.heap.page_allocator.free(stdout);
}

pub fn exitCode(init: std.process.Init, argv: []const []const u8) u8 {
    var result = spawn(init, argv, null) catch return 1;
    defer result.deinit();
    return switch (result.term) {
        .exited => |code| code,
        else => 1,
    };
}
