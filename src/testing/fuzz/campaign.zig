// Mutation campaigns are evidence sessions, not gate work: the iteration
// budget comes from the operator, and a run without a budget proves nothing.
// Decoding rejects malformed input by contract; the property under test is
// that no rejection traps, so a trap is the only failure a campaign reports.

const std = @import("std");

const targets = @import("targets.zig");

const default_iterations: u64 = 1_000;

const Options = struct {
    iterations: u64 = default_iterations,
    format: ?[]const u8 = null,
};

fn parseOptions(iterator: *std.process.Args.Iterator) !Options {
    var options = Options{};
    _ = iterator.next();
    while (iterator.next()) |arg| {
        if (std.mem.eql(u8, arg, "--iterations")) {
            const value = iterator.next() orelse return error.MissingIterationCount;
            options.iterations = std.fmt.parseInt(u64, value, 10) catch return error.InvalidIterationCount;
        } else if (std.mem.eql(u8, arg, "--format")) {
            options.format = iterator.next() orelse return error.MissingFormatName;
        } else {
            return error.UnexpectedArgument;
        }
    }
    if (options.iterations == 0) return error.EmptyCampaign;
    return options;
}

fn findTarget(name: []const u8) ?targets.Target {
    for (targets.targets) |target| {
        if (std.mem.eql(u8, target.name, name)) return target;
    }
    return null;
}

fn mutate(rng: *u64, seed: []const u8, buffer: *[targets.max_input]u8) []const u8 {
    @memcpy(buffer[0..seed.len], seed);
    var edits: u64 = 1 + (rng.* >> 33) % 8;
    while (edits > 0) : (edits -= 1) {
        rng.* = rng.* *% 6364136223846793005 +% 1442695040888963407;
        const position = (rng.* >> 16) % seed.len;
        buffer[position] = @truncate(rng.* >> 40);
    }
    return buffer[0..seed.len];
}

fn runCampaign(target: targets.Target, iterations: u64) !void {
    if (target.seed.len == 0) return error.EmptySeed;
    var rng: u64 = 0x243F6A8885A308D3;
    var buffer: [targets.max_input]u8 = undefined;
    var completed: u64 = 0;
    while (completed < iterations) : (completed += 1) {
        if (completed % 50_000 == 0) {
            std.debug.print("{s}: {d}/{d}.\n", .{ target.name, completed, iterations });
        }
        target.run(mutate(&rng, target.seed, &buffer)) catch {};
    }
    if (completed != iterations) return error.CampaignShortfall;
    std.debug.print("{s}: {d} mutations survived.\n", .{ target.name, completed });
}

pub fn main(init: std.process.Init) !void {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, std.heap.page_allocator);
    defer iterator.deinit();
    const options = try parseOptions(&iterator);
    var selected: usize = 0;
    for (targets.targets) |target| {
        if (options.format) |name| {
            if (!std.mem.eql(u8, target.name, name)) continue;
        }
        try runCampaign(target, options.iterations);
        selected += 1;
    }
    if (selected == 0) {
        std.debug.print("campaign: unknown format {s}.\n", .{options.format.?});
        return error.UnknownFormat;
    }
    std.debug.print("campaign: {d} format(s), {d} mutations each.\n", .{ selected, options.iterations });
}
