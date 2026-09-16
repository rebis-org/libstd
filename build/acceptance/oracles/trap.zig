const std = @import("std");
const nucleus = @import("nucleus");

const span = nucleus.span;
const lease = nucleus.lease;
const block = nucleus.block;
const surface = nucleus.surface;

// Re-executes per scenario: contract violations trap the process, so driver and scenarios cannot share an address space.
fn scenarioWritePastEnd() void {
    var storage: [16]u8 = undefined;
    const view = span.mutSpan(&storage, storage.len) catch unreachable;
    view.write(storage.len, "x");
}

fn scenarioReadPastEnd() void {
    var storage: [16]u8 = undefined;
    const view = span.mutSpan(&storage, storage.len) catch unreachable;
    _ = view.read(1, storage.len);
}

fn scenarioSubspanOverflow() void {
    var storage: [16]u8 = undefined;
    const view = span.mutSpan(&storage, storage.len) catch unreachable;
    _ = view.sub(std.math.maxInt(usize), 1);
}

fn scenarioOverlap() void {
    var storage: [32]u8 = undefined;
    const first = (span.constSpan(&storage, 24) catch unreachable);
    const second = (span.constSpan(storage[8..].ptr, 24) catch unreachable);
    span.requireDisjoint(first, second, "overlap check");
}

fn scenarioRevokedLease() void {
    var storage: [16]u8 = undefined;
    var slots: [4]lease.Registry.Slot = undefined;
    var registry = lease.Registry.init(&slots);
    const memory = span.constSpan(&storage, storage.len) catch unreachable;
    const token = registry.lease(memory) catch unreachable;
    registry.revoke(token);
    _ = registry.span(token, 0, 1);
}

fn scenarioUnknownLease() void {
    var slots: [4]lease.Registry.Slot = undefined;
    var registry = lease.Registry.init(&slots);
    _ = registry.span(.{ .token = 99 }, 0, 1);
}

fn scenarioStaleBlock() void {
    var storage: [32]u8 = undefined;
    var tracked = block.Block.init(&storage) catch unreachable;
    const view = tracked.acquire();
    tracked.free();
    view.write(0, "x");
}

fn scenarioDoublePoison() void {
    var storage: [32]u8 = undefined;
    var tracked = block.Block.init(&storage) catch unreachable;
    const first = tracked.acquire();
    tracked.free();
    tracked.free();
    _ = first.read(0, 1);
}

fn scenarioCopyAlias() void {
    var storage: [16]u8 = undefined;
    const lying = surface.Surface{ .ptr = &storage, .len = storage.len + 64 };
    _ = surface.nucleusCopy(lying, .{ .ptr = &storage, .len = storage.len });
}

fn scenarioCleanSessions() void {
    var left_storage: [16]u8 = undefined;
    var right_storage: [16]u8 = undefined;
    var left_slots: [2]lease.Registry.Slot = undefined;
    var right_slots: [2]lease.Registry.Slot = undefined;
    var left = lease.Registry.init(&left_slots);
    var right = lease.Registry.init(&right_slots);
    const left_lease = left.lease(span.constSpan(&left_storage, left_storage.len) catch unreachable) catch unreachable;
    const right_lease = right.lease(span.constSpan(&right_storage, right_storage.len) catch unreachable) catch unreachable;
    left.span(left_lease, 0, 8).write(0, "aaaaaaaa");
    right.span(right_lease, 0, 8).write(0, "bbbbbbbb");
    left.revoke(left_lease);
    right.span(right_lease, 8, 8).write(0, "BBBBBBBB");
    if (!std.mem.eql(u8, right_storage[0..8], "bbbbbbbb")) std.process.exit(6);
    if (!std.mem.eql(u8, right_storage[8..16], "BBBBBBBB")) std.process.exit(7);
}

fn scenarioCopyNull() void {
    std.process.exit(@intCast(surface.nucleusCopy(.{ .ptr = null, .len = 8 }, .{ .ptr = null, .len = 0 })));
}

fn scenarioCleanAccess() void {
    var storage: [16]u8 = undefined;
    const view = span.mutSpan(&storage, storage.len) catch unreachable;
    view.write(0, "abcd");
    if (!std.mem.eql(u8, view.read(0, 4), "abcd")) std.process.exit(3);
}

fn scenarioCleanDisjoint() void {
    var left: [16]u8 = undefined;
    var right: [16]u8 = undefined;
    span.requireDisjoint(
        span.constSpan(&left, left.len) catch unreachable,
        span.constSpan(&right, right.len) catch unreachable,
        "overlap check",
    );
}

fn scenarioCleanLease() void {
    var storage: [16]u8 = undefined;
    var slots: [4]lease.Registry.Slot = undefined;
    var registry = lease.Registry.init(&slots);
    const token = registry.lease(span.constSpan(&storage, storage.len) catch unreachable) catch unreachable;
    const view = registry.span(token, 4, 8);
    view.write(0, "abcd");
}

fn scenarioCleanBlock() void {
    var storage: [32]u8 = undefined;
    var tracked = block.Block.init(&storage) catch unreachable;
    const view = tracked.acquire();
    tracked.free();
    var revived = block.Block.init(&storage) catch unreachable;
    const fresh = revived.acquire();
    fresh.write(0, "abcd");
    _ = view;
}

fn scenarioCopyRoundTrip() void {
    var source: [16]u8 = undefined;
    var destination: [16]u8 = undefined;
    @memcpy(&source, "0123456789abcdef");
    const result = surface.nucleusCopy(
        .{ .ptr = &destination, .len = destination.len },
        .{ .ptr = &source, .len = source.len },
    );
    if (result != 0) std.process.exit(4);
    if (!std.mem.eql(u8, &destination, &source)) std.process.exit(5);
}

// Single table for both modes: a separate name list drifts (copy-null once shipped without driver coverage).
const Expect = union(enum) {
    trap: void,
    exit: u8,
};

const scenarios = [_]struct {
    name: []const u8,
    expect: Expect,
    run: *const fn () void,
}{
    .{ .name = "write-past-end", .expect = .trap, .run = scenarioWritePastEnd },
    .{ .name = "read-past-end", .expect = .trap, .run = scenarioReadPastEnd },
    .{ .name = "subspan-overflow", .expect = .trap, .run = scenarioSubspanOverflow },
    .{ .name = "overlap", .expect = .trap, .run = scenarioOverlap },
    .{ .name = "revoked-lease", .expect = .trap, .run = scenarioRevokedLease },
    .{ .name = "unknown-lease", .expect = .trap, .run = scenarioUnknownLease },
    .{ .name = "stale-block", .expect = .trap, .run = scenarioStaleBlock },
    .{ .name = "double-poison", .expect = .trap, .run = scenarioDoublePoison },
    .{ .name = "copy-alias", .expect = .trap, .run = scenarioCopyAlias },
    .{ .name = "clean-access", .expect = .{ .exit = 0 }, .run = scenarioCleanAccess },
    .{ .name = "clean-disjoint", .expect = .{ .exit = 0 }, .run = scenarioCleanDisjoint },
    .{ .name = "clean-lease", .expect = .{ .exit = 0 }, .run = scenarioCleanLease },
    .{ .name = "clean-block", .expect = .{ .exit = 0 }, .run = scenarioCleanBlock },
    .{ .name = "clean-sessions", .expect = .{ .exit = 0 }, .run = scenarioCleanSessions },
    // Null with nonzero length reports invalid_call, not a trap.
    .{ .name = "copy-null", .expect = .{ .exit = 1 }, .run = scenarioCopyNull },
    .{ .name = "copy-round-trip", .expect = .{ .exit = 0 }, .run = scenarioCopyRoundTrip },
};

// Signals 4-11 cover SIGILL..SIGSEGV; SIGTRAP and debug panics land in the same band.
fn isTrapSignal(term: std.process.Child.Term) bool {
    return switch (term) {
        .signal => |sig| @intFromEnum(sig) >= 4 and @intFromEnum(sig) <= 11,
        else => false,
    };
}

const Outcome = struct {
    term: std.process.Child.Term,
    output: []u8,
};

fn run(gpa: std.mem.Allocator, io: std.Io, exe: []const u8, name: []const u8) !Outcome {
    const result = try std.process.run(gpa, io, .{
        .argv = &.{ exe, name },
    });
    return .{ .term = result.term, .output = result.stderr };
}

fn trim(output: []const u8) []const u8 {
    return std.mem.trim(u8, output, " \t\n\r");
}

fn substrateImportsFormatLayers(gpa: std.mem.Allocator, io: std.Io) !bool {
    const roots = [_][]const u8{ "../leaf", "../grammar", "../adapter", "../catalog" };
    var dir = try std.Io.Dir.cwd().openDir(io, "src/nucleus", .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.path, ".zig")) continue;
        const bytes = try entry.dir.readFileAlloc(io, entry.path, gpa, .limited(1 << 22));
        defer gpa.free(bytes);
        for (roots) |root| {
            var one: [32]u8 = undefined;
            var two: [32]u8 = undefined;
            const one_up = try std.fmt.bufPrint(&one, "@import(\"{s}\")", .{root});
            const two_up = try std.fmt.bufPrint(&two, "@import(\"../{s}\")", .{root});
            if (std.mem.indexOf(u8, bytes, one_up) != null) return true;
            if (std.mem.indexOf(u8, bytes, two_up) != null) return true;
        }
    }
    return false;
}

fn drive(init: std.process.Init, self_exe: [:0]const u8) !void {
    const gpa = std.heap.page_allocator;
    var failed = false;
    for (scenarios) |scenario| {
        const outcome = try run(gpa, init.io, self_exe, scenario.name);
        switch (scenario.expect) {
            .trap => {
                if (!isTrapSignal(outcome.term)) {
                    std.debug.print("FAIL {s}: expected signal exit, got {s} ({s})\n", .{ scenario.name, @tagName(outcome.term), trim(outcome.output) });
                    failed = true;
                } else if (outcome.output.len == 0) {
                    std.debug.print("FAIL {s}: trap produced no diagnostic\n", .{scenario.name});
                    failed = true;
                } else {
                    std.debug.print("ok {s} (trapped: {s})\n", .{ scenario.name, trim(outcome.output) });
                }
            },
            .exit => |code| {
                switch (outcome.term) {
                    .exited => |actual| {
                        if (actual != code) {
                            std.debug.print("FAIL {s}: expected exit {d}, got {d}\n", .{ scenario.name, code, actual });
                            failed = true;
                        } else if (code == 0) {
                            std.debug.print("ok {s} (clean)\n", .{scenario.name});
                        } else {
                            std.debug.print("ok {s} (status {d})\n", .{ scenario.name, code });
                        }
                    },
                    else => {
                        std.debug.print("FAIL {s}: expected exit {d}, got {s}\n", .{ scenario.name, code, @tagName(outcome.term) });
                        failed = true;
                    },
                }
            },
        }
    }

    if (try substrateImportsFormatLayers(gpa, init.io)) {
        std.debug.print("FAIL substrate imports format layers\n", .{});
        failed = true;
    } else {
        std.debug.print("ok substrate import graph (no format knowledge)\n", .{});
    }

    if (failed) {
        std.debug.print("trap suite: FAILED\n", .{});
        std.process.exit(1);
    }
    std.debug.print("trap suite: all scenarios passed\n", .{});
}

pub fn main(init: std.process.Init) !void {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    const self_exe = args.next() orelse {
        std.debug.print("usage: oracles_trap [scenario]\n", .{});
        std.process.exit(2);
    };
    const name = args.next() orelse {
        try drive(init, self_exe);
        return;
    };
    for (scenarios) |scenario| {
        if (std.mem.eql(u8, name, scenario.name)) {
            scenario.run();
            std.process.exit(0);
        }
    }
    std.debug.print("Unknown scenario \"{s}\".\n", .{name});
    std.process.exit(2);
}
