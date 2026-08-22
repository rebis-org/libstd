const std = @import("std");

const archive = @import("archive.zig");
const bound = @import("bound.zig");
const checksum = @import("checksum.zig");
const harness = @import("harness.zig");
const inflate = @import("inflate.zig");
const lib = @import("lib.zig");
const lzma = @import("lzma.zig");
const primitives = @import("primitives.zig");
const protocol = @import("protocol.zig");
const registry_checks = @import("registry.zig");
const seven_zip = @import("sevenzip.zig");
const tar = @import("tar.zig");
const transform = @import("transform.zig");
const xz = @import("xz.zig");
const zstd = @import("zstd.zig");
const zip = @import("zip.zig");

const scenarios = blk: {
    const groups = [_][]const harness.Scenario{
        &protocol.scenarios,
        &transform.scenarios,
        &bound.scenarios,
        &.{registry_checks.scenario},
        &.{primitives.scenario},
        &checksum.scenarios,
        &archive.scenarios,
        &tar.scenarios,
        &zip.scenarios,
        &seven_zip.scenarios,
        &lzma.scenarios,
        &xz.scenarios,
        &zstd.scenarios,
        &inflate.scenarios,
    };
    var total: usize = 0;
    for (groups) |group| total += group.len;
    var list: [total]harness.Scenario = undefined;
    var index: usize = 0;
    for (groups) |group| {
        @memcpy(list[index..][0..group.len], group);
        index += group.len;
    }
    break :blk list;
};

pub fn main(init: std.process.Init) !void {
    harness.io = init.io;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    var filter_suite: ?[]const u8 = null;
    var filter_scenario: ?[]const u8 = null;
    var catalog_path: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--suite")) {
            filter_suite = args.next() orelse return error.MissingSuiteArgument;
        } else if (std.mem.eql(u8, arg, "--scenario")) {
            filter_scenario = args.next() orelse return error.MissingScenarioArgument;
        } else if (catalog_path == null) {
            catalog_path = arg;
        } else {
            return error.UnexpectedArgument;
        }
    }

    std.debug.print("ORACLES_START\n", .{});
    const parsed = try harness.loadCatalog(catalog_path orelse return error.MissingCatalogArgument);
    std.debug.print("oracle catalog epoch: {d}\n", .{parsed.epoch});
    for (lib.requiredStatuses()) |entry| {
        std.debug.print("oracle lib {s}: available\n", .{entry.name});
    }
    std.debug.print("SCENARIO_BLOCK\n", .{});
    for (scenarios) |scenario| {
        if (filter_suite) |name| {
            if (!std.mem.eql(u8, scenario.suite, name)) continue;
        }
        if (filter_scenario) |name| {
            if (!std.mem.eql(u8, scenario.name, name)) continue;
        }
        runScenario(scenario) catch |err| {
            std.debug.print("scenario {s} failed: {s}\n", .{ scenario.name, @errorName(err) });
            std.process.exit(1);
        };
    }
    if (filter_suite) |name| {
        if (!hasScenario("suite", name)) return error.UnknownSuiteFilter;
    }
    if (filter_scenario) |name| {
        if (!hasScenario("name", name)) return error.UnknownScenarioFilter;
    }
}

fn hasScenario(comptime field: []const u8, name: []const u8) bool {
    for (scenarios) |scenario| {
        if (std.mem.eql(u8, @field(scenario, field), name)) return true;
    }
    return false;
}

fn runScenario(scenario: harness.Scenario) !void {
    const allocator = std.heap.page_allocator;
    var runner = harness.Runner{
        .gpa = allocator,
        .scenario_name = scenario.name,
        .corpus_index = scenario.corpus,
    };
    runner.workspace = try allocator.alloc(u8, @max(scenario.workspace_size, 1));
    runner.output = try allocator.alloc(u8, @max(scenario.output_size, 1));
    runner.encoded = try allocator.alloc(u8, @max(scenario.encoded_size, 1));
    const owned_workspace = runner.workspace;
    const owned_output = runner.output;
    const owned_encoded = runner.encoded;
    defer allocator.free(owned_workspace);
    defer allocator.free(owned_output);
    defer allocator.free(owned_encoded);
    try scenario.run(&runner);
    std.debug.print("{s} done\n", .{scenario.name});
}
