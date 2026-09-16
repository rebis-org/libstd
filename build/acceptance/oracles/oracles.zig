const std = @import("std");

const components = @import("components");

const api = @import("api.zig");
const archive = @import("archive.zig");
const bound = @import("bound.zig");
const checksum = @import("checksum.zig");
const harness = @import("harness.zig");
const inflate = @import("inflate.zig");
const interop = @import("interop.zig");
const lib = @import("lib.zig");
const lzma = @import("lzma.zig");
const primitives = @import("primitives.zig");
const protocol = @import("protocol.zig");
const registry_checks = @import("registry.zig");
const seven_zip = @import("sevenzip.zig");
const tar = @import("tar.zig");
const transform = @import("transform.zig");
const xz = @import("xz.zig");
const zip = @import("zip.zig");
const zstd = @import("zstd.zig");

// Suites derive from the component table: removing a descriptor removes its suite with no central edits.
// Harness constants duplicate the table for build-side convenience; descriptors stay authoritative, drift fails the build.
comptime {
    const Pin = struct { component: []const u8, parameter: []const u8, family: u16, ordinal: u32 };
    const pins = [_]Pin{
        .{ .component = "gzip", .parameter = "modification_time", .family = 3, .ordinal = 1 },
        .{ .component = "gzip", .parameter = "extra_flags", .family = 3, .ordinal = 2 },
        .{ .component = "gzip", .parameter = "operating_system", .family = 3, .ordinal = 3 },
        .{ .component = "gzip", .parameter = "text", .family = 3, .ordinal = 4 },
        .{ .component = "gzip", .parameter = "header_crc", .family = 3, .ordinal = 5 },
        .{ .component = "gzip", .parameter = "extra", .family = 3, .ordinal = 6 },
        .{ .component = "gzip", .parameter = "name", .family = 3, .ordinal = 7 },
        .{ .component = "gzip", .parameter = "comment", .family = 3, .ordinal = 8 },
        .{ .component = "deflate", .parameter = "good", .family = 8, .ordinal = 1 },
        .{ .component = "deflate", .parameter = "nice", .family = 8, .ordinal = 2 },
        .{ .component = "deflate", .parameter = "lazy", .family = 8, .ordinal = 3 },
        .{ .component = "deflate", .parameter = "chain", .family = 8, .ordinal = 4 },
        .{ .component = "deflate", .parameter = "optimal", .family = 8, .ordinal = 5 },
        .{ .component = "zstd", .parameter = "window", .family = 4, .ordinal = 1 },
        .{ .component = "zstd", .parameter = "hash_bits", .family = 4, .ordinal = 3 },
        .{ .component = "zstd", .parameter = "skip_interior_insert", .family = 4, .ordinal = 8 },
        .{ .component = "zstd", .parameter = "double_hash", .family = 4, .ordinal = 9 },
        .{ .component = "zstd", .parameter = "row_match", .family = 4, .ordinal = 10 },
        .{ .component = "bzip2", .parameter = "block_size", .family = 5, .ordinal = 1 },
        .{ .component = "lzma", .parameter = "dictionary", .family = 6, .ordinal = 1 },
        .{ .component = "lzma", .parameter = "match_finder_depth", .family = 6, .ordinal = 2 },
        .{ .component = "lzma", .parameter = "match_finder", .family = 6, .ordinal = 5 },
        .{ .component = "xz", .parameter = "check", .family = 7, .ordinal = 1 },
        .{ .component = "xz", .parameter = "filters", .family = 7, .ordinal = 2 },
        .{ .component = "tar", .parameter = "ordinal", .family = 2, .ordinal = 1 },
        .{ .component = "tar", .parameter = "entry", .family = 2, .ordinal = 5 },
        .{ .component = "tar", .parameter = "entry_data", .family = 2, .ordinal = 6 },
        .{ .component = "tar", .parameter = "entry_method", .family = 2, .ordinal = 7 },
        .{ .component = "zip", .parameter = "password", .family = 1, .ordinal = 1 },
        .{ .component = "zip", .parameter = "algorithm", .family = 1, .ordinal = 2 },
        .{ .component = "zip", .parameter = "kdf_rounds_limit", .family = 1, .ordinal = 3 },
        .{ .component = "zip", .parameter = "password_lifetime", .family = 1, .ordinal = 4 },
    };
    for (pins) |pin| {
        const component = for (components.descriptors) |descriptor| {
            if (std.mem.eql(u8, descriptor.name, pin.component)) break descriptor;
        } else @compileError("pin names unknown component: " ++ pin.component);
        const parameter = for (component.parameters) |parameter_entry| {
            if (std.mem.eql(u8, parameter_entry.name, pin.parameter)) break parameter_entry;
        } else @compileError("pin names unknown parameter: " ++ pin.component ++ "." ++ pin.parameter);
        if (parameter.family != pin.family or parameter.ordinal != pin.ordinal)
            @compileError("harness constant drifted from descriptor: " ++ pin.component ++ "." ++ pin.parameter);
    }
}

fn componentPresent(comptime name: []const u8) bool {
    for (components.descriptors) |descriptor| {
        if (std.mem.eql(u8, descriptor.name, name)) return true;
    }
    return false;
}

const format_groups = format_block: {
    const Group = struct {
        components: []const []const u8,
        scenarios: []const harness.Scenario,
    };
    // Component keys use frozen descriptor identity ("lzma-file", "sevenzip");
    // profiles, benchmark rows, and suite labels use the released stems
    // ("lzma_file", "seven_zip"). Do not unify the spellings.
    const mapping = [_]Group{
        .{ .components = &.{ "deflate", "gzip", "bzip2" }, .scenarios = &transform.scenarios },
        .{ .components = &.{"deflate"}, .scenarios = &inflate.scenarios },
        .{ .components = &.{ "lzma", "lzma2", "lzma-file" }, .scenarios = &lzma.scenarios },
        .{ .components = &.{"xz"}, .scenarios = &xz.scenarios },
        .{ .components = &.{"zstd"}, .scenarios = &zstd.scenarios },
        .{ .components = &.{"tar"}, .scenarios = &tar.scenarios },
        .{ .components = &.{"zip"}, .scenarios = &zip.scenarios },
        .{ .components = &.{"sevenzip"}, .scenarios = &seven_zip.scenarios },
        .{ .components = &.{"rar"}, .scenarios = &archive.scenarios },
    };
    var list: []const harness.Scenario = &.{};
    for (mapping) |group| {
        const present = for (group.components) |name| {
            if (componentPresent(name)) break true;
        } else false;
        if (present) list = list ++ group.scenarios;
    }
    break :format_block list;
};

const scenarios = scenario_block: {
    const groups = [_][]const harness.Scenario{
        &protocol.scenarios,
        &bound.scenarios,
        &.{registry_checks.scenario},
        &api.scenarios,
        &interop.scenarios,
        &.{primitives.scenario},
        &checksum.scenarios,
        format_groups,
    };
    var total: usize = 0;
    for (groups) |group| total += group.len;
    var list: [total]harness.Scenario = undefined;
    var index: usize = 0;
    for (groups) |group| {
        @memcpy(list[index..][0..group.len], group);
        index += group.len;
    }
    break :scenario_block list;
};

pub fn main(init: std.process.Init) !void {
    harness.oracle_io = init.io;
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
            std.debug.print("Scenario \"{s}\" failed: {s}.\n", .{ scenario.name, @errorName(err) });
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
        .corpus_buffer = undefined,
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
