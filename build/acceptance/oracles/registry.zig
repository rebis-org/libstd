const std = @import("std");

const harness = @import("harness.zig");

fn require(ok: bool) !void {
    if (!ok) return error.RegistryCheckFailed;
}

fn descriptorByName(name: []const u8) ?*const harness.catalog.DescriptorJson {
    for (harness.catalog_descriptors) |*descriptor| {
        if (std.mem.eql(u8, descriptor.name, name)) return descriptor;
    }
    return null;
}

fn requireDescriptor(name: []const u8) !*const harness.catalog.DescriptorJson {
    return descriptorByName(name) orelse return error.MissingDescriptor;
}

fn requireUnique(descriptors: []const harness.catalog.DescriptorJson) !void {
    for (descriptors, 0..) |descriptor, index| {
        if (descriptor.id.low.len == 0 or descriptor.id.high.len == 0) return error.EmptyDescriptorId;
        for (descriptors[index + 1 ..]) |other| {
            if (std.mem.eql(u8, descriptor.name, other.name)) return error.DuplicateDescriptorName;
            if (std.mem.eql(u8, descriptor.id.low, other.id.low) and std.mem.eql(u8, descriptor.id.high, other.id.high)) {
                return error.DuplicateDescriptorId;
            }
        }
    }
}

const Expectation = struct {
    name: []const u8,
    planning: ?[]const u8 = null,
    delivery: ?[]const u8 = null,
    command_mask: ?u32 = null,
    kind: ?[]const u8 = null,
};

fn requireExpectations() !void {
    const expectations = [_]Expectation{
        .{ .name = "deflate", .planning = "replay_pass", .delivery = "provisional", .command_mask = 7 },
        .{ .name = "tar", .planning = "metadata_exact", .command_mask = 7 },
        .{ .name = "zstd", .delivery = "verified" },
        .{ .name = "xz", .delivery = "verified" },
        .{ .name = "crypto", .kind = "profile" },
    };
    for (expectations) |expected| {
        const descriptor = try requireDescriptor(expected.name);
        if (expected.planning) |value| try require(std.mem.eql(u8, descriptor.planning, value));
        if (expected.delivery) |value| try require(std.mem.eql(u8, descriptor.delivery, value));
        if (expected.command_mask) |value| try require(descriptor.command_mask == value);
        if (expected.kind) |value| try require(std.mem.eql(u8, descriptor.kind, value));
    }
}

fn requireCoreDescriptors() !void {
    const names = [_][]const u8{
        "query",
        "read",
        "write",
        "source",
        "sink",
        "profile",
        "target_command",
        "parameter",
        "resource_read",
        "resource_write",
        "resource_size",
        "resource_replay",
        "resource_seek",
        "resource_range",
    };
    for (names) |name| _ = try requireDescriptor(name);
}

pub fn run(_: *harness.Runner) anyerror!void {
    const descriptors = harness.catalog_descriptors;
    try require(descriptors.len != 0);
    try requireUnique(descriptors);
    try requireCoreDescriptors();
    try requireExpectations();
}

pub const scenario = harness.Scenario{
    .name = "registry derivation",
    .suite = "registry",
    .run = run,
    .workspace_size = 256,
    .output_size = 64,
    .encoded_size = 64,
};
