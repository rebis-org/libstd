const std = @import("std");

const acceptance = @import("acceptance.zig");
const checks = @import("checks.zig");
const dist = @import("dist.zig");
const common = @import("platform/common.zig");
const vendor = @import("vendor.zig");

pub const Category = enum {
    distribution,
    acceptance,
    vendor,
    checks,
};

pub const registry = .{
    .vendor = .{ .category = Category.vendor, .units = vendor.units, .expand = vendor.expand },
    .acceptance = .{ .category = Category.acceptance, .units = acceptance.units, .expand = acceptance.expand },
    .distribution = .{ .category = Category.distribution, .units = dist.units, .expand = dist.expand },
    .checks = .{ .category = Category.checks, .units = checks.units, .expand = checks.expand },
};

comptime {
    for (std.meta.fields(@TypeOf(registry))) |field| {
        if (!@hasField(Category, field.name)) @compileError("registry field is not a category: " ++ field.name);
        const layer = @field(registry, field.name);
        for (layer.units, 0..) |unit, index| {
            for (layer.units[0..index]) |other| {
                if (std.mem.eql(u8, unit.name, other.name)) @compileError("duplicate unit name: " ++ unit.name);
            }
        }
    }
}

pub fn expand(b: *std.Build, ctx: *common.Context) void {
    inline for (std.meta.fields(@TypeOf(registry))) |field| {
        @field(registry, field.name).expand(b, ctx);
    }
}

pub fn addListingStep(b: *std.Build) *std.Build.Step {
    const self = b.allocator.create(UnitsStep) catch @panic("OOM");
    self.* = .{
        .step = std.Build.Step.init(.{
            .id = .custom,
            .name = "units",
            .owner = b,
            .makeFn = UnitsStep.make,
        }),
    };
    b.step("units", "List registered build units").dependOn(&self.step);
    return &self.step;
}

const UnitsStep = struct {
    step: std.Build.Step,

    fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
        _ = options;
        writeList();
        step.result_cached = false;
    }
};

fn writeList() void {
    inline for (std.meta.fields(@TypeOf(registry))) |field| {
        const layer = @field(registry, field.name);
        std.debug.print("{s}:\n", .{@tagName(layer.category)});
        for (layer.units) |unit| {
            std.debug.print("  {s}\n", .{unit.name});
        }
    }
}
