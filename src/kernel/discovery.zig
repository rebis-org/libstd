const std = @import("std");
const contract = @import("interface").contract;
pub const components = @import("components");

// Table is comptime-small, so linear scan suffices. Hot dispatch lives in the drivers.
pub fn enumerate() []const contract.Descriptor {
    return &components.descriptors;
}

pub fn findByName(name: []const u8) ?*const contract.Descriptor {
    @setEvalBranchQuota(10_000);
    for (&components.descriptors) |*descriptor| {
        if (std.mem.eql(u8, descriptor.name, name)) return descriptor;
    }
    return null;
}

pub fn findById(id: contract.Id) ?*const contract.Descriptor {
    @setEvalBranchQuota(10_000);
    for (&components.descriptors) |*descriptor| {
        if (contract.idEqual(descriptor.id, id)) return descriptor;
    }
    return null;
}

// Ordinals are component data. One declaration per wire parameter.
pub fn parameter(comptime component_name: []const u8, comptime parameter_name: []const u8) contract.Parameter {
    @setEvalBranchQuota(10_000);
    const component = findByName(component_name) orelse @compileError("Unknown component \"" ++ component_name ++ "\": no descriptor declares this name.");
    for (component.parameters) |parameter_entry| {
        if (std.mem.eql(u8, parameter_entry.name, parameter_name)) return parameter_entry;
    }
    @compileError("Unknown parameter \"" ++ parameter_name ++ "\" for component \"" ++ component_name ++ "\".");
}

pub fn maxOrdinalFor(family: u16) u32 {
    var max: u32 = 0;
    for (components.descriptors) |descriptor| {
        for (descriptor.parameters) |parameter_entry| {
            if (parameter_entry.family == family and parameter_entry.ordinal > max) max = parameter_entry.ordinal;
        }
    }
    return max;
}

pub fn isSelectorKnown(family: u16, ordinal: u32) bool {
    if (family == 0) return ordinal >= 1 and ordinal <= 6;
    if (ordinal == 0) return false;
    return ordinal <= maxOrdinalFor(family);
}

// Emits catalog JSON the oracle harness parses, preserving its name-based loading seam.
pub fn renderCatalog(writer: anytype) !void {
    try writer.writeAll("{\"epoch\":7,\"descriptors\":[");
    for (components.descriptors, 0..) |descriptor, index| {
        if (index != 0) try writer.writeAll(",");
        try writer.print(
            "{{\"id\":{{\"low\":\"0x{x}\",\"high\":\"0x{x}\"}},\"name\":\"{s}\",\"kind\":\"component\",\"class\":\"{s}\"}}",
            .{ descriptor.id.low, descriptor.id.high, descriptor.name, @tagName(descriptor.class) },
        );
    }
    try writer.writeAll("]}");
}
