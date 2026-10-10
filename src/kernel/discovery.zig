const std = @import("std");
const contract = @import("interface").contract;
pub const components = @import("components");

// Table is comptime-small, so linear scan suffices. Hot dispatch lives in the drivers.
pub fn enumerate() []const contract.Descriptor {
    return &components.descriptors;
}

pub fn findByName(name: []const u8) ?*const contract.Descriptor {
    return findDescriptor(name, null);
}

pub fn findById(id: contract.Id) ?*const contract.Descriptor {
    return findDescriptor(null, id);
}

fn findDescriptor(name: ?[]const u8, id: ?contract.Id) ?*const contract.Descriptor {
    @setEvalBranchQuota(10_000);
    for (&components.descriptors) |*descriptor| {
        if (name) |wanted| {
            if (std.mem.eql(u8, descriptor.name, wanted)) return descriptor;
        } else if (id) |wanted| {
            if (contract.eql(descriptor.id, wanted)) return descriptor;
        }
    }
    return null;
}

// Ordinals are component data.
pub fn parameter(comptime component_name: []const u8, comptime parameter_name: []const u8) contract.Parameter {
    @setEvalBranchQuota(10_000);
    const component = findByName(component_name) orelse @compileError("unknown component \"" ++ component_name ++ "\": no descriptor declares this name.");
    for (component.parameters) |entry| {
        if (std.mem.eql(u8, entry.name, parameter_name)) return entry;
    }
    @compileError("unknown parameter \"" ++ parameter_name ++ "\" for component \"" ++ component_name ++ "\".");
}

pub fn maxOrdinalFor(family: u16) u32 {
    var ceiling: u32 = 0;
    for (components.descriptors) |descriptor| {
        for (descriptor.parameters) |entry| {
            if (entry.family == family and entry.ordinal > ceiling) ceiling = entry.ordinal;
        }
    }
    return ceiling;
}

pub fn isSelectorKnown(family: u16, ordinal: u32) bool {
    if (family == 0) return ordinal >= 1 and ordinal <= 6;
    if (ordinal == 0) return false;
    return ordinal <= maxOrdinalFor(family);
}
