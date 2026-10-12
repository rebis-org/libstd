const std = @import("std");

pub const components = @import("components");
const contract = @import("interface").contract;

// Table is comptime-small, so linear scan suffices. Hot dispatch lives in the drivers.
pub fn enumerate() []const contract.Descriptor {
    return &components.descriptors;
}

pub fn findByName(name: []const u8) ?*const contract.Descriptor {
    return findDescriptor(.{ .by_name = name });
}

pub fn findById(id: contract.Id) ?*const contract.Descriptor {
    return findDescriptor(.{ .by_id = id });
}

pub const Lookup = union(enum) { by_name: []const u8, by_id: contract.Id };

fn findDescriptor(lookup: Lookup) ?*const contract.Descriptor {
    @setEvalBranchQuota(10_000);
    for (&components.descriptors) |*descriptor| {
        switch (lookup) {
            .by_name => |wanted| if (std.mem.eql(u8, descriptor.name, wanted)) return descriptor,
            .by_id => |wanted| if (contract.eql(descriptor.id, wanted)) return descriptor,
        }
    }
    return null;
}

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
