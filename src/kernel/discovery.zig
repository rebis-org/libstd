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

test "discovery enumerate exposes the testing fixtures with pinned identities" {
    const all = enumerate();
    const expected = [_]struct { name: []const u8, low: u64, high: u64 }{
        .{ .name = "test_echo", .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4001 },
        .{ .name = "test_read", .low = 0x6e6b_82f0_8d91_0402, .high = 0xa7a3_5105_3d6d_4002 },
        .{ .name = "crypto", .low = 0x6e6b_82f0_8d91_0410, .high = 0xa7a3_5105_3d6d_4010 },
    };
    for (expected) |pin| {
        var hits: usize = 0;
        for (all) |descriptor| {
            if (std.mem.eql(u8, descriptor.name, pin.name)) {
                hits += 1;
                try std.testing.expectEqual(pin.low, descriptor.id.low);
                try std.testing.expectEqual(pin.high, descriptor.id.high);
            }
        }
        try std.testing.expectEqual(@as(usize, 1), hits);
    }
    // The catalog is a comptime table: repeated enumeration serves the same slice.
    try std.testing.expect(enumerate().ptr == all.ptr);
}

test "discovery fixture descriptors carry their declared class verbs and capabilities" {
    const echo = findByName("test_echo").?;
    try std.testing.expectEqual(contract.Class.slice, echo.class);
    try std.testing.expectEqual(@as(u32, 7), echo.command_mask); // inspect/decode/encode verb groups
    try std.testing.expectEqual(@as(u32, 63), echo.capabilities); // read|write|size|replay|seek|range
    try std.testing.expectEqual(contract.SizingMode.metadata_exact, echo.sizing);
    try std.testing.expectEqual(contract.CommitMode.confirmed, echo.commit);
    try std.testing.expectEqual(@as(usize, 0), echo.parameters.len);
    try std.testing.expectEqual(@as(u32, 0), echo.volumes);

    const read = findByName("test_read").?;
    try std.testing.expectEqual(contract.Class.slice, read.class);
    try std.testing.expectEqual(@as(u32, 63), read.capabilities);

    const crypto = findByName("crypto").?;
    try std.testing.expectEqual(contract.Class.grammar, crypto.class);
    try std.testing.expectEqual(@as(u32, 15), crypto.capabilities); // read|write|size|replay
    try std.testing.expectEqual(contract.SizingMode.metadata_exact, crypto.sizing);
    try std.testing.expectEqual(contract.CommitMode.confirmed, crypto.commit);
}

test "discovery findByName resolves exact names only" {
    const echo = findByName("test_echo").?;
    try std.testing.expectEqualStrings("test_echo", echo.name);
    try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0401), echo.id.low);
    try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_4001), echo.id.high);
    try std.testing.expect(findByName("Test_Echo") == null);
    try std.testing.expect(findByName("test_ech") == null);
    try std.testing.expect(findByName("test_echo_suffix") == null);
    try std.testing.expect(findByName("") == null);
}

test "discovery findById and findByName agree on the same descriptors" {
    // The lookup union tags the two entry points.
    const by_name: Lookup = .{ .by_name = "test_echo" };
    try std.testing.expectEqual(Lookup.by_name, std.meta.activeTag(by_name));
    const by_id: Lookup = .{ .by_id = .{ .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4001 } };
    try std.testing.expectEqual(Lookup.by_id, std.meta.activeTag(by_id));

    for ([_][]const u8{ "test_echo", "test_read", "crypto" }) |name| {
        const named = findByName(name).?;
        const identified = findById(named.id).?;
        try std.testing.expectEqualStrings(named.name, identified.name);
        try std.testing.expectEqual(named.id.low, identified.id.low);
        try std.testing.expectEqual(named.id.high, identified.id.high);
    }
    // A crossed word pair (echo low, read high) is a stranger.
    try std.testing.expect(findById(.{ .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4002 }) == null);
    try std.testing.expect(findById(.{ .low = 1, .high = 1 }) == null);
}

test "discovery maxOrdinalFor scans the declared parameter ceilings" {
    try std.testing.expectEqual(@as(u32, 0), maxOrdinalFor(0)); // no descriptor declares family-zero parameters
    try std.testing.expectEqual(@as(u32, 8), maxOrdinalFor(1));
    try std.testing.expectEqual(@as(u32, 16), maxOrdinalFor(2)); // tar entry_mode is the family-2 ceiling
    try std.testing.expectEqual(@as(u32, 8), maxOrdinalFor(3));
    try std.testing.expectEqual(@as(u32, 12), maxOrdinalFor(4));
    try std.testing.expectEqual(@as(u32, 0), maxOrdinalFor(9)); // family with no declared parameters
    // The family-2 ceiling is achieved by a real descriptor entry, not an off-by-one.
    const tar = findByName("tar").?;
    var found = false;
    for (tar.parameters) |entry| {
        if (entry.ordinal == 16) {
            found = true;
            try std.testing.expectEqualStrings("entry_mode", entry.name);
            try std.testing.expectEqual(@as(u16, 2), entry.family);
            try std.testing.expectEqual(contract.Representation.scalar_words, entry.representation);
        }
    }
    try std.testing.expect(found);
}

test "discovery isSelectorKnown pins family zero protocol and descriptor families" {
    // Family zero: exactly the six protocol parameters are known.
    for (1..7) |ordinal| {
        try std.testing.expect(isSelectorKnown(0, @intCast(ordinal)));
    }
    try std.testing.expect(!isSelectorKnown(0, 0));
    try std.testing.expect(!isSelectorKnown(0, 7));
    // Descriptor families: ordinal zero is never a selector.
    try std.testing.expect(!isSelectorKnown(2, 0));
    try std.testing.expect(isSelectorKnown(2, 1));
    try std.testing.expect(isSelectorKnown(2, 16));
    try std.testing.expect(!isSelectorKnown(2, 17));
    // A family with no declared parameters knows no selector.
    try std.testing.expect(!isSelectorKnown(9, 1));
}

test "discovery parameter comptime lookup resolves tar family two entries" {
    const mode = comptime parameter("tar", "entry_mode");
    try std.testing.expectEqualStrings("entry_mode", mode.name);
    try std.testing.expectEqual(@as(u16, 2), mode.family);
    try std.testing.expectEqual(@as(u16, 16), mode.ordinal);
    try std.testing.expectEqual(contract.Representation.scalar_words, mode.representation);

    const ordinal_parameter = comptime parameter("tar", "ordinal");
    try std.testing.expectEqualStrings("ordinal", ordinal_parameter.name);
    try std.testing.expectEqual(@as(u16, 1), ordinal_parameter.ordinal);

    // The comptime lookup agrees with the runtime descriptor table.
    const tar = findByName("tar").?;
    var matches: usize = 0;
    for (tar.parameters) |entry| {
        if (std.mem.eql(u8, entry.name, "entry_mode")) {
            matches += 1;
            try std.testing.expectEqual(entry.family, mode.family);
            try std.testing.expectEqual(entry.ordinal, mode.ordinal);
            try std.testing.expectEqual(entry.representation, mode.representation);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), matches);
}
