const std = @import("std");

const discovery = @import("discovery.zig");
const envelope = @import("envelope.zig");
const vocabulary = @import("vocabulary.zig");

const EnvelopeId = envelope.Id;
pub const Descriptor = vocabulary.Descriptor;

pub fn descriptorFor(id: EnvelopeId) ?*const Descriptor {
    inline for (&sorted_descriptors) |*row| {
        if (vocabulary.eql(id, row.id)) return row;
    }
    return null;
}

// An all-zero id means "no component requested", so it passes as known.
pub fn isKnownId(id: EnvelopeId) bool {
    if (vocabulary.isZero(id)) return true;
    return descriptorFor(id) != null;
}

// Discovered components must keep vocabulary-frozen identities (asserted below).
const profile_descriptors = blk: {
    @setEvalBranchQuota(50_000);
    const components = discovery.enumerate();
    var list: [components.len]Descriptor = undefined;
    for (components, 0..) |component, index| {
        list[index] = .{
            .id = .{ .low = component.id.low, .high = component.id.high },
            .name = component.name,
            .kind = .profile,
            .command_mask = component.command_mask,
            .capability_mask = component.capabilities,
            .sizing = component.sizing,
            .commit = component.commit,
            .volumes = component.volumes,
        };
    }
    break :blk list;
};

fn isIdLessThan(left: EnvelopeId, right: EnvelopeId) bool {
    return left.high < right.high or (left.high == right.high and left.low < right.low);
}

// Stable catalog document order.
pub const sorted_descriptors = blk: {
    @setEvalBranchQuota(100_000);
    var result: [vocabulary.protocol_rows.len + profile_descriptors.len]Descriptor = undefined;
    for (vocabulary.protocol_rows, 0..) |row, index| result[index] = row;
    for (profile_descriptors, 0..) |descriptor, index| result[vocabulary.protocol_rows.len + index] = descriptor;
    for (0..result.len) |index| {
        var least = index;
        for (index + 1..result.len) |candidate| {
            if (isIdLessThan(result[candidate].id, result[least].id)) least = candidate;
        }
        const displaced = result[index];
        result[index] = result[least];
        result[least] = displaced;
    }
    break :blk result;
};

// Single comptime source, so discovery and the packaged artifact cannot drift.
pub const catalog_json = blk: {
    @setEvalBranchQuota(500_000);
    var descriptor_json: []const u8 = "";
    for (sorted_descriptors, 0..) |descriptor, index| {
        descriptor_json = descriptor_json ++ std.fmt.comptimePrint(
            "    {{" ++
                "\"id\":{{\"low\":\"0x{x:0>16}\",\"high\":\"0x{x:0>16}\"}}," ++
                "\"name\":\"{s}\"," ++
                "\"kind\":\"{s}\"," ++
                "\"representation\":\"{s}\"," ++
                "\"cardinality\":\"{s}\"," ++
                "\"direction\":\"{s}\"," ++
                "\"command_mask\":{d}," ++
                "\"capability\":\"{s}\"," ++
                "\"capability_mask\":{d}," ++
                "\"sizing\":\"{s}\"," ++
                "\"commit\":\"{s}\"}}{s}\n",
            .{
                descriptor.id.low,
                descriptor.id.high,
                descriptor.name,
                @tagName(descriptor.kind),
                @tagName(descriptor.representation),
                @tagName(descriptor.cardinality),
                @tagName(descriptor.direction),
                descriptor.command_mask,
                @tagName(descriptor.capability),
                descriptor.capability_mask,
                @tagName(descriptor.sizing),
                @tagName(descriptor.commit),
                if (index + 1 == sorted_descriptors.len) "" else ",",
            },
        );
    }
    break :blk "{\n  \"epoch\": 9,\n  \"parameter_selector\": \"value_high: family(16)|ordinal(32)|attrs(8)|flags(8); value_low: scalar value\",\n  \"descriptors\": [\n" ++ descriptor_json ++ "  ]\n}\n";
};

comptime {
    // Released identities are a fixed 120-bit prefix plus an ordinal byte;
    // renaming or re-iding breaks the ABI.
    const frozen = [_]struct { name: []const u8, ordinal: u8 }{
        .{ .name = "bzip2", .ordinal = 0x09 },
        .{ .name = "deflate", .ordinal = 0x03 },
        .{ .name = "gzip", .ordinal = 0x04 },
        .{ .name = "lzma", .ordinal = 0x0a },
        .{ .name = "lzma-file", .ordinal = 0x0b },
        .{ .name = "lzma2", .ordinal = 0x0c },
        .{ .name = "lz4", .ordinal = 0x15 },
        .{ .name = "rar", .ordinal = 0x0f },
        .{ .name = "sevenzip", .ordinal = 0x08 },
        .{ .name = "tar", .ordinal = 0x05 },
        .{ .name = "xz", .ordinal = 0x0d },
        .{ .name = "zip", .ordinal = 0x06 },
        .{ .name = "zlib", .ordinal = 0x14 },
        .{ .name = "zdict", .ordinal = 0x17 },
        .{ .name = "zstd", .ordinal = 0x07 },
        .{ .name = "zstd-seekable", .ordinal = 0x16 },
    };
    for (frozen) |entry| {
        const component = discovery.findByName(entry.name) orelse
            @compileError("released component has no descriptor: " ++ entry.name ++ ".");
        const low = @as(u64, 0x6e6b_82f0_8d91_0400) | entry.ordinal;
        const high = @as(u64, 0xa7a3_5105_3d6d_4000) | entry.ordinal;
        if (component.id.low != low or component.id.high != high)
            @compileError("released component id drifted: " ++ entry.name ++ ".");
    }
}

test "catalog sorted descriptors hold every identity exactly once in ascending order" {
    try std.testing.expectEqual(
        vocabulary.protocol_rows.len + discovery.enumerate().len,
        sorted_descriptors.len,
    );
    // Strictly ascending by (high, low): the sort leaves no duplicates and no inversions.
    for (sorted_descriptors[1..], 0..) |row, index| {
        const previous = sorted_descriptors[index];
        try std.testing.expect(row.id.high > previous.id.high or
            (row.id.high == previous.id.high and row.id.low > previous.id.low));
    }
    // Every protocol row is present by identity.
    for (vocabulary.protocol_rows) |protocol_row| {
        const resolved = descriptorFor(protocol_row.id).?;
        try std.testing.expectEqualStrings(protocol_row.name, resolved.name);
    }
    // The testing fixtures land as profile rows with their pinned identities.
    const expected = [_]struct { name: []const u8, low: u64, high: u64 }{
        .{ .name = "test_echo", .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4001 },
        .{ .name = "test_read", .low = 0x6e6b_82f0_8d91_0402, .high = 0xa7a3_5105_3d6d_4002 },
        .{ .name = "crypto", .low = 0x6e6b_82f0_8d91_0410, .high = 0xa7a3_5105_3d6d_4010 },
    };
    for (expected) |pin| {
        var hits: usize = 0;
        for (sorted_descriptors) |row| {
            if (std.mem.eql(u8, row.name, pin.name)) {
                hits += 1;
                try std.testing.expectEqual(vocabulary.DescriptorKind.profile, row.kind);
                try std.testing.expectEqual(pin.low, row.id.low);
                try std.testing.expectEqual(pin.high, row.id.high);
            }
        }
        try std.testing.expectEqual(@as(usize, 1), hits);
    }
}

test "catalog descriptorFor resolves sorted rows and rejects stranger identities" {
    for (sorted_descriptors) |row| {
        const resolved = descriptorFor(row.id).?;
        try std.testing.expectEqualStrings(row.name, resolved.name);
    }
    // The zero id is not a table row.
    try std.testing.expect(descriptorFor(.{ .low = 0, .high = 0 }) == null);
    // Strangers: a crossed word pair and a foreign prefix.
    try std.testing.expect(descriptorFor(.{ .low = 0x6e6b_82f0_8d91_0402, .high = 0xa7a3_5105_3d6d_4001 }) == null);
    try std.testing.expect(descriptorFor(.{ .low = 0x6e6b_82f0_8d92_0401, .high = 0xa7a3_5105_3d6d_4001 }) == null);
}

test "catalog isKnownId accepts zero as no component and rejects strangers" {
    // An all-zero id means "no component requested", so it passes as known.
    try std.testing.expect(isKnownId(.{ .low = 0, .high = 0 }));
    for (sorted_descriptors) |row| {
        try std.testing.expect(isKnownId(row.id));
    }
    // Strangers are unknown: a crossed word pair and a foreign prefix.
    try std.testing.expect(!isKnownId(.{ .low = 0x6e6b_82f0_8d91_0402, .high = 0xa7a3_5105_3d6d_4001 }));
    try std.testing.expect(!isKnownId(.{ .low = 1, .high = 1 }));
}

test "catalog profile rows carry component semantics with tar and echo pinned" {
    const tar = descriptorFor(.{ .low = 0x6e6b_82f0_8d91_0405, .high = 0xa7a3_5105_3d6d_4005 }).?;
    try std.testing.expectEqualStrings("tar", tar.name);
    try std.testing.expectEqual(vocabulary.DescriptorKind.profile, tar.kind);
    try std.testing.expectEqual(@as(u32, 7), tar.command_mask); // Verb groups: inspect/decode/encode.
    try std.testing.expectEqual(@as(u32, 15), tar.capability_mask); // Capabilities: read|write|size|replay.
    try std.testing.expectEqual(vocabulary.SizingMode.metadata_exact, tar.sizing);
    try std.testing.expectEqual(vocabulary.CommitMode.tentative, tar.commit);
    try std.testing.expectEqual(@as(u32, 6), tar.volumes); // Volumes: read 2 | write 4.
    try std.testing.expectEqual(vocabulary.Representation.none, tar.representation);
    try std.testing.expectEqual(vocabulary.Direction.none, tar.direction);

    const echo = descriptorFor(.{ .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4001 }).?;
    try std.testing.expectEqualStrings("test_echo", echo.name);
    try std.testing.expectEqual(@as(u32, 63), echo.capability_mask);
    try std.testing.expectEqual(@as(u32, 0), echo.volumes);
    try std.testing.expectEqual(vocabulary.CommitMode.confirmed, echo.commit);
}

test "catalog json pins epoch nine and full descriptor accounting" {
    try std.testing.expect(std.mem.startsWith(u8, catalog_json, "{\n  \"epoch\": 9,\n  \"parameter_selector\": \"value_high: family(16)|ordinal(32)|attrs(8)|flags(8); value_low: scalar value\",\n  \"descriptors\": [\n"));
    try std.testing.expect(std.mem.endsWith(u8, catalog_json, "  ]\n}\n"));
    // One serialized row per sorted descriptor.
    var rows: usize = 0;
    var lines = std.mem.splitScalar(u8, catalog_json, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "    {\"id\":{\"low\":\"")) rows += 1;
    }
    try std.testing.expectEqual(sorted_descriptors.len, rows);
    // The released tar row keeps its frozen identity through serialization.
    try std.testing.expect(std.mem.find(u8, catalog_json, "\"id\":{\"low\":\"0x6e6b82f08d910405\",\"high\":\"0xa7a351053d6d4005\"},\"name\":\"tar\",\"kind\":\"profile\"") != null);
    // The whole document parses as JSON and accounts every descriptor.
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, catalog_json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 9), root.get("epoch").?.integer);
    const descriptors = root.get("descriptors").?.array;
    try std.testing.expectEqual(sorted_descriptors.len, descriptors.items.len);
}
