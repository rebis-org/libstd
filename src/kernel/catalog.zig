const std = @import("std");

const discovery = @import("discovery.zig");
const envelope = @import("envelope.zig");
const EnvelopeId = envelope.Id;
const vocabulary = @import("vocabulary.zig");
pub const Descriptor = vocabulary.Descriptor;

pub fn descriptorFor(id: EnvelopeId) ?*const Descriptor {
    inline for (&vocabulary.protocol_rows) |*row| {
        if (vocabulary.eql(id, row.id)) return row;
    }
    inline for (&profile_descriptors) |*descriptor| {
        if (vocabulary.eql(id, descriptor.id)) return descriptor;
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
        };
    }
    break :blk list;
};

// Sorted by id for a stable catalog document.
pub const sorted_descriptors = blk: {
    @setEvalBranchQuota(100_000);
    var result: [vocabulary.protocol_rows.len + profile_descriptors.len]Descriptor = undefined;
    for (vocabulary.protocol_rows, 0..) |row, index| result[index] = row;
    for (profile_descriptors, 0..) |descriptor, index| result[vocabulary.protocol_rows.len + index] = descriptor;
    for (0..result.len) |index| {
        var least = index;
        for (index + 1..result.len) |candidate| {
            const first = result[candidate].id;
            const second = result[least].id;
            if (first.high < second.high or (first.high == second.high and first.low < second.low)) least = candidate;
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
    var descriptors: []const u8 = "";
    for (sorted_descriptors, 0..) |descriptor, index| {
        descriptors = descriptors ++ std.fmt.comptimePrint(
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
    break :blk "{\n  \"epoch\": 8,\n  \"parameter_selector\": \"value_high: family(16)|ordinal(32)|attrs(8)|flags(8); value_low: scalar value\",\n  \"descriptors\": [\n" ++ descriptors ++ "  ]\n}\n";
};

comptime {
    // Renaming or re-iding a released profile breaks the ABI.
    const frozen_identities = [_]struct { name: []const u8, low: u64, high: u64 }{
        .{ .name = "bzip2", .low = 0x6e6b_82f0_8d91_0409, .high = 0xa7a3_5105_3d6d_4009 },
        .{ .name = "deflate", .low = 0x6e6b_82f0_8d91_0403, .high = 0xa7a3_5105_3d6d_4003 },
        .{ .name = "gzip", .low = 0x6e6b_82f0_8d91_0404, .high = 0xa7a3_5105_3d6d_4004 },
        .{ .name = "lzma", .low = 0x6e6b_82f0_8d91_040a, .high = 0xa7a3_5105_3d6d_400a },
        .{ .name = "lzma-file", .low = 0x6e6b_82f0_8d91_040b, .high = 0xa7a3_5105_3d6d_400b },
        .{ .name = "lzma2", .low = 0x6e6b_82f0_8d91_040c, .high = 0xa7a3_5105_3d6d_400c },
        .{ .name = "lz4", .low = 0x6e6b_82f0_8d91_0415, .high = 0xa7a3_5105_3d6d_4015 },
        .{ .name = "rar", .low = 0x6e6b_82f0_8d91_040f, .high = 0xa7a3_5105_3d6d_400f },
        .{ .name = "sevenzip", .low = 0x6e6b_82f0_8d91_0408, .high = 0xa7a3_5105_3d6d_4008 },
        .{ .name = "tar", .low = 0x6e6b_82f0_8d91_0405, .high = 0xa7a3_5105_3d6d_4005 },
        .{ .name = "xz", .low = 0x6e6b_82f0_8d91_040d, .high = 0xa7a3_5105_3d6d_400d },
        .{ .name = "zip", .low = 0x6e6b_82f0_8d91_0406, .high = 0xa7a3_5105_3d6d_4006 },
        .{ .name = "zlib", .low = 0x6e6b_82f0_8d91_0414, .high = 0xa7a3_5105_3d6d_4014 },
        .{ .name = "zdict", .low = 0x6e6b_82f0_8d91_0417, .high = 0xa7a3_5105_3d6d_4017 },
        .{ .name = "zstd", .low = 0x6e6b_82f0_8d91_0407, .high = 0xa7a3_5105_3d6d_4007 },
        .{ .name = "zstd-seekable", .low = 0x6e6b_82f0_8d91_0416, .high = 0xa7a3_5105_3d6d_4016 },
    };
    for (frozen_identities) |frozen| {
        const component = discovery.findByName(frozen.name) orelse
            @compileError("released component has no descriptor: " ++ frozen.name ++ ".");
        if (component.id.low != frozen.low or component.id.high != frozen.high)
            @compileError("released component id drifted: " ++ frozen.name ++ ".");
    }
}
