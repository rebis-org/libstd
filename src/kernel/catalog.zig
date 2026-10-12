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
    break :blk "{\n  \"epoch\": 8,\n  \"parameter_selector\": \"value_high: family(16)|ordinal(32)|attrs(8)|flags(8); value_low: scalar value\",\n  \"descriptors\": [\n" ++ descriptor_json ++ "  ]\n}\n";
};

comptime {
    // Released identities are a fixed 120-bit prefix plus a per-component
    // ordinal byte; renaming or re-iding a released profile breaks the ABI.
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
