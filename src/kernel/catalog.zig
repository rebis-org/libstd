const std = @import("std");

const discovery = @import("discovery.zig");
const envelope = @import("envelope.zig");
const EnvelopeId = envelope.Id;
const vocabulary = @import("vocabulary.zig");
pub const Descriptor = vocabulary.Descriptor;

// Wire values live in vocabulary; per-component identity and limits live in descriptors.

const all_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_write | vocabulary.resource_capability_bit_size | vocabulary.resource_capability_bit_replay | vocabulary.resource_capability_bit_seek | vocabulary.resource_capability_bit_range;
const archive_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_write | vocabulary.resource_capability_bit_size | vocabulary.resource_capability_bit_replay;
const commands_masks = vocabulary.command_mask_query | vocabulary.command_mask_read | vocabulary.command_mask_write;
const read_write_mask = vocabulary.command_mask_read | vocabulary.command_mask_write;
const query_read_mask = vocabulary.command_mask_query | vocabulary.command_mask_read;

// Policy fields only; behavioral policy lives in compose catalog.
pub const ProfileRow = struct {
    id: EnvelopeId,
    name: []const u8,
    command_mask: u32,
    capability_mask: u32,
    sizing: vocabulary.SizingMode,
    commit: vocabulary.CommitMode,
};

// Policy is component data from descriptors; fixture rows below are reference-only legacy.
pub const fixture_rows = [_]ProfileRow{
    .{ .id = vocabulary.ids.test_echo, .name = "test_echo", .command_mask = read_write_mask, .capability_mask = all_capabilities, .sizing = .metadata_exact, .commit = .confirmed },
    .{ .id = vocabulary.ids.test_read, .name = "test_read", .command_mask = query_read_mask, .capability_mask = all_capabilities, .sizing = .metadata_exact, .commit = .confirmed },
    .{ .id = vocabulary.ids.crypto, .name = "crypto", .command_mask = commands_masks, .capability_mask = archive_capabilities, .sizing = .metadata_exact, .commit = .confirmed },
};

fn idEqual(left: EnvelopeId, right: EnvelopeId) bool {
    return left.low == right.low and left.high == right.high;
}

pub fn descriptorFor(id: EnvelopeId) ?*const Descriptor {
    inline for (&vocabulary.protocol_rows) |*row| {
        if (idEqual(id, row.id)) return row;
    }
    inline for (&profile_descriptors) |*descriptor| {
        if (idEqual(id, descriptor.id)) return descriptor;
    }
    return null;
}

pub fn knownId(id: EnvelopeId) bool {
    if (id.low == 0 and id.high == 0) return true;
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
            const left = result[candidate].id;
            const right = result[least].id;
            if (left.high < right.high or (left.high == right.high and left.low < right.low)) least = candidate;
        }
        const value = result[index];
        result[index] = result[least];
        result[least] = value;
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
    break :blk "{\n  \"epoch\": 7,\n  \"parameter_selector\": \"value_high: family(16)|ordinal(32)|attrs(8)|flags(8); value_low: scalar value\",\n  \"descriptors\": [\n" ++ descriptors ++ "  ]\n}\n";
};

comptime {
    // Renaming or re-iding a released profile is an ABI break.
    const expected = [_]struct { component: []const u8, profile: []const u8 }{
        .{ .component = "bzip2", .profile = "bzip2" },
        .{ .component = "crypto", .profile = "crypto" },
        .{ .component = "deflate", .profile = "deflate" },
        .{ .component = "gzip", .profile = "gzip" },
        .{ .component = "lzma", .profile = "lzma" },
        .{ .component = "lzma-file", .profile = "lzma_file" },
        .{ .component = "lzma2", .profile = "lzma2" },
        .{ .component = "rar", .profile = "rar" },
        .{ .component = "sevenzip", .profile = "sevenzip" },
        .{ .component = "tar", .profile = "tar" },
        .{ .component = "test_echo", .profile = "test_echo" },
        .{ .component = "test_read", .profile = "test_read" },
        .{ .component = "xz", .profile = "xz" },
        .{ .component = "zip", .profile = "zip" },
        .{ .component = "zstd", .profile = "zstd" },
    };
    for (expected) |pair| {
        const component = discovery.findByName(pair.component) orelse
            @compileError("expected component descriptor missing: " ++ pair.component);
        const profile_id = @field(vocabulary.ids, pair.profile);
        if (!idEqual(.{ .low = component.id.low, .high = component.id.high }, profile_id))
            @compileError("component id drifted from the frozen profile id: " ++ pair.component);
    }
}
