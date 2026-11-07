const contract = @import("interface").contract;

const exception = @import("../common/primitive/exception.zig");
const envelope = @import("envelope.zig");

pub const CommitMode = contract.CommitMode;
pub const SizingMode = contract.SizingMode;
pub const Exception = exception.Exception;
const Id = envelope.Id;
const Status = envelope.Status;

// Wire values are frozen ABI.
pub const DescriptorKind = enum(u32) {
    command,
    parameter,
    profile,
    resource,
    diagnostic,
};

pub const Representation = enum(u32) {
    none,
    scalar_words,
    bytes,
    node_chain,
};

pub const Cardinality = enum(u8) { singleton, repeated };

pub const Direction = enum(u32) {
    none,
    in,
    out,
    in_out,
};

pub const ResourceCapability = enum(u32) {
    none,
    read,
    write,
    size,
    replay,
    seek,
    range,
};

pub const parameter_family_protocol: u16 = 0;

pub const protocol_parameter = struct {
    pub const workspace_hint: u32 = 1;
    pub const resource_limit: u32 = 2;
    pub const resource_capabilities: u32 = 3;
    pub const sizing_mode: u32 = 4;
    pub const commit_mode: u32 = 5;
    // Provider selection for mergeable builds: value_low 0 is onprem, 1 is
    // offprem. Absent means the boundary default.
    pub const provider: u32 = 6;
    pub const target_command: u32 = 24;
};

pub const command_mask_query: u32 = 1 << 0;
pub const command_mask_read: u32 = 1 << 1;
pub const command_mask_write: u32 = 1 << 2;
pub const resource_capability_bit_read: u32 = 1 << 0;
pub const resource_capability_bit_write: u32 = 1 << 1;
pub const resource_capability_bit_size: u32 = 1 << 2;
pub const resource_capability_bit_replay: u32 = 1 << 3;
pub const resource_capability_bit_seek: u32 = 1 << 4;
pub const resource_capability_bit_range: u32 = 1 << 5;
pub const parameter_rep_shift: u6 = 0;
pub const parameter_card_shift: u6 = 2;
pub const parameter_dir_shift: u6 = 4;
pub const parameter_attr_reserved_mask: u8 = 0xC0;
pub const parameter_flag_command_mask: u8 = 0x07;
pub const parameter_flag_reserved_mask: u8 = 0xF8;

pub const Selector = struct {
    family: u16,
    ordinal: u32,
    attributes: u8,
    flags: u8,
};

pub fn selectorOf(selector_bits: u64) Selector {
    return .{
        .family = @truncate(selector_bits >> 48),
        .ordinal = @truncate(selector_bits >> 16),
        .attributes = @truncate(selector_bits >> 8),
        .flags = @truncate(selector_bits),
    };
}

pub fn isSelectorValid(selector_value: Selector) bool {
    if (selector_value.attributes & parameter_attr_reserved_mask != 0) return false;
    if (selector_value.flags & parameter_flag_reserved_mask != 0) return false;
    return fieldOf(selector_value.attributes, parameter_card_shift) <= 1;
}

fn fieldOf(attributes: u8, comptime shift: u6) u2 {
    return @truncate(attributes >> shift);
}

fn attributeOf(selector_value: Selector, comptime shift: u6, comptime T: type) T {
    return @fromBackingInt(@intCast(fieldOf(selector_value.attributes, shift)));
}

pub fn representationOf(selector_value: Selector) Representation {
    return attributeOf(selector_value, parameter_rep_shift, Representation);
}

pub fn cardinalityOf(selector_value: Selector) Cardinality {
    return attributeOf(selector_value, parameter_card_shift, Cardinality);
}

pub fn directionOf(selector_value: Selector) Direction {
    return attributeOf(selector_value, parameter_dir_shift, Direction);
}

pub fn commandMaskForId(id: Id) u32 {
    if (eql(id, ids.query)) return command_mask_query;
    if (eql(id, ids.read)) return command_mask_read;
    if (eql(id, ids.write)) return command_mask_write;
    return 0;
}

pub const ErrorMap = struct {
    exception: Exception,
    name: []const u8,
    status: u32,
    diagnostic: Id,
};

pub const Descriptor = struct {
    id: Id,
    name: []const u8,
    kind: DescriptorKind,
    representation: Representation = .none,
    cardinality: Cardinality = .singleton,
    direction: Direction = .none,
    command_mask: u32 = 0,
    capability: ResourceCapability = .none,
    capability_mask: u32 = 0,
    sizing: SizingMode = .unavailable,
    commit: CommitMode = .tentative,
    // Volume-set support per command direction (read 2, write 4), carried
    // from the component descriptor; zero means no split-set shape.
    volumes: u32 = 0,
};

const all_commands_mask = command_mask_query | command_mask_read | command_mask_write;
const read_write_mask = command_mask_read | command_mask_write;
const query_write_mask = command_mask_query | command_mask_write;

pub const protocol_rows = [_]Descriptor{
    .{ .id = ids.query, .name = "query", .kind = .command, .representation = .node_chain, .command_mask = all_commands_mask },
    .{ .id = ids.read, .name = "read", .kind = .command, .representation = .node_chain, .command_mask = all_commands_mask },
    .{ .id = ids.write, .name = "write", .kind = .command, .representation = .node_chain, .command_mask = all_commands_mask },
    .{ .id = ids.diagnostic_required_capacity, .name = "diagnostic_required_capacity", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.diagnostic_available_capacity, .name = "diagnostic_available_capacity", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.diagnostic_downstream_status, .name = "diagnostic_downstream_status", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.diagnostic_subject, .name = "diagnostic_subject", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.source, .name = "source", .kind = .parameter, .representation = .bytes, .direction = .in, .command_mask = all_commands_mask },
    .{ .id = ids.sink, .name = "sink", .kind = .parameter, .representation = .bytes, .direction = .in, .command_mask = read_write_mask },
    .{ .id = ids.profile, .name = "profile", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = all_commands_mask },
    .{ .id = ids.target_command, .name = "target_command", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = command_mask_query },
    .{ .id = ids.size_bound, .name = "size_bound", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = query_write_mask },
    .{ .id = ids.parameter, .name = "parameter", .kind = .parameter, .cardinality = .repeated, .direction = .in_out, .command_mask = all_commands_mask },
    .{ .id = ids.crypto_profile, .name = "crypto_profile", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = all_commands_mask },
    .{ .id = ids.resource_read, .name = "resource_read", .kind = .resource, .representation = .scalar_words, .capability = .read },
    .{ .id = ids.resource_write, .name = "resource_write", .kind = .resource, .representation = .scalar_words, .capability = .write },
    .{ .id = ids.resource_size, .name = "resource_size", .kind = .resource, .representation = .scalar_words, .capability = .size },
    .{ .id = ids.resource_replay, .name = "resource_replay", .kind = .resource, .representation = .scalar_words, .capability = .replay },
    .{ .id = ids.resource_seek, .name = "resource_seek", .kind = .resource, .representation = .scalar_words, .capability = .seek },
    .{ .id = ids.resource_range, .name = "resource_range", .kind = .resource, .representation = .scalar_words, .capability = .range },
    .{ .id = ids.invalid_call, .name = "invalid_call", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.unsupported, .name = "unsupported", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.internal_failure, .name = "internal_failure", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.diagnostic_resource_limit, .name = "resource_limit", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.insufficient_capacity, .name = "insufficient_capacity", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.invalid_data, .name = "invalid_data", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.integrity_failure, .name = "integrity_failure", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.io_failure, .name = "io_failure", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.crypto_wrong_password, .name = "crypto_wrong_password", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.crypto_kdf_limit, .name = "crypto_kdf_limit", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.crypto_password_lifetime, .name = "crypto_password_lifetime", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.crypto_unsupported_algorithm, .name = "crypto_unsupported_algorithm", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.workspace_required_capacity, .name = "workspace_required_capacity", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = ids.workspace_available_capacity, .name = "workspace_available_capacity", .kind = .diagnostic, .representation = .node_chain },
};

// How a profile answers one direction: the three facts the boundary needs,
// nothing that restates the selecting command.
pub const CommandPolicy = struct {
    capabilities: u32,
    sizing: SizingMode,
    commit: CommitMode,
};

// Released ids pair a category nibble with an ordinal byte; the high word interleaves both, so one builder carries it.
fn releasedId(comptime low_suffix: u16) Id {
    const category: u64 = low_suffix >> 8;
    const ordinal: u64 = low_suffix & 0xff;
    return .{
        .low = 0x6e6b_82f0_8d91_0000 | category << 8 | ordinal,
        .high = 0xa7a3_5105_3d6d_0000 | category << 12 | ordinal,
    };
}

pub const ids = struct {
    pub const query = releasedId(0x0101);
    pub const read = releasedId(0x0102);
    pub const write = releasedId(0x0103);
    pub const diagnostic_required_capacity = releasedId(0x0200);
    pub const diagnostic_available_capacity = releasedId(0x0201);
    pub const diagnostic_downstream_status = releasedId(0x0202);
    pub const diagnostic_subject = releasedId(0x0203);
    pub const source = releasedId(0x0210);
    pub const sink = releasedId(0x0211);
    pub const profile = releasedId(0x0212);
    pub const target_command = releasedId(0x0218);
    pub const size_bound = releasedId(0x0219);
    pub const parameter = releasedId(0x0240);
    pub const crypto_profile = releasedId(0x0236);
    pub const resource_read = releasedId(0x0301);
    pub const resource_write = releasedId(0x0302);
    pub const resource_size = releasedId(0x0303);
    pub const resource_replay = releasedId(0x0304);
    pub const resource_seek = releasedId(0x0305);
    pub const resource_range = releasedId(0x0306);
    pub const test_echo = releasedId(0x0401);
    pub const test_read = releasedId(0x0402);
    pub const crypto = releasedId(0x0410);
    pub const callback_size = releasedId(0x0a01);
    pub const callback_read = releasedId(0x0a02);
    pub const callback_write = releasedId(0x0a03);
    pub const callback_rewind = releasedId(0x0a04);
    pub const callback_seek = releasedId(0x0a05);
    pub const invalid_call = releasedId(0x0501);
    pub const unsupported = releasedId(0x0502);
    pub const internal_failure = releasedId(0x0503);
    pub const diagnostic_resource_limit = releasedId(0x0504);
    pub const insufficient_capacity = releasedId(0x0505);
    pub const invalid_data = releasedId(0x0506);
    pub const integrity_failure = releasedId(0x0507);
    pub const io_failure = releasedId(0x0508);
    pub const crypto_wrong_password = releasedId(0x0509);
    pub const crypto_kdf_limit = releasedId(0x050a);
    pub const crypto_password_lifetime = releasedId(0x050b);
    pub const crypto_unsupported_algorithm = releasedId(0x050c);
    pub const workspace_required_capacity = releasedId(0x050d);
    pub const workspace_available_capacity = releasedId(0x050e);
};

pub const error_map = [_]ErrorMap{
    .{ .exception = error.CallException, .name = "invalid_call", .status = Status.invalid_call, .diagnostic = ids.invalid_call },
    .{ .exception = error.UnsupportedException, .name = "unsupported", .status = Status.unsupported, .diagnostic = ids.unsupported },
    .{ .exception = error.InternalException, .name = "internal_failure", .status = Status.internal_failure, .diagnostic = ids.internal_failure },
    .{ .exception = error.ResourceException, .name = "resource_limit", .status = Status.resource_limit, .diagnostic = ids.diagnostic_resource_limit },
    .{ .exception = error.CapacityException, .name = "insufficient_capacity", .status = Status.insufficient_capacity, .diagnostic = ids.insufficient_capacity },
    .{ .exception = error.DataException, .name = "invalid_data", .status = Status.invalid_data, .diagnostic = ids.invalid_data },
    .{ .exception = error.IntegrityException, .name = "integrity_failure", .status = Status.integrity_failure, .diagnostic = ids.integrity_failure },
    .{ .exception = error.IoException, .name = "io_failure", .status = Status.io_failure, .diagnostic = ids.io_failure },
};

// The wire status for an exception; the map owns the only translation.
pub fn statusFor(failure: Exception) u32 {
    inline for (error_map) |entry| if (failure == entry.exception) return entry.status;
    return Status.internal_failure;
}

// The diagnostic id paired with the status; the map owns the only translation.
pub fn diagnosticFor(failure: Exception) Id {
    inline for (error_map) |entry| if (failure == entry.exception) return entry.diagnostic;
    return ids.internal_failure;
}

pub fn eql(left: Id, right: Id) bool {
    return left.low == right.low and left.high == right.high;
}

pub fn isZero(id: Id) bool {
    return eql(id, .{ .low = 0, .high = 0 });
}

test "vocabulary selector decode splits family ordinal attributes and flags" {
    const std = @import("std");
    const decoded = selectorOf(0x0007_0000_0024_A55A);
    try std.testing.expectEqual(@as(u16, 7), decoded.family);
    try std.testing.expectEqual(@as(u32, 0x24), decoded.ordinal);
    try std.testing.expectEqual(@as(u8, 0xA5), decoded.attributes);
    try std.testing.expectEqual(@as(u8, 0x5A), decoded.flags);
    // adjacent fields do not bleed into one another
    const isolated = selectorOf(0x0000_0000_00AB_00CD);
    try std.testing.expectEqual(@as(u16, 0), isolated.family);
    try std.testing.expectEqual(@as(u32, 0xAB), isolated.ordinal);
    try std.testing.expectEqual(@as(u8, 0), isolated.attributes);
    try std.testing.expectEqual(@as(u8, 0xCD), isolated.flags);
    // family and ordinal span their full wire widths
    const wide = selectorOf(0x0001_FFFF_FFFF_0000);
    try std.testing.expectEqual(@as(u16, 1), wide.family);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), wide.ordinal);
    try std.testing.expectEqual(@as(u8, 0), wide.attributes);
    try std.testing.expectEqual(@as(u8, 0), wide.flags);
}

test "vocabulary selector validity rejects reserved attribute and flag bits" {
    const std = @import("std");
    // the reserved masks and the command-mask flag width are frozen wire values
    try std.testing.expectEqual(@as(u8, 0xC0), parameter_attr_reserved_mask);
    try std.testing.expectEqual(@as(u8, 0xF8), parameter_flag_reserved_mask);
    try std.testing.expectEqual(@as(u8, 0x07), parameter_flag_command_mask);
    // a bare selector with every field zeroed is legal
    try std.testing.expect(isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0, .flags = 0 }));
    // the low three flag bits carry the command mask and stay legal
    try std.testing.expect(isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0, .flags = 0x07 }));
    // attribute bits six and seven are reserved on the wire
    try std.testing.expect(!isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0xC0, .flags = 0 }));
    // flag bits three and above are reserved on the wire
    try std.testing.expect(!isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0, .flags = 0x08 }));
    try std.testing.expect(!isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0, .flags = 0xF8 }));
    // a cardinality field above one is invalid even without reserved bits
    try std.testing.expect(!isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0x08, .flags = 0 }));
    try std.testing.expect(!isSelectorValid(.{ .family = 0, .ordinal = 1, .attributes = 0x0C, .flags = 0 }));
    // the full legal attribute range decodes without invalidating
    try std.testing.expect(isSelectorValid(.{ .family = 1, .ordinal = 2, .attributes = 0x35, .flags = 0 }));
}

test "vocabulary selector attributes decode representation cardinality and direction" {
    const std = @import("std");
    const cases = [_]struct {
        attributes: u8,
        representation: Representation,
        cardinality: Cardinality,
        direction: Direction,
    }{
        .{ .attributes = 0x00, .representation = .none, .cardinality = .singleton, .direction = .none },
        .{ .attributes = 0x01, .representation = .scalar_words, .cardinality = .singleton, .direction = .none },
        .{ .attributes = 0x02, .representation = .bytes, .cardinality = .singleton, .direction = .none },
        .{ .attributes = 0x03, .representation = .node_chain, .cardinality = .singleton, .direction = .none },
        .{ .attributes = 0x04, .representation = .none, .cardinality = .repeated, .direction = .none },
        .{ .attributes = 0x15, .representation = .scalar_words, .cardinality = .repeated, .direction = .in },
        .{ .attributes = 0x26, .representation = .bytes, .cardinality = .repeated, .direction = .out },
        .{ .attributes = 0x37, .representation = .node_chain, .cardinality = .repeated, .direction = .in_out },
    };
    for (cases) |case| {
        const selector_value = Selector{ .family = 1, .ordinal = 2, .attributes = case.attributes, .flags = 0 };
        try std.testing.expectEqual(case.representation, representationOf(selector_value));
        try std.testing.expectEqual(case.cardinality, cardinalityOf(selector_value));
        try std.testing.expectEqual(case.direction, directionOf(selector_value));
        try std.testing.expect(isSelectorValid(selector_value));
    }
}

test "vocabulary command mask maps query read and write to wire bits" {
    const std = @import("std");
    // the three command bits are frozen wire values
    try std.testing.expectEqual(@as(u32, 1), command_mask_query);
    try std.testing.expectEqual(@as(u32, 2), command_mask_read);
    try std.testing.expectEqual(@as(u32, 4), command_mask_write);
    // each command answers to exactly its own bit
    try std.testing.expectEqual(@as(u32, 1), commandMaskForId(ids.query));
    try std.testing.expectEqual(@as(u32, 2), commandMaskForId(ids.read));
    try std.testing.expectEqual(@as(u32, 4), commandMaskForId(ids.write));
    // parameters and diagnostics never answer to a command mask
    try std.testing.expectEqual(@as(u32, 0), commandMaskForId(ids.source));
    try std.testing.expectEqual(@as(u32, 0), commandMaskForId(ids.invalid_call));
    try std.testing.expectEqual(@as(u32, 0), commandMaskForId(.{ .low = 0, .high = 0 }));
    // a low word match with a differing high word is not the command
    const near_miss = Id{ .low = ids.query.low, .high = ids.query.high +% 1 };
    try std.testing.expectEqual(@as(u32, 0), commandMaskForId(near_miss));
}

test "vocabulary released ids interleave category and ordinal across both words" {
    const std = @import("std");
    // the three commands pin the builder output byte for byte
    try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0101), ids.query.low);
    try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_1001), ids.query.high);
    try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0102), ids.read.low);
    try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_1002), ids.read.high);
    try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0103), ids.write.low);
    try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_1003), ids.write.high);
    const released = [_]Id{
        ids.query,                        ids.read,                          ids.write,
        ids.diagnostic_required_capacity, ids.diagnostic_available_capacity, ids.diagnostic_downstream_status,
        ids.diagnostic_subject,           ids.source,                        ids.sink,
        ids.profile,                      ids.target_command,                ids.size_bound,
        ids.parameter,                    ids.crypto_profile,                ids.resource_read,
        ids.resource_write,               ids.resource_size,                 ids.resource_replay,
        ids.resource_seek,                ids.resource_range,                ids.test_echo,
        ids.test_read,                    ids.crypto,                        ids.callback_size,
        ids.callback_read,                ids.callback_write,                ids.callback_rewind,
        ids.callback_seek,                ids.invalid_call,                  ids.unsupported,
        ids.internal_failure,             ids.diagnostic_resource_limit,     ids.insufficient_capacity,
        ids.invalid_data,                 ids.integrity_failure,             ids.io_failure,
        ids.crypto_wrong_password,        ids.crypto_kdf_limit,              ids.crypto_password_lifetime,
        ids.crypto_unsupported_algorithm, ids.workspace_required_capacity,   ids.workspace_available_capacity,
    };
    for (released) |id| {
        try std.testing.expect(!isZero(id));
        // the fixed prefixes hold for every category
        try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0000), id.low & 0xFFFF_FFFF_FFFF_0000);
        try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_0000), id.high & 0xFFFF_FFFF_FFFF_0000);
        // The low word carries category then ordinal; the high word mirrors both with the nibble shifted into the high half.
        const low_tail = id.low & 0xFFFF;
        const high_tail = id.high & 0xFFFF;
        try std.testing.expect(low_tail >> 8 != 0);
        try std.testing.expectEqual(@as(u64, low_tail >> 8), high_tail >> 12);
        try std.testing.expectEqual(@as(u64, low_tail & 0xFF), high_tail & 0xFF);
    }
    // released ids are pairwise distinct
    for (released, 0..) |left, i| {
        for (released[i + 1 ..]) |right| {
            try std.testing.expect(!eql(left, right));
        }
    }
}

test "vocabulary error map covers the whole exception set with distinct statuses" {
    const std = @import("std");
    // The map owns the only status-translation exception; every member appears and pins its frozen wire status.
    try std.testing.expectEqual(@as(usize, 8), error_map.len);
    const expected = [_]struct { failure: Exception, status: u32 }{
        .{ .failure = error.CallException, .status = 1 },
        .{ .failure = error.UnsupportedException, .status = 2 },
        .{ .failure = error.InternalException, .status = 8 },
        .{ .failure = error.ResourceException, .status = 7 },
        .{ .failure = error.CapacityException, .status = 3 },
        .{ .failure = error.DataException, .status = 4 },
        .{ .failure = error.IntegrityException, .status = 5 },
        .{ .failure = error.IoException, .status = 6 },
    };
    for (expected) |row| {
        try std.testing.expectEqual(row.status, statusFor(row.failure));
    }
    // the map entries agree with the translation functions
    for (error_map) |entry| {
        try std.testing.expectEqual(entry.status, statusFor(entry.exception));
        try std.testing.expect(eql(entry.diagnostic, diagnosticFor(entry.exception)));
        try std.testing.expect(entry.name.len != 0);
        try std.testing.expect(!isZero(entry.diagnostic));
    }
    // statuses and diagnostics are pairwise distinct
    for (error_map, 0..) |left, i| {
        for (error_map[i + 1 ..]) |right| {
            try std.testing.expect(left.status != right.status);
            try std.testing.expect(!eql(left.diagnostic, right.diagnostic));
        }
    }
    // every diagnostic lands on a protocol row of the same name and kind
    for (error_map) |entry| {
        var found = false;
        for (protocol_rows) |row| {
            if (eql(row.id, entry.diagnostic)) {
                found = true;
                try std.testing.expectEqualStrings(entry.name, row.name);
                try std.testing.expect(row.kind == .diagnostic);
            }
        }
        try std.testing.expect(found);
    }
}

test "vocabulary protocol rows carry unique ids with consistent shapes" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 34), protocol_rows.len);
    for (protocol_rows, 0..) |row, i| {
        try std.testing.expect(!isZero(row.id));
        try std.testing.expect(row.name.len != 0);
        for (protocol_rows[i + 1 ..]) |other| {
            try std.testing.expect(!eql(row.id, other.id));
        }
        switch (row.kind) {
            .command => {
                try std.testing.expectEqual(Representation.node_chain, row.representation);
                try std.testing.expectEqual(@as(u32, 7), row.command_mask);
                try std.testing.expectEqual(Direction.none, row.direction);
            },
            .parameter => {
                try std.testing.expect(row.direction != .none);
                try std.testing.expectEqual(@as(u32, 0), row.capability_mask);
            },
            .resource => {
                try std.testing.expectEqual(Representation.scalar_words, row.representation);
                try std.testing.expect(row.capability != .none);
                try std.testing.expectEqual(@as(u32, 0), row.command_mask);
            },
            .diagnostic => {
                try std.testing.expectEqual(Representation.node_chain, row.representation);
                try std.testing.expectEqual(@as(u32, 0), row.command_mask);
            },
            .profile => return error.TestUnexpectedResult,
        }
    }
    // the three protocol commands lead the table
    try std.testing.expect(eql(protocol_rows[0].id, ids.query));
    try std.testing.expect(eql(protocol_rows[1].id, ids.read));
    try std.testing.expect(eql(protocol_rows[2].id, ids.write));
    // selected rows pin their command gates
    var sink_row: ?Descriptor = null;
    var size_bound_row: ?Descriptor = null;
    var target_command_row: ?Descriptor = null;
    var parameter_row: ?Descriptor = null;
    for (protocol_rows) |row| {
        if (eql(row.id, ids.sink)) sink_row = row;
        if (eql(row.id, ids.size_bound)) size_bound_row = row;
        if (eql(row.id, ids.target_command)) target_command_row = row;
        if (eql(row.id, ids.parameter)) parameter_row = row;
    }
    // a sink never answers a query
    try std.testing.expectEqual(@as(u32, 6), sink_row.?.command_mask);
    // a size bound is sized for queries and writes but never read
    try std.testing.expectEqual(@as(u32, 5), size_bound_row.?.command_mask);
    // the target command selector only rides a query
    try std.testing.expectEqual(@as(u32, 1), target_command_row.?.command_mask);
    // the open parameter slot is repeated and bidirectional
    try std.testing.expectEqual(Cardinality.repeated, parameter_row.?.cardinality);
    try std.testing.expectEqual(Direction.in_out, parameter_row.?.direction);
    try std.testing.expectEqual(@as(u32, 7), parameter_row.?.command_mask);
}

test "vocabulary protocol parameters and capability bits pin their wire values" {
    const std = @import("std");
    // the protocol family owns selector family zero
    try std.testing.expectEqual(@as(u16, 0), parameter_family_protocol);
    // the six protocol parameters are the frozen ordinal set
    try std.testing.expectEqual(@as(u32, 1), protocol_parameter.workspace_hint);
    try std.testing.expectEqual(@as(u32, 2), protocol_parameter.resource_limit);
    try std.testing.expectEqual(@as(u32, 3), protocol_parameter.resource_capabilities);
    try std.testing.expectEqual(@as(u32, 4), protocol_parameter.sizing_mode);
    try std.testing.expectEqual(@as(u32, 5), protocol_parameter.commit_mode);
    try std.testing.expectEqual(@as(u32, 6), protocol_parameter.provider);
    try std.testing.expectEqual(@as(u32, 24), protocol_parameter.target_command);
    // the resource capability bits pack into the low six bits
    try std.testing.expectEqual(@as(u32, 1), resource_capability_bit_read);
    try std.testing.expectEqual(@as(u32, 2), resource_capability_bit_write);
    try std.testing.expectEqual(@as(u32, 4), resource_capability_bit_size);
    try std.testing.expectEqual(@as(u32, 8), resource_capability_bit_replay);
    try std.testing.expectEqual(@as(u32, 16), resource_capability_bit_seek);
    try std.testing.expectEqual(@as(u32, 32), resource_capability_bit_range);
}
