const contract = @import("nucleus").contract;
pub const SizingMode = contract.SizingMode;
pub const CommitMode = contract.CommitMode;

const failure = @import("../common/primitive/failure.zig");
pub const Failure = failure.Failure;
const envelope = @import("envelope.zig");
const Id = envelope.Id;
const Status = envelope.Status;

// Wire values are frozen ABI; per-profile policy lives in compose, per-component
// declaration in the descriptor files.

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

pub fn selector(
    family: u16,
    ordinal: u32,
    representation: Representation,
    cardinality: Cardinality,
    direction: Direction,
    command_mask: u32,
) u64 {
    const attributes = @as(u8, @intCast(@intFromEnum(representation))) | (@as(u8, @intCast(@intFromEnum(cardinality))) << parameter_card_shift) | (@as(u8, @intCast(@intFromEnum(direction))) << parameter_dir_shift);
    return (@as(u64, family) << 48) | (@as(u64, ordinal) << 16) | (@as(u64, attributes) << 8) | @as(u64, command_mask & parameter_flag_command_mask);
}

pub fn selectorOf(value_high: u64) Selector {
    return .{
        .family = @truncate(value_high >> 48),
        .ordinal = @truncate(value_high >> 16),
        .attributes = @truncate(value_high >> 8),
        .flags = @truncate(value_high),
    };
}

pub fn selectorValid(selector_value: Selector) bool {
    if (selector_value.attributes & parameter_attr_reserved_mask != 0) return false;
    if (selector_value.flags & parameter_flag_reserved_mask != 0) return false;
    return cardinalityFieldOf(selector_value.attributes) <= 1;
}

pub fn representationFieldOf(attributes: u8) u2 {
    return @truncate(attributes >> parameter_rep_shift);
}

pub fn cardinalityFieldOf(attributes: u8) u2 {
    return @truncate(attributes >> parameter_card_shift);
}

pub fn directionFieldOf(attributes: u8) u2 {
    return @truncate(attributes >> parameter_dir_shift);
}

pub fn representationOf(selector_value: Selector) Representation {
    return @enumFromInt(representationFieldOf(selector_value.attributes));
}

pub fn cardinalityOf(selector_value: Selector) Cardinality {
    return @enumFromInt(cardinalityFieldOf(selector_value.attributes));
}

pub fn directionOf(selector_value: Selector) Direction {
    return @enumFromInt(directionFieldOf(selector_value.attributes));
}

pub fn commandMaskForId(id: Id) u32 {
    if (idEqual(id, ids.query)) return command_mask_query;
    if (idEqual(id, ids.read)) return command_mask_read;
    if (idEqual(id, ids.write)) return command_mask_write;
    return 0;
}

pub const ErrorMap = struct {
    failure: Failure,
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
};

const commands_masks = command_mask_query | command_mask_read | command_mask_write;
const read_write_mask = command_mask_read | command_mask_write;
const query_write_mask = command_mask_query | command_mask_write;

pub const protocol_rows = [_]Descriptor{
    .{ .id = ids.query, .name = "query", .kind = .command, .representation = .node_chain, .command_mask = commands_masks },
    .{ .id = ids.read, .name = "read", .kind = .command, .representation = .node_chain, .command_mask = commands_masks },
    .{ .id = ids.write, .name = "write", .kind = .command, .representation = .node_chain, .command_mask = commands_masks },
    .{ .id = ids.diagnostic_required_capacity, .name = "diagnostic_required_capacity", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.diagnostic_available_capacity, .name = "diagnostic_available_capacity", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.diagnostic_downstream_status, .name = "diagnostic_downstream_status", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.diagnostic_subject, .name = "diagnostic_subject", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = ids.source, .name = "source", .kind = .parameter, .representation = .bytes, .direction = .in, .command_mask = commands_masks },
    .{ .id = ids.sink, .name = "sink", .kind = .parameter, .representation = .bytes, .direction = .in, .command_mask = read_write_mask },
    .{ .id = ids.profile, .name = "profile", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = commands_masks },
    .{ .id = ids.target_command, .name = "target_command", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = command_mask_query },
    .{ .id = ids.size_bound, .name = "size_bound", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = query_write_mask },
    .{ .id = ids.parameter, .name = "parameter", .kind = .parameter, .cardinality = .repeated, .direction = .in_out, .command_mask = commands_masks },
    .{ .id = ids.crypto_profile, .name = "crypto_profile", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = commands_masks },
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

pub const ProfileTag = enum {
    test_echo,
    test_read,
    deflate,
    gzip,
    zstd,
    bzip2,
    lzma,
    lzma2,
    lzma_file,
    xz,
    tar,
    zip,
    sevenzip,
    rar,
};

pub const CommandPolicy = struct {
    command: u32,
    target: u32 = 0,
    capabilities: u32,
    sizing: SizingMode,
    commit: CommitMode,
    limit_dimensions: u32 = 0,
};

pub const ids = struct {
    pub const query = Id{ .low = 0x6e6b_82f0_8d91_0101, .high = 0xa7a3_5105_3d6d_1001 };
    pub const read = Id{ .low = 0x6e6b_82f0_8d91_0102, .high = 0xa7a3_5105_3d6d_1002 };
    pub const write = Id{ .low = 0x6e6b_82f0_8d91_0103, .high = 0xa7a3_5105_3d6d_1003 };
    pub const diagnostic_required_capacity = Id{ .low = 0x6e6b_82f0_8d91_0200, .high = 0xa7a3_5105_3d6d_2000 };
    pub const diagnostic_available_capacity = Id{ .low = 0x6e6b_82f0_8d91_0201, .high = 0xa7a3_5105_3d6d_2001 };
    pub const diagnostic_downstream_status = Id{ .low = 0x6e6b_82f0_8d91_0202, .high = 0xa7a3_5105_3d6d_2002 };
    pub const diagnostic_subject = Id{ .low = 0x6e6b_82f0_8d91_0203, .high = 0xa7a3_5105_3d6d_2003 };
    pub const source = Id{ .low = 0x6e6b_82f0_8d91_0210, .high = 0xa7a3_5105_3d6d_2010 };
    pub const sink = Id{ .low = 0x6e6b_82f0_8d91_0211, .high = 0xa7a3_5105_3d6d_2011 };
    pub const profile = Id{ .low = 0x6e6b_82f0_8d91_0212, .high = 0xa7a3_5105_3d6d_2012 };
    pub const target_command = Id{ .low = 0x6e6b_82f0_8d91_0218, .high = 0xa7a3_5105_3d6d_2018 };
    pub const size_bound = Id{ .low = 0x6e6b_82f0_8d91_0219, .high = 0xa7a3_5105_3d6d_2019 };
    pub const parameter = Id{ .low = 0x6e6b_82f0_8d91_0240, .high = 0xa7a3_5105_3d6d_2040 };
    pub const crypto_profile = Id{ .low = 0x6e6b_82f0_8d91_0236, .high = 0xa7a3_5105_3d6d_2036 };
    pub const resource_read = Id{ .low = 0x6e6b_82f0_8d91_0301, .high = 0xa7a3_5105_3d6d_3001 };
    pub const resource_write = Id{ .low = 0x6e6b_82f0_8d91_0302, .high = 0xa7a3_5105_3d6d_3002 };
    pub const resource_size = Id{ .low = 0x6e6b_82f0_8d91_0303, .high = 0xa7a3_5105_3d6d_3003 };
    pub const resource_replay = Id{ .low = 0x6e6b_82f0_8d91_0304, .high = 0xa7a3_5105_3d6d_3004 };
    pub const resource_seek = Id{ .low = 0x6e6b_82f0_8d91_0305, .high = 0xa7a3_5105_3d6d_3005 };
    pub const resource_range = Id{ .low = 0x6e6b_82f0_8d91_0306, .high = 0xa7a3_5105_3d6d_3006 };
    pub const test_echo = Id{ .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4001 };
    pub const test_read = Id{ .low = 0x6e6b_82f0_8d91_0402, .high = 0xa7a3_5105_3d6d_4002 };
    pub const deflate = Id{ .low = 0x6e6b_82f0_8d91_0403, .high = 0xa7a3_5105_3d6d_4003 };
    pub const gzip = Id{ .low = 0x6e6b_82f0_8d91_0404, .high = 0xa7a3_5105_3d6d_4004 };
    pub const tar = Id{ .low = 0x6e6b_82f0_8d91_0405, .high = 0xa7a3_5105_3d6d_4005 };
    pub const zip = Id{ .low = 0x6e6b_82f0_8d91_0406, .high = 0xa7a3_5105_3d6d_4006 };
    pub const zstd = Id{ .low = 0x6e6b_82f0_8d91_0407, .high = 0xa7a3_5105_3d6d_4007 };
    pub const sevenzip = Id{ .low = 0x6e6b_82f0_8d91_0408, .high = 0xa7a3_5105_3d6d_4008 };
    pub const bzip2 = Id{ .low = 0x6e6b_82f0_8d91_0409, .high = 0xa7a3_5105_3d6d_4009 };
    pub const lzma = Id{ .low = 0x6e6b_82f0_8d91_040a, .high = 0xa7a3_5105_3d6d_400a };
    pub const lzma_file = Id{ .low = 0x6e6b_82f0_8d91_040b, .high = 0xa7a3_5105_3d6d_400b };
    pub const lzma2 = Id{ .low = 0x6e6b_82f0_8d91_040c, .high = 0xa7a3_5105_3d6d_400c };
    pub const xz = Id{ .low = 0x6e6b_82f0_8d91_040d, .high = 0xa7a3_5105_3d6d_400d };
    pub const rar = Id{ .low = 0x6e6b_82f0_8d91_040f, .high = 0xa7a3_5105_3d6d_400f };
    pub const crypto = Id{ .low = 0x6e6b_82f0_8d91_0410, .high = 0xa7a3_5105_3d6d_4010 };
    pub const callback_size = Id{ .low = 0x6e6b_82f0_8d91_0a01, .high = 0xa7a3_5105_3d6d_a001 };
    pub const callback_read = Id{ .low = 0x6e6b_82f0_8d91_0a02, .high = 0xa7a3_5105_3d6d_a002 };
    pub const callback_write = Id{ .low = 0x6e6b_82f0_8d91_0a03, .high = 0xa7a3_5105_3d6d_a003 };
    pub const callback_rewind = Id{ .low = 0x6e6b_82f0_8d91_0a04, .high = 0xa7a3_5105_3d6d_a004 };
    pub const callback_seek = Id{ .low = 0x6e6b_82f0_8d91_0a05, .high = 0xa7a3_5105_3d6d_a005 };
    pub const invalid_call = Id{ .low = 0x6e6b_82f0_8d91_0501, .high = 0xa7a3_5105_3d6d_5001 };
    pub const unsupported = Id{ .low = 0x6e6b_82f0_8d91_0502, .high = 0xa7a3_5105_3d6d_5002 };
    pub const internal_failure = Id{ .low = 0x6e6b_82f0_8d91_0503, .high = 0xa7a3_5105_3d6d_5003 };
    pub const diagnostic_resource_limit = Id{ .low = 0x6e6b_82f0_8d91_0504, .high = 0xa7a3_5105_3d6d_5004 };
    pub const insufficient_capacity = Id{ .low = 0x6e6b_82f0_8d91_0505, .high = 0xa7a3_5105_3d6d_5005 };
    pub const invalid_data = Id{ .low = 0x6e6b_82f0_8d91_0506, .high = 0xa7a3_5105_3d6d_5006 };
    pub const integrity_failure = Id{ .low = 0x6e6b_82f0_8d91_0507, .high = 0xa7a3_5105_3d6d_5007 };
    pub const io_failure = Id{ .low = 0x6e6b_82f0_8d91_0508, .high = 0xa7a3_5105_3d6d_5008 };
    pub const crypto_wrong_password = Id{ .low = 0x6e6b_82f0_8d91_0509, .high = 0xa7a3_5105_3d6d_5009 };
    pub const crypto_kdf_limit = Id{ .low = 0x6e6b_82f0_8d91_050a, .high = 0xa7a3_5105_3d6d_500a };
    pub const crypto_password_lifetime = Id{ .low = 0x6e6b_82f0_8d91_050b, .high = 0xa7a3_5105_3d6d_500b };
    pub const crypto_unsupported_algorithm = Id{ .low = 0x6e6b_82f0_8d91_050c, .high = 0xa7a3_5105_3d6d_500c };
    pub const workspace_required_capacity = Id{ .low = 0x6e6b_82f0_8d91_050d, .high = 0xa7a3_5105_3d6d_500d };
    pub const workspace_available_capacity = Id{ .low = 0x6e6b_82f0_8d91_050e, .high = 0xa7a3_5105_3d6d_500e };
};

pub const error_map = [_]ErrorMap{
    .{ .failure = error.InvalidCall, .name = "invalid_call", .status = Status.invalid_call, .diagnostic = ids.invalid_call },
    .{ .failure = error.Unsupported, .name = "unsupported", .status = Status.unsupported, .diagnostic = ids.unsupported },
    .{ .failure = error.InternalFailure, .name = "internal_failure", .status = Status.internal_failure, .diagnostic = ids.internal_failure },
    .{ .failure = error.ResourceLimit, .name = "resource_limit", .status = Status.resource_limit, .diagnostic = ids.diagnostic_resource_limit },
    .{ .failure = error.InsufficientCapacity, .name = "insufficient_capacity", .status = Status.insufficient_capacity, .diagnostic = ids.insufficient_capacity },
    .{ .failure = error.InvalidData, .name = "invalid_data", .status = Status.invalid_data, .diagnostic = ids.invalid_data },
    .{ .failure = error.IntegrityFailure, .name = "integrity_failure", .status = Status.integrity_failure, .diagnostic = ids.integrity_failure },
    .{ .failure = error.IoFailure, .name = "io_failure", .status = Status.io_failure, .diagnostic = ids.io_failure },
};

pub fn idEqual(left: Id, right: Id) bool {
    return left.low == right.low and left.high == right.high;
}

pub fn idIsZero(id: Id) bool {
    return idEqual(id, .{ .low = 0, .high = 0 });
}
