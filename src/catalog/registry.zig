const std = @import("std");

const abi = @import("../abi/contract.zig");
const Id = abi.Id;
const Status = abi.Status;
const failure = @import("../common/primitive/failure.zig");
pub const Failure = failure.Failure;

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

pub const PlanningMode = enum(u32) {
    unavailable,
    metadata_exact,
    replay_pass,
    bounded_materialization,
    // Never a policy or wire value: the adapter resolves it per call when the
    // planning_bound parameter is present on a replay_pass write.
    bound,
};

pub const DeliveryMode = enum(u32) {
    provisional,
    verified,
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
pub const parameter_family_protocol: u16 = 0;
pub const parameter_family_crypto: u16 = 1;
pub const parameter_family_archive: u16 = 2;
pub const parameter_family_gzip: u16 = 3;
pub const parameter_family_zstd: u16 = 4;
pub const parameter_family_bzip2: u16 = 5;
pub const parameter_family_lzma: u16 = 6;
pub const parameter_family_xz: u16 = 7;
pub const parameter_family_deflate: u16 = 8;

pub const protocol_parameter = struct {
    pub const workspace_hint: u32 = 1;
    pub const resource_limit: u32 = 2;
    pub const resource_capabilities: u32 = 3;
    pub const planning_mode: u32 = 4;
    pub const delivery_mode: u32 = 5;
};

pub const parameter_rep_shift: u6 = 0;
pub const parameter_card_shift: u6 = 2;
pub const parameter_dir_shift: u6 = 4;
pub const parameter_attr_reserved_mask: u8 = 0xC0;
pub const parameter_flag_command_mask: u8 = 0x07;
pub const parameter_flag_reserved_mask: u8 = 0xF8;

pub const Selector = struct {
    family: u16,
    ordinal: u32,
    attrs: u8,
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
    const attrs = @as(u8, @intCast(@intFromEnum(representation))) | (@as(u8, @intCast(@intFromEnum(cardinality))) << parameter_card_shift) | (@as(u8, @intCast(@intFromEnum(direction))) << parameter_dir_shift);
    return (@as(u64, family) << 48) | (@as(u64, ordinal) << 16) | (@as(u64, attrs) << 8) | @as(u64, command_mask & parameter_flag_command_mask);
}

pub fn selectorOf(value_high: u64) Selector {
    return .{
        .family = @truncate(value_high >> 48),
        .ordinal = @truncate(value_high >> 16),
        .attrs = @truncate(value_high >> 8),
        .flags = @truncate(value_high),
    };
}

pub fn selectorValid(sel: Selector) bool {
    if (sel.attrs & parameter_attr_reserved_mask != 0) return false;
    if (sel.flags & parameter_flag_reserved_mask != 0) return false;
    return cardOf(sel.attrs) <= 1;
}

pub fn repOf(attrs: u8) u2 {
    return @truncate(attrs >> parameter_rep_shift);
}

pub fn cardOf(attrs: u8) u2 {
    return @truncate(attrs >> parameter_card_shift);
}

pub fn dirOf(attrs: u8) u2 {
    return @truncate(attrs >> parameter_dir_shift);
}

pub fn representationOf(sel: Selector) Representation {
    return @enumFromInt(repOf(sel.attrs));
}

pub fn cardinalityOf(sel: Selector) Cardinality {
    return @enumFromInt(cardOf(sel.attrs));
}

pub fn directionOf(sel: Selector) Direction {
    return @enumFromInt(dirOf(sel.attrs));
}

pub fn commandBit(id: Id) u32 {
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
    planning: PlanningMode = .unavailable,
    delivery: DeliveryMode = .provisional,
};

pub const ProfileTag = enum {
    test_echo,
    test_read_only,
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
    seven_zip_decoded,
    seven_zip_coded,
    rar,
};

pub const CommandPolicy = struct {
    command: u32,
    target: u32 = 0,
    capabilities: u32,
    planning: PlanningMode,
    delivery: DeliveryMode,
    limit_dimensions: u32 = 0,
};

pub const ParameterSpec = struct {
    name: []const u8,
    family: u16,
    ordinal: u32,
    representation: Representation,
    cardinality: Cardinality,
    direction: Direction,
    command_mask: u32,
    required: bool = false,
};

pub const DescriptorRow = struct {
    id: Id,
    name: []const u8,
    kind: DescriptorKind,
    representation: Representation = .none,
    cardinality: Cardinality = .singleton,
    direction: Direction = .none,
    command_mask: u32 = 0,
    capability: ResourceCapability = .none,
    capability_mask: u32 = 0,
    planning: PlanningMode = .unavailable,
    delivery: DeliveryMode = .provisional,
    tag: ?ProfileTag = null,
};

const commands_masks = command_mask_query | command_mask_read | command_mask_write;
const read_write_mask = command_mask_read | command_mask_write;
const query_write_mask = command_mask_query | command_mask_write;
const all_capabilities = resource_capability_bit_read | resource_capability_bit_write | resource_capability_bit_size | resource_capability_bit_replay | resource_capability_bit_seek | resource_capability_bit_range;
const replay_capabilities = resource_capability_bit_read | resource_capability_bit_replay;
const archive_capabilities = resource_capability_bit_read | resource_capability_bit_write | resource_capability_bit_size | resource_capability_bit_replay;

pub const rows = [_]DescriptorRow{
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0101, .high = 0xa7a3_5105_3d6d_1001 }, .name = "query", .kind = .command, .representation = .node_chain, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0102, .high = 0xa7a3_5105_3d6d_1002 }, .name = "read", .kind = .command, .representation = .node_chain, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0103, .high = 0xa7a3_5105_3d6d_1003 }, .name = "write", .kind = .command, .representation = .node_chain, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0200, .high = 0xa7a3_5105_3d6d_2000 }, .name = "diagnostic_required_capacity", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0201, .high = 0xa7a3_5105_3d6d_2001 }, .name = "diagnostic_available_capacity", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0202, .high = 0xa7a3_5105_3d6d_2002 }, .name = "diagnostic_downstream_status", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0203, .high = 0xa7a3_5105_3d6d_2003 }, .name = "diagnostic_subject", .kind = .parameter, .representation = .scalar_words, .direction = .out },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0210, .high = 0xa7a3_5105_3d6d_2010 }, .name = "source", .kind = .parameter, .representation = .bytes, .direction = .in, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0211, .high = 0xa7a3_5105_3d6d_2011 }, .name = "sink", .kind = .parameter, .representation = .bytes, .direction = .in, .command_mask = read_write_mask },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0212, .high = 0xa7a3_5105_3d6d_2012 }, .name = "profile", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0218, .high = 0xa7a3_5105_3d6d_2018 }, .name = "target_command", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = command_mask_query },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0219, .high = 0xa7a3_5105_3d6d_2019 }, .name = "planning_bound", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = query_write_mask },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0240, .high = 0xa7a3_5105_3d6d_2040 }, .name = "parameter", .kind = .parameter, .representation = .none, .cardinality = .repeated, .direction = .in_out, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0236, .high = 0xa7a3_5105_3d6d_2036 }, .name = "crypto_profile", .kind = .parameter, .representation = .scalar_words, .direction = .in, .command_mask = commands_masks },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0301, .high = 0xa7a3_5105_3d6d_3001 }, .name = "resource_read", .kind = .resource, .representation = .scalar_words, .capability = .read },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0302, .high = 0xa7a3_5105_3d6d_3002 }, .name = "resource_write", .kind = .resource, .representation = .scalar_words, .capability = .write },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0303, .high = 0xa7a3_5105_3d6d_3003 }, .name = "resource_size", .kind = .resource, .representation = .scalar_words, .capability = .size },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0304, .high = 0xa7a3_5105_3d6d_3004 }, .name = "resource_replay", .kind = .resource, .representation = .scalar_words, .capability = .replay },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0305, .high = 0xa7a3_5105_3d6d_3005 }, .name = "resource_seek", .kind = .resource, .representation = .scalar_words, .capability = .seek },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0306, .high = 0xa7a3_5105_3d6d_3006 }, .name = "resource_range", .kind = .resource, .representation = .scalar_words, .capability = .range },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0401, .high = 0xa7a3_5105_3d6d_4001 }, .name = "test_echo", .kind = .profile, .command_mask = read_write_mask, .capability_mask = all_capabilities, .planning = .metadata_exact, .delivery = .verified, .tag = .test_echo },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0402, .high = 0xa7a3_5105_3d6d_4002 }, .name = "test_read_only", .kind = .profile, .command_mask = command_mask_query | command_mask_read, .capability_mask = all_capabilities, .planning = .metadata_exact, .delivery = .verified, .tag = .test_read_only },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0403, .high = 0xa7a3_5105_3d6d_4003 }, .name = "deflate", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .provisional, .tag = .deflate },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0404, .high = 0xa7a3_5105_3d6d_4004 }, .name = "gzip", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .provisional, .tag = .gzip },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0405, .high = 0xa7a3_5105_3d6d_4005 }, .name = "tar", .kind = .profile, .command_mask = commands_masks, .capability_mask = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional, .tag = .tar },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0406, .high = 0xa7a3_5105_3d6d_4006 }, .name = "zip", .kind = .profile, .command_mask = commands_masks, .capability_mask = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional, .tag = .zip },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0407, .high = 0xa7a3_5105_3d6d_4007 }, .name = "zstd", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .verified, .tag = .zstd },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0408, .high = 0xa7a3_5105_3d6d_4008 }, .name = "seven_zip_decoded", .kind = .profile, .command_mask = commands_masks, .capability_mask = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional, .tag = .seven_zip_decoded },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0409, .high = 0xa7a3_5105_3d6d_4009 }, .name = "bzip2", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .provisional, .tag = .bzip2 },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_040a, .high = 0xa7a3_5105_3d6d_400a }, .name = "lzma", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .provisional, .tag = .lzma },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_040b, .high = 0xa7a3_5105_3d6d_400b }, .name = "lzma_file", .kind = .profile, .command_mask = command_mask_query | command_mask_read, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .provisional, .tag = .lzma_file },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_040c, .high = 0xa7a3_5105_3d6d_400c }, .name = "lzma2", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .provisional, .tag = .lzma2 },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_040d, .high = 0xa7a3_5105_3d6d_400d }, .name = "xz", .kind = .profile, .command_mask = commands_masks, .capability_mask = replay_capabilities, .planning = .replay_pass, .delivery = .verified, .tag = .xz },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_040e, .high = 0xa7a3_5105_3d6d_400e }, .name = "seven_zip_coded", .kind = .profile, .command_mask = commands_masks, .capability_mask = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional, .tag = .seven_zip_coded },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_040f, .high = 0xa7a3_5105_3d6d_400f }, .name = "rar", .kind = .profile, .command_mask = command_mask_query | command_mask_read, .capability_mask = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional, .tag = .rar },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0410, .high = 0xa7a3_5105_3d6d_4010 }, .name = "crypto", .kind = .profile, .command_mask = commands_masks, .capability_mask = archive_capabilities, .planning = .metadata_exact, .delivery = .verified },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0501, .high = 0xa7a3_5105_3d6d_5001 }, .name = "invalid_call", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0502, .high = 0xa7a3_5105_3d6d_5002 }, .name = "unsupported", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0503, .high = 0xa7a3_5105_3d6d_5003 }, .name = "internal_failure", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0504, .high = 0xa7a3_5105_3d6d_5004 }, .name = "resource_limit", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0505, .high = 0xa7a3_5105_3d6d_5005 }, .name = "insufficient_capacity", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0506, .high = 0xa7a3_5105_3d6d_5006 }, .name = "invalid_data", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0507, .high = 0xa7a3_5105_3d6d_5007 }, .name = "integrity_failure", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0508, .high = 0xa7a3_5105_3d6d_5008 }, .name = "io_failure", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_0509, .high = 0xa7a3_5105_3d6d_5009 }, .name = "crypto_wrong_password", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_050a, .high = 0xa7a3_5105_3d6d_500a }, .name = "crypto_kdf_limit", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_050b, .high = 0xa7a3_5105_3d6d_500b }, .name = "crypto_password_lifetime", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_050c, .high = 0xa7a3_5105_3d6d_500c }, .name = "crypto_unsupported_algorithm", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_050d, .high = 0xa7a3_5105_3d6d_500d }, .name = "workspace_required_capacity", .kind = .diagnostic, .representation = .node_chain },
    .{ .id = Id{ .low = 0x6e6b_82f0_8d91_050e, .high = 0xa7a3_5105_3d6d_500e }, .name = "workspace_available_capacity", .kind = .diagnostic, .representation = .node_chain },
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

fn idByName(comptime name: []const u8) Id {
    inline for (rows) |row| {
        if (std.mem.eql(u8, row.name, name)) return row.id;
    }
    @compileError("unknown registry id: " ++ name);
}

pub const ids = struct {
    pub const query = idByName("query");
    pub const read = idByName("read");
    pub const write = idByName("write");
    pub const diagnostic_required_capacity = idByName("diagnostic_required_capacity");
    pub const diagnostic_available_capacity = idByName("diagnostic_available_capacity");
    pub const diagnostic_downstream_status = idByName("diagnostic_downstream_status");
    pub const diagnostic_subject = idByName("diagnostic_subject");
    pub const source = idByName("source");
    pub const sink = idByName("sink");
    pub const profile = idByName("profile");
    pub const target_command = idByName("target_command");
    pub const planning_bound = idByName("planning_bound");
    pub const parameter = idByName("parameter");
    pub const crypto_profile = idByName("crypto_profile");
    pub const resource_read = idByName("resource_read");
    pub const resource_write = idByName("resource_write");
    pub const resource_size = idByName("resource_size");
    pub const resource_replay = idByName("resource_replay");
    pub const resource_seek = idByName("resource_seek");
    pub const resource_range = idByName("resource_range");
    pub const test_echo = idByName("test_echo");
    pub const test_read_only = idByName("test_read_only");
    pub const deflate = idByName("deflate");
    pub const gzip = idByName("gzip");
    pub const tar = idByName("tar");
    pub const zip = idByName("zip");
    pub const zstd = idByName("zstd");
    pub const seven_zip_decoded = idByName("seven_zip_decoded");
    pub const bzip2 = idByName("bzip2");
    pub const lzma = idByName("lzma");
    pub const lzma_file = idByName("lzma_file");
    pub const lzma2 = idByName("lzma2");
    pub const xz = idByName("xz");
    pub const seven_zip_coded = idByName("seven_zip_coded");
    pub const rar = idByName("rar");
    pub const crypto = idByName("crypto");
    pub const callback_size = Id{ .low = 0x6e6b_82f0_8d91_0a01, .high = 0xa7a3_5105_3d6d_a001 };
    pub const callback_read = Id{ .low = 0x6e6b_82f0_8d91_0a02, .high = 0xa7a3_5105_3d6d_a002 };
    pub const callback_write = Id{ .low = 0x6e6b_82f0_8d91_0a03, .high = 0xa7a3_5105_3d6d_a003 };
    pub const callback_rewind = Id{ .low = 0x6e6b_82f0_8d91_0a04, .high = 0xa7a3_5105_3d6d_a004 };
    pub const callback_seek = Id{ .low = 0x6e6b_82f0_8d91_0a05, .high = 0xa7a3_5105_3d6d_a005 };
    pub const invalid_call = idByName("invalid_call");
    pub const unsupported = idByName("unsupported");
    pub const internal_failure = idByName("internal_failure");
    pub const diagnostic_resource_limit = idByName("resource_limit");
    pub const insufficient_capacity = idByName("insufficient_capacity");
    pub const invalid_data = idByName("invalid_data");
    pub const integrity_failure = idByName("integrity_failure");
    pub const io_failure = idByName("io_failure");
    pub const crypto_wrong_password = idByName("crypto_wrong_password");
    pub const crypto_kdf_limit = idByName("crypto_kdf_limit");
    pub const crypto_password_lifetime = idByName("crypto_password_lifetime");
    pub const crypto_unsupported_algorithm = idByName("crypto_unsupported_algorithm");
    pub const workspace_required_capacity = idByName("workspace_required_capacity");
    pub const workspace_available_capacity = idByName("workspace_available_capacity");
};

const ParamEntry = struct {
    profile: []const u8,
    name: []const u8,
    ordinal: u32,
};

const param_table = [_]ParamEntry{
    .{ .profile = "zip", .name = "password", .ordinal = 1 },
    .{ .profile = "zip", .name = "algorithm", .ordinal = 2 },
    .{ .profile = "zip", .name = "kdf_rounds_limit", .ordinal = 3 },
    .{ .profile = "zip", .name = "password_lifetime", .ordinal = 4 },
    .{ .profile = "tar", .name = "ordinal", .ordinal = 1 },
    .{ .profile = "tar", .name = "entry_count", .ordinal = 2 },
    .{ .profile = "tar", .name = "entry_name", .ordinal = 3 },
    .{ .profile = "tar", .name = "entry_size", .ordinal = 4 },
    .{ .profile = "tar", .name = "entry", .ordinal = 5 },
    .{ .profile = "tar", .name = "entry_data", .ordinal = 6 },
    .{ .profile = "tar", .name = "entry_method", .ordinal = 7 },
    .{ .profile = "tar", .name = "comment", .ordinal = 8 },
    .{ .profile = "tar", .name = "entry_typeflag", .ordinal = 9 },
    .{ .profile = "tar", .name = "entry_link_name", .ordinal = 10 },
    .{ .profile = "tar", .name = "entry_uid", .ordinal = 11 },
    .{ .profile = "tar", .name = "entry_mtime", .ordinal = 12 },
    .{ .profile = "gzip", .name = "modification_time", .ordinal = 1 },
    .{ .profile = "gzip", .name = "extra_flags", .ordinal = 2 },
    .{ .profile = "gzip", .name = "operating_system", .ordinal = 3 },
    .{ .profile = "gzip", .name = "text", .ordinal = 4 },
    .{ .profile = "gzip", .name = "header_crc", .ordinal = 5 },
    .{ .profile = "gzip", .name = "extra", .ordinal = 6 },
    .{ .profile = "gzip", .name = "name", .ordinal = 7 },
    .{ .profile = "gzip", .name = "comment", .ordinal = 8 },
    .{ .profile = "zstd", .name = "window", .ordinal = 1 },
    .{ .profile = "zstd", .name = "dictionary", .ordinal = 2 },
    .{ .profile = "zstd", .name = "hash_bits", .ordinal = 3 },
    .{ .profile = "zstd", .name = "max_chain", .ordinal = 4 },
    .{ .profile = "zstd", .name = "nice_len", .ordinal = 5 },
    .{ .profile = "zstd", .name = "search_window", .ordinal = 6 },
    .{ .profile = "zstd", .name = "lazy", .ordinal = 7 },
    .{ .profile = "zstd", .name = "skip_interior_insert", .ordinal = 8 },
    .{ .profile = "zstd", .name = "double_hash", .ordinal = 9 },
    .{ .profile = "zstd", .name = "row_match", .ordinal = 10 },
    .{ .profile = "bzip2", .name = "block_size", .ordinal = 1 },
    .{ .profile = "lzma", .name = "dictionary", .ordinal = 1 },
    .{ .profile = "lzma", .name = "match_finder_depth", .ordinal = 2 },
    .{ .profile = "lzma", .name = "lazy", .ordinal = 3 },
    .{ .profile = "lzma", .name = "nice_len", .ordinal = 4 },
    .{ .profile = "lzma", .name = "match_finder", .ordinal = 5 },
    .{ .profile = "deflate", .name = "good", .ordinal = 1 },
    .{ .profile = "deflate", .name = "nice", .ordinal = 2 },
    .{ .profile = "deflate", .name = "lazy", .ordinal = 3 },
    .{ .profile = "deflate", .name = "chain", .ordinal = 4 },
    .{ .profile = "deflate", .name = "optimal", .ordinal = 5 },
    .{ .profile = "xz", .name = "check", .ordinal = 1 },
    .{ .profile = "xz", .name = "filters", .ordinal = 2 },
};

fn paramOrdinal(comptime profile_name: []const u8, comptime param_name: []const u8) u32 {
    inline for (param_table) |entry| {
        if (std.mem.eql(u8, entry.profile, profile_name) and std.mem.eql(u8, entry.name, param_name)) return entry.ordinal;
    }
    @compileError("unknown parameter " ++ param_name ++ " for " ++ profile_name);
}

fn maxParamOrdinal(comptime profile_name: []const u8) u32 {
    var max: u32 = 0;
    inline for (param_table) |entry| {
        if (std.mem.eql(u8, entry.profile, profile_name)) {
            if (entry.ordinal > max) max = entry.ordinal;
        }
    }
    return max;
}

pub const crypto_parameter = struct {
    pub const password = paramOrdinal("zip", "password");
    pub const algorithm = paramOrdinal("zip", "algorithm");
    pub const kdf_rounds_limit = paramOrdinal("zip", "kdf_rounds_limit");
    pub const password_lifetime = paramOrdinal("zip", "password_lifetime");
};

pub const archive_parameter = struct {
    pub const ordinal = paramOrdinal("tar", "ordinal");
    pub const entry_count = paramOrdinal("tar", "entry_count");
    pub const entry_name = paramOrdinal("tar", "entry_name");
    pub const entry_size = paramOrdinal("tar", "entry_size");
    pub const entry = paramOrdinal("tar", "entry");
    pub const entry_data = paramOrdinal("tar", "entry_data");
    pub const entry_method = paramOrdinal("tar", "entry_method");
    pub const comment = paramOrdinal("tar", "comment");
    pub const entry_typeflag = paramOrdinal("tar", "entry_typeflag");
    pub const entry_link_name = paramOrdinal("tar", "entry_link_name");
    pub const entry_uid = paramOrdinal("tar", "entry_uid");
    pub const entry_mtime = paramOrdinal("tar", "entry_mtime");
};

pub const gzip_parameter = struct {
    pub const modification_time = paramOrdinal("gzip", "modification_time");
    pub const extra_flags = paramOrdinal("gzip", "extra_flags");
    pub const operating_system = paramOrdinal("gzip", "operating_system");
    pub const text = paramOrdinal("gzip", "text");
    pub const header_crc = paramOrdinal("gzip", "header_crc");
    pub const extra = paramOrdinal("gzip", "extra");
    pub const name = paramOrdinal("gzip", "name");
    pub const comment = paramOrdinal("gzip", "comment");
};

pub const zstd_parameter = struct {
    pub const window = paramOrdinal("zstd", "window");
    pub const dictionary = paramOrdinal("zstd", "dictionary");
    pub const hash_bits = paramOrdinal("zstd", "hash_bits");
    pub const max_chain = paramOrdinal("zstd", "max_chain");
    pub const nice_len = paramOrdinal("zstd", "nice_len");
    pub const search_window = paramOrdinal("zstd", "search_window");
    pub const lazy = paramOrdinal("zstd", "lazy");
    pub const skip_interior_insert = paramOrdinal("zstd", "skip_interior_insert");
    pub const double_hash = paramOrdinal("zstd", "double_hash");
    pub const row_match = paramOrdinal("zstd", "row_match");
};

pub const bzip2_parameter = struct {
    pub const block_size = paramOrdinal("bzip2", "block_size");
};

pub const lzma_parameter = struct {
    pub const dictionary = paramOrdinal("lzma", "dictionary");
    pub const match_finder_depth = paramOrdinal("lzma", "match_finder_depth");
    pub const lazy = paramOrdinal("lzma", "lazy");
    pub const nice_len = paramOrdinal("lzma", "nice_len");
    pub const match_finder = paramOrdinal("lzma", "match_finder");
};

pub const deflate_parameter = struct {
    pub const good = paramOrdinal("deflate", "good");
    pub const nice = paramOrdinal("deflate", "nice");
    pub const lazy = paramOrdinal("deflate", "lazy");
    pub const chain = paramOrdinal("deflate", "chain");
    pub const optimal = paramOrdinal("deflate", "optimal");
};

pub const xz_parameter = struct {
    pub const check = paramOrdinal("xz", "check");
    pub const filters = paramOrdinal("xz", "filters");
};

pub const descriptors = deriveDescriptors();

fn deriveDescriptors() [rows.len]Descriptor {
    var result: [rows.len]Descriptor = undefined;
    inline for (rows, 0..) |row, index| {
        result[index] = .{
            .id = row.id,
            .name = row.name,
            .kind = row.kind,
            .representation = row.representation,
            .cardinality = row.cardinality,
            .direction = row.direction,
            .command_mask = row.command_mask,
            .capability = row.capability,
            .capability_mask = row.capability_mask,
            .planning = row.planning,
            .delivery = row.delivery,
        };
    }
    return result;
}

pub const sorted_descriptors = sortDescriptors();

pub fn idEqual(left: Id, right: Id) bool {
    return left.low == right.low and left.high == right.high;
}

pub fn idIsZero(id: Id) bool {
    return idEqual(id, .{ .low = 0, .high = 0 });
}

fn idLess(left: Id, right: Id) bool {
    return left.high < right.high or (left.high == right.high and left.low < right.low);
}

fn sortDescriptors() [descriptors.len]Descriptor {
    @setEvalBranchQuota(10_000);
    var result = descriptors;
    inline for (0..result.len) |index| {
        var least = index;
        inline for (index + 1..result.len) |candidate| {
            if (idLess(result[candidate].id, result[least].id)) least = candidate;
        }
        const value = result[index];
        result[index] = result[least];
        result[least] = value;
    }
    return result;
}

fn descriptorExists(id: Id) bool {
    return descriptorFor(id) != null;
}

pub fn descriptorFor(id: Id) ?*const Descriptor {
    inline for (descriptors, 0..) |descriptor, index| {
        if (idEqual(id, descriptor.id)) return &descriptors[index];
    }
    return null;
}

pub fn tagFor(id: Id) ?ProfileTag {
    inline for (rows) |row| {
        if (idEqual(id, row.id)) return row.tag;
    }
    return null;
}

fn replayPolicy(command: u32, target: u32, comptime verified: bool) ?CommandPolicy {
    const delivery: DeliveryMode = if (verified) .verified else .provisional;
    if (command == command_mask_query) {
        if (target != command_mask_read and target != command_mask_write) return null;
        return .{ .command = command_mask_query, .target = target, .capabilities = replay_capabilities, .planning = .replay_pass, .delivery = delivery };
    }
    if (command != command_mask_read and command != command_mask_write) return null;
    return .{ .command = command, .capabilities = replay_capabilities, .planning = .replay_pass, .delivery = delivery };
}

fn archivePolicy(command: u32, target: u32) ?CommandPolicy {
    if (command == command_mask_query) {
        if (target == command_mask_read) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional };
        if (target == command_mask_write) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .planning = .metadata_exact, .delivery = .verified };
        return null;
    }
    if (command == command_mask_read) return .{ .command = command_mask_read, .capabilities = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional };
    if (command == command_mask_write) return .{ .command = command_mask_write, .capabilities = archive_capabilities, .planning = .metadata_exact, .delivery = .verified };
    return null;
}

fn rarPolicy(command: u32, target: u32) ?CommandPolicy {
    if (command == command_mask_query and target == command_mask_read) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional };
    if (command == command_mask_read) return .{ .command = command_mask_read, .capabilities = archive_capabilities, .planning = .metadata_exact, .delivery = .provisional };
    return null;
}

fn testEchoPolicy(command: u32) ?CommandPolicy {
    if (command != command_mask_read and command != command_mask_write) return null;
    return .{ .command = command, .capabilities = all_capabilities, .planning = .metadata_exact, .delivery = .provisional };
}

fn testReadPolicy(command: u32, target: u32) ?CommandPolicy {
    if (command == command_mask_query and target == command_mask_read) return .{ .command = command_mask_query, .target = target, .capabilities = all_capabilities, .planning = .metadata_exact, .delivery = .provisional };
    if (command == command_mask_read) return .{ .command = command_mask_read, .capabilities = all_capabilities, .planning = .metadata_exact, .delivery = .provisional };
    return null;
}

pub fn commandPolicyFor(id: Id, command: u32, target: u32) ?CommandPolicy {
    const tag = tagFor(id) orelse return null;
    return switch (tag) {
        .test_echo => testEchoPolicy(command),
        .test_read_only => testReadPolicy(command, target),
        .deflate, .gzip, .bzip2, .lzma, .lzma2, .lzma_file => replayPolicy(command, target, false),
        .zstd, .xz => replayPolicy(command, target, true),
        .tar, .zip, .seven_zip_decoded, .seven_zip_coded => archivePolicy(command, target),
        .rar => rarPolicy(command, target),
    };
}

pub fn selectorKnown(sel: Selector) bool {
    if (sel.family == parameter_family_protocol) return sel.ordinal >= protocol_parameter.workspace_hint and sel.ordinal <= protocol_parameter.delivery_mode;
    const max: u32 = switch (sel.family) {
        parameter_family_crypto => maxParamOrdinal("zip"),
        parameter_family_archive => maxParamOrdinal("tar"),
        parameter_family_gzip => maxParamOrdinal("gzip"),
        parameter_family_zstd => maxParamOrdinal("zstd"),
        parameter_family_bzip2 => maxParamOrdinal("bzip2"),
        parameter_family_lzma => maxParamOrdinal("lzma"),
        parameter_family_xz => maxParamOrdinal("xz"),
        parameter_family_deflate => maxParamOrdinal("deflate"),
        else => return false,
    };
    return sel.ordinal >= 1 and sel.ordinal <= max;
}

pub fn knownId(id: Id) bool {
    return descriptorExists(id) or idIsZero(id);
}

comptime {
    @setEvalBranchQuota(100_000);
    for (rows, 0..) |row, index| {
        if (idIsZero(row.id)) @compileError("registry IDs must be nonzero");
        if (row.name.len == 0) @compileError("registry descriptors require names");
        if (row.kind == .parameter and row.direction == .none) @compileError("parameter descriptors require a direction");
        if (row.kind == .command and row.command_mask == 0) @compileError("command descriptors require a command mask");
        if (row.kind == .profile and row.command_mask == 0) @compileError("profile descriptors require a command mask");
        if (row.kind == .resource and row.capability == .none) @compileError("resource descriptors require a capability");
        if (row.tag != null and row.kind != .profile) @compileError("only profile descriptors may carry execution tags");
        for (rows[index + 1 ..]) |other| {
            if (idEqual(row.id, other.id)) @compileError("registry IDs must be unique");
            if (std.mem.eql(u8, row.name, other.name)) @compileError("registry names must be unique");
        }
    }
    for (error_map) |entry| {
        if (!descriptorExists(entry.diagnostic)) @compileError("error maps require registered diagnostics");
        if (entry.status == Status.ok or entry.status > Status.internal_failure) @compileError("error maps require frozen failure statuses");
    }
}
