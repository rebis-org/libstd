const std = @import("std");

const abi = @import("abi.zig");
pub const Id = abi.Id;

pub const Ids = struct {
    query: Id,
    read: Id,
    write: Id,
    diagnostic_required_capacity: Id,
    diagnostic_available_capacity: Id,
    diagnostic_downstream_status: Id,
    diagnostic_subject: Id,
    source: Id,
    sink: Id,
    profile: Id,
    target_command: Id,
    planning_bound: Id,
    parameter: Id,
    crypto_profile: Id,
    test_echo: Id,
    test_read_only: Id,
    deflate: Id,
    gzip: Id,
    zstd: Id,
    tar: Id,
    zip: Id,
    seven_zip_decoded: Id,
    bzip2: Id,
    lzma: Id,
    lzma_file: Id,
    lzma2: Id,
    xz: Id,
    seven_zip_coded: Id,
    rar: Id,
    crypto: Id,
    invalid_call: Id,
    unsupported: Id,
    internal_failure: Id,
    resource_limit: Id,
    insufficient_capacity: Id,
    invalid_data: Id,
    integrity_failure: Id,
    io_failure: Id,
    crypto_wrong_password: Id,
    crypto_kdf_limit: Id,
    crypto_password_lifetime: Id,
    crypto_unsupported_algorithm: Id,
    workspace_required_capacity: Id,
    workspace_available_capacity: Id,
};

pub const callback_size = Id{ .low = 0x6e6b_82f0_8d91_0a01, .high = 0xa7a3_5105_3d6d_a001 };
pub const callback_read = Id{ .low = 0x6e6b_82f0_8d91_0a02, .high = 0xa7a3_5105_3d6d_a002 };
pub const callback_write = Id{ .low = 0x6e6b_82f0_8d91_0a03, .high = 0xa7a3_5105_3d6d_a003 };
pub const callback_rewind = Id{ .low = 0x6e6b_82f0_8d91_0a04, .high = 0xa7a3_5105_3d6d_a004 };
pub const callback_seek = Id{ .low = 0x6e6b_82f0_8d91_0a05, .high = 0xa7a3_5105_3d6d_a005 };

const IdJson = struct {
    low: []const u8,
    high: []const u8,
};

pub const DescriptorJson = struct {
    id: IdJson,
    name: []const u8,
    kind: []const u8,
    representation: []const u8,
    cardinality: []const u8,
    direction: []const u8,
    command_mask: u32,
    capability: []const u8,
    capability_mask: u32,
    planning: []const u8,
    delivery: []const u8,
};

const CatalogJson = struct {
    epoch: u32,
    parameter_selector: ?[]const u8 = null,
    descriptors: []DescriptorJson,
};

fn parseHexWord(text: []const u8) !u64 {
    if (text.len != 18 or !std.mem.startsWith(u8, text, "0x")) return error.InvalidHexId;
    return std.fmt.parseInt(u64, text[2..], 16);
}

pub const Catalog = struct {
    epoch: u32,
    descriptors: []DescriptorJson,
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Catalog {
    const parsed = try std.json.parseFromSlice(CatalogJson, allocator, bytes, .{});
    return .{ .epoch = parsed.value.epoch, .descriptors = parsed.value.descriptors };
}

pub fn loadIds(catalog: *const Catalog) !Ids {
    var result: Ids = undefined;
    inline for (std.meta.fields(Ids)) |field| {
        @field(result, field.name) = try findId(catalog, field.name);
    }
    return result;
}

fn findId(catalog: *const Catalog, name: []const u8) !Id {
    for (catalog.descriptors) |descriptor| {
        if (std.mem.eql(u8, descriptor.name, name)) {
            return .{
                .low = try parseHexWord(descriptor.id.low),
                .high = try parseHexWord(descriptor.id.high),
            };
        }
    }
    return error.MissingDescriptor;
}
