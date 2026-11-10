const std = @import("std");

const crypto = @import("../../common/primitive/crypto.zig");
const kernel_catalog = @import("../../kernel/catalog.zig");
const discovery = @import("../../kernel/discovery.zig");
const abi = @import("../../kernel/envelope.zig");
const node_graph = @import("../../kernel/node.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");

const Id = abi.Id;
const Node = abi.Node;
const Limits = resource.Limits;
const Workspace = resource.Workspace;
const Exception = vocabulary.Exception;

// Family 2 is one selector space; tar declares every row of it.
const family: u16 = discovery.parameter("tar", "entry").family;

pub fn row(comptime name: []const u8) u16 {
    return comptime discovery.parameter("tar", name).ordinal;
}

pub fn find(nodes: ?*Node, comptime name: []const u8) ?*Node {
    return node_graph.findSelector(nodes, family, row(name));
}

pub fn matches(node: *Node, comptime name: []const u8) bool {
    if (!vocabulary.eql(node.id, vocabulary.ids.parameter)) return false;
    const selector = vocabulary.selectorOf(node.value_high);
    return selector.family == family and selector.ordinal == row(name);
}

pub fn rowOf(node: *Node) ?u32 {
    if (!vocabulary.eql(node.id, vocabulary.ids.parameter)) return null;
    const selector = vocabulary.selectorOf(node.value_high);
    return if (selector.family == family) selector.ordinal else null;
}

pub fn count(nodes: ?*Node, comptime name: []const u8) usize {
    var total: usize = 0;
    var cursor = nodes;
    while (cursor) |node| : (cursor = node.next) {
        if (matches(node, name)) total += 1;
    }
    return total;
}

pub fn scalar(nodes: ?*Node, comptime name: []const u8) u64 {
    const node = find(nodes, name) orelse return 0;
    return node.value_low;
}

pub fn bytes(nodes: ?*Node, comptime name: []const u8) Exception![]const u8 {
    const node = find(nodes, name) orelse return &.{};
    return resource.checkedConstBytes(node.bytes, node.byte_length);
}

// A row one component owns: age's recipient material, zip's descriptors.
pub fn componentField(nodes: ?*Node, comptime component: []const u8, comptime name: []const u8) ?*Node {
    const parameter = comptime discovery.parameter(component, name);
    return node_graph.findSelector(nodes, parameter.family, parameter.ordinal);
}

pub fn componentBytes(nodes: ?*Node, comptime component: []const u8, comptime name: []const u8) Exception!?[]const u8 {
    const node = componentField(nodes, component, name) orelse return null;
    return try resource.checkedConstBytes(node.bytes, node.byte_length);
}

pub fn componentScalar(nodes: ?*Node, comptime component: []const u8, comptime name: []const u8) u64 {
    const node = componentField(nodes, component, name) orelse return 0;
    return node.value_low;
}

// A selector arrives as a u64; an unrepresentable value is malformed.
pub fn narrow(comptime T: type, value: u64) Exception!T {
    return std.math.cast(T, value) orelse error.CallException;
}

// Absent reads as zero: only a projection requires the selector.
pub fn ordinal(request: ?*Node) u64 {
    return scalar(request, "ordinal");
}

fn entryOrdinal(request: ?*Node) Exception!u64 {
    const node = find(request, "ordinal") orelse return error.CallException;
    return node.value_low;
}

pub const Projection = union(enum) { count, size: u64, metadata: u64, manifest };

pub fn projection(request: ?*Node) Exception!Projection {
    if (find(request, "entry_size") != null) return .{ .size = try entryOrdinal(request) };
    if (find(request, "entry") != null) {
        // An ordinal names one record; its absence names the whole-set
        // manifest, answered in one walk.
        if (find(request, "ordinal")) |node| return .{ .metadata = node.value_low };
        return .manifest;
    }
    return .count;
}

// The source stays part 1, so the encoded budget holds per part.
const max_parts = 64;

pub fn volumeParts(request: ?*Node, limits: Limits, workspace: *Workspace) Exception![]const []const u8 {
    const total = count(request, "archive_volumes");
    if (total == 0) return &.{};
    if (total > max_parts) return error.ResourceException;
    const parts = try workspace.take([]const u8, total);
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!matches(node, "archive_volumes")) continue;
        const part = try resource.checkedConstBytes(node.bytes, node.byte_length);
        // A part too small to carry a signature fails in the walk, as data.
        if (part.len > limits.encoded_bytes) return error.ResourceException;
        parts[index] = part;
        index += 1;
    }
    return parts;
}

// A zero granularity is malformed: presence names the split shape.
pub fn volumeSize(request: ?*Node) Exception!u64 {
    const node = find(request, "archive_volume_size") orelse return 0;
    if (node.value_low == 0) return error.CallException;
    return node.value_low;
}

// 0 writes a plain header, 1 compresses it, 2 encrypts it.
pub fn headerEncode(comptime component: []const u8, request: ?*Node) Exception!u64 {
    const parameter = comptime discovery.parameter(component, "header_encode");
    const node = node_graph.findSelector(request, parameter.family, parameter.ordinal) orelse return 0;
    if (node.value_low > 2) return error.CallException;
    return node.value_low;
}

// Four descriptors share these rows; each validates its own copy.
pub const Credentials = struct {
    pub const default_algorithm: u8 = 3;

    password: []const u8,
    algorithm: u8 = default_algorithm,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,

    pub fn optionalPassword(held: ?Credentials) ?[]const u8 {
        return if (held) |present| present.password else null;
    }

    pub fn passwordOrEmpty(held: ?Credentials) []const u8 {
        return if (held) |present| present.password else &.{};
    }

    pub fn kdfLimit(held: ?Credentials) u64 {
        return if (held) |present| present.kdf_rounds_limit else 0;
    }

    pub fn lifetime(held: ?Credentials) u64 {
        return if (held) |present| present.password_lifetime else 0;
    }
};

pub fn credentials(comptime component: []const u8, request: ?*Node, cause: *crypto.FailureCause) Exception!?Credentials {
    const password_row = comptime discovery.parameter(component, "password");
    const algorithm_row = comptime discovery.parameter(component, "algorithm");
    const kdf_row = comptime discovery.parameter(component, "kdf_rounds_limit");
    const lifetime_row = comptime discovery.parameter(component, "password_lifetime");

    cause.* = .none;
    const profile_node = node_graph.findParameter(request, vocabulary.ids.crypto_profile);
    const password_node = node_graph.findSelector(request, password_row.family, password_row.ordinal);
    if (profile_node == null and password_node == null) return null;
    const profile_id = if (profile_node) |node| blk: {
        const value: Id = .{ .low = node.value_low, .high = node.value_high };
        const descriptor = kernel_catalog.descriptorFor(value) orelse return error.UnsupportedException;
        if (descriptor.kind != .profile) return error.CallException;
        break :blk value;
    } else return error.CallException;
    if (!vocabulary.eql(profile_id, vocabulary.ids.crypto)) return error.CallException;
    const password_field = password_node orelse return error.CallException;
    const password = try resource.checkedConstBytes(password_field.bytes, password_field.byte_length);
    if (password.len == 0) return error.CallException;
    const algorithm = if (node_graph.findSelector(request, algorithm_row.family, algorithm_row.ordinal)) |node| blk: {
        // A stronger algorithm must never truncate to a weaker one.
        const value = std.math.cast(u8, node.value_low) orelse {
            cause.* = .unsupported_algorithm;
            return error.UnsupportedException;
        };
        if (value > 3) {
            cause.* = .unsupported_algorithm;
            return error.UnsupportedException;
        }
        break :blk value;
    } else Credentials.default_algorithm;
    return .{
        .password = password,
        .algorithm = algorithm,
        .kdf_rounds_limit = node_graph.parseU64(node_graph.findSelector(request, kdf_row.family, kdf_row.ordinal)),
        .password_lifetime = node_graph.parseU64(node_graph.findSelector(request, lifetime_row.family, lifetime_row.ordinal)),
    };
}
