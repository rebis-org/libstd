const std = @import("std");

const checksum = @import("../common/primitive/checksum.zig");
const crypto = @import("../common/primitive/crypto.zig");
const discovery = @import("../kernel/discovery.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const common = @import("common.zig");

const Node = abi.Node;
const Resource = resource.Resource;
const Exception = vocabulary.Exception;

// Hooks fetch their parameters by selector so family numbering stays
// descriptor-owned; the shapes mirror transform.zig.
fn optNode(request: ?*Node, comptime component: []const u8, comptime name: []const u8) ?*Node {
    const param = comptime discovery.parameter(component, name);
    return node_graph.findSelector(request, param.family, param.ordinal);
}

fn optBytes(request: ?*Node, comptime component: []const u8, comptime name: []const u8) Exception!?[]const u8 {
    const node = optNode(request, component, name) orelse return null;
    return try resource.checkedConstBytes(node.bytes, node.byte_length);
}

fn optScalar(request: ?*Node, comptime component: []const u8, comptime name: []const u8) Exception!?u32 {
    const node = optNode(request, component, name) orelse return null;
    return std.math.cast(u32, node.value_low) orelse error.CallException;
}

// Measured sources can exceed any staging buffer, so streaming keeps
// digest hooks workspace-free while the limit bounds the work.
fn feedHasher(source: *Resource, hasher: anytype, limit: u64) Exception!void {
    var buffer: [4096]u8 = undefined;
    var total: u64 = 0;
    while (true) {
        const bytes_read = try source.read(&buffer);
        if (bytes_read == 0) break;
        total = std.math.add(u64, total, bytes_read) catch return error.ResourceException;
        if (total > limit) return error.ResourceException;
        hasher.update(buffer[0..bytes_read]);
    }
}

// Value families (crc32, adler32, xxh32, xxh64) answer in one scalar word.
fn valueDigest(comptime Facade: type, comptime Value: type, invocation: *common.Invocation, args: anytype) Exception!void {
    const plan = &invocation.plan;
    if (plan.command_mask != vocabulary.command_mask_write) return error.UnsupportedException;
    const sink = invocation.sink orelse {
        invocation.response.byte_length = @sizeOf(Value);
        return;
    };
    var hasher = Facade.bind(plan.provider, args);
    try feedHasher(invocation.source, &hasher, plan.limits.decoded_bytes);
    const value = hasher.final({});
    var encoded: [@sizeOf(Value)]u8 = undefined;
    std.mem.writeInt(Value, &encoded, value, .big);
    try common.requireSink(sink, invocation.call, encoded.len);
    try common.commitBytesToSink(sink, invocation.call, &encoded);
    invocation.response.byte_length = encoded.len;
}

// Byte digests publish a fixed-width array; the comptime length keeps the
// facade's own constants out of the shared signature.
fn byteDigest(comptime Facade: type, comptime output_length: usize, invocation: *common.Invocation, args: anytype) Exception!void {
    const plan = &invocation.plan;
    if (plan.command_mask != vocabulary.command_mask_write) return error.UnsupportedException;
    const sink = invocation.sink orelse {
        invocation.response.byte_length = output_length;
        return;
    };
    var hasher = Facade.bind(plan.provider, args);
    try feedHasher(invocation.source, &hasher, plan.limits.decoded_bytes);
    const digest = hasher.finalResult();
    if (digest.len != output_length) return error.InternalException;
    try common.requireSink(sink, invocation.call, digest.len);
    try common.commitBytesToSink(sink, invocation.call, &digest);
    invocation.response.byte_length = digest.len;
}

pub fn crc32Hook(invocation: *common.Invocation) Exception!void {
    return valueDigest(checksum.Crc32, u32, invocation, {});
}

pub fn adler32Hook(invocation: *common.Invocation) Exception!void {
    return valueDigest(checksum.Adler32, u32, invocation, {});
}

pub fn xxh32Hook(invocation: *common.Invocation) Exception!void {
    const seed = try optScalar(invocation.call.request, "xxh32", "seed") orelse 0;
    return valueDigest(checksum.XxHash32, u32, invocation, seed);
}

pub fn xxh64Hook(invocation: *common.Invocation) Exception!void {
    const seed_node = optNode(invocation.call.request, "xxh64", "seed");
    const seed: u64 = if (seed_node) |node| node.value_low else 0;
    return valueDigest(checksum.XxHash64, u64, invocation, seed);
}

pub fn sha1Hook(invocation: *common.Invocation) Exception!void {
    return byteDigest(crypto.Sha1, crypto.Sha1.digest_length, invocation, crypto.Sha1.Options{});
}

pub fn sha256Hook(invocation: *common.Invocation) Exception!void {
    return byteDigest(crypto.Sha256, crypto.Sha256.digest_length, invocation, crypto.Sha256.Options{});
}

pub fn hmac_sha1Hook(invocation: *common.Invocation) Exception!void {
    const key = (try optBytes(invocation.call.request, "hmac_sha1", "key")) orelse return error.CallException;
    return byteDigest(crypto.HmacSha1, crypto.hmac_sha1_length, invocation, key);
}

pub fn hmac_sha256Hook(invocation: *common.Invocation) Exception!void {
    const key = (try optBytes(invocation.call.request, "hmac_sha256", "key")) orelse return error.CallException;
    return byteDigest(crypto.HmacSha256, crypto.hmac_sha256_length, invocation, key);
}

// The stack cap keeps derived keys off the workspace; larger requests fail
// as resource limits instead of degrading.
const max_derived_length: usize = 4096;

pub fn pbkdf2Hook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    if (plan.command_mask != vocabulary.command_mask_write) return error.UnsupportedException;
    const salt = (try optBytes(invocation.call.request, "pbkdf2", "salt")) orelse return error.CallException;
    const rounds = (try optScalar(invocation.call.request, "pbkdf2", "rounds")) orelse return error.CallException;
    const dk_len = (try optScalar(invocation.call.request, "pbkdf2", "dk_len")) orelse return error.CallException;
    if (rounds == 0 or dk_len == 0) return error.CallException;
    if (dk_len > max_derived_length) return error.ResourceException;
    const sink = invocation.sink orelse {
        invocation.response.byte_length = dk_len;
        return;
    };
    var workspace = try resource.Workspace.initTracked(invocation.call.workspace, invocation.call.workspace_capacity, &plan.workspace_required);
    const password = try common.materializeSource(.replay, invocation.source, &workspace, plan.limits.decoded_bytes);
    try common.requireSink(sink, invocation.call, dk_len);
    var derived: [max_derived_length]u8 = undefined;
    try crypto.pbkdf2HmacSha1(plan.provider, derived[0..dk_len], password, salt, rounds);
    try common.commitBytesToSink(sink, invocation.call, derived[0..dk_len]);
    invocation.response.byte_length = dk_len;
}

// Raw block cipher: 16-byte-multiple input, key 128 or 256 bits; write
// encrypts, read decrypts.
pub fn aesHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const key = (try optBytes(invocation.call.request, "aes", "key")) orelse return error.CallException;
    if (key.len != 16 and key.len != 32) return error.CallException;
    const decrypting = plan.command_mask == vocabulary.command_mask_read;
    const limit = if (decrypting) plan.limits.encoded_bytes else plan.limits.decoded_bytes;
    const sink = invocation.sink orelse {
        invocation.response.byte_length = try common.measureSource(invocation.source, limit);
        return;
    };
    var workspace = try resource.Workspace.initTracked(invocation.call.workspace, invocation.call.workspace_capacity, &plan.workspace_required);
    const input = try common.materializeSource(.replay, invocation.source, &workspace, limit);
    if (input.len % crypto.block_length != 0) return error.CallException;
    try common.checkSourceSinkOverlap(invocation.source, sink);
    try common.requireSink(sink, invocation.call, input.len);
    var offset: usize = 0;
    while (offset < input.len) : (offset += crypto.block_length) {
        const block = input[offset..][0..crypto.block_length].*;
        const transformed = if (decrypting)
            try crypto.aesDecryptBlock(plan.provider, key, block)
        else
            try crypto.aesEncryptBlock(plan.provider, key, block);
        try common.commitBytesToSink(sink, invocation.call, &transformed);
    }
    invocation.response.byte_length = input.len;
}
