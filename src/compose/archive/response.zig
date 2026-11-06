const std = @import("std");

const crypto = @import("../../common/primitive/crypto.zig");
const abi = @import("../../kernel/envelope.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");
const request = @import("request.zig");

const Call = abi.Call;
const Id = abi.Id;
const Node = abi.Node;
const Exception = vocabulary.Exception;

// A format fills only the fields its own record carries.
pub const Info = struct {
    size: u64,
    name: ?[]const u8 = null,
    mtime: ?u64 = null,
    uid: ?u64 = null,
    typeflag: ?u64 = null,
    link_name: ?[]const u8 = null,
    // Where the archive already holds the entry's bytes.
    ready: ?Span = null,

    pub fn from(raw: anytype) Info {
        const Raw = @TypeOf(raw);
        var info = Info{ .size = sizeOf(Raw, raw) };
        if (@hasField(Raw, "name")) info.name = raw.name;
        if (@hasField(Raw, "modification_time")) info.mtime = raw.modification_time;
        if (@hasField(Raw, "mtime")) info.mtime = raw.mtime;
        if (@hasField(Raw, "uid")) info.uid = raw.uid;
        if (@hasField(Raw, "typeflag")) info.typeflag = raw.typeflag;
        if (@hasField(Raw, "link_name")) info.link_name = raw.link_name;
        return info;
    }

    fn sizeOf(comptime Raw: type, raw: Raw) u64 {
        if (@hasField(Raw, "size")) return raw.size;
        if (@hasField(Raw, "uncompressed_size")) return raw.uncompressed_size;
        @compileError("the entry record carries no size: " ++ @typeName(Raw));
    }
};

pub const Span = struct { offset: u64, len: u64 };

// Only chained children are filled; a short buffer reports capacity.
pub fn publishInfo(call: *Call, response: *Node, info: Info) Exception!void {
    var cursor = response.child;
    while (cursor) |node| : (cursor = node.next) {
        const row = request.rowOf(node) orelse continue;
        if (row == request.row("entry_name")) {
            if (info.name) |text| try writeBytes(call, node, text);
        } else if (row == request.row("entry_link_name")) {
            if (info.link_name) |text| try writeBytes(call, node, text);
        } else if (row == request.row("entry_size")) {
            node.value_low = info.size;
        } else if (row == request.row("entry_mtime")) {
            if (info.mtime) |value| node.value_low = value;
        } else if (row == request.row("entry_uid")) {
            if (info.uid) |value| node.value_low = value;
        } else if (row == request.row("entry_typeflag")) {
            if (info.typeflag) |value| node.value_low = value;
        }
    }
    response.byte_length = info.size;
}

fn writeBytes(call: *Call, node: *Node, text: []const u8) Exception!void {
    if (node.byte_capacity < text.len) {
        common.writeCapacityDiagnostic(call, text.len, node.byte_capacity);
        return error.CapacityException;
    }
    const output = node.bytes orelse return error.CallException;
    @memcpy(output[0..text.len], text);
    node.byte_length = text.len;
}

// Fewer chained part nodes than parts is a capacity answer, not truncation.
pub fn publishVolumeParts(call: *Call, response: *Node, tail: []const []const u8) Exception!void {
    var cursor = response.child;
    var index: usize = 0;
    while (cursor) |node| : (cursor = node.next) {
        if (index >= tail.len) return;
        if (request.rowOf(node) != request.row("archive_volumes")) continue;
        try writeBytes(call, node, tail[index]);
        index += 1;
    }
    if (index < tail.len) {
        common.writeCapacityDiagnostic(call, tail.len, index);
        return error.CapacityException;
    }
}

// A recorded crypto cause names the diagnostic; the status follows it.
pub fn reportFailure(call: *Call, cause: crypto.FailureCause) void {
    const record: struct { id: Id, status: u32 } = switch (cause) {
        .none => return,
        .wrong_password => .{ .id = vocabulary.ids.crypto_wrong_password, .status = abi.Status.invalid_data },
        .kdf_limit => .{ .id = vocabulary.ids.crypto_kdf_limit, .status = abi.Status.resource_limit },
        .password_lifetime => .{ .id = vocabulary.ids.crypto_password_lifetime, .status = abi.Status.resource_limit },
        .unsupported_algorithm => .{ .id = vocabulary.ids.crypto_unsupported_algorithm, .status = abi.Status.unsupported },
    };
    common.writeDiagnosticScalar(call, record.id, record.status);
}
