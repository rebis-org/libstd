const std = @import("std");

const abi = @import("./envelope.zig");
const vocabulary = @import("./vocabulary.zig");
pub const Failure = vocabulary.Failure;
pub const capability_bit_read = vocabulary.resource_capability_bit_read;
pub const capability_bit_write = vocabulary.resource_capability_bit_write;
pub const capability_bit_size = vocabulary.resource_capability_bit_size;
pub const capability_bit_replay = vocabulary.resource_capability_bit_replay;
pub const capability_bit_seek = vocabulary.resource_capability_bit_seek;
pub const capability_bit_range = vocabulary.resource_capability_bit_range;
const io = @import("../common/primitive/io.zig");
pub const checkedConstBytes = io.checkedConstBytes;
pub const checkedMutBytes = io.checkedMutBytes;
pub const Workspace = io.Workspace;
pub const WorkspacePlan = io.WorkspacePlan;
pub const Limits = @import("../common/primitive/limits.zig").Limits;

pub const Resource = struct {
    call: *abi.Call,
    token_low: u64,
    token_high: u64,
    capabilities: u32,
    kind: Kind,
    offset: usize = 0,
    committed: u64 = 0,
    downstream_status: u32 = 0,

    pub const Kind = union(enum) {
        direct_read: []const u8,
        direct_write: []u8,
        callback_read,
        callback_write,
    };

    fn direct(kind: Kind, capabilities: u32) Resource {
        return .{
            .call = undefined,
            .token_low = 0,
            .token_high = 0,
            .capabilities = capabilities,
            .kind = kind,
        };
    }

    fn callbackResource(call: *abi.Call, token_low: u64, token_high: u64, capabilities: u32, reading: bool) Resource {
        return .{
            .call = call,
            .token_low = token_low,
            .token_high = token_high,
            .capabilities = capabilities,
            .kind = if (reading) .callback_read else .callback_write,
        };
    }

    fn fromNode(call: *abi.Call, node: *abi.Node, capabilities: u32, comptime is_sink: bool) Failure!Resource {
        if (node.flags & abi.node_flag_callback_resource != 0) {
            return callbackResource(call, node.value_low, node.value_high, capabilities, !is_sink);
        }
        if (is_sink) {
            return direct(.{ .direct_write = try checkedMutBytes(node.bytes, node.byte_capacity) }, capabilities);
        }
        return direct(.{ .direct_read = try checkedConstBytes(node.bytes, node.byte_length) }, capabilities);
    }

    pub fn sourceFromNode(call: *abi.Call, node: *abi.Node, capabilities: u32) Failure!Resource {
        return fromNode(call, node, capabilities, false);
    }

    pub fn sinkFromNode(call: *abi.Call, node: *abi.Node, capabilities: u32) Failure!Resource {
        return fromNode(call, node, capabilities, true);
    }

    pub fn hasCapability(self: Resource, bit: u32) bool {
        return self.capabilities & bit != 0;
    }

    pub fn requireCapability(self: Resource, bit: u32) Failure!void {
        if (!self.hasCapability(bit)) return error.Unsupported;
    }

    pub fn size(self: *Resource) Failure!usize {
        switch (self.kind) {
            .direct_read => |bytes| return bytes.len,
            .callback_read => {
                const result = try self.invoke(vocabulary.ids.callback_size, null, null);
                if (result.value_high != 0) return error.ResourceLimit;
                return std.math.cast(usize, result.value_low) orelse error.ResourceLimit;
            },
            else => return error.Unsupported,
        }
    }

    pub fn rewind(self: *Resource) Failure!void {
        switch (self.kind) {
            .direct_read => self.offset = 0,
            .direct_write => self.offset = 0,
            .callback_read => _ = try self.invoke(vocabulary.ids.callback_rewind, null, null),
            .callback_write => {},
        }
    }

    pub fn seekTo(self: *Resource, position: usize) Failure!void {
        switch (self.kind) {
            .direct_read => self.offset = @min(position, self.kind.direct_read.len),
            .direct_write => self.offset = @min(position, self.kind.direct_write.len),
            .callback_read => _ = try self.invokeWithValue(vocabulary.ids.callback_seek, null, null, position),
            .callback_write => return error.Unsupported,
        }
    }

    pub fn read(self: *Resource, staging: []u8) Failure!usize {
        if (staging.len == 0) return 0;
        switch (self.kind) {
            .direct_read => |bytes| {
                const remaining = bytes.len - self.offset;
                const byte_count = @min(staging.len, remaining);
                if (byte_count == 0) return 0;
                @memcpy(staging[0..byte_count], bytes[self.offset..][0..byte_count]);
                self.offset += byte_count;
                return byte_count;
            },
            .callback_read => {
                const result = try self.invoke(vocabulary.ids.callback_read, null, staging);
                const bytes_read = std.math.cast(usize, result.bytes) orelse return error.IoFailure;
                if (bytes_read > staging.len) return error.IoFailure;
                return bytes_read;
            },
            else => return error.Unsupported,
        }
    }

    pub fn write(self: *Resource, chunk: []const u8) Failure!usize {
        if (chunk.len == 0) return 0;
        switch (self.kind) {
            .direct_write => |destination| {
                if (self.offset + chunk.len > destination.len) return error.InsufficientCapacity;
                @memcpy(destination[self.offset..][0..chunk.len], chunk);
                self.offset += chunk.len;
                return chunk.len;
            },
            .callback_write => {
                const initial = self.committed;
                const result = try self.invoke(vocabulary.ids.callback_write, chunk, null);
                const bytes_written = std.math.cast(usize, result.bytes) orelse return error.IoFailure;
                if (bytes_written > chunk.len) return error.IoFailure;
                self.committed = std.math.add(u64, initial, bytes_written) catch return error.ResourceLimit;
                return bytes_written;
            },
            else => return error.Unsupported,
        }
    }

    pub fn writeAll(self: *Resource, chunk: []const u8) Failure!void {
        var cursor: usize = 0;
        while (cursor < chunk.len) {
            const bytes_written = try self.write(chunk[cursor..]);
            if (bytes_written == 0) return error.IoFailure;
            cursor += bytes_written;
        }
    }

    pub fn materialize(self: *Resource, staging: []u8) Failure![]const u8 {
        var cursor: usize = 0;
        while (cursor < staging.len) {
            const bytes_read = try self.read(staging[cursor..]);
            if (bytes_read == 0) break;
            cursor += bytes_read;
        }
        if (cursor == staging.len) {
            var extra: [1]u8 = undefined;
            const tail_read = try self.read(&extra);
            if (tail_read != 0) return error.ResourceLimit;
        }
        return staging[0..cursor];
    }

    fn invoke(self: *Resource, verb: abi.Id, request_bytes: ?[]const u8, response_bytes: ?[]u8) Failure!CallbackResult {
        return self.invokeWithValue(verb, request_bytes, response_bytes, self.token_low);
    }

    fn invokeWithValue(self: *Resource, verb: abi.Id, request_bytes: ?[]const u8, response_bytes: ?[]u8, value_low: u64) Failure!CallbackResult {
        const callback = self.call.callback orelse return error.InvalidCall;
        var request = abi.Node.init();
        request.value_low = value_low;
        request.value_high = self.token_high;
        if (request_bytes) |bytes| {
            request.bytes = if (bytes.len == 0) null else @constCast(bytes.ptr);
            request.byte_capacity = bytes.len;
            request.byte_length = bytes.len;
        }
        var response = abi.Node.init();
        if (response_bytes) |bytes| {
            response.bytes = if (bytes.len == 0) null else bytes.ptr;
            response.byte_capacity = bytes.len;
        }
        var callback_call = abi.Call.init();
        callback_call.operation = verb;
        callback_call.request = &request;
        callback_call.response = &response;
        callback_call.callback_context = self.call.callback_context;
        const status = callback(&callback_call);
        if (status != abi.Status.ok) {
            self.downstream_status = status;
            return error.IoFailure;
        }
        if (response_bytes != null and response.byte_length > response.byte_capacity) return error.IoFailure;
        return .{ .bytes = response.byte_length, .value_low = response.value_low, .value_high = response.value_high };
    }
};

pub const BoundedReader = struct {
    resource: *Resource,
    limit: u64,
    reader: std.Io.Reader,
    staging: [4096]u8,

    pub fn init(self: *BoundedReader, resource: *Resource, limit: u64) void {
        const initial: BoundedReader = .{
            .resource = resource,
            .limit = limit,
            .reader = undefined,
            .staging = undefined,
        };
        self.* = initial;
        self.reader = .{
            .vtable = &reader_vtable,
            .buffer = &self.staging,
            .seek = 0,
            .end = 0,
        };
    }
};

const reader_vtable = std.Io.Reader.VTable{ .stream = boundedReaderStream };

fn boundedReaderStream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const self: *BoundedReader = @fieldParentPtr("reader", reader);
    if (self.limit == 0) return error.EndOfStream;
    const max_request = std.math.cast(usize, self.limit) orelse std.math.maxInt(usize);
    const requested = @min(@backingInt(limit), max_request);
    if (requested == 0) return 0;
    var buffer: [4096]u8 = undefined;
    const chunk = @min(buffer.len, requested);
    const bytes_read = self.resource.read(buffer[0..chunk]) catch |failure| return mapResourceErrorToReadFailed(failure);
    if (bytes_read == 0) return error.EndOfStream;
    const written = writer.write(buffer[0..bytes_read]) catch return error.WriteFailed;
    if (written > bytes_read) return error.WriteFailed;
    self.limit -= written;
    return written;
}

pub const BoundedWriter = struct {
    resource: *Resource,
    limit: u64,
    writer: std.Io.Writer,

    pub fn init(resource: *Resource, limit: u64) BoundedWriter {
        return .{
            .resource = resource,
            .limit = limit,
            .writer = .{
                .vtable = &writer_vtable,
                .buffer = &.{},
                .end = 0,
            },
        };
    }
};

const writer_vtable = std.Io.Writer.VTable{ .drain = boundedWriterDrain };

fn boundedWriterDrain(writer: *std.Io.Writer, chunks: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const self: *BoundedWriter = @fieldParentPtr("writer", writer);
    var total: usize = 0;
    for (chunks[0 .. chunks.len - 1]) |part| total += part.len;
    total += chunks[chunks.len - 1].len * splat;
    if (total == 0) return 0;
    if (total > self.limit) return error.WriteFailed;
    var cursor: usize = 0;
    for (chunks[0 .. chunks.len - 1]) |part| {
        const bytes_written = self.resource.write(part) catch return error.WriteFailed;
        cursor += bytes_written;
        if (bytes_written < part.len) return cursor;
    }
    const last = chunks[chunks.len - 1];
    for (0..splat) |_| {
        const bytes_written = self.resource.write(last) catch return error.WriteFailed;
        cursor += bytes_written;
        if (bytes_written < last.len) return cursor;
    }
    self.limit -= cursor;
    return cursor;
}

fn mapResourceErrorToReadFailed(failure: Failure) std.Io.Reader.StreamError {
    return switch (failure) {
        else => error.ReadFailed,
    };
}

const CallbackResult = struct { bytes: u64, value_low: u64, value_high: u64 };
