const std = @import("std");

const abi = @import("../kernel/envelope.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
pub const Failure = vocabulary.Failure;
pub const capability_bit_read = vocabulary.resource_capability_bit_read;
pub const capability_bit_write = vocabulary.resource_capability_bit_write;
pub const capability_bit_size = vocabulary.resource_capability_bit_size;
pub const capability_bit_replay = vocabulary.resource_capability_bit_replay;
pub const capability_bit_seek = vocabulary.resource_capability_bit_seek;
pub const capability_bit_range = vocabulary.resource_capability_bit_range;
const io = @import("primitive/io.zig");
pub const checkedConstBytes = io.checkedConstBytes;
pub const checkedMutBytes = io.checkedMutBytes;
pub const Workspace = io.Workspace;
pub const WorkspacePlan = io.WorkspacePlan;
pub const Limits = @import("primitive/limits.zig").Limits;

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

    pub fn directRead(bytes: []const u8, capabilities: u32) Resource {
        // Bound at open, before any dispatch through it.
        return .{
            .call = undefined,
            .token_low = 0,
            .token_high = 0,
            .capabilities = capabilities,
            .kind = .{ .direct_read = bytes },
        };
    }

    pub fn directWrite(bytes: []u8, capabilities: u32) Resource {
        // Bound at open, before any dispatch through it.
        return .{
            .call = undefined,
            .token_low = 0,
            .token_high = 0,
            .capabilities = capabilities,
            .kind = .{ .direct_write = bytes },
        };
    }

    pub fn callbackRead(call: *abi.Call, token_low: u64, token_high: u64, capabilities: u32) Resource {
        return .{
            .call = call,
            .token_low = token_low,
            .token_high = token_high,
            .capabilities = capabilities,
            .kind = .callback_read,
        };
    }

    pub fn callbackWrite(call: *abi.Call, token_low: u64, token_high: u64, capabilities: u32) Resource {
        return .{
            .call = call,
            .token_low = token_low,
            .token_high = token_high,
            .capabilities = capabilities,
            .kind = .callback_write,
        };
    }

    pub fn sourceFromNode(call: *abi.Call, node: *abi.Node, capabilities: u32) Failure!Resource {
        if (node.flags & abi.node_flag_callback_resource != 0) {
            return callbackRead(call, node.value_low, node.value_high, capabilities);
        }
        const bytes = try checkedConstBytes(node.bytes, node.byte_length);
        return directRead(bytes, capabilities);
    }

    pub fn sinkFromNode(call: *abi.Call, node: *abi.Node, capabilities: u32) Failure!Resource {
        if (node.flags & abi.node_flag_callback_resource != 0) {
            return callbackWrite(call, node.value_low, node.value_high, capabilities);
        }
        const bytes = try checkedMutBytes(node.bytes, node.byte_capacity);
        return directWrite(bytes, capabilities);
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

    pub fn read(self: *Resource, buffer: []u8) Failure!usize {
        if (buffer.len == 0) return 0;
        switch (self.kind) {
            .direct_read => |bytes| {
                const remaining = bytes.len - self.offset;
                const byte_count = @min(buffer.len, remaining);
                if (byte_count == 0) return 0;
                @memcpy(buffer[0..byte_count], bytes[self.offset..][0..byte_count]);
                self.offset += byte_count;
                return byte_count;
            },
            .callback_read => {
                const result = try self.invoke(vocabulary.ids.callback_read, null, buffer);
                const bytes_read = std.math.cast(usize, result.bytes) orelse return error.IoFailure;
                if (bytes_read > buffer.len) return error.IoFailure;
                return bytes_read;
            },
            else => return error.Unsupported,
        }
    }

    pub fn write(self: *Resource, bytes: []const u8) Failure!usize {
        if (bytes.len == 0) return 0;
        switch (self.kind) {
            .direct_write => |destination| {
                if (self.offset + bytes.len > destination.len) return error.InsufficientCapacity;
                @memcpy(destination[self.offset..][0..bytes.len], bytes);
                self.offset += bytes.len;
                return bytes.len;
            },
            .callback_write => {
                const initial = self.committed;
                const result = try self.invoke(vocabulary.ids.callback_write, bytes, null);
                const bytes_written = std.math.cast(usize, result.bytes) orelse return error.IoFailure;
                if (bytes_written > bytes.len) return error.IoFailure;
                self.committed = std.math.add(u64, initial, bytes_written) catch return error.ResourceLimit;
                return bytes_written;
            },
            else => return error.Unsupported,
        }
    }

    pub fn writeAll(self: *Resource, bytes: []const u8) Failure!void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const bytes_written = try self.write(bytes[offset..]);
            if (bytes_written == 0) return error.IoFailure;
            offset += bytes_written;
        }
    }

    pub fn materialize(self: *Resource, buffer: []u8) Failure![]const u8 {
        var offset: usize = 0;
        while (offset < buffer.len) {
            const bytes_read = try self.read(buffer[offset..]);
            if (bytes_read == 0) break;
            offset += bytes_read;
        }
        if (offset == buffer.len) {
            var extra: [1]u8 = undefined;
            const tail_read = try self.read(&extra);
            if (tail_read != 0) return error.ResourceLimit;
        }
        return buffer[0..offset];
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
    temp: [4096]u8,

    pub fn init(self: *BoundedReader, resource: *Resource, limit: u64) void {
        const initial: BoundedReader = .{
            .resource = resource,
            .limit = limit,
            .reader = undefined,
            .temp = undefined,
        };
        self.* = initial;
        self.reader = .{
            .vtable = &reader_vtable,
            .buffer = &self.temp,
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
    const requested = @min(@intFromEnum(limit), max_request);
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

fn boundedWriterDrain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const self: *BoundedWriter = @fieldParentPtr("writer", writer);
    var total: usize = 0;
    for (data[0 .. data.len - 1]) |chunk| total += chunk.len;
    total += data[data.len - 1].len * splat;
    if (total == 0) return 0;
    if (total > self.limit) return error.WriteFailed;
    var offset: usize = 0;
    for (data[0 .. data.len - 1]) |chunk| {
        const bytes_written = writeToResource(self.resource, chunk) catch return error.WriteFailed;
        offset += bytes_written;
        if (bytes_written < chunk.len) return offset;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| {
        const bytes_written = writeToResource(self.resource, last) catch return error.WriteFailed;
        offset += bytes_written;
        if (bytes_written < last.len) return offset;
    }
    self.limit -= offset;
    return offset;
}

fn writeToResource(resource: *Resource, bytes: []const u8) Failure!usize {
    return resource.write(bytes);
}

fn mapResourceErrorToReadFailed(failure: Failure) std.Io.Reader.StreamError {
    return switch (failure) {
        error.InsufficientCapacity => error.ReadFailed,
        error.InvalidData => error.ReadFailed,
        error.IntegrityFailure => error.ReadFailed,
        error.IoFailure => error.ReadFailed,
        error.ResourceLimit => error.ReadFailed,
        error.InvalidCall => error.ReadFailed,
        error.Unsupported => error.ReadFailed,
        error.InternalFailure => error.ReadFailed,
    };
}

const CallbackResult = struct { bytes: u64, value_low: u64, value_high: u64 };
