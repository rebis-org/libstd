const std = @import("std");

const io = @import("../common/primitive/io.zig");
const abi = @import("envelope.zig");
const vocabulary = @import("vocabulary.zig");
pub const Limits = @import("../common/primitive/limits.zig").Limits;

pub const Workspace = io.Workspace;
pub const WorkspacePlan = io.WorkspacePlan;
pub const checkedConstBytes = io.checkedConstBytes;
pub const checkedMutBytes = io.checkedMutBytes;
pub const Exception = vocabulary.Exception;
pub const capability_bit_read = vocabulary.resource_capability_bit_read;
pub const capability_bit_replay = vocabulary.resource_capability_bit_replay;
pub const capability_bit_size = vocabulary.resource_capability_bit_size;
pub const capability_bit_write = vocabulary.resource_capability_bit_write;

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

    fn fromNode(call: *abi.Call, node: *abi.Node, capabilities: u32, comptime reading: bool) Exception!Resource {
        if (node.flags & abi.node_flag_callback_resource == 0) {
            return direct(if (reading)
                .{ .direct_read = try checkedConstBytes(node.bytes, node.byte_length) }
            else
                .{ .direct_write = try checkedMutBytes(node.bytes, node.byte_capacity) }, capabilities);
        }
        return .{
            .call = call,
            .token_low = node.value_low,
            .token_high = node.value_high,
            .capabilities = capabilities,
            .kind = if (reading) .callback_read else .callback_write,
        };
    }

    pub fn sourceFromNode(call: *abi.Call, node: *abi.Node, capabilities: u32) Exception!Resource {
        return fromNode(call, node, capabilities, true);
    }

    pub fn sinkFromNode(call: *abi.Call, node: *abi.Node, capabilities: u32) Exception!Resource {
        return fromNode(call, node, capabilities, false);
    }

    pub fn hasCapability(self: Resource, bit: u32) bool {
        return self.capabilities & bit != 0;
    }

    pub fn requireCapability(self: Resource, bit: u32) Exception!void {
        if (!self.hasCapability(bit)) return error.UnsupportedException;
    }

    pub fn size(self: *Resource) Exception!usize {
        switch (self.kind) {
            .direct_read => |bytes| return bytes.len,
            .callback_read => {
                const result = try self.invoke(vocabulary.ids.callback_size, null, null);
                if (result.value_high != 0) return error.ResourceException;
                return std.math.cast(usize, result.value_low) orelse error.ResourceException;
            },
            else => return error.UnsupportedException,
        }
    }

    pub fn rewind(self: *Resource) Exception!void {
        switch (self.kind) {
            .direct_read, .direct_write => self.offset = 0,
            .callback_read => _ = try self.invoke(vocabulary.ids.callback_rewind, null, null),
            .callback_write => {},
        }
    }

    pub fn read(self: *Resource, staging: []u8) Exception!usize {
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
                const bytes_read = std.math.cast(usize, result.bytes) orelse return error.IoException;
                if (bytes_read > staging.len) return error.IoException;
                return bytes_read;
            },
            else => return error.UnsupportedException,
        }
    }

    pub fn write(self: *Resource, chunk: []const u8) Exception!usize {
        if (chunk.len == 0) return 0;
        switch (self.kind) {
            .direct_write => |destination| {
                if (self.offset + chunk.len > destination.len) return error.CapacityException;
                @memcpy(destination[self.offset..][0..chunk.len], chunk);
                self.offset += chunk.len;
                return chunk.len;
            },
            .callback_write => {
                const initial = self.committed;
                const result = try self.invoke(vocabulary.ids.callback_write, chunk, null);
                const bytes_written = std.math.cast(usize, result.bytes) orelse return error.IoException;
                if (bytes_written > chunk.len) return error.IoException;
                self.committed = std.math.add(u64, initial, bytes_written) catch return error.ResourceException;
                return bytes_written;
            },
            else => return error.UnsupportedException,
        }
    }

    pub fn writeAll(self: *Resource, chunk: []const u8) Exception!void {
        var cursor: usize = 0;
        while (cursor < chunk.len) {
            const bytes_written = try self.write(chunk[cursor..]);
            if (bytes_written == 0) return error.IoException;
            cursor += bytes_written;
        }
    }

    pub fn materialize(self: *Resource, staging: []u8) Exception![]const u8 {
        var cursor: usize = 0;
        while (cursor < staging.len) {
            const bytes_read = try self.read(staging[cursor..]);
            if (bytes_read == 0) break;
            cursor += bytes_read;
        }
        if (cursor == staging.len) {
            var extra: [1]u8 = undefined;
            const tail_read = try self.read(&extra);
            if (tail_read != 0) return error.ResourceException;
        }
        return staging[0..cursor];
    }

    fn invoke(self: *Resource, verb: abi.Id, request_bytes: ?[]const u8, response_bytes: ?[]u8) Exception!CallbackResult {
        const callback = self.call.callback orelse return error.CallException;
        var request = abi.Node.init();
        request.value_low = self.token_low;
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
            return error.IoException;
        }
        if (response_bytes != null and response.byte_length > response.byte_capacity) return error.IoException;
        return .{ .bytes = response.byte_length, .value_low = response.value_low, .value_high = response.value_high };
    }
};

pub const BoundedReader = struct {
    resource: *Resource,
    limit: u64,
    reader: std.Io.Reader,
    // The reader's own fill buffer; the stream vtable stages separately,
    // since stdlib hands it a writer over this memory.
    staging: [4096]u8,

    pub fn init(self: *BoundedReader, resource: *Resource, limit: u64) void {
        self.* = .{
            .resource = resource,
            .limit = limit,
            .reader = undefined,
            .staging = undefined,
        };
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
    // std.Io.Reader aligns below u64 fields on wasm32 and arm32.
    const self: *BoundedReader = @alignCast(@fieldParentPtr("reader", reader));
    if (self.limit == 0) return error.EndOfStream;
    const requested = @min(@backingInt(limit), std.math.cast(usize, self.limit) orelse std.math.maxInt(usize));
    if (requested == 0) return 0;
    var staged: [4096]u8 = undefined;
    const chunk = staged[0..@min(staged.len, requested)];
    const bytes_read = self.resource.read(chunk) catch return error.ReadFailed;
    if (bytes_read == 0) return error.EndOfStream;
    const written = writer.write(chunk[0..bytes_read]) catch return error.WriteFailed;
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
    // std.Io.Writer aligns below u64 fields on wasm32 and arm32.
    const self: *BoundedWriter = @alignCast(@fieldParentPtr("writer", writer));
    if (chunks.len == 0) return 0;
    var total: usize = 0;
    for (chunks[0 .. chunks.len - 1]) |part| {
        total = std.math.add(usize, total, part.len) catch return error.WriteFailed;
    }
    const splatted = std.math.mul(usize, chunks[chunks.len - 1].len, splat) catch return error.WriteFailed;
    total = std.math.add(usize, total, splatted) catch return error.WriteFailed;
    if (total == 0) return 0;
    if (total > self.limit) return error.WriteFailed;
    var cursor: usize = 0;
    // The budget is charged on every path, so a short write spends only
    // what it wrote.
    defer self.limit -= cursor;
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
    return cursor;
}

const CallbackResult = struct { bytes: u64, value_low: u64, value_high: u64 };

// One test-only struct backs every callback kind, so the resource tests can steer size, read, write, and rewind responses.
const CallbackHarness = struct {
    data: []const u8,
    cursor: usize = 0,
    sink: [256]u8 = undefined,
    sink_len: usize = 0,
    response_status: u32 = 0,
    over_report: bool = false,
    short_write: usize = std.math.maxInt(usize),
    seen_token_low: u64 = 0,
    seen_token_high: u64 = 0,
};

fn harnessCallback(callback_call: *abi.Call) callconv(.c) u32 {
    const harness: *CallbackHarness = @ptrCast(@alignCast(callback_call.callback_context orelse return abi.Status.internal_failure));
    const request = callback_call.request orelse return abi.Status.invalid_call;
    const response = callback_call.response orelse return abi.Status.invalid_call;
    harness.seen_token_low = request.value_low;
    harness.seen_token_high = request.value_high;
    if (harness.response_status != 0) return harness.response_status;
    if (vocabulary.eql(callback_call.operation, vocabulary.ids.callback_size)) {
        response.value_low = harness.data.len;
        return abi.Status.ok;
    }
    if (vocabulary.eql(callback_call.operation, vocabulary.ids.callback_read)) {
        const capacity: usize = @intCast(response.byte_capacity);
        if (harness.over_report) {
            response.byte_length = capacity + 1;
            return abi.Status.ok;
        }
        const remaining = harness.data.len - harness.cursor;
        const count = @min(capacity, remaining);
        const destination = response.bytes orelse return abi.Status.invalid_call;
        @memcpy(destination[0..count], harness.data[harness.cursor..][0..count]);
        response.byte_length = count;
        harness.cursor += count;
        return abi.Status.ok;
    }
    if (vocabulary.eql(callback_call.operation, vocabulary.ids.callback_write)) {
        const length: usize = @intCast(request.byte_length);
        const take = if (harness.short_write == std.math.maxInt(usize)) length else @min(harness.short_write, length);
        if (take != 0) {
            const source_bytes = request.bytes orelse return abi.Status.invalid_call;
            @memcpy(harness.sink[harness.sink_len..][0..take], source_bytes[0..take]);
            harness.sink_len += take;
        }
        response.byte_length = if (harness.over_report) length + 1 else take;
        return abi.Status.ok;
    }
    if (vocabulary.eql(callback_call.operation, vocabulary.ids.callback_rewind)) {
        harness.cursor = 0;
        return abi.Status.ok;
    }
    return abi.Status.unsupported;
}

test "resource direct read serves chunks rewinds and signals end" {
    var storage = [_]u8{ 10, 11, 12, 13, 14, 15, 16, 17, 18 };
    var call = abi.Call.init();
    var node = abi.Node.init();
    node.bytes = &storage;
    node.byte_capacity = storage.len;
    node.byte_length = storage.len;
    var source = try Resource.sourceFromNode(&call, &node, capability_bit_read);
    try std.testing.expectEqual(@as(usize, 9), try source.size());
    var staging: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try source.read(&staging));
    try std.testing.expectEqualSlices(u8, &.{ 10, 11, 12, 13 }, &staging);
    try std.testing.expectEqual(@as(usize, 4), try source.read(&staging));
    try std.testing.expectEqualSlices(u8, &.{ 14, 15, 16, 17 }, &staging);
    // a shorter remainder delivers only what is left
    try std.testing.expectEqual(@as(usize, 1), try source.read(&staging));
    try std.testing.expectEqual(@as(u8, 18), staging[0]);
    // end of source reports zero without error
    try std.testing.expectEqual(@as(usize, 0), try source.read(&staging));
    // an empty staging window returns zero without consulting the source
    try std.testing.expectEqual(@as(usize, 0), try source.read(&.{}));
    // rewind restarts the byte window
    try source.rewind();
    var whole: [9]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 9), try source.read(&whole));
    try std.testing.expectEqualSlices(u8, &storage, &whole);
}

test "resource direct write rejects overflow and withholds size" {
    var destination: [8]u8 = @splat(0);
    var call = abi.Call.init();
    var node = abi.Node.init();
    node.bytes = &destination;
    node.byte_capacity = destination.len;
    var sink = try Resource.sinkFromNode(&call, &node, capability_bit_write);
    try std.testing.expectEqual(@as(usize, 5), try sink.write("hello"));
    try std.testing.expectEqualSlices(u8, "hello", destination[0..5]);
    // the rejected write leaves the untouched tail alone
    try std.testing.expectError(error.CapacityException, sink.write("world"));
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0 }, destination[5..8]);
    // a direct write never reports a size
    try std.testing.expectError(error.UnsupportedException, sink.size());
    // rewind restarts the destination window
    try sink.rewind();
    try std.testing.expectEqual(@as(usize, 8), try sink.write("ABCDEFGH"));
    try std.testing.expectEqualSlices(u8, "ABCDEFGH", destination[0..8]);
    // an empty chunk is a no-op even at a full window
    try std.testing.expectEqual(@as(usize, 0), try sink.write(&.{}));
    // a zero capacity node yields an empty destination
    var empty_node = abi.Node.init();
    var empty_sink = try Resource.sinkFromNode(&call, &empty_node, capability_bit_write);
    try std.testing.expectError(error.CapacityException, empty_sink.write(&.{1}));
}

test "resource capability bits gate has require and construct paths" {
    var storage = [_]u8{ 1, 2, 3 };
    var call = abi.Call.init();
    var node = abi.Node.init();
    node.bytes = &storage;
    node.byte_capacity = storage.len;
    node.byte_length = storage.len;
    var source = try Resource.sourceFromNode(&call, &node, capability_bit_read | capability_bit_size);
    try std.testing.expect(source.hasCapability(capability_bit_read));
    try std.testing.expect(source.hasCapability(capability_bit_size));
    try std.testing.expect(!source.hasCapability(capability_bit_write));
    try source.requireCapability(capability_bit_read);
    try std.testing.expectError(error.UnsupportedException, source.requireCapability(capability_bit_write));
    // a resource with no capability bits rejects every requirement
    var bare = Resource{
        .call = undefined,
        .token_low = 0,
        .token_high = 0,
        .capabilities = 0,
        .kind = .{ .direct_read = &.{} },
    };
    try std.testing.expect(!bare.hasCapability(capability_bit_read));
    try std.testing.expectError(error.UnsupportedException, bare.requireCapability(capability_bit_read));
}

test "resource callback read serves size read and rewind through the callback" {
    var harness = CallbackHarness{ .data = "abcdefghijkl" };
    var call = abi.Call.init();
    call.callback = harnessCallback;
    call.callback_context = @ptrCast(&harness);
    var node = abi.Node.init();
    node.flags = abi.node_flag_callback_resource;
    node.value_low = 0x1111_2222_3333_4444;
    node.value_high = 0x5555_6666_7777_8888;
    var source = try Resource.sourceFromNode(&call, &node, capability_bit_read);
    // the callback token travels with the resource
    switch (source.kind) {
        .callback_read => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 0x1111_2222_3333_4444), source.token_low);
    try std.testing.expectEqual(@as(u64, 0x5555_6666_7777_8888), source.token_high);
    try std.testing.expectEqual(@as(usize, 12), try source.size());
    // the callback observed the caller token
    try std.testing.expectEqual(@as(u64, 0x1111_2222_3333_4444), harness.seen_token_low);
    try std.testing.expectEqual(@as(u64, 0x5555_6666_7777_8888), harness.seen_token_high);
    var staging: [5]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try source.read(&staging));
    try std.testing.expectEqualSlices(u8, "abcde", &staging);
    try std.testing.expectEqual(@as(usize, 5), try source.read(&staging));
    try std.testing.expectEqualSlices(u8, "fghij", &staging);
    // a short remainder delivers only the tail
    try std.testing.expectEqual(@as(usize, 2), try source.read(&staging));
    try std.testing.expectEqualSlices(u8, "kl", staging[0..2]);
    // end of the callback stream reports zero
    try std.testing.expectEqual(@as(usize, 0), try source.read(&staging));
    // rewind restarts the callback cursor
    try source.rewind();
    try std.testing.expectEqual(@as(usize, 5), try source.read(&staging));
    try std.testing.expectEqualSlices(u8, "abcde", &staging);
}

test "resource callback read records downstream status and rejects over-report" {
    var staging: [4]u8 = undefined;
    // a missing callback turns the invoke path into a call failure
    var bare_call = abi.Call.init();
    var bare_node = abi.Node.init();
    bare_node.flags = abi.node_flag_callback_resource;
    var bare_source = try Resource.sourceFromNode(&bare_call, &bare_node, capability_bit_read);
    try std.testing.expectError(error.CallException, bare_source.size());
    try std.testing.expectError(error.CallException, bare_source.read(&staging));

    // a non-ok downstream status lands in downstream_status as io failure
    var failing = CallbackHarness{ .data = "abcd", .response_status = abi.Status.io_failure };
    var failing_call = abi.Call.init();
    failing_call.callback = harnessCallback;
    failing_call.callback_context = @ptrCast(&failing);
    var failing_node = abi.Node.init();
    failing_node.flags = abi.node_flag_callback_resource;
    var failing_source = try Resource.sourceFromNode(&failing_call, &failing_node, capability_bit_read);
    try std.testing.expectEqual(@as(u32, 0), failing_source.downstream_status);
    try std.testing.expectError(error.IoException, failing_source.read(&staging));
    try std.testing.expectEqual(@as(u32, 6), failing_source.downstream_status);

    // reporting more bytes than the staging capacity is an io failure
    var liar = CallbackHarness{ .data = "abcd", .over_report = true };
    var liar_call = abi.Call.init();
    liar_call.callback = harnessCallback;
    liar_call.callback_context = @ptrCast(&liar);
    var liar_node = abi.Node.init();
    liar_node.flags = abi.node_flag_callback_resource;
    var liar_source = try Resource.sourceFromNode(&liar_call, &liar_node, capability_bit_read);
    try std.testing.expectError(error.IoException, liar_source.read(&staging));
}

test "resource callback write accumulates committed totals through short writes" {
    var harness = CallbackHarness{ .data = "" };
    var call = abi.Call.init();
    call.callback = harnessCallback;
    call.callback_context = @ptrCast(&harness);
    var node = abi.Node.init();
    node.flags = abi.node_flag_callback_resource;
    var sink = try Resource.sinkFromNode(&call, &node, capability_bit_write);
    switch (sink.kind) {
        .callback_write => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 5), try sink.write("hello"));
    try std.testing.expectEqual(@as(u64, 5), sink.committed);
    try std.testing.expectEqual(@as(usize, 5), try sink.write("world"));
    try std.testing.expectEqual(@as(u64, 10), sink.committed);
    try std.testing.expectEqualSlices(u8, "helloworld", harness.sink[0..harness.sink_len]);
    // rewinding a callback write keeps the commitment
    try sink.rewind();
    try std.testing.expectEqual(@as(u64, 10), sink.committed);

    // a short writer still counts exactly what it took
    var shorty = CallbackHarness{ .data = "", .short_write = 2 };
    var shorty_call = abi.Call.init();
    shorty_call.callback = harnessCallback;
    shorty_call.callback_context = @ptrCast(&shorty);
    var shorty_node = abi.Node.init();
    shorty_node.flags = abi.node_flag_callback_resource;
    var shorty_sink = try Resource.sinkFromNode(&shorty_call, &shorty_node, capability_bit_write);
    try std.testing.expectEqual(@as(usize, 2), try shorty_sink.write("abcde"));
    try shorty_sink.writeAll("fghij");
    try std.testing.expectEqual(@as(u64, 7), shorty_sink.committed);
    try std.testing.expectEqualSlices(u8, "abfghij", shorty.sink[0..shorty.sink_len]);

    // over-reporting written bytes is an io failure that keeps the total
    var liar = CallbackHarness{ .data = "", .over_report = true };
    var liar_call = abi.Call.init();
    liar_call.callback = harnessCallback;
    liar_call.callback_context = @ptrCast(&liar);
    var liar_node = abi.Node.init();
    liar_node.flags = abi.node_flag_callback_resource;
    var liar_sink = try Resource.sinkFromNode(&liar_call, &liar_node, capability_bit_write);
    try std.testing.expectError(error.IoException, liar_sink.write("abcd"));
    try std.testing.expectEqual(@as(u64, 0), liar_sink.committed);

    // a committed counter at the ceiling fails the next write
    var full = CallbackHarness{ .data = "" };
    var full_call = abi.Call.init();
    full_call.callback = harnessCallback;
    full_call.callback_context = @ptrCast(&full);
    var full_node = abi.Node.init();
    full_node.flags = abi.node_flag_callback_resource;
    var full_sink = try Resource.sinkFromNode(&full_call, &full_node, capability_bit_write);
    full_sink.committed = std.math.maxInt(u64);
    try std.testing.expectError(error.ResourceException, full_sink.write("xyz"));
}

test "resource materialize returns exact short and overflow slices" {
    var storage = [_]u8{ 5, 4, 3, 2, 1, 0, 9, 8, 7 };
    var call = abi.Call.init();
    var node = abi.Node.init();
    node.bytes = &storage;
    node.byte_capacity = storage.len;
    node.byte_length = storage.len;

    // an exact staging area consumes the whole source
    var exact_source = try Resource.sourceFromNode(&call, &node, capability_bit_read);
    var exact: [9]u8 = undefined;
    const exact_slice = try exact_source.materialize(&exact);
    try std.testing.expectEqual(@as(usize, 9), exact_slice.len);
    try std.testing.expectEqualSlices(u8, &storage, exact_slice);

    // a roomier staging area stops at the end of the source
    var short_source = try Resource.sourceFromNode(&call, &node, capability_bit_read);
    var roomy: [12]u8 = undefined;
    const short_slice = try short_source.materialize(&roomy);
    try std.testing.expectEqual(@as(usize, 9), short_slice.len);
    try std.testing.expectEqualSlices(u8, &storage, short_slice);

    // a staging area smaller than the source trips the tail probe
    var tight_source = try Resource.sourceFromNode(&call, &node, capability_bit_read);
    var tight: [4]u8 = undefined;
    try std.testing.expectError(error.ResourceException, tight_source.materialize(&tight));

    // a declared empty source materializes to an empty slice
    var one = [_]u8{77};
    var empty_node = abi.Node.init();
    empty_node.bytes = &one;
    empty_node.byte_length = 0;
    var empty_source = try Resource.sourceFromNode(&call, &empty_node, capability_bit_read);
    var any: [3]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try empty_source.materialize(&any)).len);
}

test "resource bounded reader and writer enforce declared limits" {
    var storage: [100]u8 = undefined;
    for (&storage, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var call = abi.Call.init();
    var node = abi.Node.init();
    node.bytes = &storage;
    node.byte_capacity = storage.len;
    node.byte_length = storage.len;
    var source = try Resource.sourceFromNode(&call, &node, capability_bit_read);

    // the bounded reader serves at most the declared limit
    var bounded: BoundedReader = undefined;
    bounded.init(&source, 10);
    var out: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try bounded.reader.readSliceShort(&out));
    try std.testing.expectEqualSlices(u8, storage[0..4], &out);
    try std.testing.expectEqual(@as(usize, 4), try bounded.reader.readSliceShort(&out));
    try std.testing.expectEqualSlices(u8, storage[4..8], &out);
    // the last two bytes of the limit arrive as a short read
    try std.testing.expectEqual(@as(usize, 2), try bounded.reader.readSliceShort(&out));
    try std.testing.expectEqualSlices(u8, storage[8..10], out[0..2]);
    // past the limit the reader reports end of stream
    try std.testing.expectEqual(@as(usize, 0), try bounded.reader.readSliceShort(&out));

    // the bounded writer charges every byte against its budget
    var destination: [16]u8 = undefined;
    @memset(&destination, 0xAA);
    var sink_node = abi.Node.init();
    sink_node.bytes = &destination;
    sink_node.byte_capacity = destination.len;
    var sink = try Resource.sinkFromNode(&call, &sink_node, capability_bit_write);
    var bounded_sink = BoundedWriter.init(&sink, 8);
    try bounded_sink.writer.writeAll("12345");
    try bounded_sink.writer.writeAll("678");
    try std.testing.expectEqualSlices(u8, "12345678", destination[0..8]);
    // the ninth byte exceeds the budget and fails without writing
    try std.testing.expectError(error.WriteFailed, bounded_sink.writer.writeAll("9"));
    try std.testing.expectEqual(@as(u8, 0xAA), destination[8]);
}
