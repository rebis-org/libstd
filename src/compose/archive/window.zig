const std = @import("std");

const abi = @import("../../kernel/envelope.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");

const testing = std.testing;
const Exception = resource.Exception;
const Resource = resource.Resource;

// A fixed forward window over a streaming source: every byte enters the
// buffer once, so a huge archive costs the window, not its length.
// A slice a hold returns is valid only until the next hold or skip.
pub const View = struct {
    source: *Resource,
    buffer: []u8,
    limit: u64,
    total: ?u64,
    pulled: u64 = 0,
    filled: usize = 0,
    skipped: usize = 0,

    pub fn init(source: *Resource, buffer: []u8, declared: ?usize, limit: u64) Exception!View {
        // A per-ordinal verb walks from the TOC again, so the stream must
        // replay: the same requirement a materialized read states.
        try source.requireCapability(resource.capability_bit_replay);
        return .{
            .source = source,
            .buffer = buffer,
            .limit = limit,
            .total = if (declared) |size| size else null,
        };
    }

    // The next verb restarts from the TOC: the stream rewinds and the
    // window forgets what it pulled.
    pub fn restart(self: *View) Exception!void {
        try self.source.rewind();
        self.pulled = 0;
        self.filled = 0;
        self.skipped = 0;
    }

    // The declared archive length, when the source states one. The encoded
    // budget bills it up front: a whole archive over limit is a resource
    // answer, the same one the materialized read gives.
    pub fn declaredSize(source: *Resource, limit: u64) Exception!?usize {
        if (!source.hasCapability(resource.capability_bit_size)) return null;
        const size = try source.size();
        if (size > limit) return error.ResourceException;
        return std.math.cast(usize, size) orelse error.ResourceException;
    }

    pub fn declaredTotal(self: View) ?u64 {
        return self.total;
    }

    // Stream offset of the next byte a hold returns.
    pub fn position(self: View) u64 {
        return self.pulled - self.filled + self.skipped;
    }

    pub fn hold(self: *View, length: u64) Exception![]const u8 {
        return self.fill(length, false);
    }

    // A staging pull that tolerates the archive ending early: a whole
    // archive shorter than the staging request is the normal small case.
    pub fn holdUpTo(self: *View, length: u64) Exception![]const u8 {
        return self.fill(length, true);
    }

    pub fn skip(self: *View, count: u64) Exception!void {
        const held: u64 = self.filled - self.skipped;
        if (count <= held) {
            self.skipped += @intCast(count);
            return;
        }
        // Skipped bytes drop in bulk at the next refill, never byte-wise.
        self.filled = 0;
        self.skipped = 0;
        var remaining = count - held;
        while (remaining > 0) {
            const bytes_read = try self.drain(@min(remaining, self.buffer.len));
            if (bytes_read == 0) return error.DataException;
            remaining -= bytes_read;
        }
    }

    fn fill(self: *View, length: u64, tolerate_end: bool) Exception![]const u8 {
        const want = std.math.cast(usize, length) orelse return error.ResourceException;
        if (want > self.buffer.len) return error.ResourceException;
        if (self.filled - self.skipped < want) {
            if (self.skipped != 0) {
                std.mem.copyForwards(u8, self.buffer[0..], self.buffer[self.skipped..self.filled]);
                self.filled -= self.skipped;
                self.skipped = 0;
            }
            while (self.filled < want) {
                const bytes_read = try self.pull(want - self.filled);
                if (bytes_read == 0) {
                    // A source that stops early is a truncated archive.
                    if (!tolerate_end) return error.DataException;
                    break;
                }
            }
        }
        const available = self.filled - self.skipped;
        return self.buffer[self.skipped..][0..@min(available, want)];
    }

    fn pull(self: *View, want: usize) Exception!usize {
        const step = @min(want, self.buffer.len - self.filled);
        if (step == 0) return 0;
        const bytes_read = try self.source.read(self.buffer[self.filled..][0..step]);
        self.filled += bytes_read;
        self.pulled += bytes_read;
        if (self.pulled > self.limit) return error.ResourceException;
        return bytes_read;
    }

    fn drain(self: *View, want: usize) Exception!usize {
        const step = @min(want, self.buffer.len);
        const bytes_read = try self.source.read(self.buffer[0..step]);
        self.pulled += bytes_read;
        if (self.pulled > self.limit) return error.ResourceException;
        return bytes_read;
    }
};

test "window holds skips and refills across short deliveries" {
    var storage: [5000]u8 = undefined;
    for (&storage, 0..) |*byte, index| byte.* = @truncate(index * 7 + 3);
    const source = try callbackSource(&storage, capability_read_size);
    defer testing.allocator.destroy(source);

    var buffer: [1024]u8 = undefined;
    var view = try View.init(source.resource(), &buffer, storage.len, std.math.maxInt(u64));

    // An offset hold reads through several short callback deliveries.
    const head = try view.hold(300);
    try testing.expectEqualSlices(u8, storage[0..300], head);
    try testing.expectEqual(@as(u64, 0), view.position());

    // A skip inside the held bytes moves the front without a pull.
    try view.skip(100);
    try testing.expectEqual(@as(u64, 100), view.position());
    const middle = try view.hold(200);
    try testing.expectEqualSlices(u8, storage[100..300], middle);
    try testing.expectEqual(@as(u64, 100), view.position());

    // A skip past the held bytes drains through the window.
    try view.skip(4600);
    try testing.expectEqual(@as(u64, 4700), view.position());
    const tail = try view.hold(300);
    try testing.expectEqualSlices(u8, storage[4700..5000], tail);
}

test "window reports a short staging pull at the end of the source" {
    var storage: [100]u8 = undefined;
    for (&storage, 0..) |*byte, index| byte.* = @truncate(index);
    const source = try callbackSource(&storage, capability_read_size);
    defer testing.allocator.destroy(source);

    var buffer: [128]u8 = undefined;
    var view = try View.init(source.resource(), &buffer, null, std.math.maxInt(u64));

    // An exact hold past the end is a truncated archive.
    try testing.expectError(error.DataException, view.hold(101));
    // The tolerant staging pull returns what the archive still holds.
    const staging = try view.holdUpTo(101);
    try testing.expectEqual(@as(usize, 100), staging.len);
    try testing.expectEqualSlices(u8, &storage, staging);
    // A hold past a drained source stays a data answer.
    try view.skip(100);
    try testing.expectError(error.DataException, view.hold(1));

    // The next verb restarts: the rewind resets every counter.
    try view.restart();
    try testing.expectEqual(@as(u64, 0), view.position());
    try testing.expectEqualSlices(u8, storage[0..50], try view.hold(50));
}

test "window rejects a hold wider than the buffer and an over-budget pull" {
    var storage: [64]u8 = undefined;
    @memset(&storage, 0xAB);
    const source = try callbackSource(&storage, capability_read_size);
    defer testing.allocator.destroy(source);

    var buffer: [32]u8 = undefined;
    // A declared archive larger than the window is the normal big case.
    var view = try View.init(source.resource(), &buffer, storage.len, std.math.maxInt(u64));
    try testing.expectError(error.ResourceException, view.hold(buffer.len + 1));

    // An undeclared source pays the encoded budget byte by byte.
    const uncounted = try callbackSource(&storage, capability_read);
    defer testing.allocator.destroy(uncounted);
    var open_view = try View.init(uncounted.resource(), &buffer, null, 50);
    try testing.expectEqualSlices(u8, storage[0..32], try open_view.hold(32));
    try open_view.skip(30);
    // The refill past the 50-byte budget is a resource answer.
    try testing.expectError(error.ResourceException, open_view.hold(30));
}

test "window charges a declared archive over the encoded budget up front" {
    var storage: [64]u8 = undefined;
    @memset(&storage, 0xCD);
    const source = try callbackSource(&storage, capability_read_size);
    defer testing.allocator.destroy(source);

    try testing.expectError(error.ResourceException, View.declaredSize(source.resource(), 63));
    try testing.expectEqual(@as(?usize, 64), try View.declaredSize(source.resource(), 64));
    try testing.expectEqual(@as(?usize, 64), try View.declaredSize(source.resource(), std.math.maxInt(u64)));

    // A source that states no size declares nothing, whatever the budget.
    const uncounted = try callbackSource(&storage, capability_read);
    defer testing.allocator.destroy(uncounted);
    try testing.expectEqual(@as(?usize, null), try View.declaredSize(uncounted.resource(), std.math.maxInt(u64)));
}

// Every window source replays: the per-ordinal verbs restart the walk.
const capability_read: u32 = resource.capability_bit_read | resource.capability_bit_replay;
const capability_read_size: u32 = capability_read | resource.capability_bit_size;

// A callback source that answers size and delivers at most four bytes per
// read, so every refill crosses several short deliveries.
const FixedSource = struct {
    call: abi.Call,
    node: abi.Node,
    resource_value: Resource,
    bytes: []const u8,
    cursor: usize = 0,

    fn resource(self: *FixedSource) *Resource {
        return &self.resource_value;
    }
};

fn fixedCallback(envelope: *abi.Call) callconv(.c) u32 {
    const source: *FixedSource = @ptrCast(@alignCast(envelope.callback_context orelse return abi.Status.internal_failure));
    const response = envelope.response orelse return abi.Status.invalid_call;
    if (vocabulary.eql(envelope.operation, vocabulary.ids.callback_size)) {
        response.value_low = source.bytes.len;
        return abi.Status.ok;
    }
    if (vocabulary.eql(envelope.operation, vocabulary.ids.callback_read)) {
        const capacity: usize = @intCast(response.byte_capacity);
        const count = @min(capacity, 4, source.bytes.len - source.cursor);
        const destination = response.bytes orelse return abi.Status.invalid_call;
        @memcpy(destination[0..count], source.bytes[source.cursor..][0..count]);
        source.cursor += count;
        response.byte_length = count;
        return abi.Status.ok;
    }
    if (vocabulary.eql(envelope.operation, vocabulary.ids.callback_rewind)) {
        source.cursor = 0;
        return abi.Status.ok;
    }
    return abi.Status.unsupported;
}

fn callbackSource(bytes: []const u8, capabilities: u32) !*FixedSource {
    const source = try testing.allocator.create(FixedSource);
    source.* = .{
        .call = abi.Call.init(),
        .node = abi.Node.init(),
        .resource_value = undefined,
        .bytes = bytes,
    };
    source.call.callback = fixedCallback;
    source.call.callback_context = @ptrCast(source);
    source.node.flags = abi.node_flag_callback_resource;
    source.resource_value = try Resource.sourceFromNode(&source.call, &source.node, capabilities);
    return source;
}
