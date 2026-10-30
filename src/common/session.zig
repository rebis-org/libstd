const std = @import("std");

const exception_prim = @import("primitive/exception.zig");

const testing = std.testing;
const Exception = exception_prim.Exception;

// Existence is the capability;
// the enum only picks a strategy for layers that know it exists.

pub const SeekCost = enum {
    none,
    constant,
    linear,
};

pub const SliceSource = struct {
    bytes: []const u8,
    pos: usize,

    pub const seek_cost: SeekCost = .constant;

    pub fn init(bytes: []const u8) SliceSource {
        return .{ .bytes = bytes, .pos = 0 };
    }

    pub fn take(self: *SliceSource, buf: []u8) Exception!usize {
        const n = @min(self.bytes.len - self.pos, buf.len);
        @memcpy(buf[0..n], self.bytes[self.pos..][0..n]);
        self.pos += n;
        return n;
    }

    pub fn discard(self: *SliceSource, n: u64) Exception!void {
        // A count beyond any address span is a data error, not capacity.
        const count = std.math.cast(usize, n) orelse return error.DataException;
        if (count > self.bytes.len - self.pos) return error.DataException;
        self.pos += count;
    }

    // Slicing returns a new value: the parent keeps its position.
    pub fn slice(self: SliceSource, offset: u64, length: u64) Exception!SliceSource {
        const off = std.math.cast(usize, offset) orelse return error.DataException;
        const len = std.math.cast(usize, length) orelse return error.DataException;
        // Reject at creation: an out-of-range window must never exist.
        if (off > self.bytes.len or len > self.bytes.len - off) return error.DataException;
        return .{ .bytes = self.bytes[off..][0..len], .pos = 0 };
    }

    pub fn seekTo(self: *SliceSource, offset: u64) Exception!void {
        const off = std.math.cast(usize, offset) orelse return error.DataException;
        if (off > self.bytes.len) return error.DataException;
        self.pos = off;
    }
};

pub const ReaderSource = struct {
    reader: *std.Io.Reader,
    declared_len: u64,
    consumed: u64,
    epoch: u64,

    pub const seek_cost: SeekCost = .none;

    pub fn init(reader: *std.Io.Reader, declared_len: u64) ReaderSource {
        return .{ .reader = reader, .declared_len = declared_len, .consumed = 0, .epoch = 0 };
    }

    pub fn take(self: *ReaderSource, buf: []u8) Exception!usize {
        const budget = self.declared_len - self.consumed;
        if (budget == 0) return 0;
        const want: usize = if (budget >= buf.len) buf.len else @intCast(budget);
        const got = self.reader.readSliceShort(buf[0..want]) catch |err| switch (err) {
            error.ReadFailed => return error.IoException,
        };
        // Short delivery with budget left is truncation, not end of source.
        if (got < want) return error.DataException;
        self.consumed += got;
        // A source-level pull moves the shared position,
        // so it revokes windows like slicing.
        if (got != 0) self.epoch += 1;
        return got;
    }

    pub fn discard(self: *ReaderSource, n: u64) Exception!void {
        if (n > self.declared_len - self.consumed) return error.DataException;
        try self.discardExact(n);
    }

    // Positioning is forward-only: discard is the only way to move.
    pub fn slice(self: *ReaderSource, offset: u64, length: u64) Exception!Window {
        if (offset < self.consumed) return error.DataException;
        if (offset > self.declared_len or length > self.declared_len - offset) return error.DataException;
        const len = std.math.cast(usize, length) orelse return error.DataException;
        // The new window is exclusive even if the discard below fails.
        self.epoch += 1;
        try self.discardExact(offset - self.consumed);
        return Window{
            .src = self,
            .limited = self.reader.limited(.limited(len), &.{}),
            .born_epoch = self.epoch,
            .len = length,
            .pos = 0,
        };
    }

    fn discardExact(self: *ReaderSource, n: u64) Exception!void {
        var remaining = n;
        while (remaining > 0) {
            const chunk = std.math.cast(usize, remaining) orelse std.math.maxInt(usize);
            const got = self.reader.discardShort(chunk) catch |err| switch (err) {
                error.ReadFailed => return error.IoException,
            };
            // Track short progress: later forward-only checks must see the truth.
            self.consumed += got;
            if (got != 0) self.epoch += 1;
            if (got < chunk) return error.DataException;
            remaining -= got;
        }
    }
};

pub const Window = struct {
    src: *ReaderSource,
    limited: std.Io.Reader.Limited,
    born_epoch: u64,
    len: u64,
    pos: u64,

    pub const seek_cost: SeekCost = .none;

    fn check(self: *const Window) void {
        if (self.born_epoch != self.src.epoch)
            @panic("session: window used after exclusivity was superseded");
    }

    pub fn take(self: *Window, buf: []u8) Exception!usize {
        self.check();
        const budget = self.len - self.pos;
        if (budget == 0) return 0;
        const want: usize = if (budget >= buf.len) buf.len else @intCast(budget);
        // Clamping at the budget makes past-window bytes structurally unreachable.
        const got = self.limited.interface.readSliceShort(buf[0..want]) catch |err| switch (err) {
            error.ReadFailed => return error.IoException,
        };
        if (got < want) return error.DataException;
        self.pos += got;
        // Keep the source position truthful: later checks depend on it.
        self.src.consumed += got;
        return got;
    }

    pub fn discard(self: *Window, n: u64) Exception!void {
        self.check();
        if (n > self.len - self.pos) return error.DataException;
        var remaining = n;
        while (remaining > 0) {
            const chunk = std.math.cast(usize, remaining) orelse std.math.maxInt(usize);
            const got = self.limited.interface.discardShort(chunk) catch |err| switch (err) {
                error.ReadFailed => return error.IoException,
            };
            self.pos += got;
            self.src.consumed += got;
            if (got < chunk) return error.DataException;
            remaining -= got;
        }
    }

    // Sub-windows mirror the parent: relative coordinates, forward-only.
    pub fn slice(self: *Window, offset: u64, length: u64) Exception!Window {
        self.check();
        if (offset < self.pos) return error.DataException;
        if (offset > self.len or length > self.len - offset) return error.DataException;
        const len = std.math.cast(usize, length) orelse return error.DataException;
        var remaining = offset - self.pos;
        while (remaining > 0) {
            const chunk = std.math.cast(usize, remaining) orelse std.math.maxInt(usize);
            const got = self.limited.interface.discardShort(chunk) catch |err| switch (err) {
                error.ReadFailed => return error.IoException,
            };
            self.pos += got;
            self.src.consumed += got;
            if (got < chunk) return error.DataException;
            remaining -= got;
        }
        // The sub-window becomes exclusive; the parent dies with this bump.
        self.src.epoch += 1;
        return Window{
            .src = self.src,
            .limited = self.src.reader.limited(.limited(len), &.{}),
            .born_epoch = self.src.epoch,
            .len = length,
            .pos = 0,
        };
    }
};

// The cursor contract is structural:
// conformance is member existence, never an interface type.
//
// The name lives in caller scratch and ends at the next next();
// reader-owned storage cannot be trusted across pulls.
pub const Info = struct {
    name: []const u8,
    data_size: u64,
};

// The name is data, fit against the buffer is capacity;
// zero and exact-fit are legal, overflow is CapacityException.
pub const NameScratch = struct {
    buffer: []u8,

    pub fn init(buffer: []u8) NameScratch {
        return .{ .buffer = buffer };
    }

    pub fn take(self: *NameScratch, source: anytype, len: usize) Exception![]const u8 {
        if (len > self.buffer.len) return error.CapacityException;
        const got = try source.take(self.buffer[0..len]);
        if (got < len) return error.DataException;
        return self.buffer[0..got];
    }
};

// Outer, Transform, Inner are one-way roles:
// Outer locates, Transform changes bytes, Inner produces the cursor.
//
// MemberRange offsets are base-source coordinates;
// encoding is Outer vocabulary the protocol never interprets.
pub fn MemberRange(comptime Encoding: type) type {
    return struct {
        offset: u64,
        length: u64,
        encoding: Encoding,
    };
}

// The whole chain resolves at comptime:
// one monomorphized type, no runtime dispatch anywhere.
//
// The transform instance lives in the caller's scratch,
// so the scratch must outlive the returned cursor.
pub fn Nested(comptime Outer: type, comptime Transform: anytype, comptime Inner: anytype) type {
    return struct {
        // Witnesses and adapters need the derived types as first-class names;
        // re-deriving would drift.
        const MemberReturn = @typeInfo(@TypeOf(Outer.member)).@"fn".return_type.?;
        pub const LocatedSource = @typeInfo(MemberReturn).error_union.payload;
        pub const TransformState = Transform(LocatedSource);
        pub const TransformedSource = @typeInfo(@typeInfo(@TypeOf(TransformState.reader)).@"fn".return_type.?).pointer.child;
        pub const InnerCursor = Inner(TransformedSource);

        pub const scratch_size: usize = Outer.scratch_size + TransformState.scratch_size + InnerCursor.scratch_size;

        // The transform instance sits in scratch, so the whole scratch carries
        // its alignment; Inner's folds in through the max.
        pub const scratch_alignment: usize = @max(@alignOf(TransformState), if (@hasDecl(InnerCursor, "scratch_alignment")) InnerCursor.scratch_alignment else 1);

        pub fn scratchSize() usize {
            return scratch_size;
        }

        pub fn open(base: anytype, name: []const u8, scratch: []align(scratch_alignment) u8) Exception!InnerCursor {
            // A short buffer is a capacity failure, never a data error.
            if (scratch.len < scratch_size) return error.CapacityException;
            // Segment boundaries are comptime; runtime cost is three pointer adjustments.
            const outer_scratch = scratch[0..Outer.scratch_size];
            const ts_scratch = scratch[Outer.scratch_size..][0..TransformState.scratch_size];
            const is_scratch = scratch[Outer.scratch_size + TransformState.scratch_size ..][0..InnerCursor.scratch_size];

            var outer = try Outer.init(base, outer_scratch);
            const located = try outer.member(name);
            const ts = try TransformState.wrap(located, ts_scratch);
            return InnerCursor.open(ts.reader(), is_scratch);
        }
    };
}

// The table row: used marks free, ino is the key, count is the
// entries produced. The caller owns the array.
pub const GroupSlot = struct {
    used: bool = false,
    ino: u64 = 0,
    count: u32 = 0,
};

// Collapse wraps a finished cursor from outside the chain;
// the one structural demand is an ino field.
//
// A repeat is folded inside next and its payload sinks there;
// the group head is produced untouched.
pub fn Collapse(comptime Inner: type) type {
    return struct {
        const Self = @This();

        // Derived from the Inner's own next signature,
        // so the model cannot drift from the real return.
        const NextReturn = @typeInfo(@TypeOf(Inner.next)).@"fn".return_type.?;
        const InnerInfo = @typeInfo(@typeInfo(NextReturn).error_union.payload).optional.child;

        // Zig 0.17 has no type synthesis, so embedding is the only
        // zero-dispatch way to extend the entry model.
        pub const EntryInfo = struct {
            entry: InnerInfo,
            collapsed: bool,
            link_ordinal: u32,
        };

        pub const scratch_size: usize = Inner.scratch_size;

        inner: Inner,
        slots: []GroupSlot,
        mask: usize,

        // The table is a third caller input like scratch:
        // the caller owns storage, open claims it by initializing it.
        pub fn open(source: anytype, scratch: []u8, group_table: []GroupSlot) Exception!Self {
            // Non-power-of-two cannot index-mask; the refusal answers like exhaustion.
            if (group_table.len == 0 or (group_table.len & (group_table.len - 1)) != 0) {
                return error.CapacityException;
            }
            for (group_table) |*slot| slot.* = .{};
            return .{
                .inner = try Inner.open(source, scratch),
                .slots = group_table,
                .mask = group_table.len - 1,
            };
        }

        pub fn next(self: *Self) Exception!?EntryInfo {
            const raw = (try self.inner.next()) orelse return null;
            const ordinal = try self.bumpGroup(raw.ino);
            if (ordinal > 0) {
                // The repeat's payload sinks inside next, so a collapsed entry never offers bytes.
                _ = try self.inner.skipData();
            }
            return .{ .entry = raw, .collapsed = ordinal > 0, .link_ordinal = ordinal };
        }

        pub fn readData(self: *Self, writer: *std.Io.Writer) Exception!usize {
            return self.inner.readData(writer);
        }

        pub fn skipData(self: *Self) Exception!usize {
            return self.inner.skipData();
        }

        // The first free slot on the probe path belongs to this key,
        // so insert and lookup are one loop.
        fn bumpGroup(self: *Self, ino: u64) Exception!u32 {
            // Low bits only hash; identity is the full 64-bit comparison.
            const home = @as(usize, @truncate(ino)) & self.mask;
            var i: usize = 0;
            while (i < self.slots.len) : (i += 1) {
                const slot = &self.slots[(home + i) & self.mask];
                if (!slot.used) {
                    slot.* = .{ .used = true, .ino = ino, .count = 1 };
                    return 0;
                }
                if (slot.ino == ino) {
                    slot.count += 1;
                    return slot.count - 1;
                }
            }
            // Breaching the caller's table is a capacity answer, never a silent drop.
            return error.CapacityException;
        }
    };
}

// Everything below is assertion-side machinery, never referenced by the protocol.

const Record = struct { name: []const u8, data: []const u8 };

const fixed_table_records = [_]Record{
    .{ .name = "alpha", .data = "aaaa" },
    .{ .name = "gamma", .data = "bbbb" },
    .{ .name = "", .data = "cccc" },
};

fn recordBytesSize(comptime data_len: usize, comptime records: []const Record) usize {
    comptime var size: usize = 0;
    for (records) |r| size += 2 + r.name.len + data_len;
    return size;
}

// Fixtures assemble from the record list so a wrong length field cannot sneak in.
fn recordBytes(comptime data_len: usize, comptime records: []const Record) [recordBytesSize(data_len, records)]u8 {
    var out: [recordBytesSize(data_len, records)]u8 = undefined;
    comptime var i: usize = 0;
    inline for (records) |r| {
        comptime std.debug.assert(r.data.len == data_len);
        std.mem.writeInt(u16, out[i..][0..2], r.name.len, .little);
        i += 2;
        @memcpy(out[i..][0..r.name.len], r.name);
        i += r.name.len;
        @memcpy(out[i..][0..data_len], r.data);
        i += data_len;
    }
    return out;
}

// Counts verb calls so the skip sink is proven by observation.
fn CountingSource(comptime Source: type) type {
    return struct {
        const Self = @This();

        pub const seek_cost: SeekCost = Source.seek_cost;

        inner: Source,
        takes: usize = 0,
        discards: usize = 0,
        taken_bytes: usize = 0,
        discarded_bytes: u64 = 0,

        pub fn take(self: *Self, buf: []u8) Exception!usize {
            self.takes += 1;
            const got = try self.inner.take(buf);
            // Byte counters advance only on success:
            // the mirror must see what left the source.
            self.taken_bytes += got;
            return got;
        }

        pub fn discard(self: *Self, n: u64) Exception!void {
            self.discards += 1;
            try self.inner.discard(n);
            self.discarded_bytes += n;
        }
    };
}

// Synthetic cursor: [name_len: u16][name][data: data_len] records over any source.
fn FixedRecords(comptime Source: type, comptime data_len: usize) type {
    return struct {
        const Self = @This();

        pub const scratch_size: usize = 16;

        source: *Source,
        names: NameScratch,
        pending: usize,

        pub fn open(source: *Source, scratch: []u8) Exception!Self {
            return .{ .source = source, .names = NameScratch.init(scratch), .pending = 0 };
        }

        pub fn next(self: *Self) Exception!?Info {
            // An unconsumed entry is finished here so every next() starts at a record boundary.
            if (self.pending > 0) {
                try self.source.discard(self.pending);
                self.pending = 0;
            }
            var header: [2]u8 = undefined;
            const got = try self.source.take(&header);
            if (got == 0) return null;
            // A short header delivery is a truncated record, not the end of entries.
            if (got < 2) return error.DataException;
            const name_len: usize = std.mem.readInt(u16, &header, .little);
            const name = try self.names.take(self.source, name_len);
            self.pending = data_len;
            return .{ .name = name, .data_size = data_len };
        }

        pub fn readData(self: *Self, writer: *std.Io.Writer) Exception!usize {
            var staged: [32]u8 = undefined;
            // The budget is captured once so truncation compares against the full
            // declaration, never what already moved.
            const budget = self.pending;
            var total: usize = 0;
            while (total < budget) {
                const want = @min(budget - total, staged.len);
                const got = try self.source.take(staged[0..want]);
                // A source that stops inside the declared budget is truncated.
                if (got == 0) return error.DataException;
                writer.writeAll(staged[0..got]) catch |err| switch (err) {
                    error.WriteFailed => return error.IoException,
                };
                total += got;
                self.pending -= got;
            }
            return total;
        }

        pub fn skipData(self: *Self) Exception!usize {
            const n = self.pending;
            // The sink is Source.discard, never pull-and-drop.
            try self.source.discard(n);
            self.pending = 0;
            return n;
        }
    };
}

// Absolute regions: comptime keeps a wrong offset from becoming a test bug.
const MemberSpec = struct { name: []const u8, offset: u64, length: u64 };

const fixed_table_members = [_]MemberSpec{
    .{ .name = "records", .offset = 0, .length = recordBytesSize(4, &fixed_table_records) },
};

// Locates by name and hands out whatever Base.slice yields,
// so one table serves both sources.
fn TableOuter(comptime Base: type, comptime members: []const MemberSpec) type {
    return struct {
        const Self = @This();

        const Encoding = enum { plain };

        const SliceReturn = @typeInfo(@TypeOf(Base.slice)).@"fn".return_type.?;
        pub const LocatedSource = @typeInfo(SliceReturn).error_union.payload;

        pub const scratch_size: usize = 0;

        base: *Base,

        pub fn init(base: *Base, scratch: []u8) Exception!Self {
            _ = scratch;
            return .{ .base = base };
        }

        pub fn findMember(name: []const u8) Exception!MemberRange(Encoding) {
            inline for (members) |m| {
                if (std.mem.eql(u8, m.name, name)) {
                    return .{ .offset = m.offset, .length = m.length, .encoding = .plain };
                }
            }
            // An unknown member is a capability answer, not a data failure.
            return error.UnsupportedException;
        }

        pub fn member(self: *Self, name: []const u8) Exception!LocatedSource {
            const located = try findMember(name);
            return self.base.slice(located.offset, located.length);
        }
    };
}

// The degenerate transform proves the seam:
// any behavioral difference is attributable to the glue.
fn Identity(comptime Source: type) type {
    return struct {
        const Self = @This();

        pub const scratch_size: usize = @sizeOf(Self);

        source: Source,

        pub fn wrap(source: Source, scratch: []u8) Exception!*Self {
            if (scratch.len < scratch_size) return error.CapacityException;
            // The instance lives in scratch so its source is borrowed from a stable address.
            const self: *Self = @ptrCast(@alignCast(scratch.ptr));
            self.source = source;
            return self;
        }

        pub fn reader(self: *Self) *Source {
            return &self.source;
        }
    };
}

// The Inner role takes one argument, so the data length is curried here.
fn FixedRecords4(comptime Source: type) type {
    return FixedRecords(Source, 4);
}

// A fixed tail pattern, distinct from any fixture byte, makes an overread unambiguous.
const canary_bytes = [8]u8{ 0xC3, 0x5A, 0x81, 0xEE, 0x17, 0x6D, 0xB2, 0x44 };

// The shared reader must sit exactly at the canary and hand it back undisturbed.
fn expectReaderCanary(src: *ReaderSource) !void {
    var got: [canary_bytes.len]u8 = undefined;
    try testing.expectEqual(@as(usize, canary_bytes.len), try src.take(&got));
    try testing.expectEqualSlices(u8, &canary_bytes, &got);
    var one: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try src.take(&one));
}

// A stale name slice reads as the successor once scratch is reused;
// the rewrite witnesses the lifetime.
fn expectScratchRewrote(stale: []const u8, expected: []const u8) !void {
    try testing.expectEqualSlices(u8, expected, stale);
}

// A superseded window fails the epoch equality the trap checks;
// a fresh one passes it.
fn expectWindowSuperseded(w: anytype) !void {
    try testing.expect(w.born_epoch != w.src.epoch);
}

const CutClass = enum { clean, truncated };

// A cut is clean where it aligns with every enclosing boundary, else a truncation.
fn cutExpectation(clean: []const usize, cut: usize) CutClass {
    for (clean) |c| {
        if (c == cut) return .clean;
    }
    return .truncated;
}

// Clean cuts succeed; every other cut answers DataException.
fn truncationSweep(
    full: []const u8,
    clean: []const usize,
    comptime run: fn ([]const u8) Exception!void,
) !void {
    var cut: usize = 0;
    while (cut <= full.len) : (cut += 1) {
        if (cutExpectation(clean, cut) == .clean) {
            try run(full[0..cut]);
        } else {
            try testing.expectError(error.DataException, run(full[0..cut]));
        }
    }
}

// Skip must source exactly what read sourced;
// delivered counters differ by exactly the dropped bytes.
fn expectSkipMirrorsRead(skip: anytype, read: anytype, dropped: usize) !void {
    try testing.expectEqual(read.sourced_bytes, skip.sourced_bytes);
    try testing.expectEqual(read.decoded_bytes, skip.decoded_bytes + dropped);
}

// A well-formed stream is the full fixture or empty; every other cut is a truncation.
fn t012SweepDriver(bytes: []const u8) Exception!void {
    if (bytes.len != 0 and bytes.len != 6) return error.DataException;
}

// Canary, counters, and sweeps carve the same fixture bytes.
const fixed_table_bytes = recordBytes(4, &fixed_table_records);

// The canary sits directly behind the fixture, so an overread must eat into it.
const fixed_table_canary_buffer = fixed_table_bytes ++ canary_bytes;

// The same body runs over both sources; only the window semantics branch.
fn fixedTableProperties(base: anytype, tally: anytype) !void {
    const Base = @typeInfo(@TypeOf(base)).pointer.child;
    const N = Nested(TableOuter(Base, &fixed_table_members), Identity, FixedRecords4);

    comptime {
        // Capability is declared by existence.
        if (Base == SliceSource) {
            std.debug.assert(@hasDecl(N.LocatedSource, "seekTo"));
            std.debug.assert(N.LocatedSource.seek_cost == .constant);
        } else {
            std.debug.assert(!@hasDecl(N.LocatedSource, "seekTo"));
            std.debug.assert(N.LocatedSource.seek_cost == .none);
        }
        // Every verb unions exactly the frozen vocabulary with its payload.
        const verbs = .{ N.open, N.InnerCursor.next, N.InnerCursor.readData, N.InnerCursor.skipData };
        for (verbs) |v| {
            const ret = @typeInfo(@TypeOf(v)).@"fn".return_type.?;
            std.debug.assert(ret == (Exception!@typeInfo(ret).error_union.payload));
        }
    }

    // The window is claimed before the open, so the open supersedes it.
    var earlier = try base.slice(0, 8);

    var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
    var cursor = try N.open(base, "records", &scratch);

    var data: [4]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);

    // The name is readable while the entry is current.
    const first = (try cursor.next()).?;
    try testing.expectEqualStrings("alpha", first.name);
    try testing.expectEqual(@as(u64, 4), first.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
    try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);

    // The successor rewrites the scratch, witnessing the name lifetime.
    const second = (try cursor.next()).?;
    try testing.expectEqualStrings("gamma", second.name);
    try expectScratchRewrote(first.name, "gamma");
    w.end = 0;
    try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
    try testing.expectEqualStrings("bbbb", w.buffer[0..w.end]);

    // The zero-length name is a legal entry.
    const third = (try cursor.next()).?;
    try testing.expectEqual(@as(usize, 0), third.name.len);
    w.end = 0;
    try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
    try testing.expectEqualStrings("cccc", w.buffer[0..w.end]);

    // The traversal ends exactly at the member boundary.
    try testing.expect((try cursor.next()) == null);

    // The protocol cannot reach an allocator; the counters confirm silence.
    try testing.expectEqual(@as(usize, 0), tally.allocs);
    try testing.expectEqual(@as(usize, 0), tally.frees);

    // A further read is empty, a further skip is a data failure.
    try testing.expectEqual(@as(usize, 0), try cursor.source.take(&data));
    try testing.expectError(error.DataException, cursor.source.discard(1));

    if (comptime Base == SliceSource) {
        // In contrast, slicing is value semantics; the earlier view stays valid.
        var ev: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), try earlier.take(&ev));
        try testing.expectEqualSlices(u8, fixed_table_bytes[0..8], &ev);
        try testing.expectEqual(@as(usize, 0), base.pos);
        // The bytes behind the member stay reachable through the base.
        var canary_view = try base.slice(fixed_table_bytes.len, canary_bytes.len);
        var cv: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), try canary_view.take(&cv));
        try testing.expectEqualSlices(u8, &canary_bytes, &cv);
    } else {
        // The window born before the open is superseded.
        try expectWindowSuperseded(&earlier);
        // Canary: the shared reader sits at the fixture end.
        try expectReaderCanary(base);
    }
}

// Read and skip consume the same source bytes;
// skip pulls only the structural bytes.
fn fixedTableCounterPair(comptime CS: type, read_cs: *CS, skip_cs: *CS) !void {
    var read_scratch: [16]u8 = undefined;
    var read_cursor = try FixedRecords(CS, 4).open(read_cs, &read_scratch);
    var data: [4]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    while (try read_cursor.next()) |_| {
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try read_cursor.readData(&w));
    }

    var skip_scratch: [16]u8 = undefined;
    var skip_cursor = try FixedRecords(CS, 4).open(skip_cs, &skip_scratch);
    while (try skip_cursor.next()) |_| {
        try testing.expectEqual(@as(usize, 4), try skip_cursor.skipData());
    }

    // The structural count derives from the record list,
    // not a hand-picked constant.
    const structural = comptime blk: {
        var n: usize = 0;
        for (fixed_table_records) |r| n += 2 + r.name.len;
        break :blk n;
    };
    try testing.expectEqual(structural, skip_cs.taken_bytes);
    try testing.expectEqual(@as(u64, 3 * 4), skip_cs.discarded_bytes);
    // Identical total consumption, split differently.
    try testing.expectEqual(
        read_cs.taken_bytes + read_cs.discarded_bytes,
        skip_cs.taken_bytes + skip_cs.discarded_bytes,
    );
    // The read path never sinks: every byte went through take.
    try testing.expectEqual(@as(usize, 0), read_cs.discards);
}

// Synthetic codec: [len: u16][payload ^ key] blocks, key a pure function of
// the block index, so encoder and decoder agree.
//
// Counter semantics: sourced_bytes counts everything that left the source,
// decoded_bytes only what take delivered.
fn Chunked(comptime Source: type) type {
    return struct {
        const Self = @This();

        pub const scratch_size: usize = @sizeOf(Self);

        // The seek answer is derived: a seekable base means linear replay,
        // a forward-only base means none.
        pub const seek_cost: SeekCost = if (@hasDecl(Source, "seekTo")) .linear else .none;

        source: Source,
        block_remaining: u64 = 0,
        block_index: u64 = 0,
        block_key: u8 = 0,
        sourced_bytes: u64 = 0,
        decoded_bytes: u64 = 0,

        pub fn wrap(source: Source, scratch: []u8) Exception!*Self {
            if (scratch.len < scratch_size) return error.CapacityException;
            // Field defaults reset the walk; only the source rides in from the caller.
            const self: *Self = @ptrCast(@alignCast(scratch.ptr));
            self.* = .{ .source = source };
            return self;
        }

        pub fn reader(self: *Self) *Self {
            return self;
        }

        pub fn take(self: *Self, buf: []u8) Exception!usize {
            // A zero-length request must not consume framing.
            if (buf.len == 0) return 0;
            var filled: usize = 0;
            while (filled < buf.len) {
                if (self.block_remaining == 0) {
                    var header: [2]u8 = undefined;
                    const got = try self.source.take(&header);
                    self.sourced_bytes += got;
                    // A clean end mid-fill delivers what is decoded;
                    // whether that is legal is the caller's question.
                    if (got == 0) break;
                    if (got < 2) return error.DataException;
                    const len = std.mem.readInt(u16, &header, .little);
                    // The encoder never emits an empty block; a zero would spin the walk.
                    if (len == 0) return error.DataException;
                    self.block_remaining = len;
                    // The key is captured at header time:
                    // the block may span later take calls.
                    self.block_key = blockKey(self.block_index);
                    self.block_index += 1;
                }
                const want_u64 = @min(self.block_remaining, buf.len - filled);
                const want: usize = std.math.cast(usize, want_u64) orelse return error.DataException;
                const got = try self.source.take(buf[filled..][0..want]);
                self.sourced_bytes += got;
                // The block header declared these bytes; a short delivery is truncation.
                if (got < want) return error.DataException;
                for (buf[filled..][0..got]) |*b| b.* ^= self.block_key;
                self.block_remaining -= got;
                self.decoded_bytes += got;
                filled += got;
            }
            return filled;
        }

        pub fn discard(self: *Self, n: u64) Exception!void {
            var remaining = n;
            while (remaining > 0) {
                if (self.block_remaining == 0) {
                    var header: [2]u8 = undefined;
                    const got = try self.source.take(&header);
                    self.sourced_bytes += got;
                    // Mid-skip there is no clean end: the framing already declared a budget.
                    if (got < 2) return error.DataException;
                    const len = std.mem.readInt(u16, &header, .little);
                    if (len == 0) return error.DataException;
                    self.block_remaining = len;
                    self.block_key = blockKey(self.block_index);
                    self.block_index += 1;
                }
                const step = @min(remaining, self.block_remaining);
                // Payload skips sink to discard, never taken, never decoded.
                try self.source.discard(step);
                self.sourced_bytes += step;
                self.block_remaining -= step;
                remaining -= step;
            }
        }

        // Zig 0.17 has no conditional declarations, so seekTo is always declared;
        // seek_cost stays the honest answer.
        pub fn seekTo(self: *Self, offset: u64) Exception!void {
            if (comptime !@hasDecl(Source, "seekTo"))
                @compileError("session: chunked seek needs a seekable base; seek_cost is none here");
            try self.source.seekTo(0);
            // The replay starts a fresh walk; the counters describe this one.
            self.* = .{ .source = self.source };
            try self.discard(offset);
        }
    };
}

// Inner format: [name_len: u16][name][data_len: u32][data].
// The 8-byte scratch holds the longest name exactly.
fn LengthPrefixed(comptime Source: type) type {
    return struct {
        const Self = @This();

        pub const scratch_size: usize = 8;

        source: *Source,
        names: NameScratch,
        pending: u64,

        pub fn open(source: *Source, scratch: []u8) Exception!Self {
            return .{ .source = source, .names = NameScratch.init(scratch), .pending = 0 };
        }

        pub fn next(self: *Self) Exception!?Info {
            if (self.pending > 0) {
                try self.source.discard(self.pending);
                self.pending = 0;
            }
            var header: [2]u8 = undefined;
            const got = try self.source.take(&header);
            if (got == 0) return null;
            if (got < 2) return error.DataException;
            const name_len: usize = std.mem.readInt(u16, &header, .little);
            const name = try self.names.take(self.source, name_len);
            var dlen: [4]u8 = undefined;
            const dg = try self.source.take(&dlen);
            // The budget field is four bytes or the record is truncated,
            // including the clean end.
            if (dg < 4) return error.DataException;
            self.pending = std.mem.readInt(u32, &dlen, .little);
            return .{ .name = name, .data_size = self.pending };
        }

        pub fn readData(self: *Self, writer: *std.Io.Writer) Exception!usize {
            const budget = self.pending;
            if (budget == 0) return 0;
            var staged: [32]u8 = undefined;
            var total: u64 = 0;
            while (total < budget) {
                const want_u64 = @min(budget - total, staged.len);
                const want: usize = std.math.cast(usize, want_u64) orelse return error.DataException;
                const got = try self.source.take(staged[0..want]);
                // A source that stops inside the u32 budget is truncated.
                if (got == 0) return error.DataException;
                writer.writeAll(staged[0..got]) catch |err| switch (err) {
                    error.WriteFailed => return error.IoException,
                };
                total += got;
                self.pending -= got;
            }
            return @intCast(total);
        }

        pub fn skipData(self: *Self) Exception!usize {
            const n = std.math.cast(usize, self.pending) orelse return error.CapacityException;
            if (n > 0) try self.source.discard(n);
            self.pending = 0;
            return n;
        }
    };
}

const chunked_lp_records = [_]Record{
    .{ .name = "manifest", .data = "0123456789" },
    .{ .name = "tiny", .data = "ab" },
    .{ .name = "empty", .data = "" },
};

fn lpBytesSize(comptime records: []const Record) usize {
    comptime var size: usize = 0;
    for (records) |r| size += 2 + r.name.len + 4 + r.data.len;
    return size;
}

// Assembles the member stream so a wrong length field cannot sneak in.
fn lpBytes(comptime records: []const Record) [lpBytesSize(records)]u8 {
    var out: [lpBytesSize(records)]u8 = undefined;
    comptime var i: usize = 0;
    inline for (records) |r| {
        std.mem.writeInt(u16, out[i..][0..2], r.name.len, .little);
        i += 2;
        @memcpy(out[i..][0..r.name.len], r.name);
        i += r.name.len;
        std.mem.writeInt(u32, out[i..][0..4], r.data.len, .little);
        i += 4;
        @memcpy(out[i..][0..r.data.len], r.data);
        i += r.data.len;
    }
    return out;
}

const chunk_block_len = 8;

// One key definition serves encoder and decoder, so the two cannot drift.
fn blockKey(block_index: u64) u8 {
    return @truncate(0x9E *% block_index +% 0x5A);
}

fn chunkedBytesSize(comptime decoded_len: usize) usize {
    const full = decoded_len / chunk_block_len;
    const rest = decoded_len % chunk_block_len;
    return full * (chunk_block_len + 2) + (if (rest == 0) 0 else rest + 2);
}

// The declared block length lets discard sink a whole payload without reading it.
fn chunkedBytes(comptime decoded: []const u8) [chunkedBytesSize(decoded.len)]u8 {
    var out: [chunkedBytesSize(decoded.len)]u8 = undefined;
    comptime var i: usize = 0;
    comptime var o: usize = 0;
    comptime var block: u64 = 0;
    inline while (i < decoded.len) {
        const len = @min(chunk_block_len, decoded.len - i);
        std.mem.writeInt(u16, out[o..][0..2], len, .little);
        o += 2;
        inline for (0..len) |j| {
            out[o + j] = decoded[i + j] ^ blockKey(block);
        }
        o += len;
        i += len;
        block += 1;
    }
    return out;
}

const chunked_lp_decoded = lpBytes(&chunked_lp_records);
const chunked_lp_wire = chunkedBytes(&chunked_lp_decoded);

const chunked_lp_members = [_]MemberSpec{
    .{ .name = "payload", .offset = 0, .length = chunked_lp_wire.len },
};

// A cut inside a declared block is a truncation
// even when the record there completed.
const chunked_lp_clean = [_]usize{
    0,
    chunkedBytesSize(lpBytesSize(chunked_lp_records[0..1])),
    chunked_lp_wire.len,
};

const chunked_lp_canary_buffer = chunked_lp_wire ++ canary_bytes;

// The full skip witness lives in the mirror pair;
// the window section branches over both sources.
fn chunkedLpProperties(base: anytype, tally: anytype) !void {
    const Base = @typeInfo(@TypeOf(base)).pointer.child;
    const N = Nested(TableOuter(Base, &chunked_lp_members), Chunked, LengthPrefixed);

    comptime {
        // The transform derives its own seek answer;
        // seek_cost is the only honest probe.
        if (Base == SliceSource) {
            std.debug.assert(@hasDecl(N.LocatedSource, "seekTo"));
            std.debug.assert(N.LocatedSource.seek_cost == .constant);
            std.debug.assert(N.TransformState.seek_cost == .linear);
        } else {
            std.debug.assert(!@hasDecl(N.LocatedSource, "seekTo"));
            std.debug.assert(N.LocatedSource.seek_cost == .none);
            std.debug.assert(N.TransformState.seek_cost == .none);
        }
        // Every verb unions exactly the frozen vocabulary with its payload.
        const verbs = .{ N.open, N.InnerCursor.next, N.InnerCursor.readData, N.InnerCursor.skipData };
        for (verbs) |v| {
            const ret = @typeInfo(@TypeOf(v)).@"fn".return_type.?;
            std.debug.assert(ret == (Exception!@typeInfo(ret).error_union.payload));
        }
    }

    // The window is claimed before the open, so the open supersedes it.
    var earlier = try base.slice(0, 8);

    var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
    var cursor = try N.open(base, "payload", &scratch);

    var data: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);

    // The exact-fit name fills the scratch
    // and straddles a block boundary.
    const first = (try cursor.next()).?;
    try testing.expectEqualStrings("manifest", first.name);
    try testing.expectEqual(@as(u64, 10), first.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 10), try cursor.readData(&w));
    try testing.expectEqualStrings("0123456789", w.buffer[0..w.end]);

    // The shorter successor overwrites the scratch prefix;
    // the invalidation is the observation.
    const second = (try cursor.next()).?;
    try testing.expectEqualStrings("tiny", second.name);
    try testing.expectEqual(@as(u64, 2), second.data_size);
    try testing.expect(!std.mem.eql(u8, first.name, "manifest"));
    w.end = 0;
    try testing.expectEqual(@as(usize, 2), try cursor.readData(&w));
    try testing.expectEqualStrings("ab", w.buffer[0..w.end]);

    // The equal successor rewrites in full, the canonical lifetime witness.
    const third = (try cursor.next()).?;
    try testing.expectEqualStrings("empty", third.name);
    try testing.expectEqual(@as(u64, 0), third.data_size);
    try expectScratchRewrote(second.name, "empt");
    w.end = 0;
    try testing.expectEqual(@as(usize, 0), try cursor.readData(&w));

    // The traversal ends exactly at the member boundary.
    try testing.expect((try cursor.next()) == null);

    // Everything on the wire was sourced;
    // only the decoded stream counts as delivered.
    try testing.expectEqual(@as(u64, chunked_lp_wire.len), cursor.source.sourced_bytes);
    try testing.expectEqual(@as(u64, chunked_lp_decoded.len), cursor.source.decoded_bytes);

    // The run was allocation-silent.
    try testing.expectEqual(@as(usize, 0), tally.allocs);
    try testing.expectEqual(@as(usize, 0), tally.frees);

    // Exhaustion is exact; a further discard is a data failure.
    try testing.expectEqual(@as(usize, 0), try cursor.source.take(&data));
    try testing.expectError(error.DataException, cursor.source.discard(1));

    if (comptime Base == SliceSource) {
        // In contrast, slicing is value semantics; the earlier view stays valid.
        var ev: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), try earlier.take(&ev));
        try testing.expectEqualSlices(u8, chunked_lp_wire[0..8], &ev);
        try testing.expectEqual(@as(usize, 0), base.pos);
        // The bytes behind the member stay reachable through the base.
        var canary_view = try base.slice(chunked_lp_wire.len, canary_bytes.len);
        var cv: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), try canary_view.take(&cv));
        try testing.expectEqualSlices(u8, &canary_bytes, &cv);
    } else {
        // The window born before the open is superseded.
        try expectWindowSuperseded(&earlier);
        // Canary: the shared reader sits at the member end.
        try expectReaderCanary(base);
    }
}

// Read and skip source identical bytes;
// skip's delivered falls short by exactly the dropped payload.
fn chunkedLpMirrorPair(comptime Base: type, read_base: *Base, skip_base: *Base) !void {
    const N = Nested(TableOuter(Base, &chunked_lp_members), Chunked, LengthPrefixed);

    var read_scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
    var read_cursor = try N.open(read_base, "payload", &read_scratch);
    var data: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    while (try read_cursor.next()) |_| {
        w.end = 0;
        _ = try read_cursor.readData(&w);
    }

    var skip_scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
    var skip_cursor = try N.open(skip_base, "payload", &skip_scratch);
    while (try skip_cursor.next()) |_| {
        // The per-call witness: skipData leaves decoded_bytes untouched.
        const before = skip_cursor.source.decoded_bytes;
        _ = try skip_cursor.skipData();
        try testing.expectEqual(before, skip_cursor.source.decoded_bytes);
    }

    // The dropped total derives from the record list,
    // not a hand-picked constant.
    const dropped = comptime blk: {
        var n: usize = 0;
        for (chunked_lp_records) |r| n += r.data.len;
        break :blk n;
    };
    // Absolute anchors before the mirror relation.
    try testing.expectEqual(@as(u64, chunked_lp_wire.len), read_cursor.source.sourced_bytes);
    try testing.expectEqual(@as(u64, chunked_lp_decoded.len), read_cursor.source.decoded_bytes);
    try testing.expectEqual(@as(u64, chunked_lp_decoded.len - dropped), skip_cursor.source.decoded_bytes);
    try expectSkipMirrorsRead(skip_cursor.source, read_cursor.source, dropped);
}

// Every truncation class inside the member must answer DataException;
// only block-aligned record boundaries complete.
fn chunkedLpSweepBody(comptime B: type, base: B) Exception!void {
    const TransformState = Chunked(B);
    var ts_scratch: [TransformState.scratch_size]u8 align(@alignOf(TransformState)) = undefined;
    const ts = try TransformState.wrap(base, &ts_scratch);
    const InnerCursor = LengthPrefixed(TransformState);
    var is_scratch: [InnerCursor.scratch_size]u8 = undefined;
    var cursor = try InnerCursor.open(ts.reader(), &is_scratch);
    var data: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    while (try cursor.next()) |_| {
        w.end = 0;
        _ = try cursor.readData(&w);
    }
}

fn chunkedLpSweepSlice(bytes: []const u8) Exception!void {
    const base = SliceSource.init(bytes);
    return chunkedLpSweepBody(SliceSource, base);
}

fn chunkedLpSweepReader(bytes: []const u8) Exception!void {
    var fixed: std.Io.Reader = .fixed(bytes);
    const base = ReaderSource.init(&fixed, bytes.len);
    return chunkedLpSweepBody(ReaderSource, base);
}

// The inner here is itself a Nested composition;
// its coordinates are relative to the located source.
const double_nested_manifest_records = [_]Record{
    .{ .name = "list", .data = "01234567890123456789" },
};

const double_nested_payload_records = [_]Record{
    .{ .name = "alpha", .data = "aaaa" },
    .{ .name = "beta", .data = "bbbbb" },
};

// Both members decode to 30 bytes and encode to 38,
// so one declared length serves both.
const double_nested_manifest_decoded = lpBytes(&double_nested_manifest_records);
const double_nested_manifest_wire = chunkedBytes(&double_nested_manifest_decoded);

const double_nested_payload_decoded = lpBytes(&double_nested_payload_records);
const double_nested_payload_wire = chunkedBytes(&double_nested_payload_decoded);

// Manifest, payload, canary in one buffer: one buffer bounds the whole traversal.
const double_nested_base = double_nested_manifest_wire ++ double_nested_payload_wire;
const double_nested_canary_buffer = double_nested_base ++ canary_bytes;

const double_nested_outer_members = [_]MemberSpec{
    .{ .name = "manifest", .offset = 0, .length = double_nested_manifest_wire.len },
    .{ .name = "payload", .offset = double_nested_manifest_wire.len, .length = double_nested_payload_wire.len },
};

// The inner coordinates are relative:
// the records member starts at zero inside either parent.
const double_nested_inner_members = [_]MemberSpec{
    .{ .name = "records", .offset = 0, .length = double_nested_payload_wire.len },
};

// The adapter is the hinge: the Inner takes the source
// the outer cursor yields, and the sub-chain resolves from it.
//
// The outer cursor's scratch is re-carved into the sub-chain's shares,
// so one caller buffer backs both chains.
fn SubNestedAsInner(comptime Source: type) type {
    return struct {
        const Self = @This();

        pub const N2 = Nested(TableOuter(Source, &double_nested_inner_members), Chunked, LengthPrefixed);

        pub const scratch_size: usize = N2.scratch_size;
        pub const scratch_alignment: usize = N2.scratch_alignment;

        cursor: N2.InnerCursor,

        pub fn open(source: *Source, scratch: []u8) Exception!Self {
            // The outer scratch arrives unaligned;
            // the caller declared the raised alignment for exactly this handoff.
            const sub_scratch: []align(N2.scratch_alignment) u8 = @alignCast(scratch);
            return .{ .cursor = try N2.open(source, "records", sub_scratch) };
        }

        pub fn next(self: *Self) Exception!?Info {
            return self.cursor.next();
        }

        pub fn readData(self: *Self, writer: *std.Io.Writer) Exception!usize {
            return self.cursor.readData(writer);
        }

        pub fn skipData(self: *Self) Exception!usize {
            return self.cursor.skipData();
        }
    };
}

// Both members traverse the full stack;
// counters are read from the inner cursor because the adapter forwards.
fn doubleNestedProperties(base: anytype, tally: anytype) !void {
    const Base = @typeInfo(@TypeOf(base)).pointer.child;
    const N1 = Nested(TableOuter(Base, &double_nested_outer_members), Identity, SubNestedAsInner);

    comptime {
        // Each transform derives its seek answer
        // from its located source.
        if (Base == SliceSource) {
            std.debug.assert(@hasDecl(N1.LocatedSource, "seekTo"));
            std.debug.assert(N1.LocatedSource.seek_cost == .constant);
            std.debug.assert(@hasDecl(N1.InnerCursor.N2.LocatedSource, "seekTo"));
            std.debug.assert(N1.InnerCursor.N2.TransformState.seek_cost == .linear);
        } else {
            std.debug.assert(!@hasDecl(N1.LocatedSource, "seekTo"));
            std.debug.assert(N1.LocatedSource.seek_cost == .none);
            std.debug.assert(!@hasDecl(N1.InnerCursor.N2.LocatedSource, "seekTo"));
            std.debug.assert(N1.InnerCursor.N2.TransformState.seek_cost == .none);
        }
        // Every verb unions exactly the
        // frozen vocabulary with its payload.
        const verbs = .{ N1.open, N1.InnerCursor.next, N1.InnerCursor.readData, N1.InnerCursor.skipData };
        for (verbs) |v| {
            const ret = @typeInfo(@TypeOf(v)).@"fn".return_type.?;
            std.debug.assert(ret == (Exception!@typeInfo(ret).error_union.payload));
        }
        const sub_verbs = .{ N1.InnerCursor.N2.open, N1.InnerCursor.N2.InnerCursor.next, N1.InnerCursor.N2.InnerCursor.readData, N1.InnerCursor.N2.InnerCursor.skipData };
        for (sub_verbs) |v| {
            const ret = @typeInfo(@TypeOf(v)).@"fn".return_type.?;
            std.debug.assert(ret == (Exception!@typeInfo(ret).error_union.payload));
        }
    }

    // The window is claimed before any open.
    var earlier = try base.slice(0, 8);

    var data: [24]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);

    // The manifest member is first because the reader source is forward-only.
    var m_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
    var manifest = try N1.open(base, "manifest", &m_scratch);

    const list = (try manifest.next()).?;
    try testing.expectEqualStrings("list", list.name);
    try testing.expectEqual(@as(u64, 20), list.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 20), try manifest.readData(&w));
    try testing.expectEqualStrings("01234567890123456789", w.buffer[0..w.end]);
    try testing.expect((try manifest.next()) == null);

    // The whole member wire was sourced; the decoded stream is what take delivered.
    try testing.expectEqual(@as(u64, double_nested_manifest_wire.len), manifest.cursor.source.sourced_bytes);
    try testing.expectEqual(@as(u64, double_nested_manifest_decoded.len), manifest.cursor.source.decoded_bytes);

    // Exhaustion is exact, and neither verb reaches the payload member.
    try testing.expectEqual(@as(usize, 0), try manifest.cursor.source.take(&data));
    try testing.expectError(error.DataException, manifest.cursor.source.discard(1));

    // The payload member: the same stack, the second member of the same base.
    var p_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
    var payload = try N1.open(base, "payload", &p_scratch);

    const alpha = (try payload.next()).?;
    try testing.expectEqualStrings("alpha", alpha.name);
    try testing.expectEqual(@as(u64, 4), alpha.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 4), try payload.readData(&w));
    try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);

    const beta = (try payload.next()).?;
    try testing.expectEqualStrings("beta", beta.name);
    try testing.expectEqual(@as(u64, 5), beta.data_size);
    // The shorter successor rewrote the scratch prefix,
    // so the stale alias stopped reading its old bytes.
    try testing.expect(!std.mem.eql(u8, alpha.name, "alpha"));
    w.end = 0;
    try testing.expectEqual(@as(usize, 5), try payload.readData(&w));
    try testing.expectEqualStrings("bbbbb", w.buffer[0..w.end]);
    try testing.expect((try payload.next()) == null);

    try testing.expectEqual(@as(u64, double_nested_payload_wire.len), payload.cursor.source.sourced_bytes);
    try testing.expectEqual(@as(u64, double_nested_payload_decoded.len), payload.cursor.source.decoded_bytes);
    try testing.expectEqual(@as(usize, 0), try payload.cursor.source.take(&data));
    try testing.expectError(error.DataException, payload.cursor.source.discard(1));

    // An unknown name and an inner name asked at the outer cursor are both capability answers.
    try testing.expectError(error.UnsupportedException, N1.open(base, "nope", &p_scratch));
    try testing.expectError(error.UnsupportedException, N1.open(base, "records", &p_scratch));

    // The protocol cannot reach an allocator; the counters confirm silence.
    try testing.expectEqual(@as(usize, 0), tally.allocs);
    try testing.expectEqual(@as(usize, 0), tally.frees);

    if (comptime Base == SliceSource) {
        // In contrast, value semantics; the canary behind both members stays reachable.
        var ev: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), try earlier.take(&ev));
        try testing.expectEqualSlices(u8, double_nested_base[0..8], &ev);
        try testing.expectEqual(@as(usize, 0), base.pos);
        var canary_view = try base.slice(double_nested_base.len, canary_bytes.len);
        var cv: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), try canary_view.take(&cv));
        try testing.expectEqualSlices(u8, &canary_bytes, &cv);
    } else {
        // The earlier window is superseded and the reader sits behind both members.
        try expectWindowSuperseded(&earlier);
        try expectReaderCanary(base);
    }
}

// Through the whole stack, read and skip source identical bytes;
// skip's delivered falls short by the dropped payload.
fn doubleNestedMirrorPair(comptime Base: type, read_base: *Base, skip_base: *Base) !void {
    const N1 = Nested(TableOuter(Base, &double_nested_outer_members), Identity, SubNestedAsInner);

    var read_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
    var read_cursor = try N1.open(read_base, "payload", &read_scratch);
    var data: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    while (try read_cursor.next()) |_| {
        w.end = 0;
        _ = try read_cursor.readData(&w);
    }

    var skip_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
    var skip_cursor = try N1.open(skip_base, "payload", &skip_scratch);
    while (try skip_cursor.next()) |_| {
        // The per-call witness: skipData leaves decoded_bytes untouched.
        const before = skip_cursor.cursor.source.decoded_bytes;
        _ = try skip_cursor.skipData();
        try testing.expectEqual(before, skip_cursor.cursor.source.decoded_bytes);
    }

    // The dropped total derives from the record list,
    // not a hand-picked constant.
    const dropped = comptime blk: {
        var n: usize = 0;
        for (double_nested_payload_records) |r| n += r.data.len;
        break :blk n;
    };
    // Absolute anchors before the mirror relation.
    try testing.expectEqual(@as(u64, double_nested_payload_wire.len), read_cursor.cursor.source.sourced_bytes);
    try testing.expectEqual(@as(u64, double_nested_payload_decoded.len), read_cursor.cursor.source.decoded_bytes);
    try testing.expectEqual(@as(u64, double_nested_payload_decoded.len - dropped), skip_cursor.cursor.source.decoded_bytes);
    try expectSkipMirrorsRead(skip_cursor.cursor.source, read_cursor.cursor.source, dropped);
}

// Every failure class the whole stack can produce must answer DataException.
fn doubleNestedRun(comptime Base: type, base: *Base, name: []const u8) Exception!void {
    const N1 = Nested(TableOuter(Base, &double_nested_outer_members), Identity, SubNestedAsInner);
    var scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
    var cursor = try N1.open(base, name, &scratch);
    var data: [24]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    while (try cursor.next()) |_| {
        w.end = 0;
        _ = try cursor.readData(&w);
    }
}

fn doubleNestedPayloadSweepSlice(bytes: []const u8) Exception!void {
    var base = SliceSource.init(bytes);
    return doubleNestedRun(SliceSource, &base, "payload");
}

fn doubleNestedPayloadSweepReader(bytes: []const u8) Exception!void {
    var fixed: std.Io.Reader = .fixed(bytes);
    var base = ReaderSource.init(&fixed, bytes.len);
    return doubleNestedRun(ReaderSource, &base, "payload");
}

fn doubleNestedManifestSweepSlice(bytes: []const u8) Exception!void {
    var base = SliceSource.init(bytes);
    return doubleNestedRun(SliceSource, &base, "manifest");
}

fn doubleNestedManifestSweepReader(bytes: []const u8) Exception!void {
    var fixed: std.Io.Reader = .fixed(bytes);
    var base = ReaderSource.init(&fixed, bytes.len);
    return doubleNestedRun(ReaderSource, &base, "manifest");
}

// The zero pad keeps both member locations legal,
// so the rejection comes from the inner walk.
const double_nested_short_payload_pad: [18]u8 = @splat(0);
const double_nested_short_payload_base = double_nested_manifest_wire ++ double_nested_payload_wire[0..20].* ++ double_nested_short_payload_pad;

// The outer roles driven by hand:
// equal content and counters prove the glue adds no behavior.
fn doubleNestedManualOuterRun(comptime Base: type, base: *Base) !void {
    const Outer1 = TableOuter(Base, &double_nested_outer_members);
    const T1 = Identity(Outer1.LocatedSource);
    // One buffer backs both outer roles: the table ignores its zero-length share.
    var t1_scratch: [T1.scratch_size]u8 align(@alignOf(T1)) = undefined;
    var outer = try Outer1.init(base, t1_scratch[0..Outer1.scratch_size]);
    const located = try outer.member("payload");
    const t1 = try T1.wrap(located, t1_scratch[Outer1.scratch_size..]);

    const N2 = Nested(TableOuter(Outer1.LocatedSource, &double_nested_inner_members), Chunked, LengthPrefixed);
    var n2_scratch: [N2.scratch_size]u8 align(N2.scratch_alignment) = undefined;
    var cursor = try N2.open(t1.reader(), "records", &n2_scratch);

    var data: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    const first = (try cursor.next()).?;
    try testing.expectEqualStrings("alpha", first.name);
    try testing.expectEqual(@as(u64, 4), first.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
    try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);
    const second = (try cursor.next()).?;
    try testing.expectEqualStrings("beta", second.name);
    try testing.expectEqual(@as(u64, 5), second.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 5), try cursor.readData(&w));
    try testing.expectEqualStrings("bbbbb", w.buffer[0..w.end]);
    try testing.expect((try cursor.next()) == null);

    try testing.expectEqual(@as(u64, double_nested_payload_wire.len), cursor.source.sourced_bytes);
    try testing.expectEqual(@as(u64, double_nested_payload_decoded.len), cursor.source.decoded_bytes);

    // Table isolation, the other direction:
    // an outer name is not an inner member.
    try testing.expectError(error.UnsupportedException, N2.open(t1.reader(), "manifest", &n2_scratch));
}

// The fixtures pin the fit edges:
// exact-fit, zero-length, and one byte past.
const name_fit_records = [_]Record{
    .{ .name = "0123456789abcdef", .data = "zzzz" },
    .{ .name = "", .data = "yyyy" },
};

const name_fit_bytes = recordBytes(4, &name_fit_records);

const name_fit_members = [_]MemberSpec{
    .{ .name = "records", .offset = 0, .length = name_fit_bytes.len },
};

const name_overflow_records = [_]Record{
    .{ .name = "0123456789abcdefg", .data = "zzzz" },
};

const name_overflow_bytes = recordBytes(4, &name_overflow_records);

const name_overflow_members = [_]MemberSpec{
    .{ .name = "records", .offset = 0, .length = name_overflow_bytes.len },
};

// A cut is clean exactly at record boundaries;
// the set derives from the same list the builder reads.
const fixed_table_clean = blk: {
    var cuts: [fixed_table_records.len + 1]usize = undefined;
    cuts[0] = 0;
    var acc: usize = 0;
    for (fixed_table_records, 0..) |r, i| {
        acc += 2 + r.name.len + 4;
        cuts[i + 1] = acc;
    }
    break :blk cuts;
};

// Every truncation class the fixed layout can produce must answer DataException.
fn fixedTableSweepBody(comptime S: type, source: *S) Exception!void {
    const InnerCursor = FixedRecords(S, 4);
    var scratch: [InnerCursor.scratch_size]u8 = undefined;
    var cursor = try InnerCursor.open(source, &scratch);
    var data: [4]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    while (try cursor.next()) |_| {
        w.end = 0;
        _ = try cursor.readData(&w);
    }
}

fn fixedTableSweepSlice(bytes: []const u8) Exception!void {
    var base = SliceSource.init(bytes);
    return fixedTableSweepBody(SliceSource, &base);
}

fn fixedTableSweepReader(bytes: []const u8) Exception!void {
    var fixed: std.Io.Reader = .fixed(bytes);
    var base = ReaderSource.init(&fixed, bytes.len);
    var win = try base.slice(0, bytes.len);
    return fixedTableSweepBody(Window, &win);
}

const window_fixture = "0123456789abcdefghijklmn";

test "SliceSource: bounded window, canary, parent stays valid" {
    var src = SliceSource.init(window_fixture);

    var w = try src.slice(8, 8);
    try testing.expect(@TypeOf(w) == SliceSource);

    // The last bytes inside the window are readable.
    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try w.take(&buf));
    try testing.expectEqualStrings("89ab", &buf);
    try testing.expectEqual(@as(usize, 4), try w.take(&buf));
    try testing.expectEqualStrings("cdef", &buf);

    // Exhaustion reports 0 instead of the canary bytes.
    try testing.expectEqual(@as(usize, 0), try w.take(&buf));
    try testing.expectError(error.DataException, w.discard(1));

    // Pure value semantics: slicing did not move the parent.
    try testing.expectEqual(@as(usize, 4), try src.take(&buf));
    try testing.expectEqualStrings("0123", &buf);
}

test "SliceSource: discard positions, seekTo rewinds, end is exact" {
    var src = SliceSource.init(window_fixture);

    var buf: [3]u8 = undefined;
    try src.discard(5);
    try testing.expectEqual(@as(usize, 3), try src.take(&buf));
    try testing.expectEqualStrings("567", &buf);

    try src.seekTo(21);
    try testing.expectEqual(@as(usize, 3), try src.take(&buf));
    try testing.expectEqualStrings("lmn", &buf);
    try testing.expectEqual(@as(usize, 0), try src.take(&buf));

    // A read straddling the end returns the short count, not an error.
    try src.seekTo(23);
    try testing.expectEqual(@as(usize, 1), try src.take(&buf));
    try testing.expectEqualStrings("n", buf[0..1]);
    try testing.expectEqual(@as(usize, 0), try src.take(&buf));
    try testing.expectError(error.DataException, src.discard(1));
    try testing.expectError(error.DataException, src.seekTo(window_fixture.len + 1));
}

test "SliceSource: out-of-bounds slice rejected at creation" {
    var src = SliceSource.init(window_fixture);
    try testing.expectError(error.DataException, src.slice(17, 8));
    try testing.expectError(error.DataException, src.slice(25, 0));

    // The empty window at the very end is a legal boundary.
    var empty = try src.slice(window_fixture.len, 0);
    var buf: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try empty.take(&buf));
    try testing.expectError(error.DataException, empty.discard(1));
}

test "ReaderSource: slice discards forward, canary stays unread" {
    var fixed: std.Io.Reader = .fixed(window_fixture);
    var src = ReaderSource.init(&fixed, window_fixture.len);

    var w = try src.slice(8, 8);
    try testing.expect(@TypeOf(w) == Window);
    try testing.expectEqual(@as(u64, 8), src.consumed);

    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try w.take(&buf));
    try testing.expectEqualStrings("89ab", &buf);
    try testing.expectEqual(@as(usize, 4), try w.take(&buf));
    try testing.expectEqualStrings("cdef", &buf);
    try testing.expectEqual(@as(u64, 16), src.consumed);

    try testing.expectEqual(@as(usize, 0), try w.take(&buf));
    try testing.expectError(error.DataException, w.discard(1));

    // The canary region was never consumed through the window.
    var tail: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 8), try src.take(&tail));
    try testing.expectEqualStrings("ghijklmn", &tail);
}

test "ReaderSource: window exclusivity invalidates the parent" {
    var fixed: std.Io.Reader = .fixed(window_fixture);
    var src = ReaderSource.init(&fixed, window_fixture.len);

    const w1 = try src.slice(0, 12);
    // Testing here has no panic assertion facility,
    // so the trap is observed through the very flag the trap checks.
    var w2 = try src.slice(12, 4);
    try testing.expect(w1.born_epoch != src.epoch);
    try testing.expect(w2.born_epoch == src.epoch);

    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try w2.take(&buf));
    try testing.expectEqualStrings("cdef", &buf);
}

test "ReaderSource: backward and out-of-bounds slice rejected" {
    var fixed: std.Io.Reader = .fixed(window_fixture);
    var src = ReaderSource.init(&fixed, window_fixture.len);

    try testing.expectError(error.DataException, src.slice(20, 8));
    try testing.expectError(error.DataException, src.slice(25, 0));

    var w = try src.slice(8, 8);
    var buf: [2]u8 = undefined;
    _ = try w.take(&buf);
    try testing.expectEqual(@as(u64, 10), src.consumed);
    // The stream cannot rewind: a member behind the position must be reopened.
    try testing.expectError(error.DataException, src.slice(4, 4));
}

test "ReaderSource: declared window over truncated underlying fails on read" {
    var fixed: std.Io.Reader = .fixed(window_fixture[0..16]);
    var src = ReaderSource.init(&fixed, window_fixture.len);

    // Creation validates coordinates only; the missing bytes surface at read time.
    var w = try src.slice(8, 8);
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 8), try w.take(&buf));
    try testing.expectEqualStrings("89abcdef", &buf);

    var w2 = try src.slice(16, 8);
    try testing.expectError(error.DataException, w2.take(&buf));
    try testing.expectError(error.DataException, src.take(&buf));
}

test "source capabilities are declared by existence" {
    try testing.expect(@hasDecl(SliceSource, "seekTo"));
    try testing.expect(!@hasDecl(ReaderSource, "seekTo"));
    try testing.expect(!@hasDecl(Window, "seekTo"));
    try testing.expect(SliceSource.seek_cost == .constant);
    try testing.expect(ReaderSource.seek_cost == .none);
    try testing.expect(Window.seek_cost == .none);
}

test "cursor: entry order and data are correct" {
    const fixture = comptime recordBytes(4, &fixed_table_records);
    var src = SliceSource.init(&fixture);
    var scratch: [16]u8 = undefined;
    var cursor = try FixedRecords(SliceSource, 4).open(&src, &scratch);

    var data: [4]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);

    const first = (try cursor.next()).?;
    try testing.expectEqualStrings("alpha", first.name);
    try testing.expectEqual(@as(u64, 4), first.data_size);
    try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
    try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);

    const second = (try cursor.next()).?;
    try testing.expectEqualStrings("gamma", second.name);
    try testing.expectEqual(@as(usize, 4), try cursor.skipData());

    const third = (try cursor.next()).?;
    // A zero-length name is a legal entry.
    try testing.expectEqualStrings("", third.name);
    try testing.expectEqual(@as(usize, 4), try cursor.skipData());

    try testing.expect((try cursor.next()) == null);
}

test "cursor: readData and skipData consume the same region" {
    const fixture = comptime recordBytes(4, &fixed_table_records);
    var src_read = SliceSource.init(&fixture);
    var src_skip = SliceSource.init(&fixture);
    var scratch_read: [16]u8 = undefined;
    var scratch_skip: [16]u8 = undefined;
    var cur_read = try FixedRecords(SliceSource, 4).open(&src_read, &scratch_read);
    var cur_skip = try FixedRecords(SliceSource, 4).open(&src_skip, &scratch_skip);

    _ = (try cur_read.next()).?;
    _ = (try cur_skip.next()).?;
    var data: [4]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);
    try testing.expectEqual(@as(usize, 4), try cur_read.readData(&w));
    try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);
    try testing.expectEqual(@as(usize, 4), try cur_skip.skipData());

    // Both continue from the end of the same byte region.
    const n_read = (try cur_read.next()).?;
    const n_skip = (try cur_skip.next()).?;
    try testing.expectEqualStrings(n_read.name, n_skip.name);
    try testing.expectEqual(n_read.data_size, n_skip.data_size);
    try testing.expectEqual(src_read.pos, src_skip.pos);

    _ = try cur_read.skipData();
    _ = try cur_skip.skipData();
    _ = (try cur_read.next()).?;
    _ = (try cur_skip.next()).?;
    _ = try cur_read.skipData();
    _ = try cur_skip.skipData();
    try testing.expect((try cur_read.next()) == null);
    try testing.expect((try cur_skip.next()) == null);
    try testing.expectEqual(src_read.pos, src_skip.pos);
}

test "cursor: skipData sinks to Source.discard, not read-then-drop" {
    const fixture = comptime recordBytes(4, &fixed_table_records);
    var src = CountingSource(SliceSource){ .inner = SliceSource.init(&fixture) };
    var scratch: [16]u8 = undefined;
    var cursor = try FixedRecords(CountingSource(SliceSource), 4).open(&src, &scratch);

    _ = (try cursor.next()).?;
    const takes_before = src.takes;
    try testing.expectEqual(@as(usize, 4), try cursor.skipData());
    // The payload left through discard without one extra take.
    try testing.expectEqual(takes_before, src.takes);
    try testing.expectEqual(@as(usize, 1), src.discards);
}

test "cursor: name lifetime ends at next (scratch reuse observed)" {
    const fixture = comptime recordBytes(4, &fixed_table_records);
    var src = SliceSource.init(&fixture);
    var scratch: [16]u8 = undefined;
    var cursor = try FixedRecords(SliceSource, 4).open(&src, &scratch);

    const first = (try cursor.next()).?;
    // Same-length successors make the overwrite total.
    const second = (try cursor.next()).?;
    try testing.expectEqualStrings("gamma", first.name);
    try testing.expectEqualStrings("gamma", second.name);
}

test "cursor: name capacity boundary, exact fit legal, overflow capacity" {
    const records = [_]Record{
        .{ .name = "abcd", .data = "xx" },
        .{ .name = "abcde", .data = "xx" },
    };
    const fixture = comptime recordBytes(2, &records);
    var src = SliceSource.init(&fixture);
    var scratch: [4]u8 = undefined;
    var cursor = try FixedRecords(SliceSource, 2).open(&src, &scratch);

    // Filling the name field exactly is not overflow.
    const full_fit = (try cursor.next()).?;
    try testing.expectEqualStrings("abcd", full_fit.name);
    try testing.expectEqual(@as(usize, 2), try cursor.skipData());

    // The second record is well-formed; the buffer is too small: capacity, not data.
    try testing.expectError(error.CapacityException, cursor.next());
}

test "cursor: truncation at every record boundary" {
    const full = comptime recordBytes(4, &fixed_table_records);

    // Inside the length field and inside the name: next() itself fails.
    inline for (.{ 1, 5 }) |cut| {
        var src = SliceSource.init(full[0..cut]);
        var scratch: [16]u8 = undefined;
        var cursor = try FixedRecords(SliceSource, 4).open(&src, &scratch);
        try testing.expectError(error.DataException, cursor.next());
    }

    // Inside the payload: next() succeeds and both verbs hit the missing bytes.
    {
        var src = SliceSource.init(full[0..9]);
        var scratch: [16]u8 = undefined;
        var cursor = try FixedRecords(SliceSource, 4).open(&src, &scratch);
        _ = (try cursor.next()).?;
        var data: [4]u8 = undefined;
        var w = std.Io.Writer.fixed(&data);
        try testing.expectError(error.DataException, cursor.readData(&w));
    }
    {
        var src = SliceSource.init(full[0..9]);
        var scratch: [16]u8 = undefined;
        var cursor = try FixedRecords(SliceSource, 4).open(&src, &scratch);
        _ = (try cursor.next()).?;
        try testing.expectError(error.DataException, cursor.skipData());
    }
}

test "Nested: fixed-table composition matches direct traversal" {
    const N = Nested(TableOuter(SliceSource, &fixed_table_members), Identity, FixedRecords4);

    // Comptime wiring is witnessed by type identity:
    // the cursor N.open returns InnerCursor the inner over the located source.
    comptime {
        const OpenReturn = @typeInfo(@TypeOf(N.open)).@"fn".return_type.?;
        const InnerCursor = @typeInfo(OpenReturn).error_union.payload;
        std.debug.assert(InnerCursor == FixedRecords(SliceSource, 4));
        std.debug.assert(N.scratchSize() ==
            TableOuter(SliceSource, &fixed_table_members).scratch_size +
                Identity(SliceSource).scratch_size +
                FixedRecords(SliceSource, 4).scratch_size);
    }

    const fixture = comptime recordBytes(4, &fixed_table_records);
    var base = SliceSource.init(&fixture);

    var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
    var nested = try N.open(&base, "records", &scratch);

    // The hand-run of the same traversal: any divergence is a Nested bug.
    var direct_src = try base.slice(0, fixture.len);
    var inner_scratch: [16]u8 = undefined;
    var direct = try FixedRecords(SliceSource, 4).open(&direct_src, &inner_scratch);

    var nested_buf: [4]u8 = undefined;
    var nested_w = std.Io.Writer.fixed(&nested_buf);
    var direct_buf: [4]u8 = undefined;
    var direct_w = std.Io.Writer.fixed(&direct_buf);

    while (true) {
        const nested_entry = try nested.next();
        const direct_entry = try direct.next();
        try testing.expectEqual(direct_entry == null, nested_entry == null);
        if (direct_entry == null) break;

        try testing.expectEqualStrings(direct_entry.?.name, nested_entry.?.name);
        try testing.expectEqual(direct_entry.?.data_size, nested_entry.?.data_size);

        nested_w.end = 0;
        try testing.expectEqual(@as(usize, 4), try nested.readData(&nested_w));
        direct_w.end = 0;
        try testing.expectEqual(@as(usize, 4), try direct.readData(&direct_w));
        try testing.expectEqualSlices(u8, direct_w.buffer[0..direct_w.end], nested_w.buffer[0..nested_w.end]);
    }

    // Slicing is value semantics: the composed traversal never moved the base.
    try testing.expectEqual(@as(usize, 0), base.pos);

    // An unknown member is the Outer's capability answer.
    try testing.expectError(error.UnsupportedException, N.open(&base, "nope", &scratch));
}

// Every battery helper is exercised here first,
// so a battery failure points at the property.
test "assertions: infrastructure mechanics (tally, canary, cut matrix, mirrors)" {
    // The tally forwards through std.testing.allocator,
    // so leak checking stays armed while counters move.
    const Tally = struct {
        const Self = @This();
        allocs: usize = 0,
        frees: usize = 0,

        fn allocator(self: *Self) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable = std.mem.Allocator.VTable{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        };

        fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return std.testing.allocator.vtable.alloc(std.testing.allocator.ptr, len, alignment, ret_addr);
        }

        fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            _ = ctx;
            return std.testing.allocator.vtable.resize(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            _ = ctx;
            return std.testing.allocator.vtable.remap(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.frees += 1;
            std.testing.allocator.vtable.free(std.testing.allocator.ptr, memory, alignment, ret_addr);
        }
    };

    const t0: Tally = .{};
    try testing.expectEqual(@as(usize, 0), t0.allocs);
    try testing.expectEqual(@as(usize, 0), t0.frees);

    var t: Tally = .{};
    const a = t.allocator();
    const mem = try a.alloc(u8, 8);
    try testing.expectEqual(@as(usize, 1), t.allocs);
    a.free(mem);
    try testing.expectEqual(@as(usize, 1), t.frees);

    // Aligned cuts are clean; everything between boundaries is an inner truncation.
    try testing.expect(cutExpectation(&.{ 0, 6 }, 0) == .clean);
    try testing.expect(cutExpectation(&.{ 0, 6 }, 6) == .clean);
    try testing.expect(cutExpectation(&.{ 0, 6 }, 3) == .truncated);

    // Clean prefixes succeed, the rest fail with DataException.
    const full = [6]u8{ 1, 2, 3, 4, 5, 6 };
    try truncationSweep(&full, &.{ 0, 6 }, t012SweepDriver);

    // The reader stops exactly behind the fixture and hands the canary back.
    const canary_fixture = comptime ([4]u8{ 1, 2, 3, 4 } ++ canary_bytes);
    var fixed: std.Io.Reader = .fixed(&canary_fixture);
    var src = ReaderSource.init(&fixed, canary_fixture.len);
    var head: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try src.take(&head));
    try expectReaderCanary(&src);

    // Once the successor overwrote the scratch, the stale alias reads as the successor.
    var scratch: [16]u8 = undefined;
    @memcpy(scratch[0..5], "alpha");
    const stale: []const u8 = scratch[0..5];
    @memcpy(scratch[0..5], "gamma");
    try expectScratchRewrote(stale, "gamma");

    // The old window fails the epoch equality, the fresh one passes it.
    var wfixed: std.Io.Reader = .fixed(window_fixture);
    var wsrc = ReaderSource.init(&wfixed, window_fixture.len);
    const w1 = try wsrc.slice(0, 12);
    const w2 = try wsrc.slice(12, 4);
    try expectWindowSuperseded(w1);
    try testing.expect(w2.born_epoch == wsrc.epoch);

    // Byte counters: take and discard move exactly their byte counts.
    const cs_fixture = "0123456789";
    var cs = CountingSource(SliceSource){ .inner = SliceSource.init(cs_fixture) };
    var cs_buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try cs.take(&cs_buf));
    try cs.discard(2);
    try testing.expectEqual(@as(usize, 1), cs.takes);
    try testing.expectEqual(@as(usize, 4), cs.taken_bytes);
    try testing.expectEqual(@as(usize, 1), cs.discards);
    try testing.expectEqual(@as(u64, 2), cs.discarded_bytes);

    // Identical sourced bytes; delivered differs by exactly what skip dropped.
    try expectSkipMirrorsRead(
        .{ .sourced_bytes = 20, .decoded_bytes = 12 },
        .{ .sourced_bytes = 20, .decoded_bytes = 20 },
        8,
    );
}

test "fixed-table format: eight-property battery over both sources" {
    // Local to the test block: the Allocator symbol never appears in non-test code.
    const Tally = struct {
        const Self = @This();
        allocs: usize = 0,
        frees: usize = 0,

        fn allocator(self: *Self) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable = std.mem.Allocator.VTable{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        };

        fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return std.testing.allocator.vtable.alloc(std.testing.allocator.ptr, len, alignment, ret_addr);
        }

        fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            _ = ctx;
            return std.testing.allocator.vtable.resize(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            _ = ctx;
            return std.testing.allocator.vtable.remap(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.frees += 1;
            std.testing.allocator.vtable.free(std.testing.allocator.ptr, memory, alignment, ret_addr);
        }
    };

    var tally: Tally = .{};

    var slice_base = SliceSource.init(&fixed_table_canary_buffer);
    try fixedTableProperties(&slice_base, &tally);

    var fixed: std.Io.Reader = .fixed(&fixed_table_canary_buffer);
    var reader_base = ReaderSource.init(&fixed, fixed_table_canary_buffer.len);
    try fixedTableProperties(&reader_base, &tally);
}

test "fixed-table format: skip mirrors read in the source counters" {
    // Slice side: each path gets its own base over the same fixture.
    {
        var read_cs = CountingSource(SliceSource){ .inner = SliceSource.init(&fixed_table_bytes) };
        var skip_cs = CountingSource(SliceSource){ .inner = SliceSource.init(&fixed_table_bytes) };
        try fixedTableCounterPair(CountingSource(SliceSource), &read_cs, &skip_cs);
    }
    // Reader side: each path gets its own reader,
    // because two windows would interleave positions.
    {
        var r1: std.Io.Reader = .fixed(&fixed_table_bytes);
        var b1 = ReaderSource.init(&r1, fixed_table_bytes.len);
        var r2: std.Io.Reader = .fixed(&fixed_table_bytes);
        var b2 = ReaderSource.init(&r2, fixed_table_bytes.len);
        var read_cs = CountingSource(Window){ .inner = try b1.slice(0, fixed_table_bytes.len) };
        var skip_cs = CountingSource(Window){ .inner = try b2.slice(0, fixed_table_bytes.len) };
        try fixedTableCounterPair(CountingSource(Window), &read_cs, &skip_cs);
    }
}

test "chunked length-prefixed format: eight-property battery over both sources" {
    // Local to the test block: the Allocator symbol never appears in non-test code.
    const Tally = struct {
        const Self = @This();
        allocs: usize = 0,
        frees: usize = 0,

        fn allocator(self: *Self) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable = std.mem.Allocator.VTable{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        };

        fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return std.testing.allocator.vtable.alloc(std.testing.allocator.ptr, len, alignment, ret_addr);
        }

        fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            _ = ctx;
            return std.testing.allocator.vtable.resize(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            _ = ctx;
            return std.testing.allocator.vtable.remap(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.frees += 1;
            std.testing.allocator.vtable.free(std.testing.allocator.ptr, memory, alignment, ret_addr);
        }
    };

    var tally: Tally = .{};

    var slice_base = SliceSource.init(&chunked_lp_canary_buffer);
    try chunkedLpProperties(&slice_base, &tally);

    var fixed: std.Io.Reader = .fixed(&chunked_lp_canary_buffer);
    var reader_base = ReaderSource.init(&fixed, chunked_lp_canary_buffer.len);
    try chunkedLpProperties(&reader_base, &tally);
}

test "chunked length-prefixed format: skip mirrors read and never decodes dropped payload" {
    // Slice side: each path gets its own base over the same wire.
    {
        var read_base = SliceSource.init(&chunked_lp_wire);
        var skip_base = SliceSource.init(&chunked_lp_wire);
        try chunkedLpMirrorPair(SliceSource, &read_base, &skip_base);
    }
    // Reader side: each path gets its own reader,
    // because two windows would interleave positions.
    {
        var r1: std.Io.Reader = .fixed(&chunked_lp_wire);
        var b1 = ReaderSource.init(&r1, chunked_lp_wire.len);
        var r2: std.Io.Reader = .fixed(&chunked_lp_wire);
        var b2 = ReaderSource.init(&r2, chunked_lp_wire.len);
        try chunkedLpMirrorPair(ReaderSource, &b1, &b2);
    }
}

test "chunked length-prefixed format: truncation at every wire cut, both sources" {
    try truncationSweep(&chunked_lp_wire, &chunked_lp_clean, chunkedLpSweepSlice);
    try truncationSweep(&chunked_lp_wire, &chunked_lp_clean, chunkedLpSweepReader);
}

test "chunked length-prefixed format: linear seek replays blocks and reopens cleanly" {
    // The replay span and its wire cost derive from the record list.
    const record1_decoded = comptime lpBytesSize(chunked_lp_records[0..1]);
    const record1_wire = comptime chunkedBytesSize(lpBytesSize(chunked_lp_records[0..1]));

    const TransformState = Chunked(SliceSource);
    const InnerCursor = LengthPrefixed(TransformState);
    const base = SliceSource.init(&chunked_lp_wire);
    var ts_scratch: [TransformState.scratch_size]u8 align(@alignOf(TransformState)) = undefined;
    const ts = try TransformState.wrap(base, &ts_scratch);
    var is_scratch: [InnerCursor.scratch_size]u8 = undefined;
    var cursor = try InnerCursor.open(ts.reader(), &is_scratch);
    var data: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&data);

    // Record 1 read in full first, so the replay has a walk to abandon.
    const first = (try cursor.next()).?;
    try testing.expectEqualStrings("manifest", first.name);
    w.end = 0;
    try testing.expectEqual(@as(usize, 10), try cursor.readData(&w));
    try testing.expectEqualStrings("0123456789", w.buffer[0..w.end]);

    // The linear seek replays the span as a pure discard:
    // sourced proves headers were reread, zero decoded proves no decode.
    try ts.seekTo(record1_decoded);
    try testing.expectEqual(@as(u64, record1_wire), ts.sourced_bytes);
    try testing.expectEqual(@as(u64, 0), ts.decoded_bytes);

    // A fresh inner resumes at the seek target:
    // record 2, record 3, clean end.
    var is_scratch2: [InnerCursor.scratch_size]u8 = undefined;
    var resumed = try InnerCursor.open(ts.reader(), &is_scratch2);
    const second = (try resumed.next()).?;
    try testing.expectEqualStrings("tiny", second.name);
    try testing.expectEqual(@as(u64, 2), second.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 2), try resumed.readData(&w));
    try testing.expectEqualStrings("ab", w.buffer[0..w.end]);
    const third = (try resumed.next()).?;
    try testing.expectEqualStrings("empty", third.name);
    try testing.expectEqual(@as(u64, 0), third.data_size);
    w.end = 0;
    try testing.expectEqual(@as(usize, 0), try resumed.readData(&w));
    try testing.expect((try resumed.next()) == null);

    // The whole wire was sourced;
    // only the post-seek decoded span counts as delivered.
    try testing.expectEqual(@as(u64, chunked_lp_wire.len), ts.sourced_bytes);
    try testing.expectEqual(@as(u64, chunked_lp_decoded.len - record1_decoded), ts.decoded_bytes);
}

test "double-nested format: whole-stack battery over both sources" {
    // Local to the test block: the Allocator symbol never appears in non-test code.
    const Tally = struct {
        const Self = @This();
        allocs: usize = 0,
        frees: usize = 0,

        fn allocator(self: *Self) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable = std.mem.Allocator.VTable{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        };

        fn allocFn(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.allocs += 1;
            return std.testing.allocator.vtable.alloc(std.testing.allocator.ptr, len, alignment, ret_addr);
        }

        fn resizeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            _ = ctx;
            return std.testing.allocator.vtable.resize(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn remapFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            _ = ctx;
            return std.testing.allocator.vtable.remap(std.testing.allocator.ptr, memory, alignment, new_len, ret_addr);
        }

        fn freeFn(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.frees += 1;
            std.testing.allocator.vtable.free(std.testing.allocator.ptr, memory, alignment, ret_addr);
        }
    };

    var tally: Tally = .{};

    var slice_base = SliceSource.init(&double_nested_canary_buffer);
    try doubleNestedProperties(&slice_base, &tally);

    var fixed: std.Io.Reader = .fixed(&double_nested_canary_buffer);
    var reader_base = ReaderSource.init(&fixed, double_nested_canary_buffer.len);
    try doubleNestedProperties(&reader_base, &tally);
}

test "double-nested format: skip mirrors read through the whole stack" {
    // Slice side: each path gets its own base over the same bytes.
    {
        var read_base = SliceSource.init(&double_nested_base);
        var skip_base = SliceSource.init(&double_nested_base);
        try doubleNestedMirrorPair(SliceSource, &read_base, &skip_base);
    }
    // Reader side: each path gets its own reader,
    // because two windows would interleave positions.
    {
        var r1: std.Io.Reader = .fixed(&double_nested_base);
        var b1 = ReaderSource.init(&r1, double_nested_base.len);
        var r2: std.Io.Reader = .fixed(&double_nested_base);
        var b2 = ReaderSource.init(&r2, double_nested_base.len);
        try doubleNestedMirrorPair(ReaderSource, &b1, &b2);
    }
}

test "double-nested format: per-layer truncation at every base cut, both sources" {
    // Any cut short of the full base fails,
    // at the outer location or inside the inner walk.
    try truncationSweep(&double_nested_base, &.{double_nested_base.len}, doubleNestedPayloadSweepSlice);
    try truncationSweep(&double_nested_base, &.{double_nested_base.len}, doubleNestedPayloadSweepReader);
    // Every cut from the manifest end upward completes;
    // a contiguous clean range cannot be listed.
    var cut: usize = 0;
    while (cut <= double_nested_base.len) : (cut += 1) {
        if (cut >= double_nested_manifest_wire.len) {
            try doubleNestedManifestSweepSlice(double_nested_base[0..cut]);
            try doubleNestedManifestSweepReader(double_nested_base[0..cut]);
        } else {
            try testing.expectError(error.DataException, doubleNestedManifestSweepSlice(double_nested_base[0..cut]));
            try testing.expectError(error.DataException, doubleNestedManifestSweepReader(double_nested_base[0..cut]));
        }
    }
}

test "double-nested format: inner chain over the manually located source" {
    {
        var base = SliceSource.init(&double_nested_base);
        try doubleNestedManualOuterRun(SliceSource, &base);
    }
    {
        var fixed: std.Io.Reader = .fixed(&double_nested_base);
        var base = ReaderSource.init(&fixed, double_nested_base.len);
        try doubleNestedManualOuterRun(ReaderSource, &base);
    }
}

test "double-nested format: inner-layer rejection with outer windows intact" {
    // Slice side: value semantics keep the base untouched,
    // so the manifest still opens after the rejection.
    {
        const N1 = Nested(TableOuter(SliceSource, &double_nested_outer_members), Identity, SubNestedAsInner);
        var base = SliceSource.init(&double_nested_short_payload_base);
        var scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
        var cursor = try N1.open(&base, "payload", &scratch);
        const alpha = (try cursor.next()).?;
        try testing.expectEqualStrings("alpha", alpha.name);
        var data: [8]u8 = undefined;
        var w = std.Io.Writer.fixed(&data);
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
        try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);
        // The zero pad is a declared zero-length block: reject, never spin.
        try testing.expectError(error.DataException, cursor.next());
        // The failure stayed inside the payload member;
        // the manifest opens over the untouched base.
        var m_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
        var manifest = try N1.open(&base, "manifest", &m_scratch);
        const list = (try manifest.next()).?;
        try testing.expectEqualStrings("list", list.name);
        var mdata: [24]u8 = undefined;
        var mw = std.Io.Writer.fixed(&mdata);
        mw.end = 0;
        try testing.expectEqual(@as(usize, 20), try manifest.readData(&mw));
        try testing.expectEqualStrings("01234567890123456789", mw.buffer[0..mw.end]);
        try testing.expect((try manifest.next()) == null);
    }
    // Reader side: manifest first, then the payload opens clean
    // and the same zero pad answers DataException.
    {
        const N1 = Nested(TableOuter(ReaderSource, &double_nested_outer_members), Identity, SubNestedAsInner);
        var fixed: std.Io.Reader = .fixed(&double_nested_short_payload_base);
        var base = ReaderSource.init(&fixed, double_nested_short_payload_base.len);
        var m_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
        var manifest = try N1.open(&base, "manifest", &m_scratch);
        const list = (try manifest.next()).?;
        try testing.expectEqualStrings("list", list.name);
        var mdata: [24]u8 = undefined;
        var mw = std.Io.Writer.fixed(&mdata);
        mw.end = 0;
        try testing.expectEqual(@as(usize, 20), try manifest.readData(&mw));
        try testing.expectEqualStrings("01234567890123456789", mw.buffer[0..mw.end]);
        try testing.expect((try manifest.next()) == null);

        var p_scratch: [N1.scratch_size]u8 align(N1.scratch_alignment) = undefined;
        var cursor = try N1.open(&base, "payload", &p_scratch);
        const alpha = (try cursor.next()).?;
        try testing.expectEqualStrings("alpha", alpha.name);
        var data: [8]u8 = undefined;
        var w = std.Io.Writer.fixed(&data);
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
        try testing.expectEqualStrings("aaaa", w.buffer[0..w.end]);
        try testing.expectError(error.DataException, cursor.next());
    }
}

test "boundary list: window end exact, one byte past is refused" {
    // Slice face: the window drains to its last byte and refuses the next;
    // the parent never moved.
    {
        var base = SliceSource.init(&fixed_table_canary_buffer);
        var win = try base.slice(0, fixed_table_bytes.len);
        var head: [fixed_table_bytes.len - 1]u8 = undefined;
        try testing.expectEqual(head.len, try win.take(&head));
        var last: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try win.take(&last));
        try testing.expectEqual(fixed_table_bytes[fixed_table_bytes.len - 1], last[0]);
        try testing.expectEqual(@as(usize, 0), try win.take(&last));
        try testing.expectError(error.DataException, win.discard(1));
        // The byte behind the window end stays reachable:
        // canary readback through the parent.
        var cv: [canary_bytes.len]u8 = undefined;
        var canary_view = try base.slice(fixed_table_bytes.len, canary_bytes.len);
        try testing.expectEqual(canary_bytes.len, try canary_view.take(&cv));
        try testing.expectEqualSlices(u8, &canary_bytes, &cv);
    }
    // Window face: the refusal must not leak the canary behind the member.
    {
        var fixed: std.Io.Reader = .fixed(&fixed_table_canary_buffer);
        var base = ReaderSource.init(&fixed, fixed_table_canary_buffer.len);
        var win = try base.slice(0, fixed_table_bytes.len);
        var head: [fixed_table_bytes.len - 1]u8 = undefined;
        try testing.expectEqual(head.len, try win.take(&head));
        var last: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 1), try win.take(&last));
        try testing.expectEqual(fixed_table_bytes[fixed_table_bytes.len - 1], last[0]);
        try testing.expectEqual(@as(usize, 0), try win.take(&last));
        try testing.expectError(error.DataException, win.discard(1));
        try expectReaderCanary(&base);
    }
    // Sub-window face: the refusal holds one step deeper, at a record boundary.
    {
        const rec1_wire = comptime 2 + fixed_table_records[0].name.len + 4;
        const rec2_wire = comptime 2 + fixed_table_records[1].name.len + 4;
        var fixed: std.Io.Reader = .fixed(&fixed_table_canary_buffer);
        var base = ReaderSource.init(&fixed, fixed_table_canary_buffer.len);
        var win = try base.slice(0, fixed_table_bytes.len);
        var sub = try win.slice(rec1_wire, rec2_wire);
        var all: [rec2_wire]u8 = undefined;
        try testing.expectEqual(rec2_wire, try sub.take(&all));
        try testing.expectEqualSlices(u8, fixed_table_bytes[rec1_wire..][0..rec2_wire], &all);
        var one: [1]u8 = undefined;
        try testing.expectEqual(@as(usize, 0), try sub.take(&one));
        try testing.expectError(error.DataException, sub.discard(1));
    }
}

test "boundary list: truncation at each layer boundary, both sources" {
    // Every cut of the plain-record member: record boundaries are clean,
    // everything else answers DataException.
    try truncationSweep(&fixed_table_bytes, &fixed_table_clean, fixedTableSweepSlice);
    try truncationSweep(&fixed_table_bytes, &fixed_table_clean, fixedTableSweepReader);

    // Block-boundary cuts fail when a record continues through them;
    // a cut inside a declared block fails on the block's declaration.
    const cut_block_mid_record = comptime chunkedBytesSize(2 * chunk_block_len);
    const cut_record1_end = comptime chunkedBytesSize(lpBytesSize(chunked_lp_records[0..1]));
    const cut_record2_mid_block = comptime chunkedBytesSize(lpBytesSize(chunked_lp_records[0..2]));
    // The fixture must keep the two boundary kinds apart,
    // or the cases collapse into one.
    try testing.expect(cut_block_mid_record != cut_record1_end);
    try testing.expectError(error.DataException, chunkedLpSweepSlice(chunked_lp_wire[0..cut_block_mid_record]));
    try testing.expectError(error.DataException, chunkedLpSweepReader(chunked_lp_wire[0..cut_block_mid_record]));
    try chunkedLpSweepSlice(chunked_lp_wire[0..cut_record1_end]);
    try chunkedLpSweepReader(chunked_lp_wire[0..cut_record1_end]);
    try testing.expectError(error.DataException, chunkedLpSweepSlice(chunked_lp_wire[0..cut_record2_mid_block]));
    try testing.expectError(error.DataException, chunkedLpSweepReader(chunked_lp_wire[0..cut_record2_mid_block]));

    // Cuts at, before, and short of the member offset fail at the location;
    // exactly the offset still serves manifest.
    const payload_offset: usize = comptime blk: {
        for (double_nested_outer_members) |m| {
            if (std.mem.eql(u8, m.name, "payload")) break :blk @intCast(m.offset);
        }
        unreachable;
    };
    try testing.expectError(error.DataException, doubleNestedPayloadSweepSlice(double_nested_base[0..payload_offset]));
    try testing.expectError(error.DataException, doubleNestedPayloadSweepSlice(double_nested_base[0 .. payload_offset - 1]));
    try testing.expectError(error.DataException, doubleNestedPayloadSweepSlice(double_nested_base[0 .. double_nested_base.len - 1]));
    try doubleNestedManifestSweepSlice(double_nested_base[0..payload_offset]);
    try testing.expectError(error.DataException, doubleNestedPayloadSweepReader(double_nested_base[0..payload_offset]));
    try testing.expectError(error.DataException, doubleNestedPayloadSweepReader(double_nested_base[0 .. payload_offset - 1]));
    try testing.expectError(error.DataException, doubleNestedPayloadSweepReader(double_nested_base[0 .. double_nested_base.len - 1]));
    try doubleNestedManifestSweepReader(double_nested_base[0..payload_offset]);
}

test "boundary list: zero-length and exactly-full names are legal" {
    // The legal pair: exact-fit, then zero-length. Slice face first.
    {
        var base = SliceSource.init(&name_fit_bytes);
        const N = Nested(TableOuter(SliceSource, &name_fit_members), Identity, FixedRecords4);
        var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
        var cursor = try N.open(&base, "records", &scratch);
        const full = (try cursor.next()).?;
        try testing.expectEqualStrings("0123456789abcdef", full.name);
        var data: [4]u8 = undefined;
        var w = std.Io.Writer.fixed(&data);
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
        try testing.expectEqualStrings("zzzz", w.buffer[0..w.end]);
        const empty = (try cursor.next()).?;
        try testing.expectEqual(@as(usize, 0), empty.name.len);
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
        try testing.expectEqualStrings("yyyy", w.buffer[0..w.end]);
        try testing.expect((try cursor.next()) == null);
    }
    // Reader face: the same pair through the exclusive window.
    {
        var fixed: std.Io.Reader = .fixed(&name_fit_bytes);
        var base = ReaderSource.init(&fixed, name_fit_bytes.len);
        const N = Nested(TableOuter(ReaderSource, &name_fit_members), Identity, FixedRecords4);
        var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
        var cursor = try N.open(&base, "records", &scratch);
        const full = (try cursor.next()).?;
        try testing.expectEqualStrings("0123456789abcdef", full.name);
        var data: [4]u8 = undefined;
        var w = std.Io.Writer.fixed(&data);
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
        try testing.expectEqualStrings("zzzz", w.buffer[0..w.end]);
        const empty = (try cursor.next()).?;
        try testing.expectEqual(@as(usize, 0), empty.name.len);
        w.end = 0;
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&w));
        try testing.expectEqualStrings("yyyy", w.buffer[0..w.end]);
        try testing.expect((try cursor.next()) == null);
    }
    // One byte past the scratch: the name is data, so the misfit is capacity.
    {
        var base = SliceSource.init(&name_overflow_bytes);
        const N = Nested(TableOuter(SliceSource, &name_overflow_members), Identity, FixedRecords4);
        var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
        var cursor = try N.open(&base, "records", &scratch);
        try testing.expectError(error.CapacityException, cursor.next());
    }
    {
        var fixed: std.Io.Reader = .fixed(&name_overflow_bytes);
        var base = ReaderSource.init(&fixed, name_overflow_bytes.len);
        const N = Nested(TableOuter(ReaderSource, &name_overflow_members), Identity, FixedRecords4);
        var scratch: [N.scratch_size]u8 align(N.scratch_alignment) = undefined;
        var cursor = try N.open(&base, "records", &scratch);
        try testing.expectError(error.CapacityException, cursor.next());
    }
}

test "boundary list: cast paths map out-of-range u64 to DataException" {
    // The exact conversion the protocol uses refuses out-of-range values;
    // the 32-bit rows run the same sites at real widths.
    try testing.expect(std.math.cast(u32, @as(u64, 1) << 40) == null);
    try testing.expectEqual(@as(u32, 0x1234_5678), std.math.cast(u32, @as(u64, 0x1234_5678)).?);

    // On this host the range checks answer, on a 32-bit host the cast fails first;
    // both land in DataException.
    {
        var base = SliceSource.init(&fixed_table_bytes);
        try testing.expectError(error.DataException, base.discard(std.math.maxInt(u64)));
        try testing.expectError(error.DataException, base.slice(std.math.maxInt(u64), 1));
        try testing.expectError(error.DataException, base.slice(0, std.math.maxInt(u64)));
        try testing.expectError(error.DataException, base.seekTo(std.math.maxInt(u64)));
        // A refused extreme consumed nothing.
        try testing.expectEqual(@as(usize, 0), base.pos);
    }
    {
        var fixed: std.Io.Reader = .fixed(&fixed_table_bytes);
        var base = ReaderSource.init(&fixed, fixed_table_bytes.len);
        try testing.expectError(error.DataException, base.discard(std.math.maxInt(u64)));
        try testing.expectError(error.DataException, base.slice(std.math.maxInt(u64), 1));
        try testing.expectError(error.DataException, base.slice(1, std.math.maxInt(u64)));
        try testing.expectEqual(@as(u64, 0), base.consumed);
    }
    {
        var fixed: std.Io.Reader = .fixed(&fixed_table_bytes);
        var base = ReaderSource.init(&fixed, fixed_table_bytes.len);
        var win = try base.slice(0, fixed_table_bytes.len);
        try testing.expectError(error.DataException, win.discard(std.math.maxInt(u64)));
        try testing.expectError(error.DataException, win.slice(1, std.math.maxInt(u64)));
    }
}

test "boundary list: one transform, two sources, distinct types and capabilities" {
    comptime {
        // The base picks the policy, the transform derives its own answer,
        // the wrapper forwards.
        std.debug.assert(SliceSource.seek_cost == .constant);
        std.debug.assert(ReaderSource.seek_cost == .none);
        std.debug.assert(Window.seek_cost == .none);
        std.debug.assert(Chunked(SliceSource).seek_cost == .linear);
        std.debug.assert(Chunked(ReaderSource).seek_cost == .none);
        std.debug.assert(Chunked(Window).seek_cost == .none);
        std.debug.assert(CountingSource(SliceSource).seek_cost == .constant);
        std.debug.assert(CountingSource(Window).seek_cost == .none);
        // Capability by existence: seekTo is declared on the seekable source only.
        std.debug.assert(@hasDecl(SliceSource, "seekTo"));
        std.debug.assert(!@hasDecl(ReaderSource, "seekTo"));
        std.debug.assert(!@hasDecl(Window, "seekTo"));
        // The same role over the pair is two monomorphizations: no runtime dispatch.
        std.debug.assert(Chunked(SliceSource) != Chunked(ReaderSource));
        std.debug.assert(FixedRecords4(SliceSource) != FixedRecords4(ReaderSource));
        std.debug.assert(Identity(SliceSource) != Identity(ReaderSource));
        const NL = Nested(TableOuter(SliceSource, &chunked_lp_members), Chunked, LengthPrefixed);
        const NR = Nested(TableOuter(ReaderSource, &chunked_lp_members), Chunked, LengthPrefixed);
        std.debug.assert(NL != NR);
        std.debug.assert(NL.LocatedSource.seek_cost == .constant);
        std.debug.assert(NR.LocatedSource.seek_cost == .none);
        std.debug.assert(NL.TransformState.seek_cost == .linear);
        std.debug.assert(NR.TransformState.seek_cost == .none);
    }
}

// The inode entry model: the two-field minimum plus group key and link count,
// so Collapse's ino demand is exercised realistically.
const InodeInfo = struct {
    name: []const u8,
    data_size: u64,
    ino: u64,
    nlink: u32,
};

const InodeRecord = struct { name: []const u8, ino: u64, nlink: u32, data: []const u8 };

fn inodeRecordBytesSize(comptime data_len: usize, comptime records: []const InodeRecord) usize {
    comptime var size: usize = 0;
    for (records) |r| size += 2 + r.name.len + 8 + 4 + data_len;
    return size;
}

// Same discipline as the record builder:
// a wrong length field cannot sneak in.
fn inodeRecordBytes(comptime data_len: usize, comptime records: []const InodeRecord) [inodeRecordBytesSize(data_len, records)]u8 {
    var out: [inodeRecordBytesSize(data_len, records)]u8 = undefined;
    comptime var i: usize = 0;
    inline for (records) |r| {
        comptime std.debug.assert(r.data.len == data_len);
        std.mem.writeInt(u16, out[i..][0..2], r.name.len, .little);
        i += 2;
        @memcpy(out[i..][0..r.name.len], r.name);
        i += r.name.len;
        std.mem.writeInt(u64, out[i..][0..8], r.ino, .little);
        i += 8;
        std.mem.writeInt(u32, out[i..][0..4], r.nlink, .little);
        i += 4;
        @memcpy(out[i..][0..data_len], r.data);
        i += data_len;
    }
    return out;
}

// One ino, nlink=3, payloads differ so a misattributed read is unambiguous.
const inode_repeat_records = [_]InodeRecord{
    .{ .name = "head", .ino = 0x5A5A_5A5A_1234_5678, .nlink = 3, .data = "aaaa" },
    .{ .name = "tail", .ino = 0x5A5A_5A5A_1234_5678, .nlink = 3, .data = "bbbb" },
    .{ .name = "then", .ino = 0x5A5A_5A5A_1234_5678, .nlink = 3, .data = "cccc" },
};

const inode_repeat_bytes = inodeRecordBytes(4, &inode_repeat_records);

// Three distinct inos, so the decorated walk must match the bare one
// entry for entry.
const inode_distinct_records = [_]InodeRecord{
    .{ .name = "one", .ino = 11, .nlink = 1, .data = "aaaa" },
    .{ .name = "two", .ino = 22, .nlink = 1, .data = "bbbb" },
    .{ .name = "three", .ino = 33, .nlink = 1, .data = "cccc" },
};

const inode_distinct_bytes = inodeRecordBytes(4, &inode_distinct_records);

// The inode inner: [name_len: u16][name][ino: u64][nlink: u32][data: data_len].
fn InodeRecords(comptime Source: type, comptime data_len: usize) type {
    return struct {
        const Self = @This();

        pub const scratch_size: usize = 16;

        source: *Source,
        names: NameScratch,
        pending: usize,

        pub fn open(source: *Source, scratch: []u8) Exception!Self {
            return .{ .source = source, .names = NameScratch.init(scratch), .pending = 0 };
        }

        pub fn next(self: *Self) Exception!?InodeInfo {
            // An unconsumed entry is finished here so every next() starts at a record boundary.
            if (self.pending > 0) {
                try self.source.discard(self.pending);
                self.pending = 0;
            }
            var header: [2]u8 = undefined;
            const got = try self.source.take(&header);
            if (got == 0) return null;
            if (got < 2) return error.DataException;
            const name_len: usize = std.mem.readInt(u16, &header, .little);
            const name = try self.names.take(self.source, name_len);
            // Both id fields ride together so one bounded pull covers the fixed tail.
            var ids: [12]u8 = undefined;
            const got_ids = try self.source.take(&ids);
            if (got_ids < ids.len) return error.DataException;
            self.pending = data_len;
            return .{
                .name = name,
                .data_size = data_len,
                .ino = std.mem.readInt(u64, ids[0..8], .little),
                .nlink = std.mem.readInt(u32, ids[8..12], .little),
            };
        }

        pub fn readData(self: *Self, writer: *std.Io.Writer) Exception!usize {
            var staged: [32]u8 = undefined;
            const budget = self.pending;
            var total: usize = 0;
            while (total < budget) {
                const want = @min(budget - total, staged.len);
                const got = try self.source.take(staged[0..want]);
                if (got == 0) return error.DataException;
                writer.writeAll(staged[0..got]) catch |err| switch (err) {
                    error.WriteFailed => return error.IoException,
                };
                total += got;
                self.pending -= got;
            }
            return total;
        }

        pub fn skipData(self: *Self) Exception!usize {
            const n = self.pending;
            try self.source.discard(n);
            self.pending = 0;
            return n;
        }
    };
}

test "collapse: three-entry group folds repeats through the sink" {
    // The counting wrapper observes the fold's routing:
    // taken proves repeats never left through take, discarded proves the sink.
    var src = CountingSource(SliceSource){ .inner = SliceSource.init(&inode_repeat_bytes) };
    const Inner = InodeRecords(CountingSource(SliceSource), 4);
    var scratch: [Inner.scratch_size]u8 = undefined;
    var table: [2]GroupSlot = undefined;
    var cursor = try Collapse(Inner).open(&src, &scratch, &table);

    // The group head is produced untouched: no fold mark, ordinal 0.
    const head = (try cursor.next()).?;
    try testing.expect(!head.collapsed);
    try testing.expectEqual(@as(u32, 0), head.link_ordinal);
    try testing.expectEqualStrings("head", head.entry.name);
    try testing.expectEqual(inode_repeat_records[0].ino, head.entry.ino);
    try testing.expectEqual(@as(u32, 3), head.entry.nlink);
    var head_data: [4]u8 = undefined;
    var hw = std.Io.Writer.fixed(&head_data);
    try testing.expectEqual(@as(usize, 4), try cursor.readData(&hw));
    try testing.expectEqualStrings("aaaa", hw.buffer[0..hw.end]);

    // The two repeats arrive marked, in group order, fold already done.
    const second = (try cursor.next()).?;
    try testing.expect(second.collapsed);
    try testing.expectEqual(@as(u32, 1), second.link_ordinal);
    try testing.expectEqualStrings("tail", second.entry.name);
    try testing.expectEqual(head.entry.ino, second.entry.ino);
    const third = (try cursor.next()).?;
    try testing.expect(third.collapsed);
    try testing.expectEqual(@as(u32, 2), third.link_ordinal);
    try testing.expectEqualStrings("then", third.entry.name);
    try testing.expect((try cursor.next()) == null);

    // Every header, name, and id field left through take, plus exactly one payload.
    const expected_taken = comptime blk: {
        var t: usize = 0;
        for (inode_repeat_records) |r| t += 2 + r.name.len + 12;
        break :blk t;
    };
    try testing.expectEqual(expected_taken + 4, src.taken_bytes);
    // The repeats' payloads left through the sink only;
    // read-then-drop would have shown on the take side.
    try testing.expectEqual(@as(u64, (inode_repeat_records.len - 1) * 4), src.discarded_bytes);
    try testing.expectEqual(inode_repeat_records.len - 1, src.discards);
}

test "collapse: distinct inos match the bare cursor field by field" {
    var src = SliceSource.init(&inode_distinct_bytes);
    const Inner = InodeRecords(SliceSource, 4);
    var scratch: [Inner.scratch_size]u8 = undefined;
    var table: [4]GroupSlot = undefined;
    var cursor = try Collapse(Inner).open(&src, &scratch, &table);
    var bare_src = SliceSource.init(&inode_distinct_bytes);
    var bare_scratch: [Inner.scratch_size]u8 = undefined;
    var bare = try Inner.open(&bare_src, &bare_scratch);
    while (true) {
        const folded = try cursor.next();
        const plain = try bare.next();
        if (plain == null) {
            try testing.expect(folded == null);
            break;
        }
        const f = folded.?;
        const p = plain.?;
        // No repeats in this stream: nothing is folded, nothing is sunk.
        try testing.expect(!f.collapsed);
        try testing.expectEqual(@as(u32, 0), f.link_ordinal);
        // Every underlying field, by name: a later field can never silently escape
        // the comparison.
        const fields = @typeInfo(InodeInfo).@"struct";
        inline for (fields.field_names, fields.field_types) |fname, ftype| {
            if (ftype == []const u8) {
                try testing.expectEqualSlices(u8, @field(f.entry, fname), @field(p, fname));
            } else {
                try testing.expectEqual(@field(f.entry, fname), @field(p, fname));
            }
        }
        // Both sides consume the entry so the walks stay aligned.
        var fd: [4]u8 = undefined;
        var fw = std.Io.Writer.fixed(&fd);
        try testing.expectEqual(@as(usize, 4), try cursor.readData(&fw));
        var pd: [4]u8 = undefined;
        var pw = std.Io.Writer.fixed(&pd);
        try testing.expectEqual(@as(usize, 4), try bare.readData(&pw));
        try testing.expectEqualSlices(u8, fw.buffer[0..fw.end], pw.buffer[0..pw.end]);
    }
}

test "collapse: table exhaustion and bad table sizes are capacity answers" {
    // One slot, two distinct groups: the second insert breaches the caller's bound.
    {
        var src = SliceSource.init(&inode_distinct_bytes);
        const Inner = InodeRecords(SliceSource, 4);
        var scratch: [Inner.scratch_size]u8 = undefined;
        var table: [1]GroupSlot = undefined;
        var cursor = try Collapse(Inner).open(&src, &scratch, &table);
        _ = (try cursor.next()).?;
        try testing.expectError(error.CapacityException, cursor.next());
    }
    // A non-power-of-two capacity cannot index-mask; the refusal happens at open.
    {
        var src = SliceSource.init(&inode_distinct_bytes);
        const Inner = InodeRecords(SliceSource, 4);
        var scratch: [Inner.scratch_size]u8 = undefined;
        var table: [3]GroupSlot = undefined;
        try testing.expectError(error.CapacityException, Collapse(Inner).open(&src, &scratch, &table));
    }
    // The empty table is refused for the same reason.
    {
        var src = SliceSource.init(&inode_distinct_bytes);
        const Inner = InodeRecords(SliceSource, 4);
        var scratch: [Inner.scratch_size]u8 = undefined;
        var table: [0]GroupSlot = undefined;
        try testing.expectError(error.CapacityException, Collapse(Inner).open(&src, &scratch, &table));
    }
}
