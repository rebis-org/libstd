const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const session = @import("../../../common/session.zig");
const cpio = @import("onprem.zig");

const Exception = exception_prim.Exception;

// One walker serves every XAR-shell format whose payload ends in cpio; the name stays valid until the next call.
pub fn Walker(comptime Chain: type, comptime member_name: []const u8) type {
    return struct {
        pub const EntryInfo = struct {
            name: []const u8,
            mode: u32,
            uid: u32,
            gid: u32,
            size: u64,
            modification_time: u64,
            ordinal: u64,
            ino: u32,
            nlink: u32,
            // Set only by a collapsing cursor: the ordinal that owns the group data.
            link_ordinal: ?u64 = null,
        };

        pub const LinkMode = enum { records, collapse };

        // Open-addressed group table: a zero `ordinal_plus_one` marks a free slot.
        pub const Link = struct {
            ino: u32,
            ordinal_plus_one: u64,
        };

        pub const Cursor = struct {
            inner: Chain.InnerCursor,
            pending: ?cpio.RecordInfo = null,
            mode: LinkMode = .records,
            links: []Link = &.{},
            link_count: usize = 0,

            pub fn init(base: anytype, scratch: []u8) Exception!Cursor {
                return initWithLinks(base, scratch, .records, &.{});
            }

            // `links` is the caller's table for collapsing: a power-of-two slice,
            // sized past the number of distinct groups, cleared here.
            pub fn initWithLinks(base: anytype, scratch: []u8, mode: LinkMode, links: []Link) Exception!Cursor {
                return initWithLinksContext(base, scratch, mode, links, null);
            }

            // A transform with wrapWith receives the context; null opens the
            // plain chain, so both entry points share one instantiation.
            pub fn initWithLinksContext(
                base: anytype,
                scratch: []u8,
                mode: LinkMode,
                links: []Link,
                context: ?*const anyopaque,
            ) Exception!Cursor {
                if (mode == .collapse and (links.len == 0 or !std.math.isPowerOfTwo(links.len))) return error.CallException;
                if (mode == .collapse) {
                    for (links) |*entry| entry.* = .{ .ino = 0, .ordinal_plus_one = 0 };
                }
                const inner = if (context) |carried|
                    try Chain.openWith(base, member_name, scratch, carried)
                else
                    try Chain.open(base, member_name, scratch);
                return .{ .inner = inner, .mode = mode, .links = links };
            }

            // An unread member is skipped here, so a caller may walk names only.
            pub fn next(self: *Cursor) Exception!?EntryInfo {
                const record = (try self.inner.next()) orelse return null;
                var info = recordInfo(record);
                if (self.mode == .collapse and isLinkName(info)) {
                    if (self.findLink(info.ino)) |owner| {
                        // The group's first record owns the payload; this name links.
                        _ = try self.inner.skipData();
                        info.link_ordinal = owner;
                        return info;
                    }
                    try self.insertLink(info.ino, info.ordinal);
                }
                self.pending = record;
                return info;
            }

            pub fn readData(self: *Cursor, destination: []u8) Exception!void {
                const record = self.pending orelse return error.CallException;
                if (destination.len < record.size) return error.CapacityException;
                const size: usize = std.math.cast(usize, record.size) orelse return error.ResourceException;
                var sink = std.Io.Writer.fixed(destination[0..size]);
                _ = try self.inner.readData(&sink);
                self.pending = null;
            }

            pub fn skipData(self: *Cursor) Exception!void {
                self.pending = null;
                _ = try self.inner.skipData();
            }

            // The observability counters prove what a walk decoded.
            pub fn decodedChunks(self: *Cursor) u64 {
                return self.inner.source.decodedChunks();
            }

            pub fn decodedBytes(self: *Cursor) u64 {
                return self.inner.source.decodedBytes();
            }

            fn recordInfo(record: cpio.RecordInfo) EntryInfo {
                return .{
                    .name = record.name,
                    .mode = record.mode,
                    .uid = record.uid,
                    .gid = record.gid,
                    .size = record.size,
                    .modification_time = record.modification_time,
                    .ordinal = record.ordinal,
                    .ino = record.ino,
                    .nlink = record.nlink,
                };
            }

            fn slot(self: *Cursor, ino: u32) usize {
                return (@as(usize, ino) *% 0x9E37_79B1) & (self.links.len - 1);
            }

            fn findLink(self: *Cursor, ino: u32) ?u64 {
                var index = self.slot(ino);
                var probes: usize = 0;
                while (probes < self.links.len) : (probes += 1) {
                    const entry = self.links[index];
                    if (entry.ordinal_plus_one == 0) return null;
                    if (entry.ino == ino) return entry.ordinal_plus_one - 1;
                    index = (index + 1) & (self.links.len - 1);
                }
                return null;
            }

            fn insertLink(self: *Cursor, ino: u32, ordinal: u64) Exception!void {
                var index = self.slot(ino);
                var probes: usize = 0;
                while (probes < self.links.len) : (probes += 1) {
                    if (self.links[index].ordinal_plus_one == 0) {
                        self.links[index] = .{ .ino = ino, .ordinal_plus_one = ordinal + 1 };
                        self.link_count += 1;
                        return;
                    }
                    index = (index + 1) & (self.links.len - 1);
                }
                return error.ResourceException;
            }
        };

        // A directory's nlink counts its subdirectories, so it never folds;
        // other nlink>1 names may share data.
        fn isLinkName(info: EntryInfo) bool {
            return info.nlink > 1 and info.mode & 0o170000 != 0o040000;
        }

        pub fn inspectCount(base: anytype, scratch: []u8) Exception!u64 {
            var cursor = try Cursor.init(base, scratch);
            var count: u64 = 0;
            while (try cursor.next() != null) count = try bounds.addU64(count, 1);
            return count;
        }

        pub fn inspectOrdinal(base: anytype, ordinal: u64, scratch: []u8) Exception!EntryInfo {
            var cursor = try Cursor.init(base, scratch);
            while (try cursor.next()) |info| {
                if (info.ordinal == ordinal) return info;
            }
            return error.DataException;
        }

        pub fn decodeOrdinal(base: anytype, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
            return decodeOrdinalContext(base, ordinal, output, scratch, null);
        }

        pub fn decodeOrdinalContext(
            base: anytype,
            ordinal: u64,
            output: []u8,
            scratch: []u8,
            context: ?*const anyopaque,
        ) Exception!usize {
            var cursor = try Cursor.initWithLinksContext(base, scratch, .records, &.{}, context);
            while (try cursor.next()) |info| {
                if (info.ordinal != ordinal) continue;
                const size = std.math.cast(usize, info.size) orelse return error.ResourceException;
                if (output.len < size) return error.CapacityException;
                try cursor.readData(output[0..size]);
                return size;
            }
            return error.DataException;
        }
    };
}
