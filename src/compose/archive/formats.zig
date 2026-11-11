const std = @import("std");

const seam = @import("seam");

const bounds = @import("../../common/primitive/bounds.zig");
const crypto = @import("../../common/primitive/crypto.zig");
const abi = @import("../../kernel/envelope.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const age_seam = @import("../../representation/grammar/age/seam.zig");
const cpio_archive = @import("../../representation/grammar/cpio/onprem.zig");
const cpio_seam = @import("../../representation/grammar/cpio/seam.zig");
const pkg_archive = @import("../../representation/grammar/pkg/onprem.zig");
const rar_archive = @import("../../representation/grammar/rar/onprem.zig");
const rar_recovery = @import("../../representation/grammar/rar/recovery.zig");
const rar_writer = @import("../../representation/grammar/rar/writer.zig");
const sevenzip_archive = @import("../../representation/grammar/sevenzip/onprem.zig");
const tar_archive = @import("../../representation/grammar/tar/onprem.zig");
const tar_seam = @import("../../representation/grammar/tar/seam.zig");
const wim_seam = @import("../../representation/grammar/wim/seam.zig");
const xar_seam = @import("../../representation/grammar/xar/seam.zig");
const xip_seam = @import("../../representation/grammar/xip/seam.zig");
const zip_archive = @import("../../representation/grammar/zip/onprem.zig");
const apfs_seam = @import("../../representation/volume/apfs/seam.zig");
const dwarfs_seam = @import("../../representation/volume/dwarfs/seam.zig");
const iso_seam = @import("../../representation/volume/iso/seam.zig");
const squashfs_seam = @import("../../representation/volume/squashfs/seam.zig");
const common = @import("../common.zig");
const read = @import("read.zig");
const request = @import("request.zig");
const response = @import("response.zig");
const run = @import("run.zig");
const volumes = @import("volumes.zig");
const window = @import("window.zig");
const write = @import("write.zig");

const Provider = seam.Provider;
const Node = abi.Node;
const Exception = vocabulary.Exception;
const Info = read.Info;
const Run = run.Run;

fn fillPlain(entry: anytype, node: *Node) Exception!void {
    entry.* = .{
        .name = try request.bytes(node.child, "entry_name"),
        .data = try request.bytes(node.child, "entry_data"),
    };
}

fn fillOwned(entry: anytype, node: *Node) Exception!void {
    entry.* = .{
        .name = try request.bytes(node.child, "entry_name"),
        .data = try request.bytes(node.child, "entry_data"),
        .uid = if (request.find(node.child, "entry_uid")) |field| try request.narrow(u32, field.value_low) else 0,
        .modification_time = request.scalar(node.child, "entry_mtime"),
    };
}

// The protocol always hands a buffer; a seam that sizes alone ignores it.
fn sizeFree(comptime S: type) fn (Provider, []const S.Entry, []u8) Exception!u64 {
    return struct {
        fn size(provider: Provider, entries: []const S.Entry, scratch: []u8) Exception!u64 {
            _ = scratch;
            return S.archiveSize(provider, entries);
        }
    }.size;
}

// Six formats differ from this codec only in their entry mapping.
pub fn Seam(comptime S: type, comptime sizing: anytype) type {
    return struct {
        pub const Entry = S.Entry;

        pub const Read = struct {
            run: *Run,
            archive: []const u8,
            scratch: []u8,

            pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
                _ = tail;
                return .{
                    .run = running,
                    .archive = archive,
                    .scratch = try running.core.workspace.take(u8, S.scratch_size),
                };
            }

            pub fn count(self: *Read) Exception!u64 {
                return S.inspectCount(self.run.provider(), self.archive, self.scratch);
            }

            pub fn locate(self: *Read, ordinal: u64) Exception!Info {
                return Info.from(try S.inspectOrdinal(self.run.provider(), self.archive, ordinal, self.scratch));
            }

            pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
                return S.decodeOrdinal(self.run.provider(), self.archive, ordinal, output, self.scratch);
            }
        };

        pub const Write = struct {
            run: *Run,
            entries: []const S.Entry,
            scratch: []u8,

            pub fn init(running: *Run, entries: []const S.Entry) Exception!Write {
                return .{
                    .run = running,
                    .entries = entries,
                    .scratch = try running.core.workspace.take(u8, S.scratch_size),
                };
            }

            pub fn size(self: *Write) Exception!u64 {
                return sizing(self.run.provider(), self.entries, self.scratch);
            }

            pub fn encode(self: *Write, output: []u8) Exception!usize {
                return S.encode(self.run.provider(), self.entries, output, self.scratch);
            }
        };
    };
}

fn withFill(comptime Codec: type, comptime mapping: anytype) type {
    return struct {
        pub const Entry = Codec.Entry;
        pub const Read = Codec.Read;
        pub const Write = Codec.Write;

        pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
            _ = running;
            return mapping(entry, node);
        }
    };
}

pub const xar = withFill(Seam(xar_seam, xar_seam.archiveSize), fillOwned);

// The xip format reads a callback source through a fixed forward window;
// a direct span keeps its zero-copy path.
pub const xip = struct {
    pub const Entry = xip_seam.Entry;

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        return fillOwned(entry, node);
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        scratch: []u8,
        view: ?window.View = null,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            _ = tail;
            return .{
                .run = running,
                .archive = archive,
                .scratch = try running.core.workspace.take(u8, xip_seam.scratch_size),
            };
        }

        pub fn initView(running: *Run, tail: []const []const u8) Exception!Read {
            _ = tail;
            const source = running.source();
            const limit = running.limits().encoded_bytes;
            // The window trims to a smaller declared archive; a bigger one
            // costs the full capacity.
            const declared = try window.View.declaredSize(source, limit);
            const buffer = try running.core.workspace.take(u8, @min(declared orelse xip_seam.window_capacity, xip_seam.window_capacity));
            return .{
                .run = running,
                .archive = &.{},
                .scratch = try running.core.workspace.take(u8, xip_seam.scratch_size),
                .view = try window.View.init(source, buffer, declared, limit),
            };
        }

        // Each verb restarts the walk from the TOC, like the whole-archive
        // path re-reads its stable snapshot.
        fn restart(self: *Read) Exception!void {
            const view = &(self.view orelse return);
            return view.restart();
        }

        pub fn count(self: *Read) Exception!u64 {
            try self.restart();
            if (self.view) |*view| return xip_seam.inspectCountView(window.View, self.run.provider(), view, self.scratch);
            return xip_seam.inspectCount(self.run.provider(), self.archive, self.scratch);
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            try self.restart();
            if (self.view) |*view| return Info.from(try xip_seam.inspectOrdinalView(window.View, self.run.provider(), view, ordinal, self.scratch));
            return Info.from(try xip_seam.inspectOrdinal(self.run.provider(), self.archive, ordinal, self.scratch));
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            try self.restart();
            if (self.view) |*view| return xip_seam.decodeOrdinalView(window.View, self.run.provider(), view, ordinal, output, self.scratch);
            return xip_seam.decodeOrdinal(self.run.provider(), self.archive, ordinal, output, self.scratch);
        }

        const ManifestWalk = struct {
            call: *abi.Call,
            groups: ?*abi.Node,
            filled: u64 = 0,
            short: bool = false,
        };

        fn manifestEntry(ptr: *anyopaque, info: xip_seam.EntryInfo) Exception!void {
            const walk: *ManifestWalk = @ptrCast(@alignCast(ptr));
            if (walk.short) return;
            const group = walk.groups orelse {
                walk.short = true;
                return;
            };
            walk.groups = group.next;
            try response.publishGroupInfo(walk.call, group, Info.from(info));
            walk.filled += 1;
        }

        // One walk fills one group per entry; a short chain answers as
        // capacity once the count is known.
        pub fn manifest(self: *Read, call: *abi.Call, reply: *abi.Node) Exception!u64 {
            try self.restart();
            var walk = ManifestWalk{ .call = call, .groups = reply.child };
            const sink = xip_seam.ManifestSink{ .ctx = @ptrCast(&walk), .fill = manifestEntry };
            const total = if (self.view) |*view|
                try xip_seam.inspectAllView(window.View, self.run.provider(), view, self.scratch, sink)
            else
                try xip_seam.inspectAll(self.run.provider(), self.archive, self.scratch, sink);
            if (walk.short) {
                common.writeCapacityDiagnostic(call, total, walk.filled);
                return error.CapacityException;
            }
            return total;
        }
    };

    pub const Write = Seam(xip_seam, xip_seam.archiveSize).Write;
};

pub const squashfs = withFill(Seam(squashfs_seam, squashfs_seam.archiveSize), fillPlain);
pub const apfs = withFill(Seam(apfs_seam, apfs_seam.archiveSize), fillPlain);
pub const dwarfs = withFill(Seam(dwarfs_seam, sizeFree(dwarfs_seam)), fillPlain);
pub const iso = withFill(Seam(iso_seam, sizeFree(iso_seam)), fillPlain);

// The cpio format walks the archive in place, so it claims no buffer.
pub const cpio = struct {
    pub const Entry = cpio_seam.Entry;

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        return fillOwned(entry, node);
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            _ = tail;
            return .{ .run = running, .archive = archive };
        }

        pub fn count(self: *Read) Exception!u64 {
            return cpio_seam.inspectCount(self.run.provider(), self.archive);
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            return Info.from(try cpio_seam.inspectOrdinal(self.run.provider(), self.archive, ordinal));
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            return cpio_seam.decodeOrdinal(self.run.provider(), self.archive, ordinal, output);
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            return .{ .run = running, .entries = entries };
        }

        pub fn size(self: *Write) Exception!u64 {
            return cpio_seam.archiveSize(self.run.provider(), self.entries);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return cpio_seam.encode(self.run.provider(), self.entries, output);
        }
    };
};

// Writes emit gzip; reads sniff, so every package reads back.
const pkg_compression: pkg_archive.Compression = .gzip;

pub const pkg = struct {
    pub const Entry = pkg_archive.Entry;

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        return fillOwned(entry, node);
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        scratch: []u8,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            _ = tail;
            return .{ .run = running, .archive = archive, .scratch = try running.core.workspace.take(u8, pkg_archive.scratch_size) };
        }

        pub fn count(self: *Read) Exception!u64 {
            return pkg_archive.inspectCount(self.archive, self.scratch);
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            return Info.from(try pkg_archive.inspectOrdinal(self.archive, ordinal, self.scratch));
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            return pkg_archive.decodeOrdinal(self.archive, ordinal, output, self.scratch);
        }

        const ManifestWalk = struct {
            call: *abi.Call,
            groups: ?*abi.Node,
            filled: u64 = 0,
            short: bool = false,
        };

        fn manifestEntry(ptr: *anyopaque, info: pkg_archive.EntryInfo) Exception!void {
            const walk: *ManifestWalk = @ptrCast(@alignCast(ptr));
            if (walk.short) return;
            const group = walk.groups orelse {
                walk.short = true;
                return;
            };
            walk.groups = group.next;
            try response.publishGroupInfo(walk.call, group, Info.from(info));
            walk.filled += 1;
        }

        pub fn manifest(self: *Read, call: *abi.Call, reply: *abi.Node) Exception!u64 {
            var walk = ManifestWalk{ .call = call, .groups = reply.child };
            const sink = pkg_archive.ManifestSink{ .ctx = @ptrCast(&walk), .fill = manifestEntry };
            const total = try pkg_archive.inspectAll(self.archive, self.scratch, sink);
            if (walk.short) {
                common.writeCapacityDiagnostic(call, total, walk.filled);
                return error.CapacityException;
            }
            return total;
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        scratch: []u8,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            const content = std.math.cast(usize, try cpio_archive.archiveSize(entries)) orelse return error.ResourceException;
            return .{
                .run = running,
                .entries = entries,
                .scratch = try running.core.workspace.take(u8, pkg_archive.writeScratchSize(content, pkg_compression)),
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return pkg_archive.archiveSize(self.entries, self.scratch, pkg_compression);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return pkg_archive.encode(self.entries, output, self.scratch, pkg_compression);
        }
    };
};

pub const age = struct {
    pub const Entry = age_seam.Entry;

    // Presence opts this format into the crypto family.
    pub const credential_component = "age";

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        return fillPlain(entry, node);
    }

    // The store holds one entry; the parameters name its recipient.
    fn parseOptions(credentials: ?request.Credentials, nodes: ?*Node) Exception!age_seam.Options {
        var selected = age_seam.Options{ .password = request.Credentials.passwordOrEmpty(credentials) };
        if (try request.componentBytes(nodes, "age", "identity")) |bytes| selected.identity = bytes;
        if (try request.componentBytes(nodes, "age", "recipient")) |bytes| selected.recipient = bytes;
        if (request.componentField(nodes, "age", "work_factor")) |field| selected.work_factor = try request.narrow(u8, field.value_low);
        if (request.componentField(nodes, "age", "armor")) |field| selected.armor = field.value_low != 0;
        return selected;
    }

    // The scrypt peak is 1024 * N bytes in the split buffer's back half.
    fn scratchTake(workspace: *resource.Workspace, selected: age_seam.Options) Exception![]u8 {
        const peak = if (selected.password.len != 0)
            @as(usize, 4096) + (@as(usize, 1024) << @intCast(selected.work_factor))
        else
            0;
        return workspace.take(u8, @max(age_seam.scratch_size, peak) * 2);
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        options: age_seam.Options,
        scratch: []u8,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            _ = tail;
            const selected = try parseOptions(running.credentials, running.requestNode());
            return .{
                .run = running,
                .archive = archive,
                .options = selected,
                .scratch = try scratchTake(running.core.workspace, selected),
            };
        }

        // The walk validates the frame; the store holds exactly one entry.
        pub fn count(self: *Read) Exception!u64 {
            _ = age_seam.inspectCount(self.run.provider(), self.archive, self.scratch) catch |err| switch (err) {
                error.UnsupportedException => return error.UnsupportedException,
                error.ResourceException => return error.ResourceException,
                else => return error.DataException,
            };
            return 1;
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            const raw = age_seam.inspectOrdinal(self.run.provider(), self.archive, ordinal, self.options, self.scratch) catch |err| {
                self.run.cause = switch (err) {
                    error.IntegrityException => .wrong_password,
                    error.ResourceException => .kdf_limit,
                    error.UnsupportedException => .unsupported_algorithm,
                    else => .none,
                };
                return err;
            };
            return Info.from(raw);
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            return age_seam.decodeOrdinal(self.run.provider(), self.archive, ordinal, output, self.scratch, self.options) catch |err| {
                self.run.cause = switch (err) {
                    error.IntegrityException => .wrong_password,
                    error.ResourceException => .kdf_limit,
                    error.UnsupportedException => .unsupported_algorithm,
                    else => .none,
                };
                return err;
            };
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        options: age_seam.Options,
        scratch: []u8,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            const selected = try parseOptions(running.credentials, running.requestNode());
            return .{
                .run = running,
                .entries = entries,
                .options = selected,
                .scratch = try scratchTake(running.core.workspace, selected),
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return age_seam.archiveSize(self.run.provider(), self.entries, self.options, self.scratch);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return age_seam.encode(self.run.provider(), self.entries, output, self.scratch, self.options);
        }
    };
};

// The wim format keeps both shapes: a set joins into the equivalent archive.
pub const wim = struct {
    pub const Entry = wim_seam.Entry;

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        return fillPlain(entry, node);
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        parts: []const []const u8,
        scratch: []u8,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            return .{
                .run = running,
                .archive = archive,
                .parts = if (tail.len == 0) &.{} else try volumes.list(archive, tail, running.core.workspace),
                // The parse carve scales with the blob count and the
                // metadata image; the tracked take reports the need.
                .scratch = try running.core.workspace.take(u8, try wim_seam.parseScratchLen(archive)),
            };
        }

        pub fn count(self: *Read) Exception!u64 {
            return if (self.parts.len == 0)
                wim_seam.inspectCount(self.run.provider(), self.archive, self.scratch)
            else
                wim_seam.volumeInspectCount(self.run.provider(), self.parts, self.scratch);
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            return Info.from(if (self.parts.len == 0)
                try wim_seam.inspectOrdinal(self.run.provider(), self.archive, ordinal, self.scratch)
            else
                try wim_seam.volumeInspectOrdinal(self.run.provider(), self.parts, ordinal, self.scratch));
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            if (self.parts.len == 0) return wim_seam.decodeOrdinal(self.run.provider(), self.archive, ordinal, output, self.scratch);
            return wim_seam.volumeDecodeOrdinal(self.run.provider(), self.parts, ordinal, output, self.scratch);
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        scratch: []u8,
        encoded: []u8 = &.{},
        split_scratch: []u8 = &.{},

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            return .{
                .run = running,
                .entries = entries,
                // The tree and metadata image scale with the entry set;
                // the tracked take reports the shortfall.
                .scratch = try running.core.workspace.take(u8, try wim_seam.writeScratchLen(entries)),
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return wim_seam.archiveSize(self.run.provider(), self.entries, self.scratch);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return wim_seam.encode(self.run.provider(), self.entries, output, self.scratch);
        }

        // A split plans over an encoded image, so the write stages one first.
        pub fn volumePlan(self: *Write, volume_size: u64) Exception!write.Extent {
            const required = std.math.cast(usize, try self.size()) orelse return error.ResourceException;
            self.encoded = try self.run.core.workspace.take(u8, required);
            if (try self.encode(self.encoded) != required) return error.InternalException;
            // The span table scales with the blob count, past the fixed read scratch.
            self.split_scratch = try self.run.core.workspace.take(u8, try wim_seam.splitScratchLen(self.encoded));
            const plan = try wim_seam.splitPlan(self.run.provider(), self.encoded, volume_size, self.split_scratch);
            return .{ .total = plan.total, .count = plan.count };
        }

        pub fn volumeEmit(self: *Write, output: []u8, volume_size: u64, extent: write.Extent) Exception![]const []const u8 {
            const lengths = try self.run.core.workspace.take(u64, extent.count);
            const emitted = try wim_seam.splitEmit(self.run.provider(), self.encoded, volume_size, output, lengths, self.split_scratch);
            if (emitted.total != extent.total or emitted.count != extent.count) return error.InternalException;
            return volumes.byLength(output, lengths[0..emitted.count], self.run.core.workspace);
        }
    };
};

pub const tar = struct {
    pub const Entry = tar_seam.Entry;

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        entry.* = .{
            .name = try request.bytes(node.child, "entry_name"),
            .data = try request.bytes(node.child, "entry_data"),
            .link_name = try request.bytes(node.child, "entry_link_name"),
            .uid = if (request.find(node.child, "entry_uid")) |field| try request.narrow(u32, field.value_low) else 0,
            .modification_time = request.scalar(node.child, "entry_mtime"),
            .typeflag = if (request.find(node.child, "entry_typeflag")) |field| try request.narrow(u8, field.value_low) else 0,
            .mode = if (request.find(node.child, "entry_mode")) |field| try request.narrow(u32, field.value_low) else 0o644,
        };
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        parts: []const []const u8,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            return .{
                .run = running,
                .archive = archive,
                .parts = if (tail.len == 0) &.{} else try volumes.list(archive, tail, running.core.workspace),
            };
        }

        pub fn count(self: *Read) Exception!u64 {
            return if (self.parts.len == 0)
                tar_seam.inspectCount(self.run.provider(), self.archive)
            else
                tar_seam.volumeInspectCount(self.run.provider(), self.parts);
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            if (self.parts.len != 0) {
                return Info.from(try tar_seam.volumeInspectOrdinal(self.run.provider(), self.parts, ordinal));
            }
            const raw = try tar_seam.inspectOrdinal(self.run.provider(), self.archive, ordinal);
            var info = Info.from(raw);
            // A stored entry's bytes are contiguous in the archive already.
            if (raw.sparse == null) info.ready = .{ .offset = raw.data_offset, .len = raw.size };
            return info;
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            if (self.parts.len == 0) return tar_seam.decodeOrdinal(self.run.provider(), self.archive, ordinal, output);
            // A member holds at most one segment per volume.
            const segments = try self.run.core.workspace.take(tar_archive.VolumeSegment, self.parts.len);
            return tar_seam.volumeDecodeOrdinal(self.run.provider(), self.parts, ordinal, output, segments);
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        scratch: []u8,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            return .{
                .run = running,
                .entries = entries,
                .scratch = try running.core.workspace.take(u8, tar_archive.scratch_size),
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return tar_seam.archiveSize(self.run.provider(), self.entries);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return tar_seam.encode(self.run.provider(), self.entries, output, self.scratch);
        }

        pub fn volumePlan(self: *Write, volume_size: u64) Exception!write.Extent {
            const plan = try tar_seam.volumeSizeGnu(self.run.provider(), self.entries, volume_size);
            return .{ .total = plan.total, .count = plan.count };
        }

        pub fn volumeEmit(self: *Write, output: []u8, volume_size: u64, extent: write.Extent) Exception![]const []const u8 {
            const lengths = try self.run.core.workspace.take(u64, extent.count);
            const emitted = try tar_seam.volumeEncodeGnu(self.run.provider(), self.entries, output, lengths, volume_size, self.scratch);
            // The encoder must confirm the plan before the lengths slice.
            if (emitted.total != extent.total or emitted.count != extent.count) return error.InternalException;
            return volumes.byLength(output, lengths[0..emitted.count], self.run.core.workspace);
        }
    };
};

// Disk offsets are relative, so a spanned set needs join and disk starts.
pub const zip = struct {
    pub const Entry = zip_archive.Entry;

    // Presence opts this format into the crypto family.
    pub const credential_component = "zip";

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        entry.* = .{
            .name = try request.bytes(node.child, "entry_name"),
            .data = try request.bytes(node.child, "entry_data"),
            .method = if (request.find(node.child, "entry_method")) |field| try request.narrow(u16, field.value_low) else 8,
        };
        // A nonzero value streams: zeroed local sizes and a trailing descriptor.
        if (request.componentScalar(node.child, "zip", "data_descriptor") != 0) entry.flags |= 0x0008;
        const credentials = running.credentials orelse return;
        entry.encrypted = true;
        entry.password = credentials.password;
        entry.zipcrypto = credentials.algorithm == 0;
        if (!entry.zipcrypto) entry.aes_strength = credentials.algorithm;
        entry.kdf_rounds_limit = credentials.kdf_rounds_limit;
        entry.password_lifetime = credentials.password_lifetime;
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        parts: []const []const u8,
        join: []u8,
        disk_starts: []usize,
        entry: zip_archive.Info = undefined,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            var selected: Read = .{
                .run = running,
                .archive = archive,
                .parts = &.{},
                .join = &.{},
                .disk_starts = &.{},
            };
            if (tail.len != 0) {
                selected.parts = try volumes.list(archive, tail, running.core.workspace);
                selected.join = try running.core.workspace.take(u8, try volumes.setBytes(archive, tail));
                selected.disk_starts = try running.core.workspace.take(usize, selected.parts.len);
            }
            return selected;
        }

        pub fn count(self: *Read) Exception!u64 {
            const total = if (self.parts.len == 0)
                try zip_archive.zipInspectCountEx(self.archive, self.run.limits())
            else
                try zip_archive.zipInspectCountSpanned(self.parts, self.join, self.disk_starts, self.run.limits());
            return total;
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            const index = std.math.cast(usize, ordinal) orelse return error.CallException;
            self.entry = if (self.parts.len == 0)
                try zip_archive.zipInspectOrdinalEx(self.archive, index, self.run.limits())
            else
                try zip_archive.zipInspectOrdinalSpanned(self.parts, index, self.join, self.disk_starts, self.run.limits());
            return Info.from(self.entry);
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            const index = std.math.cast(usize, ordinal) orelse return error.CallException;
            // The target is open: staging and history first, the remainder last.
            const staging: []u8 = if (self.entry.encrypted) try self.run.core.workspace.take(u8, self.entry.compressed_size) else &.{};
            const history = try self.run.core.workspace.take(u8, if (self.entry.actual_method == 9) zip_archive.deflate64_decode_history_size else zip_archive.deflate_history_size);
            const options: zip_archive.ZipDecodeOptions = .{
                .password = request.Credentials.optionalPassword(self.run.credentials),
                .kdf_rounds_limit = request.Credentials.kdfLimit(self.run.credentials),
                .password_lifetime = request.Credentials.lifetime(self.run.credentials),
                .failure_cause = &self.run.cause,
                .staging = staging,
                .scratch = try self.run.core.workspace.take(u8, self.run.core.workspace.remaining()),
                .history = history,
                .provider = self.run.provider(),
            };
            return if (self.parts.len == 0)
                zip_archive.zipDecodeOrdinal(self.archive, index, output, options)
            else
                zip_archive.zipDecodeOrdinalSpanned(self.parts, index, output, self.join, self.disk_starts, options);
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        comment: []const u8,
        history: []u8,
        measurement: []u8,
        scratch: []u8,
        staging: []u8,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            const comment = try request.bytes(running.requestNode(), "comment");
            var needs_deflate64 = false;
            var scratch_required: usize = 0;
            for (entries) |entry| {
                if (entry.method == 9) needs_deflate64 = true;
                scratch_required = @max(scratch_required, zip_archive.encodeScratchSize(entry));
            }
            const history = try running.core.workspace.take(u8, if (needs_deflate64) zip_archive.deflate64_history_size else zip_archive.deflate_history_size);
            const measurement = try running.core.workspace.take(u8, zip_archive.deflate_measurement_buffer_size);
            const scratch = try running.core.workspace.take(u8, scratch_required);
            var widest: usize = 0;
            for (entries) |entry| {
                if (!entry.encrypted) continue;
                widest = @max(widest, try zip_archive.compressedSize(entry, history, measurement, scratch));
            }
            const staging: []u8 = if (widest != 0) try running.core.workspace.take(u8, @max(widest, zip_archive.deflate_measurement_buffer_size)) else &.{};
            return .{
                .run = running,
                .entries = entries,
                .comment = comment,
                .history = history,
                .measurement = measurement,
                .scratch = scratch,
                .staging = staging,
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return try zip_archive.requiredSize(self.entries, self.comment, self.history, self.measurement, self.scratch, &self.run.cause);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return zip_archive.encode(self.entries, self.comment, output, self.run.provider(), self.history, self.measurement, self.staging, self.scratch, &self.run.cause);
        }

        pub fn volumePlan(self: *Write, volume_size: u64) Exception!write.Extent {
            const required = std.math.cast(usize, try self.size()) orelse return error.ResourceException;
            const total = try bounds.addUsize(required, 4);
            const plan = try zip_archive.spannedVolumeExtents(total, volume_size);
            return .{ .total = total, .count = std.math.cast(usize, plan.volumes) orelse return error.ResourceException };
        }

        pub fn volumeEmit(self: *Write, output: []u8, volume_size: u64, extent: write.Extent) Exception![]const []const u8 {
            const result = try zip_archive.encodeSpanned(self.entries, self.comment, output, volume_size, self.run.provider(), self.history, self.measurement, self.staging, self.scratch, &self.run.cause);
            if (result.total_len != extent.total) return error.InternalException;
            return volumes.byChunk(output[0..result.total_len], volume_size, self.run.core.workspace);
        }
    };
};

pub const sevenzip = struct {
    pub const Entry = sevenzip_archive.Entry;

    // Presence opts this format into the crypto family.
    pub const credential_component = "sevenzip";

    // A streaming source may declare no size; replay measures the bytes.
    pub const materialization: common.SourceSizing = .replay;

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        entry.* = .{
            .name = try request.bytes(node.child, "entry_name"),
            .data = try request.bytes(node.child, "entry_data"),
            .method = if (request.find(node.child, "entry_method")) |field| try method(field.value_low) else .copy,
        };
        if (request.find(node.child, "entry_filter")) |field| {
            // Filters are rare, so each claims its own slot as it arrives.
            const slot = try running.core.workspace.take(sevenzip_archive.CoderMethod, 1);
            slot[0] = try method(field.value_low);
            entry.filters = slot;
        }
        const credentials = running.credentials orelse return;
        entry.encrypted = true;
        entry.password = credentials.password;
        entry.kdf_rounds_limit = credentials.kdf_rounds_limit;
        entry.password_lifetime = credentials.password_lifetime;
    }

    fn method(selector: u64) Exception!sevenzip_archive.CoderMethod {
        return switch (selector) {
            0 => .copy,
            1 => .deflate,
            2 => .bzip2,
            3 => .lzma,
            4 => .lzma2,
            5 => .delta,
            6 => .x86,
            7 => .ppc,
            8 => .ia64,
            9 => .arm,
            10 => .armt,
            11 => .sparc,
            12 => .arm64,
            13 => .riscv,
            14 => .ppmd,
            else => error.CallException,
        };
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            // A joined set inspects exactly as a single archive does.
            const joined = if (tail.len == 0)
                archive
            else
                try sevenzip_archive.sevenZipJoinVolumes(try volumes.list(archive, tail, running.core.workspace), running.core.workspace, running.limits());
            return .{
                .run = running,
                .archive = joined,
            };
        }

        fn loadOptions(self: *Read) sevenzip_archive.SevenZipLoadOptions {
            return .{
                .password = request.Credentials.optionalPassword(self.run.credentials),
                .kdf_rounds_limit = request.Credentials.kdfLimit(self.run.credentials),
                .password_lifetime = request.Credentials.lifetime(self.run.credentials),
                .failure_cause = &self.run.cause,
                .provider = self.run.provider(),
            };
        }

        pub fn count(self: *Read) Exception!u64 {
            const options = self.loadOptions();
            return sevenzip_archive.sevenZipInspectCountEx(self.archive, self.run.core.workspace, self.run.limits(), &options);
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            const options = self.loadOptions();
            return Info.from(try sevenzip_archive.sevenZipInspectOrdinalEx(self.archive, self.run.core.workspace, self.run.limits(), ordinal, &options));
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            return sevenzip_archive.sevenZipDecodeOrdinal(self.archive, self.run.core.workspace, self.run.limits(), ordinal, output, .{
                .password = request.Credentials.optionalPassword(self.run.credentials),
                .kdf_rounds_limit = request.Credentials.kdfLimit(self.run.credentials),
                .password_lifetime = request.Credentials.lifetime(self.run.credentials),
                .failure_cause = &self.run.cause,
                .provider = self.run.provider(),
            });
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        packed_entries: []const sevenzip_archive.PackedEntry,
        header: sevenzip_archive.SevenZipHeaderOptions,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            const header_encode = try request.headerEncode("sevenzip", running.requestNode());
            return .{
                .run = running,
                .entries = entries,
                .packed_entries = try sevenzip_archive.sevenZipPack(entries, running.provider(), running.core.workspace, running.limits(), &running.cause),
                // -mhe stores the header without compression, like the reference writer.
                .header = .{
                    .compress = header_encode == 1,
                    .encrypt = header_encode == 2,
                    .password = request.Credentials.passwordOrEmpty(running.credentials),
                    .kdf_rounds_limit = request.Credentials.kdfLimit(running.credentials),
                    .password_lifetime = request.Credentials.lifetime(running.credentials),
                    .failure_cause = &running.cause,
                },
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return try sevenzip_archive.sevenZipPackedSize(self.entries, self.packed_entries, self.run.core.workspace, self.run.provider(), self.run.limits(), self.header);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return sevenzip_archive.sevenZipWritePacked(self.entries, self.packed_entries, output, self.run.core.workspace, self.run.provider(), self.run.limits(), self.header);
        }

        pub fn volumePlan(self: *Write, volume_size: u64) Exception!write.Extent {
            const required = std.math.cast(usize, try self.size()) orelse return error.ResourceException;
            const layout = try sevenzip_archive.sevenZipVolumeExtents(required, volume_size);
            return .{ .total = layout.total_len, .count = std.math.cast(usize, layout.volumes) orelse return error.ResourceException };
        }

        pub fn volumeEmit(self: *Write, output: []u8, volume_size: u64, extent: write.Extent) Exception![]const []const u8 {
            const layout = try sevenzip_archive.sevenZipWritePackedVolumes(self.entries, self.packed_entries, output, volume_size, self.run.core.workspace, self.run.provider(), self.run.limits(), self.header);
            if (layout.total_len != extent.total or layout.volumes != extent.count) return error.InternalException;
            return volumes.byChunk(output[0..layout.total_len], volume_size, self.run.core.workspace);
        }
    };
};

// Largest decrypted-header staging either RAR family needs.
// RAR5 caps a header at 2 MiB; RAR4 headers are u16-sized and aligned.
const rar_header_scratch_size = 2 * 1024 * 1024 + 16;

// On x86 a u64 aligns to 4, and these buffers are re-read as u64 words.
const StateOctet = extern struct { bytes: [8]u8 align(8) };

pub const rar = struct {
    pub const Entry = rar_writer.RarEntry;

    // Presence opts this format into the crypto family.
    pub const credential_component = "rar";

    pub fn fill(entry: *Entry, node: *Node, running: *Run) Exception!void {
        _ = running;
        const name = try request.bytes(node.child, "entry_name");
        if (!std.unicode.utf8ValidateSlice(name)) return error.CallException;
        entry.* = .{
            .name = name,
            .data = try request.bytes(node.child, "entry_data"),
            .mtime = @truncate(request.scalar(node.child, "entry_mtime")),
            .method = if (request.find(node.child, "entry_method")) |field| try request.narrow(u8, field.value_low) else 0,
        };
    }

    pub const Read = struct {
        run: *Run,
        archive: []const u8,
        parts: []const []const u8,
        options: rar_archive.DecodeOptions,
        entry: rar_archive.RarInfo = undefined,

        pub fn init(running: *Run, archive: []const u8, tail: []const []const u8) Exception!Read {
            // -hp archives need decrypted-header staging, capped by the largest part.
            const header_scratch = if (running.credentials != null)
                try running.core.workspace.take(u8, @min(rar_header_scratch_size, volumes.largest(archive, tail) + 16))
            else
                try running.core.workspace.take(u8, 0);
            return .{
                .run = running,
                .archive = archive,
                .parts = if (tail.len == 0) &.{} else try volumes.list(archive, tail, running.core.workspace),
                .options = .{
                    .password = request.Credentials.optionalPassword(running.credentials),
                    .scratch = header_scratch,
                    .kdf_rounds_limit = request.Credentials.kdfLimit(running.credentials),
                    .password_lifetime = request.Credentials.lifetime(running.credentials),
                    .failure_cause = &running.cause,
                    .provider = running.provider(),
                },
            };
        }

        pub fn count(self: *Read) Exception!u64 {
            const total = if (self.parts.len == 0)
                try rar_archive.rarInspectCountOpts(self.archive, self.run.limits().entries, self.options)
            else
                try rar_archive.rarVolumeCount(self.parts, self.run.limits().entries, self.options);
            return total;
        }

        pub fn locate(self: *Read, ordinal: u64) Exception!Info {
            const index = std.math.cast(usize, ordinal) orelse return error.ResourceException;
            self.entry = if (self.parts.len == 0)
                try rar_archive.rarInspectOrdinalOpts(self.archive, index, self.run.limits().entries, self.options)
            else
                try rar_archive.rarVolumeInspectOrdinal(self.parts, index, self.run.limits().entries, self.options);
            return Info.from(self.entry);
        }

        pub fn read(self: *Read, ordinal: u64, output: []u8) Exception!usize {
            const index = std.math.cast(usize, ordinal) orelse return error.ResourceException;
            const entry = self.entry;
            const decrypting = self.options.password != null;
            // A split set gathers parts, so its stage covers the whole set.
            const packed_stage = if (self.parts.len != 0)
                try self.run.core.workspace.take(u8, try volumes.totalBytes(self.parts))
            else if (decrypting)
                try self.run.core.workspace.take(u8, @min(self.archive.len, std.math.cast(usize, self.run.limits().encoded_bytes) orelse std.math.maxInt(usize)))
            else
                try self.run.core.workspace.take(u8, 0);
            // The volume walk records one part slot per entry it passes.
            const split_parts = try self.run.core.workspace.take(rar_archive.SplitPart, self.parts.len);
            // One window serves the solid replay; the group maximum arrives with inspect.
            const window_len = std.math.cast(usize, @max(entry.window_bytes, entry.group_window_bytes)) orelse return error.ResourceException;
            var buffers: rar_archive.DecodeBuffers = .{
                .state = &.{},
                .window = &.{},
                .table_pool = &.{},
                .pending50 = &.{},
                .pending29 = &.{},
                .filter_scratch = &.{},
                .ppm_heap = &.{},
                .packed_stage = packed_stage,
                .split_parts = split_parts,
            };
            if (entry.method != 0) {
                const state_octets = try self.run.core.workspace.take(StateOctet, (rar_archive.max_unpacker_bytes + 7) / 8);
                buffers = .{
                    .state = std.mem.sliceAsBytes(state_octets),
                    .window = try self.run.core.workspace.take(u8, window_len),
                    .table_pool = try self.run.core.workspace.take(u16, rar_archive.table_pool_words),
                    .pending50 = try self.run.core.workspace.take(rar_archive.PendingFilter50, rar_archive.max_pending50),
                    .pending29 = try self.run.core.workspace.take(rar_archive.PendingFilter29, rar_archive.max_pending29),
                    .filter_scratch = try self.run.core.workspace.take(u8, window_len + rar_archive.filter_scratch_extra),
                    .ppm_heap = try self.run.core.workspace.take(u8, self.run.core.workspace.remaining()),
                    .packed_stage = packed_stage,
                    .split_parts = split_parts,
                };
            }
            return if (self.parts.len == 0)
                rar_archive.rarDecodeOrdinal(self.archive, index, output, &buffers, self.options)
            else
                rar_archive.rarVolumeDecodeOrdinal(self.parts, index, output, &buffers, self.options);
        }
    };

    pub const Write = struct {
        run: *Run,
        entries: []const Entry,
        options: rar_writer.WriteOptions,
        buffers: rar_writer.WriteBuffers,

        pub fn init(running: *Run, entries: []const Entry) Exception!Write {
            const header_encode = try request.headerEncode("rar", running.requestNode());
            // 1 encrypts file data, 2 also encrypts headers.
            var write_options: rar_writer.WriteOptions = .{
                .password = request.Credentials.passwordOrEmpty(running.credentials),
                .encrypt_headers = header_encode == 2,
                .kdf_rounds_limit = request.Credentials.kdfLimit(running.credentials),
                .failure_cause = &running.cause,
            };
            if (write_options.encrypt_headers and write_options.password.len == 0) return error.CallException;
            // The split granularity opts the RAR5 volume writer in.
            const volume_size = try request.volumeSize(running.requestNode());
            if (volume_size != 0) write_options.volume_size = std.math.cast(usize, volume_size) orelse return error.ResourceException;
            // Recovery redundancy is percent; the writer caps and cross-checks it.
            if (request.componentField(running.requestNode(), "rar", "recovery_percent")) |field| {
                write_options.recovery_percent = try request.narrow(u16, field.value_low);
            }
            var widest: usize = 0;
            var packed_total: usize = 0;
            for (entries) |entry| {
                widest = @max(widest, entry.data.len);
                packed_total = try bounds.addUsize(packed_total, rar_writer.packedBoundEx(entry, write_options.password.len != 0 and !entry.is_directory));
            }
            const sizes = rar_writer.pack50Sizes(widest);
            const packed_buf = try running.core.workspace.take(u8, packed_total);
            // The recovery coder refuses empty tables, so a recovery
            // request takes its GF(2^16) tables from the workspace.
            var buffers = rar_writer.WriteBuffers{
                .hash = try running.core.workspace.take(u32, sizes.hash_words),
                .hash2 = try running.core.workspace.take(u32, sizes.hash2_words),
                .hash3 = try running.core.workspace.take(u32, sizes.hash3_words),
                .bt_left = try running.core.workspace.take(u32, sizes.bt_words),
                .bt_right = try running.core.workspace.take(u32, sizes.bt_words),
                .tokens = try running.core.workspace.take(rar_writer.LzToken, sizes.token_count),
                .staging = try running.core.workspace.take(u8, sizes.staging_bytes),
                .packed_buf = packed_buf,
                .packed_sizes = try running.core.workspace.take(usize, entries.len),
                .crypt_salts = try running.core.workspace.take([16]u8, entries.len),
                .crypt_ivs = try running.core.workspace.take([16]u8, entries.len),
            };
            if (write_options.recovery_percent != 0) {
                buffers.rs_exp = try running.core.workspace.take(u16, rar_recovery.gf_exp_len);
                buffers.rs_log = try running.core.workspace.take(u32, rar_recovery.gf_log_len);
            }
            return .{
                .run = running,
                .entries = entries,
                .options = write_options,
                .buffers = buffers,
            };
        }

        pub fn size(self: *Write) Exception!u64 {
            return try rar_writer.rarWriteSizeEx(self.entries, &self.buffers, self.options);
        }

        pub fn encode(self: *Write, output: []u8) Exception!usize {
            return rar_writer.rarEncodeEx(self.entries, output, &self.buffers, self.run.provider(), self.options);
        }

        pub fn volumePlan(self: *Write, volume_size: u64) Exception!write.Extent {
            // The granularity already rides the write options; the plan reads it there.
            _ = volume_size;
            const plan = try rar_writer.rarVolumeSize(self.entries, &self.buffers, self.options);
            return .{ .total = plan.total, .count = plan.count };
        }

        pub fn volumeEmit(self: *Write, output: []u8, volume_size: u64, extent: write.Extent) Exception![]const []const u8 {
            _ = volume_size;
            const slices = try self.run.core.workspace.take([]u8, extent.count);
            if (try rar_writer.rarEncodeVolumes(self.entries, output, slices, &self.buffers, self.run.provider(), self.options) != extent.count) return error.InternalException;
            const parts = try self.run.core.workspace.take([]const u8, extent.count);
            for (slices, 0..) |slice, index| parts[index] = slice;
            return parts;
        }
    };
};
