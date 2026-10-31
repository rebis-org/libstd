const std = @import("std");

const components = @import("components");
// The shared interface surface: spans, contract types, diagnostics.
pub const interface = @import("interface");
const contract = @import("interface").contract;

// Session and driver composition primitives for caller-assembled work.
pub const composition = @import("compose/composition.zig");
pub const drivers = @import("compose/drivers.zig");
pub const executor = @import("compose/executor.zig");
pub const machines = @import("compose/machines.zig");
pub const sessions = @import("compose/sessions.zig");

pub const ProfileTag = components.ProfileTag;
pub const Descriptor = contract.Descriptor;

// The representation descriptors behind the namespaces below, read-only.
// This is the same generated table the catalog document serves, so the
// two cannot drift. The protocol fixtures stay out of the projection.

pub const descriptors = blk: {
    @setEvalBranchQuota(50_000);
    var list: [components.descriptors.len]contract.Descriptor = undefined;
    var count: usize = 0;
    for (components.descriptors) |descriptor| {
        if (isProtocolFixture(descriptor.name)) continue;
        list[count] = descriptor;
        count += 1;
    }
    break :blk list[0..count].*;
};

// The tag behind a descriptor's wire name; null for a name no descriptor claims.
pub fn tagForName(comptime name: []const u8) ?ProfileTag {
    return components.tagForName(name);
}

fn isProtocolFixture(comptime name: []const u8) bool {
    return std.mem.eql(u8, name, "test_echo") or
        std.mem.eql(u8, name, "test_read") or
        std.mem.eql(u8, name, "crypto");
}

// Format implementations by layer. Entries are the existing onprem modules;
// nothing is re-wrapped, so every format keeps its own types and verbs.
pub const leaf = struct {
    pub const bcj = @import("representation/leaf/bcj/onprem.zig");
    pub const bcj2 = @import("representation/leaf/bcj2/onprem.zig");
    pub const brotli = @import("representation/leaf/brotli/onprem.zig");
    pub const bzip2 = @import("representation/leaf/bzip2/onprem.zig");
    pub const deflate = @import("representation/leaf/deflate/onprem.zig");
    pub const delta = @import("representation/leaf/delta/onprem.zig");
    pub const lz4 = @import("representation/leaf/lz4/onprem.zig");
    pub const lzma = @import("representation/leaf/lzma/onprem.zig");
    pub const lzma2 = @import("representation/leaf/lzma2/onprem.zig");
    pub const lzo = @import("representation/leaf/lzo/onprem.zig");
    pub const ppmd = @import("representation/leaf/ppmd/onprem.zig");
    pub const zstd = @import("representation/leaf/zstd/onprem.zig");
    // Dictionary operations live on the zstd implementation itself.
    pub const zdict = zstd;
};

pub const grammar = struct {
    pub const age = @import("representation/grammar/age/onprem.zig");
    pub const cpio = @import("representation/grammar/cpio/onprem.zig");
    pub const gzip = @import("representation/grammar/gzip/onprem.zig");
    // The generated tag keeps the wire name's hyphen; the module keeps the
    // existing directory name.
    pub const lzma_file = @import("representation/grammar/lzma/onprem.zig");
    pub const pkg = @import("representation/grammar/pkg/onprem.zig");
    pub const rar = struct {
        pub const onprem = @import("representation/grammar/rar/onprem.zig");
        pub const writer = @import("representation/grammar/rar/writer.zig");
    };
    pub const sevenzip = @import("representation/grammar/sevenzip/onprem.zig");
    pub const tar = @import("representation/grammar/tar/onprem.zig");
    pub const wim = @import("representation/grammar/wim/onprem.zig");
    pub const xar = @import("representation/grammar/xar/onprem.zig");
    pub const xip = @import("representation/grammar/xip/onprem.zig");
    pub const xz = @import("representation/grammar/xz/onprem.zig");
    pub const zip = @import("representation/grammar/zip/onprem.zig");
    pub const zlib = @import("representation/grammar/zlib/onprem.zig");
    pub const zstd_seekable = @import("representation/grammar/zstd_seekable/onprem.zig");
};

pub const volume = struct {
    pub const apfs = @import("representation/volume/apfs/onprem.zig");
    pub const dwarfs = @import("representation/volume/dwarfs/onprem.zig");
    pub const iso = @import("representation/volume/iso/onprem.zig");
    pub const squashfs = @import("representation/volume/squashfs/onprem.zig");
};

// Provider-parameterized variants, only where a format already has one.
pub const seam = struct {
    pub const zstd = @import("representation/leaf/zstd/seam.zig");
    pub const lzma = @import("representation/leaf/lzma/seam.zig");
    pub const lzma2 = @import("representation/leaf/lzma2/seam.zig");
    pub const brotli = @import("representation/leaf/brotli/seam.zig");
    pub const deflate = @import("representation/leaf/deflate/seam.zig");
    pub const age = @import("representation/grammar/age/seam.zig");
    pub const cpio = @import("representation/grammar/cpio/seam.zig");
    pub const tar = @import("representation/grammar/tar/seam.zig");
    pub const wim = @import("representation/grammar/wim/seam.zig");
    pub const xar = @import("representation/grammar/xar/seam.zig");
    pub const xip = @import("representation/grammar/xip/seam.zig");
    pub const apfs = @import("representation/volume/apfs/seam.zig");
    pub const dwarfs = @import("representation/volume/dwarfs/seam.zig");
    pub const iso = @import("representation/volume/iso/seam.zig");
    pub const squashfs = @import("representation/volume/squashfs/seam.zig");
};

// The projection from a profile tag to its public namespace. Protocol
// fixtures resolve to null: they stay outside the format namespace.
pub fn namespaceFor(comptime tag: components.ProfileTag) ?type {
    return switch (tag) {
        .age => grammar.age,
        .apfs => volume.apfs,
        .bcj => leaf.bcj,
        .bcj2 => leaf.bcj2,
        .brotli => leaf.brotli,
        .bzip2 => leaf.bzip2,
        .cpio => grammar.cpio,
        .deflate => leaf.deflate,
        .delta => leaf.delta,
        .dwarfs => volume.dwarfs,
        .gzip => grammar.gzip,
        .iso => volume.iso,
        .lz4 => leaf.lz4,
        .lzma => leaf.lzma,
        .lzma_file => grammar.lzma_file,
        .lzma2 => leaf.lzma2,
        .lzo => leaf.lzo,
        .ppmd => leaf.ppmd,
        .pkg => grammar.pkg,
        .rar => grammar.rar,
        .sevenzip => grammar.sevenzip,
        .squashfs => volume.squashfs,
        .tar => grammar.tar,
        .wim => grammar.wim,
        .xar => grammar.xar,
        .xip => grammar.xip,
        .xz => grammar.xz,
        .zdict => leaf.zdict,
        .zip => grammar.zip,
        .zlib => grammar.zlib,
        .zstd => leaf.zstd,
        .zstd_seekable => grammar.zstd_seekable,
        .test_echo, .test_read, .crypto => null,
    };
}

comptime {
    @setEvalBranchQuota(100_000);
    // Every representation descriptor resolves to a public namespace. A new
    // descriptor without an assembly entry, a renamed entry, or a stale one
    // all fail compilation here or in the switch above.
    for (components.descriptors) |descriptor| {
        if (isProtocolFixture(descriptor.name)) continue;
        const tag = components.tagForName(descriptor.name) orelse
            @compileError("representation descriptor has no profile tag: " ++ descriptor.name);
        if (namespaceFor(tag) == null)
            @compileError("representation descriptor has no public assembly namespace: " ++ descriptor.name);
    }
}
