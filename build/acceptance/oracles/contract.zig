const std = @import("std");

const contract = @import("nucleus").contract;
const kernel = @import("kernel");

// Enumeration must cover class-shaped verbs and omit absent components (miss maps to unsupported).
const CatalogEntry = struct {
    name: []const u8,
    kind: []const u8,
};

const Catalog = struct {
    descriptors: []CatalogEntry,
};

var failures: usize = 0;

fn check(ok_condition: bool, label: []const u8) void {
    if (ok_condition) {
        std.debug.print("ok {s}\n", .{label});
    } else {
        std.debug.print("FAIL {s}\n", .{label});
        failures += 1;
    }
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const catalog_path = args.next() orelse return error.MissingArgument;
    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, catalog_path, allocator, .limited(1 << 24));
    const catalog = try std.json.parseFromSliceLeaky(Catalog, allocator, text, .{ .ignore_unknown_fields = true });

    const mapping = [_]struct { profile: []const u8, component: []const u8 }{
        .{ .profile = "deflate", .component = "deflate" },
        .{ .profile = "gzip", .component = "gzip" },
        .{ .profile = "tar", .component = "tar" },
        .{ .profile = "zip", .component = "zip" },
        .{ .profile = "zstd", .component = "zstd" },
        .{ .profile = "sevenzip", .component = "sevenzip" },
        .{ .profile = "bzip2", .component = "bzip2" },
        .{ .profile = "lzma", .component = "lzma" },
        .{ .profile = "lzma_file", .component = "lzma-file" },
        .{ .profile = "lzma2", .component = "lzma2" },
        .{ .profile = "xz", .component = "xz" },
        .{ .profile = "sevenzip", .component = "sevenzip" },
        .{ .profile = "rar", .component = "rar" },
    };

    var catalog_profiles: usize = 0;
    for (catalog.descriptors) |entry| {
        if (!std.mem.eql(u8, entry.kind, "profile")) continue;
        catalog_profiles += 1;
        for (&mapping) |pair| {
            if (std.mem.eql(u8, entry.name, pair.profile)) {
                check(kernel.discovery.findByName(pair.component) != null, pair.profile);
            }
        }
    }
    // One profile row per component plus descriptor-less protocol fixtures.
    const all = kernel.discovery.enumerate();
    check(catalog_profiles == all.len, "catalog profile count");
    check(all.len == 18, "descriptor count");
    for (all) |*descriptor| {
        check(kernel.discovery.findById(descriptor.id) == descriptor, "id lookup round trip");
    }

    for (all) |*descriptor| {
        var missing_non_encode = false;
        for (contract.verbsFor(descriptor.class)) |verb| {
            const encode_direction = verb == .encode or verb == .encode_stream or verb == .encode_ordinal;
            var present = false;
            for (descriptor.verbs) |declared| {
                if (declared == verb) present = true;
            }
            if (!present and !encode_direction) missing_non_encode = true;
        }
        check(!missing_non_encode, descriptor.name);
    }

    check(kernel.discovery.findByName("absent-component") == null, "absent lookup omitted");

    if (failures != 0) std.process.exit(1);
    std.debug.print("contract check: all checks passed\n", .{});
}
