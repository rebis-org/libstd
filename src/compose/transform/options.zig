const std = @import("std");

const discovery = @import("../../kernel/discovery.zig");
const abi = @import("../../kernel/envelope.zig");
const node_graph = @import("../../kernel/node.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const gzip = @import("../../representation/grammar/gzip/onprem.zig");
const lzma_file = @import("../../representation/grammar/lzma/onprem.zig");
const xz = @import("../../representation/grammar/xz/onprem.zig");
const brotli = @import("../../representation/leaf/brotli/onprem.zig");
const bzip2 = @import("../../representation/leaf/bzip2/onprem.zig");
const deflate = @import("../../representation/leaf/deflate/onprem.zig");
const lz4 = @import("../../representation/leaf/lz4/onprem.zig");
const lzma = @import("../../representation/leaf/lzma/onprem.zig");
const ppmd = @import("../../representation/leaf/ppmd/onprem.zig");
const zstd = @import("../../representation/leaf/zstd/onprem.zig");

const Node = abi.Node;
const Exception = vocabulary.Exception;

const deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 };

// The one place a request node becomes a typed value; a projection only asks whether a selector is present.
pub fn optNode(request: ?*Node, comptime component: []const u8, comptime name: []const u8) ?*Node {
    const param = comptime discovery.parameter(component, name);
    return node_graph.findSelector(request, param.family, param.ordinal);
}

pub fn optCast(request: ?*Node, comptime component: []const u8, comptime name: []const u8, comptime T: type) Exception!?T {
    const node = optNode(request, component, name) orelse return null;
    return std.math.cast(T, node.value_low) orelse error.CallException;
}

fn optBool(request: ?*Node, comptime component: []const u8, comptime name: []const u8) bool {
    const node = optNode(request, component, name) orelse return false;
    return node.value_low != 0;
}

pub fn optBytes(request: ?*Node, comptime component: []const u8, comptime name: []const u8) Exception!?[]const u8 {
    const node = optNode(request, component, name) orelse return null;
    return try resource.checkedConstBytes(node.bytes, node.byte_length);
}

pub fn parsePpmdOptions(request: ?*Node) Exception!ppmd.Options {
    var options: ppmd.Options = .{ .order = 6, .mem_size = 16 << 20 };
    if (try optCast(request, "ppmd", "order", u32)) |value| options.order = value;
    if (try optCast(request, "ppmd", "memory", u32)) |value| options.mem_size = value;
    if (try optCast(request, "ppmd", "unpack_size", u64)) |value| options.unpack_size = value;
    return options;
}

pub fn parseGzipOptions(request: ?*Node, command_mask: u32) Exception!gzip.Options {
    var options: gzip.Options = .{
        .modification_time = 0,
        .extra_flags = 0,
        .operating_system = 255,
        .text = false,
        .header_crc = false,
        .extra = &.{},
        .name = &.{},
        .comment = &.{},
        .deflate = try parseDeflateOptions(request, command_mask),
    };
    if (try optCast(request, "gzip", "modification_time", u32)) |value| options.modification_time = value;
    if (try optCast(request, "gzip", "extra_flags", u8)) |value| options.extra_flags = value;
    if (try optCast(request, "gzip", "operating_system", u8)) |value| options.operating_system = value;
    options.text = optBool(request, "gzip", "text");
    options.header_crc = optBool(request, "gzip", "header_crc");
    if (try optBytes(request, "gzip", "extra")) |value| options.extra = value;
    if (try optBytes(request, "gzip", "name")) |value| options.name = value;
    if (try optBytes(request, "gzip", "comment")) |value| options.comment = value;
    return options;
}

pub fn parseDeflateOptions(request: ?*Node, command_mask: u32) Exception!deflate.Options {
    var options = deflate_options;
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return options;
    if (try optCast(request, "deflate", "good", u16)) |value| options.good = value;
    if (try optCast(request, "deflate", "nice", u16)) |value| options.nice = value;
    if (try optCast(request, "deflate", "lazy", u16)) |value| options.lazy = value;
    if (try optCast(request, "deflate", "chain", u16)) |value| options.chain = value;
    if (optNode(request, "deflate", "optimal")) |node| options.optimal = node.value_low != 0;
    if (optNode(request, "deflate", "strategy")) |node| {
        if (node.value_low > @backingInt(deflate.Strategy.rle)) return error.CallException;
        options.strategy = @fromBackingInt(@intCast(node.value_low));
    }
    return options;
}

pub fn parseLz4Options(request: ?*Node, command_mask: u32) Exception!lz4.Options {
    var options: lz4.Options = .{};
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return options;
    if (try optCast(request, "lz4", "block_size", u32)) |value| options.block_size = value;
    if (optNode(request, "lz4", "block_checksum")) |node| options.block_checksum = node.value_low != 0;
    if (optNode(request, "lz4", "content_checksum")) |node| options.content_checksum = node.value_low != 0;
    if (try optCast(request, "lz4", "acceleration", u32)) |value| options.acceleration = value;
    if (try optCast(request, "lz4", "search_depth", u32)) |value| options.search_depth = value;
    return options;
}

pub fn parseZstdOptions(request: ?*Node, command_mask: u32) Exception!zstd.Options {
    var options: zstd.Options = .{
        .window_size = try parseZstdWindow(optNode(request, "zstd", "window")),
        .dictionary = try parseZstdDictionary(optNode(request, "zstd", "dictionary")),
    };
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(request, "zstd", "hash_bits", u5)) |hash_bits| {
            if (hash_bits < 10 or hash_bits > 17) return error.CallException;
            options.hash_bits = hash_bits;
        }
        if (try optCast(request, "zstd", "max_chain", u32)) |max_chain| {
            if (max_chain == 0) return error.CallException;
            options.max_chain = max_chain;
        }
        if (try optCast(request, "zstd", "nice_len", u32)) |nice_len| {
            if (nice_len < 3) return error.CallException;
            options.nice_len = nice_len;
        }
        if (try optCast(request, "zstd", "search_window", u32)) |search_window| {
            if (search_window == 0) return error.CallException;
            options.search_window = search_window;
        }
        if (optNode(request, "zstd", "lazy")) |node| options.lazy = node.value_low != 0;
        if (optNode(request, "zstd", "skip_interior_insert")) |node| options.skip_interior_insert = node.value_low != 0;
        if (optNode(request, "zstd", "double_hash")) |node| options.double_hash = node.value_low != 0;
        if (optNode(request, "zstd", "row_match")) |node| options.row_match = node.value_low != 0;
        if (try optCast(request, "zstd", "strategy", u32)) |strategy| {
            if (strategy > 3) return error.CallException;
            options.strategy = strategy;
        }
        if (try optCast(request, "zstd", "entropy", u32)) |entropy| {
            if (entropy > 1) return error.CallException;
            options.entropy = entropy;
        }
    }
    return options;
}

fn parseZstdWindow(node: ?*Node) Exception!u32 {
    const n = node orelse return error.CallException;
    const window = std.math.cast(u32, n.value_low) orelse return error.CallException;
    if (window < zstd.window_size_min or window > zstd.window_size_max) return error.CallException;
    return window;
}

fn parseZstdDictionary(node: ?*Node) Exception!?[]const u8 {
    const n = node orelse return null;
    if (n.value_low != 0 or n.child != null) return error.CallException;
    return @as(?[]const u8, try resource.checkedConstBytes(n.bytes, n.byte_length));
}

pub fn parseBrotliOptions(request: ?*Node, command_mask: u32) Exception!brotli.Options {
    var options: brotli.Options = .{};
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(request, "brotli", "quality", u32)) |quality| {
            if (quality > 11) return error.CallException;
            options.quality = quality;
        }
    }
    return options;
}

pub fn parseBzip2Options(request: ?*Node, command_mask: u32) Exception!bzip2.Options {
    var options: bzip2.Options = .{};
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(request, "bzip2", "block_size", u32)) |block_size| {
            if (block_size < bzip2.block_size_min or block_size > bzip2.block_size_max) return error.CallException;
            options.block_size = block_size;
        }
    }
    return options;
}

fn parseDictionary(comptime component: []const u8, request: ?*Node, fallback: ?u32) Exception!u32 {
    const dictionary_size = (try optCast(request, component, "dictionary", u32)) orelse {
        if (fallback) |size| return size;
        return error.CallException;
    };
    if (dictionary_size < lzma.dictionary_min or dictionary_size > lzma.dictionary_max) return error.CallException;
    return dictionary_size;
}

pub fn parseLzmaDictionary(request: ?*Node) Exception!u32 {
    return parseDictionary("lzma", request, null);
}

pub fn parseLzmaFileDictionary(request: ?*Node) Exception!u32 {
    return parseDictionary("lzma-file", request, lzma_file.default_dictionary);
}

pub const LzmaMatchParams = struct {
    match_finder_depth: u32 = 32,
    lazy: bool = false,
    lazy_set: bool = false,
    nice_len: u32 = 273,
    match_finder: lzma.MatchFinder = .bt4,
};

pub fn parseLzmaMatchParams(request: ?*Node, command_mask: u32) Exception!LzmaMatchParams {
    var params = LzmaMatchParams{};
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return params;
    if (try optCast(request, "lzma", "match_finder_depth", u32)) |depth| {
        if (depth == 0) return error.CallException;
        params.match_finder_depth = depth;
    }
    if (optNode(request, "lzma", "lazy")) |node| {
        params.lazy = node.value_low != 0;
        params.lazy_set = true;
    }
    if (try optCast(request, "lzma", "nice_len", u32)) |nice_len| {
        if (nice_len < 2 or nice_len > 273) return error.CallException;
        params.nice_len = nice_len;
    }
    if (optNode(request, "lzma", "match_finder")) |node| {
        params.match_finder = switch (node.value_low) {
            0 => .hash_chain,
            1 => .bt4,
            else => return error.CallException,
        };
    }
    // BT4 defaults to lazy matching unless the caller explicitly opts into greedy.
    if (!params.lazy_set and params.match_finder == .bt4) {
        params.lazy = true;
    }
    return params;
}

pub fn parseXzCheck(node: ?*Node) Exception!xz.CheckType {
    const n = node orelse return .crc32;
    const value = n.value_low;
    return switch (value) {
        0 => .none,
        1 => .crc32,
        4 => .crc64,
        0x0A => .sha256,
        else => error.UnsupportedException,
    };
}

pub fn parseXzFilters(node: ?*Node) Exception!xz.FilterChoice {
    const n = node orelse return .none;
    const value: u32 = @truncate(n.value_low);
    return switch (value) {
        0 => .none,
        1 => .delta,
        2 => .x86,
        3 => .ppc,
        4 => .ia64,
        5 => .arm,
        6 => .armt,
        7 => .sparc,
        8 => .arm64,
        9 => .riscv,
        else => error.CallException,
    };
}
