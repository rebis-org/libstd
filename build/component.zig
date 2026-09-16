const std = @import("std");

// Emits a comptime table so adding or removing a component touches only its own files.
const RawParameter = struct {
    name: []const u8,
    family: u16,
    ordinal: u8,
    representation: []const u8,
};

const RawLimits = struct {
    window: u64 = 0,
    block: u64 = 0,
    history: u64 = 0,
};

const RawParameterValue = struct { family: u16, ordinal: u32, value: u64 };

const RawTuning = struct {
    name: []const u8 = "",
    params: []const RawParameterValue = &.{},
    ref_params: []const u8 = "",
    cmd_args: []const []const u8 = &.{},
    lib_level: ?i32 = null,
    bypass: bool = false,
};

const RawBenchmark = struct {
    row: []const u8,
    params: []const u8 = "",
    kind: []const u8,
    ext: []const u8,
    cmd: ?[]const u8 = null,
    lib: ?[]const u8 = null,
    bin: ?[]const u8 = null,
    fmt: u8 = 0,
    store: bool = false,
    archive: bool = false,
    method: bool = false,
    decode_only: bool = false,
    ref_params: []const u8 = "",
    tunings: []const RawTuning = &.{},
};

const RawId = struct {
    low: []const u8,
    high: []const u8,
};

const RawDescriptor = struct {
    id: RawId,
    name: []const u8,
    class: []const u8,
    verbs: []const []const u8,
    parameters: []const RawParameter = &.{},
    capabilities: []const []const u8 = &.{},
    sizing: []const u8 = "unavailable",
    commit: []const u8 = "tentative",
    limits: RawLimits = .{},
    benchmark: ?RawBenchmark = null,
};

const known_classes = [_][]const u8{ "slice", "streaming", "grammar", "filter" };
const known_verbs = [_][]const u8{
    "required_size", "decoded_size",  "encoded_size_bound", "encode",         "decode",
    "encode_stream", "decode_stream", "inspect",            "decode_ordinal", "encode_ordinal",
};
const known_representations = [_][]const u8{ "scalar_words", "bytes", "node_chain", "none" };
const known_capabilities = [_][]const u8{ "read", "write", "size", "replay", "seek", "range" };
const known_sizing = [_][]const u8{ "unavailable", "metadata_exact", "measured" };
const known_commit = [_][]const u8{ "tentative", "confirmed" };

// Maps verbs to command bits: sizing answers query, decode serves read, encode serves write.
fn commandBitForVerb(verb: []const u8) ?u32 {
    if (std.mem.eql(u8, verb, "required_size") or std.mem.eql(u8, verb, "decoded_size") or std.mem.eql(u8, verb, "encoded_size_bound") or std.mem.eql(u8, verb, "inspect")) return 1;
    if (std.mem.eql(u8, verb, "decode") or std.mem.eql(u8, verb, "decode_stream") or std.mem.eql(u8, verb, "decode_ordinal")) return 2;
    if (std.mem.eql(u8, verb, "encode") or std.mem.eql(u8, verb, "encode_stream") or std.mem.eql(u8, verb, "encode_ordinal")) return 4;
    return null;
}

fn contains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| if (std.mem.eql(u8, item, needle)) return true;
    return false;
}

fn safeText(text: []const u8) bool {
    for (text) |character| {
        if (character == '"' or character == '\\' or character < 0x20) return false;
    }
    return true;
}

fn quoted(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "\"{s}\"", .{value});
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    // Explicit file args keep the scan's cache key honest in both directions.
    var descriptors: std.ArrayList(RawDescriptor) = .empty;
    var output_path: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (!std.mem.endsWith(u8, arg, ".descriptor.zon")) {
            output_path = arg;
            break;
        }
        const text = try std.Io.Dir.cwd().readFileAlloc(init.io, arg, allocator, .limited(1 << 20));
        const source = try allocator.dupeZ(u8, text);
        var diagnostics: std.zon.parse.Diagnostics = .{};
        const parsed = std.zon.parse.fromSliceAlloc(RawDescriptor, allocator, source, &diagnostics, .{}) catch |err| {
            std.debug.print("Failed to parse descriptor \"{s}\": {s}.\n", .{ arg, @errorName(err) });
            return err;
        };
        try descriptors.append(allocator, parsed);
    }
    const resolved_output_path = output_path orelse return error.MissingArgument;

    std.mem.sort(RawDescriptor, descriptors.items, {}, struct {
        fn lessThan(_: void, left: RawDescriptor, right: RawDescriptor) bool {
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.lessThan);

    for (descriptors.items) |descriptor| {
        if (!contains(&known_classes, descriptor.class)) return error.UnknownClass;
        for (descriptor.verbs) |verb| if (!contains(&known_verbs, verb)) return error.UnknownVerb;
        for (descriptor.parameters) |parameter| {
            if (!contains(&known_representations, parameter.representation)) return error.UnknownRepresentation;
        }
        for (descriptor.capabilities) |capability| if (!contains(&known_capabilities, capability)) return error.UnknownCapability;
        if (!contains(&known_sizing, descriptor.sizing)) return error.UnknownSizing;
        if (!contains(&known_commit, descriptor.commit)) return error.UnknownCommit;
        if (!safeText(descriptor.name)) return error.UnsafeText;
        if (descriptor.benchmark) |benchmark| {
            if (!safeText(benchmark.row) or !safeText(benchmark.params)) return error.UnsafeText;
        }
    }
    for (descriptors.items, 0..) |descriptor, index| {
        for (descriptors.items[index + 1 ..]) |other| {
            if (std.mem.eql(u8, descriptor.name, other.name)) return error.DuplicateName;
            if (std.mem.eql(u8, descriptor.id.low, other.id.low) and std.mem.eql(u8, descriptor.id.high, other.id.high)) return error.DuplicateId;
        }
    }

    var output: std.ArrayList(u8) = .empty;
    try output.appendSlice(allocator, "const contract = @import(\"nucleus\").contract;\n\npub const descriptors = [_]contract.Descriptor{\n");
    for (descriptors.items) |descriptor| {
        try output.print(allocator, "    .{{ .id = .{{ .low = {s}, .high = {s} }}, .name = \"{s}\", .class = .{s}, .verbs = &.{{ ", .{ descriptor.id.low, descriptor.id.high, descriptor.name, descriptor.class });
        for (descriptor.verbs, 0..) |verb, verb_index| {
            if (verb_index != 0) try output.appendSlice(allocator, ", ");
            try output.print(allocator, ".{s}", .{verb});
        }
        try output.appendSlice(allocator, " }, .parameters = &.{ ");
        for (descriptor.parameters, 0..) |parameter, parameter_index| {
            if (parameter_index != 0) try output.appendSlice(allocator, ", ");
            try output.print(allocator, ".{{ .name = \"{s}\", .family = {d}, .ordinal = {d}, .representation = .{s} }}", .{ parameter.name, parameter.family, parameter.ordinal, parameter.representation });
        }
        try output.appendSlice(allocator, " }, .capabilities = ");
        var bits: u32 = 0;
        for (descriptor.capabilities) |capability| {
            for (known_capabilities, 0..) |bit_name, bit_index| {
                if (std.mem.eql(u8, bit_name, capability)) {
                    bits |= @as(u32, 1) << @intCast(bit_index);
                }
            }
        }
        var command_mask: u32 = 0;
        for (descriptor.verbs) |verb| {
            command_mask |= commandBitForVerb(verb) orelse return error.UnknownVerb;
        }
        try output.print(allocator, "{d}, .command_mask = {d}, .sizing = .{s}, .commit = .{s}, .limits = .{{ .window = {d}, .block = {d}, .history = {d} }}", .{ bits, command_mask, descriptor.sizing, descriptor.commit, descriptor.limits.window, descriptor.limits.block, descriptor.limits.history });
        if (descriptor.benchmark) |benchmark| {
            try output.print(allocator, ", .benchmark = .{{ .row = \"{s}\", .params = \"{s}\" }}", .{ benchmark.row, benchmark.params });
        }
        try output.appendSlice(allocator, " },\n");
    }
    try output.appendSlice(allocator, "};\n\n");
    try output.appendSlice(allocator, "pub const Param = struct { family: u16, ordinal: u32, value: u64 };\n");
    try output.appendSlice(allocator, "pub const Tuning = struct { name: []const u8, params: []const Param, ref_params: []const u8, cmd_args: []const []const u8, lib_level: ?i32, bypass: bool };\n");
    try output.appendSlice(allocator, "pub const Benchmark = struct { row: []const u8, params: []const u8, kind: []const u8, ext: []const u8, cmd: ?[]const u8, lib: ?[]const u8, bin: ?[]const u8, fmt: u8, store: bool, archive: bool, method: bool, decode_only: bool, ref_params: []const u8, tunings: []const Tuning };\n\n");
    try output.appendSlice(allocator, "pub const benchmarks = [_]Benchmark{");
    for (descriptors.items) |descriptor| {
        const benchmark = descriptor.benchmark orelse continue;
        try output.print(allocator, ".{{ .row = \"{s}\", .params = \"{s}\", .kind = \"{s}\", .ext = \"{s}\", .cmd = {s}, .lib = {s}, .bin = {s}, .fmt = {d}, .store = {}, .archive = {}, .method = {}, .decode_only = {}, .ref_params = \"{s}\", .tunings = &.{{ ", .{
            benchmark.row,
            benchmark.params,
            benchmark.kind,
            benchmark.ext,
            if (benchmark.cmd) |value| try quoted(allocator, value) else "null",
            if (benchmark.lib) |value| try quoted(allocator, value) else "null",
            if (benchmark.bin) |value| try quoted(allocator, value) else "null",
            benchmark.fmt,
            benchmark.store,
            benchmark.archive,
            benchmark.method,
            benchmark.decode_only,
            benchmark.ref_params,
        });
        for (benchmark.tunings) |tuning| {
            try output.print(allocator, ".{{ .name = \"{s}\", .params = &.{{ ", .{tuning.name});
            for (tuning.params) |param| {
                try output.print(allocator, ".{{ .family = {d}, .ordinal = {d}, .value = {d} }}, ", .{ param.family, param.ordinal, param.value });
            }
            try output.appendSlice(allocator, "}, .ref_params = \"");
            try output.appendSlice(allocator, tuning.ref_params);
            try output.appendSlice(allocator, "\", .cmd_args = &.{ ");
            for (tuning.cmd_args) |arg| {
                try output.print(allocator, "\"{s}\", ", .{arg});
            }
            try output.print(allocator, "}}, .lib_level = {?}, .bypass = {} }}, ", .{ tuning.lib_level, tuning.bypass });
        }
        try output.appendSlice(allocator, "} },\n");
    }
    try output.appendSlice(allocator, "};\n");

    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = resolved_output_path, .data = output.items });
}
