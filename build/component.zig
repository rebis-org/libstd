const std = @import("std");

// Emits a comptime table, so a component change touches only its own files.
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

// Verb groups map to command bits: a sizing verb answers a query, a decode verb
// serves a read, and an encode verb serves a write.
const sizing_verbs = [_][]const u8{ "required_size", "decoded_size", "encoded_size_bound", "inspect" };
const decode_verbs = [_][]const u8{ "decode", "decode_stream", "decode_ordinal" };
const encode_verbs = [_][]const u8{ "encode", "encode_stream", "encode_ordinal" };

fn commandBitForVerb(verb: []const u8) ?u32 {
    if (has(&sizing_verbs, verb)) return 1;
    if (has(&decode_verbs, verb)) return 2;
    if (has(&encode_verbs, verb)) return 4;
    return null;
}

fn has(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |item| if (std.mem.eql(u8, item, needle)) return true;
    return false;
}

fn isSafeText(text: []const u8) bool {
    for (text) |character| {
        if (character == '"' or character == '\\' or character < 0x20) return false;
    }
    return true;
}

fn isSafeTag(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text, 0..) |character, index| {
        const word = character == '_' or character == '-' or
            (character >= 'a' and character <= 'z') or
            (character >= 'A' and character <= 'Z') or
            (index != 0 and character >= '0' and character <= '9');
        if (!word) return false;
    }
    return true;
}

fn quote(allocator: std.mem.Allocator, inner: []const u8) ![]const u8 {
    return allocator.print("\"{s}\"", .{inner});
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    // Each descriptor is a file argument, because a directory argument is unfingerprinted.
    var descriptors: std.ArrayList(RawDescriptor) = .empty;
    var output_path: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (!std.mem.endsWith(u8, arg, ".descriptor.zon")) {
            output_path = arg;
            break;
        }
        const text = try std.Io.Dir.cwd().readFileAlloc(init.io, arg, allocator, .limited(1 << 20));
        const source = try allocator.dupeSentinel(u8, text, 0);
        var diagnostics: std.zon.parse.Diagnostics = undefined;
        const parsed = std.zon.parse.fromSlice(RawDescriptor, .{
            .gpa = std.heap.page_allocator,
            .arena = allocator,
            .source = source,
            .diagnostics = &diagnostics,
        }) catch |err| {
            std.debug.print("failed to parse descriptor \"{s}\": {s}.\n", .{ arg, @errorName(err) });
            return err;
        };
        try descriptors.append(allocator, parsed);
    }
    const resolved_output_path = output_path orelse return error.missing_argument;

    std.mem.sort(RawDescriptor, descriptors.items, {}, struct {
        fn lessThan(_: void, left: RawDescriptor, right: RawDescriptor) bool {
            return std.mem.order(u8, left.name, right.name) == .lt;
        }
    }.lessThan);

    for (descriptors.items) |descriptor| {
        if (!has(&known_classes, descriptor.class)) return error.unknown_class;
        for (descriptor.verbs) |verb| if (!has(&known_verbs, verb)) return error.unknown_verb;
        for (descriptor.parameters) |parameter| {
            if (!has(&known_representations, parameter.representation)) return error.unknown_representation;
            if (!isSafeText(parameter.name)) return error.unsafe_text;
        }
        for (descriptor.capabilities) |capability| if (!has(&known_capabilities, capability)) return error.unknown_capability;
        if (!has(&known_sizing, descriptor.sizing)) return error.unknown_sizing;
        if (!has(&known_commit, descriptor.commit)) return error.unknown_commit;
        if (!isSafeText(descriptor.name) or !isSafeTag(descriptor.name)) return error.unsafe_text;
        if (!isSafeText(descriptor.id.low) or !isSafeText(descriptor.id.high)) return error.unsafe_text;
        if (descriptor.benchmark) |benchmark| {
            if (!isSafeText(benchmark.row) or !isSafeText(benchmark.params)) return error.unsafe_text;
            if (!isSafeText(benchmark.kind) or !isSafeText(benchmark.ext) or !isSafeText(benchmark.ref_params)) return error.unsafe_text;
            if (benchmark.cmd) |text| if (!isSafeText(text)) return error.unsafe_text;
            if (benchmark.lib) |text| if (!isSafeText(text)) return error.unsafe_text;
            if (benchmark.bin) |text| if (!isSafeText(text)) return error.unsafe_text;
            for (benchmark.tunings) |tuning| {
                if (!isSafeText(tuning.name) or !isSafeText(tuning.ref_params)) return error.unsafe_text;
                for (tuning.cmd_args) |arg| if (!isSafeText(arg)) return error.unsafe_text;
            }
        }
    }
    for (descriptors.items, 0..) |descriptor, index| {
        for (descriptors.items[index + 1 ..]) |other| {
            if (std.mem.eql(u8, descriptor.name, other.name)) return error.duplicate_name;
            if (std.mem.eql(u8, descriptor.id.low, other.id.low) and std.mem.eql(u8, descriptor.id.high, other.id.high)) return error.duplicate_id;
        }
    }

    var output: std.ArrayList(u8) = .empty;
    try output.appendSlice(allocator, "const std = @import(\"std\");\nconst contract = @import(\"interface\").contract;\n\npub const descriptors = [_]contract.Descriptor{\n");
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
        var capability_bits: u32 = 0;
        for (descriptor.capabilities) |capability| {
            for (known_capabilities, 0..) |bit_name, bit_index| {
                if (std.mem.eql(u8, bit_name, capability)) {
                    capability_bits |= @as(u32, 1) << @intCast(bit_index);
                }
            }
        }
        var command_mask: u32 = 0;
        for (descriptor.verbs) |verb| {
            command_mask |= commandBitForVerb(verb) orelse return error.unknown_verb;
        }
        try output.print(allocator, "{d}, .command_mask = {d}, .sizing = .{s}, .commit = .{s}, .limits = .{{ .window = {d}, .block = {d}, .history = {d} }}", .{ capability_bits, command_mask, descriptor.sizing, descriptor.commit, descriptor.limits.window, descriptor.limits.block, descriptor.limits.history });
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
            if (benchmark.cmd) |value| try quote(allocator, value) else "null",
            if (benchmark.lib) |value| try quote(allocator, value) else "null",
            if (benchmark.bin) |value| try quote(allocator, value) else "null",
            benchmark.fmt,
            benchmark.store,
            benchmark.archive,
            benchmark.method,
            benchmark.decode_only,
            benchmark.ref_params,
        });
        for (benchmark.tunings) |tuning| {
            try output.print(allocator, ".{{ .name = \"{s}\", .params = &.{{ ", .{tuning.name});
            for (tuning.params) |parameter| {
                try output.print(allocator, ".{{ .family = {d}, .ordinal = {d}, .value = {d} }}, ", .{ parameter.family, parameter.ordinal, parameter.value });
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
    try emitTagTable(allocator, &output, descriptors.items);

    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = resolved_output_path, .data = output.items });
}

// The table derives every other identity from the descriptor, so a component is one
// descriptor file plus one convention-named hook.
fn profileTag(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const tagged = try allocator.dupe(u8, name);
    for (tagged) |*character| {
        if (character.* == '-') character.* = '_';
    }
    return tagged;
}

fn emitTagTable(allocator: std.mem.Allocator, output: *std.ArrayList(u8), descriptors: []const RawDescriptor) !void {
    try output.appendSlice(allocator, "\npub const ProfileTag = enum {\n");
    for (descriptors) |descriptor| {
        try output.print(allocator, "    {s},\n", .{try profileTag(allocator, descriptor.name)});
    }
    try output.appendSlice(allocator, "};\n\npub fn tagForName(name: []const u8) ?ProfileTag {\n");
    for (descriptors) |descriptor| {
        try output.print(allocator, "    if (std.mem.eql(u8, name, \"{s}\")) return .{s};\n", .{ descriptor.name, try profileTag(allocator, descriptor.name) });
    }
    try output.appendSlice(allocator, "    return null;\n}\n");
}
