// Verbs name capability only. Type-safe binding to codec code lives in the drivers.
pub const Id = struct {
    low: u64,
    high: u64,
};

pub const Class = enum { slice, streaming, grammar, filter };

pub const Verb = enum {
    required_size,
    decoded_size,
    encoded_size_bound,
    encode,
    decode,
    encode_stream,
    decode_stream,
    inspect,
    decode_ordinal,
    encode_ordinal,
};

pub fn verbsFor(class: Class) []const Verb {
    return switch (class) {
        .slice => &.{ .required_size, .decoded_size, .encoded_size_bound, .encode, .decode },
        .streaming => &.{ .encode_stream, .decode_stream, .decoded_size, .encoded_size_bound },
        .grammar => &.{ .inspect, .decode_ordinal, .encode_ordinal },
        .filter => &.{ .encode, .decode },
    };
}

pub const Representation = enum { scalar_words, bytes, node_chain, none };

pub const SizingMode = enum {
    unavailable,
    metadata_exact,
    measured,
    materialization,
    bounded,
};

pub const CommitMode = enum {
    tentative,
    confirmed,
};

pub const Parameter = struct {
    name: []const u8,
    family: u16,
    ordinal: u16,
    representation: Representation,
};

pub const Limits = struct {
    window: u64 = 0,
    block: u64 = 0,
    history: u64 = 0,
};

pub const Benchmark = struct {
    row: []const u8,
    params: []const u8,
};

pub const Descriptor = struct {
    id: Id,
    name: []const u8,
    class: Class,
    verbs: []const Verb,
    parameters: []const Parameter = &.{},
    capabilities: u32 = 0,
    command_mask: u32 = 0,
    sizing: SizingMode = .unavailable,
    commit: CommitMode = .tentative,
    limits: Limits = .{},
    benchmark: ?Benchmark = null,
};

pub fn eql(first: Id, second: Id) bool {
    return first.low == second.low and first.high == second.high;
}
