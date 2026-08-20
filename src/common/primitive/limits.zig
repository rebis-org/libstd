const std = @import("std");

pub const Limits = struct {
    encoded_bytes: u64 = std.math.maxInt(u64),
    decoded_bytes: u64 = std.math.maxInt(u64),
    callback_bytes: u64 = std.math.maxInt(u64),
    entries: u64 = std.math.maxInt(u64),
    metadata_records: u64 = std.math.maxInt(u64),
    nesting_depth: u64 = std.math.maxInt(u64),
    codec_work: u64 = std.math.maxInt(u64),

    pub fn fromScalar(value: u64) Limits {
        const limit = if (value == 0) std.math.maxInt(u64) else value;
        return .{
            .encoded_bytes = limit,
            .decoded_bytes = limit,
            .codec_work = limit,
        };
    }
};
