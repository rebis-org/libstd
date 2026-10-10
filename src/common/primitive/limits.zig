const std = @import("std");

pub const Limits = struct {
    encoded_bytes: u64 = std.math.maxInt(u64),
    decoded_bytes: u64 = std.math.maxInt(u64),
    callback_bytes: u64 = std.math.maxInt(u64),
    entries: u64 = std.math.maxInt(u64),
    metadata_records: u64 = std.math.maxInt(u64),
    nesting_depth: u64 = std.math.maxInt(u64),
    codec_work: u64 = std.math.maxInt(u64),

    pub fn fromScalar(scalar: u64) Limits {
        const ceiling = if (scalar == 0) std.math.maxInt(u64) else scalar;
        return .{
            .encoded_bytes = ceiling,
            .decoded_bytes = ceiling,
            .codec_work = ceiling,
        };
    }
};
