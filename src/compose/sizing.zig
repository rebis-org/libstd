const zstd = @import("../leaf/zstd.zig");

// Single-sourced: envelope and bypass paths must agree exactly or framing diverges output. Frame boundaries reset matchfinder history, so this is output-correctness, not a hint.

pub fn encodeHistoryLen(input_len: usize, dict_len: usize, options: zstd.Options) usize {
    const frame_budget = if (zstd.useDfast(options) or zstd.useRowMatch(options))
        @min(input_len, zstd.encoder_frame_size_max)
    else
        @min(@as(usize, options.window_size), zstd.encoder_frame_size_max);
    return dict_len + @max(frame_budget, options.window_size) + zstd.block_size_max;
}

pub fn decodeHistoryLen(options: zstd.Options) usize {
    return @as(usize, options.window_size) + zstd.block_size_max;
}
