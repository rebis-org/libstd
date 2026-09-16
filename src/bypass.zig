// Rooted at src/: module confinement requires it for compose/ to reach leaf/ and nucleus/.
pub const bypass = @import("compose/bypass.zig");
pub const Options = bypass.Options;
pub const zstdEncode = bypass.zstdEncode;
pub const zstdDecodeStream = bypass.zstdDecodeStream;
pub const zstdEncodeBound = bypass.zstdEncodeBound;
pub const zstdEncodeHistoryLen = bypass.zstdEncodeHistoryLen;
