// Unit-test entry for the grammar layer, wired into `zig build unit`. The
// module root has to sit at src/ so the grammar's `../common` imports stay
// inside the module path.
test {
    _ = @import("grammar/rar/onprem.zig");
    // Writer tests cover create→inspect→decode round trips the facade alone never runs.
    _ = @import("grammar/rar/writer.zig");
    _ = @import("grammar/zlib/onprem.zig");
    _ = @import("grammar/lzma/onprem.zig");
    _ = @import("grammar/zstd_seekable/onprem.zig");
    _ = @import("grammar/sevenzip/onprem.zig");
    _ = @import("grammar/zip/onprem.zig");
    _ = @import("grammar/tar/onprem.zig");
    _ = @import("grammar/xz/onprem.zig");
    _ = @import("leaf/lz4/onprem.zig");
    _ = @import("leaf/zstd/onprem.zig");
    _ = @import("leaf/zstd/offprem.zig");
    _ = @import("leaf/lzma/offprem.zig");
    _ = @import("leaf/lzma2/offprem.zig");
    _ = @import("grammar/tar/offprem.zig");
    _ = @import("testing/fuzz/decode.zig");
}
