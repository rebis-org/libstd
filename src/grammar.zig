// Unit-test entry for the grammar layer, wired into `zig build unit`. The
// module root has to sit at src/ so the grammar's `../common` imports stay
// inside the module path.
test {
    _ = @import("grammar/rar.zig");
    // Writer tests cover create→inspect→decode round trips the facade alone never runs.
    _ = @import("grammar/rar/writer.zig");
    _ = @import("grammar/zlib.zig");
    _ = @import("grammar/lzma.zig");
    _ = @import("grammar/zstd_seekable.zig");
    _ = @import("grammar/sevenzip.zig");
    _ = @import("grammar/zip.zig");
    _ = @import("grammar/tar.zig");
    _ = @import("grammar/xz.zig");
    _ = @import("leaf/lz4.zig");
    _ = @import("leaf/zstd.zig");
}
