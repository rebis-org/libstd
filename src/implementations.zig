// Unit-test entry for every implementation above the kernel.
// The src/ root keeps `../common` imports inside the module path.
test {
    _ = @import("grammar/rar/onprem.zig");
    // Writer tests cover create→inspect→decode round trips the facade alone never runs.
    _ = @import("grammar/rar/writer.zig");
    _ = @import("grammar/zlib/onprem.zig");
    _ = @import("grammar/lzma/onprem.zig");
    _ = @import("grammar/gzip/onprem.zig");
    _ = @import("grammar/zstd_seekable/onprem.zig");
    _ = @import("grammar/sevenzip/onprem.zig");
    _ = @import("grammar/zip/onprem.zig");
    _ = @import("grammar/cpio/offprem.zig");
    _ = @import("grammar/cpio/onprem.zig");
    _ = @import("grammar/tar/onprem.zig");
    _ = @import("grammar/wim/offprem.zig");
    _ = @import("grammar/wim/onprem.zig");
    _ = @import("grammar/xar/offprem.zig");
    _ = @import("grammar/xar/onprem.zig");
    _ = @import("grammar/xz/onprem.zig");
    _ = @import("leaf/lz4/onprem.zig");
    _ = @import("leaf/zstd/onprem.zig");
    _ = @import("leaf/brotli/onprem.zig");
    _ = @import("leaf/zstd/offprem.zig");
    _ = @import("leaf/lzma/offprem.zig");
    _ = @import("leaf/lzma2/offprem.zig");
    _ = @import("grammar/tar/offprem.zig");
    _ = @import("testing/fuzz/decode.zig");
    _ = @import("leaf/lzo/onprem.zig");
    _ = @import("volume/iso/offprem.zig");
    _ = @import("volume/iso/onprem.zig");
    _ = @import("volume/squashfs/offprem.zig");
    _ = @import("volume/squashfs/onprem.zig");
}
