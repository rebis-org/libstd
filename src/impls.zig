// Unit-test entry for every implementation above the kernel.
// The src/ root keeps `../common` imports inside the module path.
test {
    _ = @import("representation/grammar/rar/onprem.zig");
    // Writer tests cover create→inspect→decode round trips the facade alone never runs.
    _ = @import("representation/grammar/rar/writer.zig");
    _ = @import("representation/grammar/zlib/onprem.zig");
    _ = @import("representation/grammar/lzma/onprem.zig");
    _ = @import("representation/grammar/gzip/onprem.zig");
    _ = @import("representation/grammar/zstd_seekable/onprem.zig");
    _ = @import("representation/grammar/sevenzip/onprem.zig");
    _ = @import("representation/grammar/zip/onprem.zig");
    _ = @import("representation/grammar/cpio/offprem.zig");
    _ = @import("representation/grammar/cpio/onprem.zig");
    _ = @import("representation/grammar/tar/onprem.zig");
    _ = @import("representation/grammar/wim/offprem.zig");
    _ = @import("representation/grammar/wim/onprem.zig");
    _ = @import("representation/grammar/xar/offprem.zig");
    _ = @import("representation/grammar/xar/onprem.zig");
    _ = @import("representation/grammar/age/onprem.zig");
    _ = @import("representation/grammar/xz/onprem.zig");
    _ = @import("representation/leaf/bcj/onprem.zig");
    _ = @import("representation/leaf/lz4/onprem.zig");
    _ = @import("representation/leaf/zstd/onprem.zig");
    _ = @import("representation/leaf/brotli/onprem.zig");
    _ = @import("representation/leaf/zstd/offprem.zig");
    _ = @import("representation/leaf/lzma/offprem.zig");
    _ = @import("representation/leaf/lzma2/offprem.zig");
    _ = @import("representation/grammar/tar/offprem.zig");
    _ = @import("testing/fuzz/decode.zig");
    _ = @import("representation/leaf/lzo/onprem.zig");
    _ = @import("representation/volume/dwarfs/offprem.zig");
    _ = @import("representation/volume/dwarfs/onprem.zig");
    _ = @import("representation/volume/apfs/onprem.zig");
    _ = @import("representation/volume/iso/offprem.zig");
    _ = @import("representation/volume/iso/onprem.zig");
    _ = @import("representation/volume/squashfs/offprem.zig");
    _ = @import("representation/volume/squashfs/onprem.zig");
}
