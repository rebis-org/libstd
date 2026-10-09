const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

// Callers pick an implementation per capability at build time; add a case here to
// carry any other implementation that matches the same interface. Both
// Both implementations expose the state as `adler` so the wrapper in
// checksum.zig stays implementation-neutral.
pub const Implementation = enum { onprem, offprem };

pub const Inner = switch (options.adler32_impl) {
    .onprem => onprem.Adler32,
    .offprem => std.hash.Adler32,
};
