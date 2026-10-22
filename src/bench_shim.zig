// Benchmark-harness door: the micro module cannot reach into src/ by relative
// import (module fences), so this root re-exports the leaf entry points the
// micro cases drive. Production code does not import this file.
pub const brotli = @import("representation/leaf/brotli/onprem.zig");
pub const kernels = @import("common/kernels.zig");
