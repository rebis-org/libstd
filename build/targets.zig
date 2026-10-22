const std = @import("std");

const common = @import("platform/common.zig");

pub const Unit = common.SingleUnit;

// The support matrix: what `zig build targets` compiles, and what the docs
// guarantee. Tier 1 is the consumer-facing set (Linux, Android, Darwin,
// Windows and their primary ABIs); the BSD and WASI rows are compile-only
// breadth, not runtime promises. watchOS stays out: the 0.17 backend cannot
// build it (build/platform/darwin.zig records the block).
pub const matrix = [_]std.Target.Query{
    // Linux, glibc and musl.
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .riscv64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .riscv64, .os_tag = .linux, .abi = .musl },
    .{ .cpu_arch = .loongarch64, .os_tag = .linux, .abi = .gnu },
    // Android rides on the linux tag through its own ABIs, 32-bit included
    // now that the usize/u64 port landed.
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .android },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .android },
    .{ .cpu_arch = .arm, .os_tag = .linux, .abi = .androideabi },
    .{ .cpu_arch = .x86, .os_tag = .linux, .abi = .android },
    // HarmonyOS, same mechanism.
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .ohos },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .ohos },
    // Darwin: macOS and the Apple mobile family.
    .{ .cpu_arch = .x86_64, .os_tag = .macos },
    .{ .cpu_arch = .aarch64, .os_tag = .macos },
    .{ .cpu_arch = .aarch64, .os_tag = .ios, .abi = .simulator },
    .{ .cpu_arch = .x86_64, .os_tag = .ios, .abi = .simulator },
    .{ .cpu_arch = .aarch64, .os_tag = .ios },
    .{ .cpu_arch = .aarch64, .os_tag = .maccatalyst },
    .{ .cpu_arch = .x86_64, .os_tag = .maccatalyst },
    .{ .cpu_arch = .aarch64, .os_tag = .tvos },
    .{ .cpu_arch = .aarch64, .os_tag = .visionos },
    // Windows, both ABIs and both tiers of hardware.
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    .{ .cpu_arch = .aarch64, .os_tag = .windows, .abi = .msvc },
    .{ .cpu_arch = .aarch64, .os_tag = .windows, .abi = .gnu },
    // Compile-only breadth: the BSDs and WASI. No runtime promise, no limit.
    .{ .cpu_arch = .x86_64, .os_tag = .freebsd },
    .{ .cpu_arch = .aarch64, .os_tag = .freebsd },
    .{ .cpu_arch = .x86_64, .os_tag = .openbsd },
    .{ .cpu_arch = .aarch64, .os_tag = .openbsd },
    .{ .cpu_arch = .wasm32, .os_tag = .wasi },
};

pub const units = [_]Unit{.{ .name = "targets" }};

pub fn expand(b: *std.Build, ctx: *const common.Settings) void {
    const step = b.step("targets", "Compile the library across the support matrix");
    // Both linkages: the static archive and the shared object exercise
    // different export machinery, and consumers pick per form.
    inline for (matrix) |query| {
        const target = b.resolveTargetQuery(query);
        inline for ([_]std.lang.LinkMode{ .static, .dynamic }) |linkage| {
            const library = common.addLibrary(b, target, ctx.optimize, linkage, ctx);
            step.dependOn(&library.step);
        }
    }
}
