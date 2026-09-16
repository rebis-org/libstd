const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const abi = @import("../kernel/envelope.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const vocabulary = @import("../kernel/vocabulary.zig");
const Failure = vocabulary.Failure;
const archive = @import("archive.zig");
const catalog = @import("catalog.zig");
const common = @import("common.zig");
const transform = @import("transform.zig");

const ProfileHook = *const fn (plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void;

// Single shared hook signature keeps the call site from drifting per profile.
fn hookForTag(comptime tag: vocabulary.ProfileTag) ProfileHook {
    return switch (tag) {
        .test_echo, .test_read => transform.testHook,
        .deflate => transform.deflateHook,
        .gzip => transform.gzipHook,
        .zstd => transform.zstdHook,
        .bzip2 => transform.bzip2Hook,
        .lzma => transform.lzmaHook,
        .lzma2 => transform.lzma2Hook,
        .lzma_file => transform.lzmaFileHook,
        .xz => transform.xzHook,
        .tar => archive.tarHook,
        .zip => archive.zipHook,
        .sevenzip => archive.sevenZipHook,
        .rar => archive.rarHook,
    };
}

pub fn dispatchToProfileHook(profile_id: Id, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    return switch (catalog.profileTagForId(profile_id) orelse return error.Unsupported) {
        inline else => |tag| hookForTag(tag)(plan, source, sink, call, response, sizing, commit, limits, command_mask),
    };
}
