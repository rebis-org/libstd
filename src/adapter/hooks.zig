const std = @import("std");

const abi = @import("../abi/contract.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const registry = @import("../catalog/registry.zig");
const Failure = registry.Failure;
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const archive = @import("archive.zig");
const common = @import("common.zig");
const transform = @import("transform.zig");

pub fn dispatch(profile_id: Id, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    return switch (registry.tagFor(profile_id) orelse return error.Unsupported) {
        .test_echo => transform.testHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .test_read_only => transform.testHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .deflate => transform.deflateHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .gzip => transform.gzipHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .zstd => transform.zstdHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .bzip2 => transform.bzip2Hook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .lzma => transform.lzmaHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .lzma2 => transform.lzma2Hook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .lzma_file => transform.lzmaFileHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .xz => transform.xzHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .tar => archive.tarHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .zip => archive.zipHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .seven_zip_decoded => archive.sevenZipDecodedHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .seven_zip_coded => archive.sevenZipCodedHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
        .rar => archive.rarHook(plan, source, sink, call, response, planning, delivery, limits, command_mask),
    };
}
