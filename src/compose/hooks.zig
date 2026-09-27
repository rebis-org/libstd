const resource = @import("../kernel/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const abi = @import("../kernel/envelope.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const vocabulary = @import("../kernel/vocabulary.zig");
const Failure = vocabulary.Failure;
const discovery = @import("../kernel/discovery.zig");
const components = @import("components");
const archive = @import("archive.zig");
const catalog = @import("catalog.zig");
const common = @import("common.zig");
const transform = @import("transform.zig");

const ProfileHook = *const fn (plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void;

// Convention dispatch: the hook for a tag lives in transform.zig or archive.zig
// as `<tag>Hook`, so a new component needs no edit here. A missing declaration
// is an explicit unsupported, never a fallthrough.
fn unsupportedHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = plan;
    _ = source;
    _ = sink;
    _ = call;
    _ = response;
    _ = sizing;
    _ = commit;
    _ = limits;
    _ = command_mask;
    return error.Unsupported;
}

const handler_map = blk: {
    @setEvalBranchQuota(50_000);
    const fields = @typeInfo(components.ProfileTag).@"enum".fields;
    var entries: [fields.len]struct { []const u8, ProfileHook } = undefined;
    for (fields, 0..) |field, index| {
        // Both fixtures share the single echo hook, which predates the `<tag>Hook` naming convention.
        if (std.mem.eql(u8, field.name, "test_echo") or std.mem.eql(u8, field.name, "test_read")) {
            entries[index] = .{ field.name, transform.testHook };
            continue;
        }
        const hook_name = field.name ++ "Hook";
        if (@hasDecl(transform, hook_name)) {
            entries[index] = .{ field.name, @field(transform, hook_name) };
        } else if (@hasDecl(archive, hook_name)) {
            entries[index] = .{ field.name, @field(archive, hook_name) };
        } else {
            entries[index] = .{ field.name, unsupportedHook };
        }
    }
    break :blk std.StaticStringMap(ProfileHook).initComptime(entries);
};

const std = @import("std");

pub fn dispatchToProfileHook(profile_id: Id, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    if (discovery.findById(catalog.toContract(profile_id))) |descriptor| {
        const tag = components.tagForName(descriptor.name) orelse return error.Unsupported;
        const hook = handler_map.get(@tagName(tag)) orelse return error.Unsupported;
        return hook(plan, source, sink, call, response, sizing, commit, limits, command_mask);
    }
    return error.Unsupported;
}
