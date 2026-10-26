const std = @import("std");

const components = @import("components");

const abi = @import("../kernel/envelope.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const archive = @import("archive.zig");
const catalog = @import("catalog.zig");
const common = @import("common.zig");
const transform = @import("transform.zig");

const Id = abi.Id;
const Exception = vocabulary.Exception;

const ProfileHook = *const fn (invocation: *common.Invocation) Exception!void;

// Convention dispatch: the hook for a tag lives as `<tag>Hook`.
fn unsupportedHook(invocation: *common.Invocation) Exception!void {
    _ = invocation;
    return error.UnsupportedException;
}

const handler_map = blk: {
    @setEvalBranchQuota(50_000);
    const tag_info = @typeInfo(components.ProfileTag).@"enum";
    var entries: [tag_info.field_names.len]struct { []const u8, ProfileHook } = undefined;
    for (tag_info.field_names, 0..) |field_name, index| {
        // Both fixtures share the single echo hook.
        if (std.mem.eql(u8, field_name, "test_echo") or std.mem.eql(u8, field_name, "test_read")) {
            entries[index] = .{ field_name, transform.testHook };
            continue;
        }
        const hook_name = field_name ++ "Hook";
        if (@hasDecl(transform, hook_name)) {
            entries[index] = .{ field_name, @field(transform, hook_name) };
        } else if (@hasDecl(archive, hook_name)) {
            entries[index] = .{ field_name, @field(archive, hook_name) };
        } else {
            entries[index] = .{ field_name, unsupportedHook };
        }
    }
    break :blk std.StaticStringMap(ProfileHook).initComptime(entries);
};

pub fn dispatchToProfileHook(profile_id: Id, invocation: *common.Invocation) Exception!void {
    const tag = catalog.profileTagForId(profile_id) orelse return error.UnsupportedException;
    const hook = handler_map.get(@tagName(tag)) orelse return error.UnsupportedException;
    return hook(invocation);
}
