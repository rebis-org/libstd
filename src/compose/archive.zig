const crypto = @import("../common/primitive/crypto.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const formats = @import("archive/formats.zig");
const read = @import("archive/read.zig");
const request = @import("archive/request.zig");
const response = @import("archive/response.zig");
const run = @import("archive/run.zig");
const write = @import("archive/write.zig");
const common = @import("common.zig");

const Exception = vocabulary.Exception;
const Run = run.Run;
const Invocation = common.Invocation;

// hooks.zig resolves `<tag>Hook` here, one bound name per profile.
pub const tarHook = bind(formats.tar);
pub const cpioHook = bind(formats.cpio);
pub const xarHook = bind(formats.xar);
pub const xipHook = bind(formats.xip);
pub const pkgHook = bind(formats.pkg);
pub const wimHook = bind(formats.wim);
pub const isoHook = bind(formats.iso);
pub const apfsHook = bind(formats.apfs);
pub const dwarfsHook = bind(formats.dwarfs);
pub const squashfsHook = bind(formats.squashfs);
pub const ageHook = bind(formats.age);
pub const zipHook = bind(formats.zip);
pub const sevenzipHook = bind(formats.sevenzip);
pub const rarHook = bind(formats.rar);

fn bind(comptime F: type) *const fn (*Invocation) Exception!void {
    return struct {
        fn hook(invocation: *Invocation) Exception!void {
            return serve(F, invocation);
        }
    }.hook;
}

fn serve(comptime F: type, invocation: *Invocation) Exception!void {
    const call = invocation.call;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &invocation.plan.workspace_required);
    var running = Run{ .core = .{ .invocation = invocation, .workspace = &workspace } };
    // The crypto answer rides every exit path; the cause names the answer.
    errdefer response.reportFailure(call, running.cause);
    if (@hasDecl(F, "credential_component")) {
        running.credentials = try request.credentials(F.credential_component, call.request, &running.cause);
    }
    switch (invocation.plan.command_mask) {
        vocabulary.command_mask_read => try read.serve(F, &running),
        vocabulary.command_mask_write => try write.serve(F, &running),
        else => return error.UnsupportedException,
    }
}
