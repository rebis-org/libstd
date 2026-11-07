const seam = @import("seam");

const abi = @import("../../kernel/envelope.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");
const core_run = @import("../run.zig");

const Provider = seam.Provider;
const Node = abi.Node;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Workspace = resource.Workspace;
const Exception = vocabulary.Exception;

// The call a transform hook sees: the shared core plus its selection, so it never re-reads the envelope.
pub const Run = struct {
    core: core_run.Core,

    pub fn requestNode(self: Run) ?*Node {
        return self.core.requestNode();
    }

    pub fn call(self: Run) *abi.Call {
        return self.core.call();
    }

    pub fn plan(self: Run) *const common.ExecutionPlan {
        return self.core.plan();
    }

    pub fn provider(self: Run) Provider {
        return self.core.provider();
    }

    pub fn limits(self: Run) Limits {
        return self.core.limits();
    }

    pub fn source(self: Run) *Resource {
        return self.core.source();
    }

    pub fn sink(self: Run) ?*Resource {
        return self.core.sink();
    }

    pub fn response(self: Run) *Node {
        return self.core.response();
    }

    pub fn sizing(self: Run) vocabulary.SizingMode {
        return self.core.sizing();
    }

    pub fn commit(self: Run) vocabulary.CommitMode {
        return self.core.commit();
    }

    pub fn commandMask(self: Run) u32 {
        return self.core.commandMask();
    }

    pub fn workspace(self: Run) *Workspace {
        return self.core.workspace;
    }
};

pub const Hook = fn (*Run) Exception!void;

// A codec reads the source twice - count, then commit - so the call must be replayable and measured.
pub fn requireReplay(running: *const Run, comptime confirmed: bool) Exception!void {
    const sizing = running.sizing();
    if (sizing != .measured and sizing != .bounded) return error.UnsupportedException;
    const expected: vocabulary.CommitMode = if (confirmed) .confirmed else .tentative;
    if (running.commit() != expected) return error.UnsupportedException;
    const source = running.source();
    if (!source.hasCapability(resource.capability_bit_read) or !source.hasCapability(resource.capability_bit_replay)) {
        return error.UnsupportedException;
    }
}

// One carve per call, before the hook picks its route: every route draws from the same workspace.
pub fn serve(invocation: *common.Invocation, comptime hook: Hook) Exception!void {
    const call = invocation.call;
    var workspace = try Workspace.initTracked(call.workspace, call.workspace_capacity, &invocation.plan.workspace_required);
    var running = Run{ .core = .{ .invocation = invocation, .workspace = &workspace } };
    return hook(&running);
}
