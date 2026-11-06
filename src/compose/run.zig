const seam = @import("seam");

const abi = @import("../kernel/envelope.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const common = @import("common.zig");

const Provider = seam.Provider;
const Node = abi.Node;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Workspace = resource.Workspace;

// The call a codec sees: envelope, resolved plan, source and sink, and the workspace carved for this call.
pub const Core = struct {
    invocation: *common.Invocation,
    workspace: *Workspace,

    pub fn requestNode(self: Core) ?*Node {
        return self.invocation.call.request;
    }

    pub fn call(self: Core) *abi.Call {
        return self.invocation.call;
    }

    pub fn plan(self: Core) *const common.ExecutionPlan {
        return &self.invocation.plan;
    }

    pub fn provider(self: Core) Provider {
        return self.invocation.plan.provider;
    }

    pub fn limits(self: Core) Limits {
        return self.invocation.plan.limits;
    }

    pub fn source(self: Core) *Resource {
        return self.invocation.source;
    }

    pub fn sink(self: Core) ?*Resource {
        return self.invocation.sink;
    }

    pub fn response(self: Core) *Node {
        return self.invocation.response;
    }

    pub fn sizing(self: Core) vocabulary.SizingMode {
        return self.invocation.plan.sizing;
    }

    pub fn commit(self: Core) vocabulary.CommitMode {
        return self.invocation.plan.commit;
    }

    pub fn commandMask(self: Core) u32 {
        return self.invocation.plan.command_mask;
    }
};
