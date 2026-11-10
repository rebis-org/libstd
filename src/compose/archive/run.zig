const Provider = @import("seam").Provider;

const crypto = @import("../../common/primitive/crypto.zig");
const abi = @import("../../kernel/envelope.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");
const core_run = @import("../run.zig");
const request = @import("request.zig");

const Node = abi.Node;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Exception = vocabulary.Exception;

// The call an archive format sees: the shared core, plus the credentials it verifies and the cause it records.
pub const Run = struct {
    core: core_run.Core,
    credentials: ?request.Credentials = null,
    cause: crypto.FailureCause = .none,

    pub fn requestNode(self: Run) ?*Node {
        return self.core.requestNode();
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
};

fn entryCount(run: Run) usize {
    return request.count(run.requestNode(), "entry");
}

// Wire order is the ordinal order the codec addresses.
pub fn collect(comptime E: type, comptime fill: anytype, run: *Run) Exception![]const E {
    const list = try run.core.workspace.take(E, entryCount(run.*));
    var index: usize = 0;
    var cursor = run.requestNode();
    while (cursor) |node| : (cursor = node.next) {
        if (!request.matches(node, "entry")) continue;
        try fill(&list[index], node, run);
        index += 1;
    }
    return list;
}
