const catalog = @import("./catalog.zig");
const discovery = @import("./discovery.zig");
const abi = @import("./envelope.zig");
const vocabulary = @import("./vocabulary.zig");

const Failure = vocabulary.Failure;

const max_graph_depth = 32;
const max_node_count = 1024;

pub fn validateGraph(siblings: ?*abi.Node, direction: vocabulary.Direction, command_mask: u32) Failure!void {
    var traversal = Traversal{
        .direction = direction,
        .command_mask = command_mask,
    };
    try validateNode(siblings, &traversal, 0);
}

const Traversal = struct {
    direction: vocabulary.Direction,
    command_mask: u32,
    count: usize = 0,
    ancestors: [max_graph_depth + 1]?*abi.Node = @splat(null),
};

fn validateNode(siblings: ?*abi.Node, traversal: *Traversal, depth: usize) Failure!void {
    if (depth > max_graph_depth) return error.ResourceLimit;
    var cursor = siblings;
    while (cursor) |node| {
        if (traversal.count == max_node_count) return error.ResourceLimit;
        traversal.count += 1;
        if (!node.isValid()) return error.InvalidCall;
        for (traversal.ancestors[0..depth]) |ancestor| {
            if (ancestor == node) return error.InvalidCall;
        }
        if (vocabulary.eql(node.id, vocabulary.ids.parameter)) {
            const selector = vocabulary.selectorOf(node.value_high);
            try validateParameter(node, siblings, traversal, selector);
            if (vocabulary.representationOf(selector) == .node_chain) {
                try validateChildren(node, traversal, depth);
            }
            cursor = node.next;
            continue;
        }
        const entry = catalog.descriptorFor(node.id) orelse {
            if ((node.flags & abi.node_flag_optional) == 0) return error.Unsupported;
            cursor = node.next;
            continue;
        };
        switch (entry.kind) {
            .parameter => {
                if (!isDirectionAccepted(entry.direction, traversal.direction)) return error.Unsupported;
                if (traversal.direction == .in and (entry.command_mask & traversal.command_mask) == 0) return error.Unsupported;
            },
            .diagnostic => {
                if (traversal.direction != .out) return error.Unsupported;
            },
            else => return error.Unsupported,
        }
        try validateRepresentation(node, entry.representation, false);
        if (entry.cardinality == .singleton and hasDuplicateSibling(siblings, node)) return error.InvalidCall;
        if (entry.representation == .node_chain) {
            try validateChildren(node, traversal, depth);
        }
        cursor = node.next;
    }
}

fn validateChildren(node: *abi.Node, traversal: *Traversal, depth: usize) Failure!void {
    traversal.ancestors[depth] = node;
    try validateNode(node.child, traversal, depth + 1);
    traversal.ancestors[depth] = null;
}

fn isDirectionAccepted(declared: vocabulary.Direction, used: vocabulary.Direction) bool {
    return switch (used) {
        .in => declared == .in or declared == .in_out,
        .out => declared == .out or declared == .in_out,
        else => false,
    };
}

fn validateRepresentation(node: *abi.Node, representation: vocabulary.Representation, allow_value_high: bool) Failure!void {
    switch (representation) {
        .scalar_words => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0 or node.child != null) return error.InvalidCall;
        },
        .node_chain => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0) return error.InvalidCall;
        },
        .bytes => {
            if (node.child != null or node.byte_length > node.byte_capacity) return error.InvalidCall;
            if ((node.flags & abi.node_flag_callback_resource) != 0) {
                if (node.bytes != null or node.byte_capacity != 0) return error.InvalidCall;
            } else {
                if (node.value_low != 0 or (!allow_value_high and node.value_high != 0) or (node.byte_capacity != 0 and node.bytes == null)) return error.InvalidCall;
            }
        },
        .none => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0 or node.child != null or node.value_low != 0 or node.value_high != 0) return error.InvalidCall;
        },
    }
}

const SiblingKey = struct {
    id: abi.Id,
    selector: u64,
};

fn siblingKey(node: *abi.Node) SiblingKey {
    if (vocabulary.eql(node.id, vocabulary.ids.parameter)) return .{ .id = node.id, .selector = node.value_high };
    return .{ .id = node.id, .selector = 0 };
}

fn validateParameter(node: *abi.Node, siblings: ?*abi.Node, traversal: *Traversal, selector: vocabulary.Selector) Failure!void {
    if (!vocabulary.isSelectorValid(selector)) return error.InvalidCall;
    if (!discovery.isSelectorKnown(selector.family, selector.ordinal)) return error.Unsupported;
    if (!isDirectionAccepted(vocabulary.directionOf(selector), traversal.direction)) return error.Unsupported;
    if (traversal.direction == .in and (selector.flags & traversal.command_mask) == 0) return error.Unsupported;
    try validateRepresentation(node, vocabulary.representationOf(selector), true);
    if (vocabulary.cardinalityOf(selector) == .singleton and hasDuplicateSibling(siblings, node)) return error.InvalidCall;
}

fn findIf(siblings: ?*abi.Node, context: anytype, comptime matches: fn (*abi.Node, @TypeOf(context)) bool) ?*abi.Node {
    var cursor = siblings;
    while (cursor) |node| : (cursor = node.next) {
        if (matches(node, context)) return node;
    }
    return null;
}

fn isDuplicateCandidate(node: *abi.Node, wanted: SiblingKey) bool {
    const key = siblingKey(node);
    return vocabulary.eql(key.id, wanted.id) and key.selector == wanted.selector;
}

fn isIdMatch(node: *abi.Node, id: abi.Id) bool {
    return vocabulary.eql(node.id, id);
}

const SelectorQuery = struct { family: u16, ordinal: u32 };

fn isSelectorMatch(node: *abi.Node, query: SelectorQuery) bool {
    if (!vocabulary.eql(node.id, vocabulary.ids.parameter)) return false;
    const selector = vocabulary.selectorOf(node.value_high);
    return selector.family == query.family and selector.ordinal == query.ordinal;
}

fn hasDuplicateSibling(siblings: ?*abi.Node, target: *abi.Node) bool {
    const wanted = siblingKey(target);
    var cursor = siblings;
    while (cursor) |node| : (cursor = node.next) {
        if (node == target) return false;
        if (isDuplicateCandidate(node, wanted)) return true;
    }
    return false;
}

pub fn findParameter(siblings: ?*abi.Node, id: abi.Id) ?*abi.Node {
    return findIf(siblings, id, isIdMatch);
}

pub fn findSelector(siblings: ?*abi.Node, family: u16, ordinal: u32) ?*abi.Node {
    return findIf(siblings, SelectorQuery{ .family = family, .ordinal = ordinal }, isSelectorMatch);
}

pub fn findChild(parent: *abi.Node, id: abi.Id) Failure!?*abi.Node {
    var match: ?*abi.Node = null;
    var cursor = parent.child;
    while (cursor) |node| : (cursor = node.next) {
        if (!vocabulary.eql(node.id, id)) continue;
        if (match != null) return error.InvalidCall;
        match = node;
    }
    return match;
}

pub fn parseU64(node: ?*abi.Node) u64 {
    const found = node orelse return 0;
    return found.value_low;
}
