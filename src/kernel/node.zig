const abi = @import("./envelope.zig");
const vocabulary = @import("./vocabulary.zig");
const catalog = @import("./catalog.zig");
const discovery = @import("./discovery.zig");
const Failure = vocabulary.Failure;

const max_depth = 32;
const max_count = 1024;

pub fn validateGraph(siblings: ?*abi.Node, direction: vocabulary.Direction, command_mask: u32) Failure!void {
    var tracker = Context{
        .direction = direction,
        .command_mask = command_mask,
    };
    try validateNode(siblings, &tracker, 0);
}

const Context = struct {
    direction: vocabulary.Direction,
    command_mask: u32,
    count: usize = 0,
    ancestors: [max_depth + 1]?*abi.Node = @splat(null),
};

fn validateNode(siblings: ?*abi.Node, tracker: *Context, depth: usize) Failure!void {
    if (depth > max_depth) return error.ResourceLimit;
    var cursor = siblings;
    while (cursor) |node| {
        if (tracker.count == max_count) return error.ResourceLimit;
        tracker.count += 1;
        if (!node.isValid()) return error.InvalidCall;
        for (tracker.ancestors[0..depth]) |ancestor| {
            if (ancestor == node) return error.InvalidCall;
        }
        if (vocabulary.eql(node.id, vocabulary.ids.parameter)) {
            const selector = vocabulary.selectorOf(node.value_high);
            try validateParameter(node, siblings, tracker, selector);
            if (vocabulary.representationOf(selector) == .node_chain) {
                try validateChildren(node, tracker, depth);
            }
            cursor = node.next;
            continue;
        }
        const descriptor = catalog.descriptorFor(node.id);
        if (descriptor == null) {
            if ((node.flags & abi.node_flag_optional) != 0) {
                cursor = node.next;
                continue;
            }
            return error.Unsupported;
        }
        const entry = descriptor.?;
        switch (entry.kind) {
            .parameter => {
                if (!isDirectionAccepted(entry.direction, tracker.direction)) return error.Unsupported;
                if (tracker.direction == .in and (entry.command_mask & tracker.command_mask) == 0) return error.Unsupported;
            },
            .diagnostic => {
                if (tracker.direction != .out) return error.Unsupported;
            },
            else => return error.Unsupported,
        }
        try checkRepresentation(node, entry.representation, false);
        if (entry.cardinality == .singleton and hasDuplicateSibling(siblings, node)) return error.InvalidCall;
        if (entry.representation == .node_chain) {
            try validateChildren(node, tracker, depth);
        }
        cursor = node.next;
    }
}

fn validateChildren(node: *abi.Node, tracker: *Context, depth: usize) Failure!void {
    tracker.ancestors[depth] = node;
    try validateNode(node.child, tracker, depth + 1);
    tracker.ancestors[depth] = null;
}

fn isDirectionAccepted(declared: vocabulary.Direction, used: vocabulary.Direction) bool {
    return switch (used) {
        .in => declared == .in or declared == .in_out,
        .out => declared == .out or declared == .in_out,
        else => false,
    };
}

fn checkRepresentation(node: *abi.Node, representation: vocabulary.Representation, allow_value_high: bool) Failure!void {
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

fn validateParameter(node: *abi.Node, siblings: ?*abi.Node, tracker: *Context, selector: vocabulary.Selector) Failure!void {
    if (!vocabulary.isSelectorValid(selector)) return error.InvalidCall;
    if (!discovery.isSelectorKnown(selector.family, selector.ordinal)) return error.Unsupported;
    if (!isDirectionAccepted(vocabulary.directionOf(selector), tracker.direction)) return error.Unsupported;
    if (tracker.direction == .in and (selector.flags & tracker.command_mask) == 0) return error.Unsupported;
    try checkRepresentation(node, vocabulary.representationOf(selector), true);
    if (vocabulary.cardinalityOf(selector) == .singleton and hasDuplicateSibling(siblings, node)) return error.InvalidCall;
}

fn hasDuplicateSibling(siblings: ?*abi.Node, target: *abi.Node) bool {
    const wanted = siblingKey(target);
    var cursor = siblings;
    while (cursor) |node| : (cursor = node.next) {
        if (node == target) return false;
        const key = siblingKey(node);
        if (vocabulary.eql(key.id, wanted.id) and key.selector == wanted.selector) return true;
    }
    return false;
}

pub fn findParameter(siblings: ?*abi.Node, id: abi.Id) ?*abi.Node {
    var cursor = siblings;
    while (cursor) |node| : (cursor = node.next) {
        if (vocabulary.eql(node.id, id)) return node;
    }
    return null;
}

pub fn findSelector(siblings: ?*abi.Node, family: u16, ordinal: u32) ?*abi.Node {
    var cursor = siblings;
    while (cursor) |node| : (cursor = node.next) {
        if (!vocabulary.eql(node.id, vocabulary.ids.parameter)) continue;
        const selector = vocabulary.selectorOf(node.value_high);
        if (selector.family == family and selector.ordinal == ordinal) return node;
    }
    return null;
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
    const present = node orelse return 0;
    return present.value_low;
}
