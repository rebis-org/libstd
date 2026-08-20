const std = @import("std");

const abi = @import("../abi/contract.zig");
const registry = @import("../catalog/registry.zig");
const Failure = registry.Failure;

const max_depth = 32;
const max_count = 1024;

pub fn validateGraph(first: ?*abi.Node, direction: registry.Direction, command_mask: u32) Failure!void {
    var context = Context{
        .direction = direction,
        .command_mask = command_mask,
    };
    try validateNode(first, &context, 0);
}

const Context = struct {
    direction: registry.Direction,
    command_mask: u32,
    count: usize = 0,
    ancestors: [max_depth + 1]?*abi.Node = .{null} ** (max_depth + 1),
};

fn validateNode(first: ?*abi.Node, context: *Context, depth: usize) Failure!void {
    if (depth > max_depth) return error.ResourceLimit;
    var cursor = first;
    while (cursor) |node| {
        if (context.count == max_count) return error.ResourceLimit;
        context.count += 1;
        if (!node.valid()) return error.InvalidCall;
        for (context.ancestors[0..depth]) |ancestor| {
            if (ancestor == node) return error.InvalidCall;
        }
        if (registry.idEqual(node.id, registry.ids.parameter)) {
            const sel = registry.selectorOf(node.value_high);
            try validateParameter(node, first, context, sel);
            if (registry.representationOf(sel) == .node_chain) {
                context.ancestors[depth] = node;
                try validateNode(node.child, context, depth + 1);
                context.ancestors[depth] = null;
            }
            cursor = node.next;
            continue;
        }
        const descriptor = registry.descriptorFor(node.id);
        if (descriptor == null) {
            if ((node.flags & abi.node_flag_optional) != 0) {
                cursor = node.next;
                continue;
            }
            return error.Unsupported;
        }
        const info = descriptor.?;
        switch (info.kind) {
            .parameter => {
                if (!directionAccepts(info.direction, context.direction)) return error.Unsupported;
                if (context.direction == .in and (info.command_mask & context.command_mask) == 0) return error.Unsupported;
            },
            .diagnostic => {
                if (context.direction != .out) return error.Unsupported;
            },
            else => return error.Unsupported,
        }
        try validateRepresentation(node, info);
        if (info.cardinality == .singleton and hasDuplicateSibling(first, node)) return error.InvalidCall;
        if (info.representation == .node_chain) {
            context.ancestors[depth] = node;
            try validateNode(node.child, context, depth + 1);
            context.ancestors[depth] = null;
        }
        cursor = node.next;
    }
}

fn directionAccepts(descriptor_direction: registry.Direction, usage: registry.Direction) bool {
    return switch (usage) {
        .in => descriptor_direction == .in or descriptor_direction == .in_out,
        .out => descriptor_direction == .out or descriptor_direction == .in_out,
        else => false,
    };
}

fn validateRepresentation(node: *abi.Node, descriptor: *const registry.Descriptor) Failure!void {
    switch (descriptor.representation) {
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
                if (node.value_low != 0 or node.value_high != 0 or (node.byte_capacity != 0 and node.bytes == null)) return error.InvalidCall;
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
    if (registry.idEqual(node.id, registry.ids.parameter)) return .{ .id = node.id, .selector = node.value_high };
    return .{ .id = node.id, .selector = 0 };
}

fn validateParameter(node: *abi.Node, first: ?*abi.Node, context: *Context, sel: registry.Selector) Failure!void {
    if (!registry.selectorValid(sel)) return error.InvalidCall;
    if (!registry.selectorKnown(sel)) return error.Unsupported;
    if (!directionAccepts(registry.directionOf(sel), context.direction)) return error.Unsupported;
    if (context.direction == .in and (sel.flags & context.command_mask) == 0) return error.Unsupported;
    const representation = registry.representationOf(sel);
    switch (representation) {
        .scalar_words => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0 or node.child != null) {
                return error.InvalidCall;
            }
        },
        .node_chain => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0) return error.InvalidCall;
        },
        .bytes => {
            if (node.child != null or node.byte_length > node.byte_capacity) return error.InvalidCall;
            if ((node.flags & abi.node_flag_callback_resource) != 0) {
                if (node.bytes != null or node.byte_capacity != 0) return error.InvalidCall;
            } else {
                if (node.value_low != 0 or (node.byte_capacity != 0 and node.bytes == null)) return error.InvalidCall;
            }
        },
        .none => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0 or node.child != null or node.value_low != 0 or node.value_high != 0) return error.InvalidCall;
        },
    }
    if (registry.cardinalityOf(sel) == .singleton and hasDuplicateSibling(first, node)) return error.InvalidCall;
}

fn hasDuplicateSibling(first: ?*abi.Node, needle: *abi.Node) bool {
    const needle_key = siblingKey(needle);
    var cursor = first;
    while (cursor) |node| : (cursor = node.next) {
        if (node == needle) return false;
        const key = siblingKey(node);
        if (registry.idEqual(key.id, needle_key.id) and key.selector == needle_key.selector) return true;
    }
    return false;
}

pub fn findParameter(first: ?*abi.Node, id: abi.Id) ?*abi.Node {
    var cursor = first;
    while (cursor) |node| : (cursor = node.next) {
        if (registry.idEqual(node.id, id)) return node;
    }
    return null;
}

pub fn findSelector(first: ?*abi.Node, family: u16, ordinal: u32) ?*abi.Node {
    var cursor = first;
    while (cursor) |node| : (cursor = node.next) {
        if (!registry.idEqual(node.id, registry.ids.parameter)) continue;
        const sel = registry.selectorOf(node.value_high);
        if (sel.family == family and sel.ordinal == ordinal) return node;
    }
    return null;
}

pub fn findChild(parent: *abi.Node, id: abi.Id) Failure!?*abi.Node {
    var found: ?*abi.Node = null;
    var cursor = parent.child;
    while (cursor) |node| : (cursor = node.next) {
        if (!registry.idEqual(node.id, id)) continue;
        if (found != null) return error.InvalidCall;
        found = node;
    }
    return found;
}

pub fn parseU64(node: ?*abi.Node) u64 {
    const n = node orelse return 0;
    return n.value_low;
}
