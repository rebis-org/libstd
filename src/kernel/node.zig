const catalog = @import("catalog.zig");
const discovery = @import("discovery.zig");
const abi = @import("envelope.zig");
const vocabulary = @import("vocabulary.zig");

const Exception = vocabulary.Exception;

const max_graph_depth = 32;
const max_node_count = 1024;
// The response graph is host-built: a manifest chains one group
// per entry, so its budget rides the entry count.
const max_response_node_count = 1 << 20;

pub fn validateGraph(siblings: ?*abi.Node, direction: vocabulary.Direction, command_mask: u32) Exception!void {
    const max_count: usize = if (direction == .out) max_response_node_count else max_node_count;
    var traversal = Traversal{
        .direction = direction,
        .command_mask = command_mask,
        .max_count = max_count,
    };
    try validateNode(siblings, &traversal, 0);
}

const Traversal = struct {
    direction: vocabulary.Direction,
    command_mask: u32,
    count: usize = 0,
    max_count: usize,
    ancestors: [max_graph_depth + 1]?*abi.Node = @splat(null),
};

fn validateNode(siblings: ?*abi.Node, traversal: *Traversal, depth: usize) Exception!void {
    if (depth > max_graph_depth) return error.ResourceException;
    var cursor = siblings;
    while (cursor) |node| {
        if (traversal.count == traversal.max_count) return error.ResourceException;
        traversal.count += 1;
        if (!node.isValid()) return error.CallException;
        for (traversal.ancestors[0..depth]) |ancestor| {
            if (ancestor == node) return error.CallException;
        }
        var representation: vocabulary.Representation = undefined;
        if (vocabulary.eql(node.id, vocabulary.ids.parameter)) {
            const selector = vocabulary.selectorOf(node.value_high);
            try validateParameter(node, siblings, traversal, selector);
            representation = vocabulary.representationOf(selector);
        } else {
            const entry = catalog.descriptorFor(node.id) orelse {
                if ((node.flags & abi.node_flag_optional) == 0) return error.UnsupportedException;
                cursor = node.next;
                continue;
            };
            switch (entry.kind) {
                .parameter => {
                    if (!isDirectionAccepted(entry.direction, traversal.direction)) return error.UnsupportedException;
                    if (traversal.direction == .in and (entry.command_mask & traversal.command_mask) == 0) return error.UnsupportedException;
                },
                .diagnostic => {
                    if (traversal.direction != .out) return error.UnsupportedException;
                },
                else => return error.UnsupportedException,
            }
            try validateRepresentation(node, entry.representation, false);
            if (entry.cardinality == .singleton and hasDuplicateSibling(siblings, node)) return error.CallException;
            representation = entry.representation;
        }
        if (representation == .node_chain) {
            try validateChildren(node, traversal, depth);
        }
        cursor = node.next;
    }
}

fn validateChildren(node: *abi.Node, traversal: *Traversal, depth: usize) Exception!void {
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

fn validateRepresentation(node: *abi.Node, representation: vocabulary.Representation, allow_value_high: bool) Exception!void {
    switch (representation) {
        .scalar_words => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0 or node.child != null) return error.CallException;
        },
        .node_chain => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0) return error.CallException;
        },
        .bytes => {
            if (node.child != null or node.byte_length > node.byte_capacity) return error.CallException;
            if ((node.flags & abi.node_flag_callback_resource) != 0) {
                if (node.bytes != null or node.byte_capacity != 0) return error.CallException;
            } else {
                if (node.value_low != 0 or (!allow_value_high and node.value_high != 0) or (node.byte_capacity != 0 and node.bytes == null)) return error.CallException;
            }
        },
        .none => {
            if (node.bytes != null or node.byte_capacity != 0 or node.byte_length != 0 or node.child != null or node.value_low != 0 or node.value_high != 0) return error.CallException;
        },
    }
}

const SiblingKey = struct {
    id: abi.Id,
    selector: u64,
};

fn siblingKey(node: *abi.Node) SiblingKey {
    // Duplicate detection must match findSelector: family and ordinal, with
    // flags ignored, or two same-selector parameters evade the singleton rule.
    if (vocabulary.eql(node.id, vocabulary.ids.parameter)) {
        const selector = vocabulary.selectorOf(node.value_high);
        return .{ .id = node.id, .selector = (@as(u64, selector.family) << 32) | selector.ordinal };
    }
    return .{ .id = node.id, .selector = 0 };
}

fn validateParameter(node: *abi.Node, siblings: ?*abi.Node, traversal: *Traversal, selector: vocabulary.Selector) Exception!void {
    if (!vocabulary.isSelectorValid(selector)) return error.CallException;
    if (!discovery.isSelectorKnown(selector.family, selector.ordinal)) return error.UnsupportedException;
    if (!isDirectionAccepted(vocabulary.directionOf(selector), traversal.direction)) return error.UnsupportedException;
    if (traversal.direction == .in and (selector.flags & traversal.command_mask) == 0) return error.UnsupportedException;
    try validateRepresentation(node, vocabulary.representationOf(selector), true);
    if (vocabulary.cardinalityOf(selector) == .singleton and hasDuplicateSibling(siblings, node)) return error.CallException;
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

pub fn findChild(parent: *abi.Node, id: abi.Id) Exception!?*abi.Node {
    var match: ?*abi.Node = null;
    var cursor = parent.child;
    while (cursor) |node| : (cursor = node.next) {
        if (!vocabulary.eql(node.id, id)) continue;
        if (match != null) return error.CallException;
        match = node;
    }
    return match;
}

pub fn parseU64(node: ?*abi.Node) u64 {
    const found = node orelse return 0;
    return found.value_low;
}

// Test-only: family-zero parameter node; attrs holds representation,
// cardinality, direction.
fn testParameterNode(ordinal: u32, attrs: u8, flags: u8) abi.Node {
    var node = abi.Node.init();
    node.id = vocabulary.ids.parameter;
    node.value_high = (@as(u64, ordinal) << 16) | (@as(u64, attrs) << 8) | flags;
    return node;
}

test "node validate graph accepts protocol parameters catalog rows and nested chains" {
    const std = @import("std");
    // An empty bytes payload still validates.
    var source_node = abi.Node.init();
    source_node.id = vocabulary.ids.source;
    try validateGraph(&source_node, .in, 7);
    try std.testing.expect(source_node.isValid());

    // A sink row validates under a read traversal.
    var sink_node = abi.Node.init();
    sink_node.id = vocabulary.ids.sink;
    try validateGraph(&sink_node, .in, 2);
    try std.testing.expect(sink_node.isValid());

    // A diagnostic row validates under an out traversal.
    var diagnostic_node = abi.Node.init();
    diagnostic_node.id = vocabulary.ids.diagnostic_required_capacity;
    try validateGraph(&diagnostic_node, .out, 0);
    try std.testing.expect(diagnostic_node.isValid());

    // A scalar family-zero parameter validates with the query flag set.
    var hint = testParameterNode(1, 0x11, 1);
    try validateGraph(&hint, .in, 1);
    try std.testing.expect(hint.isValid());

    // A chain parameter validates together with its child.
    var chain = testParameterNode(1, 0x13, 1);
    var child_source = abi.Node.init();
    child_source.id = vocabulary.ids.source;
    chain.child = &child_source;
    try validateGraph(&chain, .in, 7);
    try std.testing.expect(chain.isValid());
    try std.testing.expect(child_source.isValid());
}

test "node validate graph rejects invalid frames unknown ids and direction mismatches" {
    const std = @import("std");
    // An undersized structure is refused.
    var malformed = abi.Node.init();
    malformed.id = vocabulary.ids.source;
    malformed.structure_size -= 1;
    try std.testing.expectError(error.CallException, validateGraph(&malformed, .in, 7));

    // Unknown identity without the optional flag is refused.
    var stranger = abi.Node.init();
    stranger.id = .{ .low = 0xdead_beef_0000_0001, .high = 0xdead_beef_0000_0001 };
    try std.testing.expectError(error.UnsupportedException, validateGraph(&stranger, .in, 7));

    // The optional flag turns the same stranger into an ignorable node.
    var optional_stranger = stranger;
    optional_stranger.flags = abi.node_flag_optional;
    try validateGraph(&optional_stranger, .in, 7);

    // Diagnostic row refuses an in traversal.
    var diagnostic_node = abi.Node.init();
    diagnostic_node.id = vocabulary.ids.diagnostic_required_capacity;
    try std.testing.expectError(error.UnsupportedException, validateGraph(&diagnostic_node, .in, 7));

    // Source row (direction in) refuses an out traversal.
    var source_node = abi.Node.init();
    source_node.id = vocabulary.ids.source;
    try std.testing.expectError(error.UnsupportedException, validateGraph(&source_node, .out, 7));

    // Source row under an in traversal with no command bits in common.
    try std.testing.expectError(error.UnsupportedException, validateGraph(&source_node, .in, 0));

    // Parameter selector beyond the known protocol range.
    var unknown_selector = testParameterNode(7, 0x11, 1);
    try std.testing.expectError(error.UnsupportedException, validateGraph(&unknown_selector, .in, 1));

    // Parameter selector with a reserved attribute bit.
    var reserved_attrs = testParameterNode(1, 0x51, 1);
    try std.testing.expectError(error.CallException, validateGraph(&reserved_attrs, .in, 1));

    // Scalar parameter carrying a child.
    var with_child = testParameterNode(1, 0x11, 1);
    var stray = abi.Node.init();
    stray.id = vocabulary.ids.source;
    with_child.child = &stray;
    try std.testing.expectError(error.CallException, validateGraph(&with_child, .in, 1));

    // Bytes row with length beyond capacity.
    var overlong = abi.Node.init();
    overlong.id = vocabulary.ids.source;
    overlong.byte_length = 5;
    try std.testing.expectError(error.CallException, validateGraph(&overlong, .in, 7));
}

test "node duplicate singleton detection keys on selector family and ordinal" {
    const std = @import("std");
    // Two singleton parameters with the same family and ordinal collide even
    // when their command flags differ.
    var first = testParameterNode(1, 0x11, 1);
    var second = testParameterNode(1, 0x11, 2);
    first.next = &second;
    try std.testing.expectError(error.CallException, validateGraph(&first, .in, 3));

    // Repeated cardinality admits the same pair.
    var repeated_first = testParameterNode(1, 0x15, 1);
    var repeated_second = testParameterNode(1, 0x15, 2);
    repeated_first.next = &repeated_second;
    try validateGraph(&repeated_first, .in, 3);

    // Different ordinals never collide.
    var distinct_first = testParameterNode(1, 0x11, 1);
    var distinct_second = testParameterNode(2, 0x11, 2);
    distinct_first.next = &distinct_second;
    try validateGraph(&distinct_first, .in, 3);
}

test "node validate graph rejects cycles and enforces depth and count budgets" {
    const std = @import("std");
    // Self-referential child chain: the ancestor scan catches the cycle.
    var cyclic = testParameterNode(1, 0x13, 1);
    cyclic.child = &cyclic;
    try std.testing.expectError(error.CallException, validateGraph(&cyclic, .in, 1));

    // A 32-level chain lands the deepest node at depth 31, in budget...
    var deep_nodes: [32]abi.Node = undefined;
    for (&deep_nodes, 0..) |*node, index| {
        node.* = testParameterNode(1, 0x13, 1);
        if (index + 1 < deep_nodes.len) node.child = &deep_nodes[index + 1];
    }
    try validateGraph(&deep_nodes[0], .in, 1);

    // ...the 33rd level crosses it: validateNode rejects depth 33 even for a
    // null child cursor.
    var overdeep_nodes: [33]abi.Node = undefined;
    for (&overdeep_nodes, 0..) |*node, index| {
        node.* = testParameterNode(1, 0x13, 1);
        if (index + 1 < overdeep_nodes.len) node.child = &overdeep_nodes[index + 1];
    }
    try std.testing.expectError(error.ResourceException, validateGraph(&overdeep_nodes[0], .in, 1));

    // The sibling budget admits 1024 nodes and refuses the 1025th.
    var wide: [1024]abi.Node = undefined;
    for (&wide, 0..) |*node, index| {
        node.* = testParameterNode(1, 0x15, 1); // Repeated cardinality: duplicates allowed.
        if (index + 1 < wide.len) node.next = &wide[index + 1];
    }
    try validateGraph(&wide[0], .in, 1);

    var wider: [1025]abi.Node = undefined;
    for (&wider, 0..) |*node, index| {
        node.* = testParameterNode(1, 0x15, 1);
        if (index + 1 < wider.len) node.next = &wider[index + 1];
    }
    try std.testing.expectError(error.ResourceException, validateGraph(&wider[0], .in, 1));
}

test "node find helpers resolve parameters selectors and unique children" {
    const std = @import("std");
    var hint = testParameterNode(1, 0x11, 1);
    var source_node = abi.Node.init();
    source_node.id = vocabulary.ids.source;
    var limit = testParameterNode(2, 0x11, 2);
    hint.next = &source_node;
    source_node.next = &limit;
    const siblings: ?*abi.Node = &hint;

    try std.testing.expectEqual(&source_node, findParameter(siblings, vocabulary.ids.source));
    try std.testing.expect(findParameter(siblings, vocabulary.ids.sink) == null);

    try std.testing.expectEqual(&hint, findSelector(siblings, 0, 1));
    try std.testing.expectEqual(&limit, findSelector(siblings, 0, 2));
    try std.testing.expect(findSelector(siblings, 0, 3) == null);

    // Null counts as zero; parseU64 answers the low scalar word.
    try std.testing.expectEqual(@as(u64, 0), parseU64(null));
    try std.testing.expectEqual(@as(u64, 0), parseU64(siblings));
    limit.value_low = 0x1234_abcd_5678_ef90;
    try std.testing.expectEqual(@as(u64, 0x1234_abcd_5678_ef90), parseU64(&limit));

    // Along the chain, findChild resolves each child by id.
    var parent = testParameterNode(1, 0x13, 1);
    var source_child = abi.Node.init();
    source_child.id = vocabulary.ids.source;
    var sink_child = abi.Node.init();
    sink_child.id = vocabulary.ids.sink;
    source_child.next = &sink_child;
    parent.child = &source_child;

    try std.testing.expectEqual(&source_child, try findChild(&parent, vocabulary.ids.source));
    try std.testing.expectEqual(&sink_child, try findChild(&parent, vocabulary.ids.sink));
    try std.testing.expect(try findChild(&parent, vocabulary.ids.query) == null);

    // A repeated child id is ambiguous and refused.
    var second_source = abi.Node.init();
    second_source.id = vocabulary.ids.source;
    sink_child.next = &second_source;
    try std.testing.expectError(error.CallException, findChild(&parent, vocabulary.ids.source));
    // Unambiguous ids still resolve.
    try std.testing.expectEqual(&sink_child, try findChild(&parent, vocabulary.ids.sink));
}
