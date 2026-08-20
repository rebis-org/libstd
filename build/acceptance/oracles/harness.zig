const std = @import("std");

const abi = @import("abi.zig");
pub const Id = abi.Id;
pub const Node = abi.Node;
pub const Call = abi.Call;
pub const Callback = abi.Callback;
pub const Status = abi.Status;
pub const idEqual = abi.idEqual;
pub const catalog = @import("catalog.zig");

pub const cap_read: u32 = 1 << 0;
pub const cap_write: u32 = 1 << 1;
pub const cap_size: u32 = 1 << 2;
pub const cap_replay: u32 = 1 << 3;
pub const cap_seek: u32 = 1 << 4;
pub const cap_range: u32 = 1 << 5;
pub const plan_unavailable: u64 = 0;
pub const plan_metadata_exact: u64 = 1;
pub const plan_replay_pass: u64 = 2;
pub const plan_bounded_materialization: u64 = 3;
pub const delivery_provisional: u64 = 0;
pub const delivery_verified: u64 = 1;
pub const cmd_query: u32 = 1 << 0;
pub const cmd_read: u32 = 1 << 1;
pub const cmd_write: u32 = 1 << 2;
pub const cmd_all: u32 = cmd_query | cmd_read | cmd_write;
pub const cmd_query_write: u32 = cmd_query | cmd_write;
pub const param_family_protocol: u16 = 0;
pub const param_family_crypto: u16 = 1;
pub const param_family_archive: u16 = 2;
pub const param_family_gzip: u16 = 3;
pub const param_family_zstd: u16 = 4;
pub const param_family_bzip2: u16 = 5;
pub const param_family_lzma: u16 = 6;
pub const param_family_deflate: u16 = 8;
pub const param_family_xz: u16 = 7;
pub const protocol_workspace_hint: u32 = 1;
pub const protocol_resource_limit: u32 = 2;
pub const protocol_resource_capabilities: u32 = 3;
pub const protocol_planning_mode: u32 = 4;
pub const protocol_delivery_mode: u32 = 5;
pub const crypto_password: u32 = 1;
pub const crypto_algorithm: u32 = 2;
pub const crypto_kdf_rounds_limit: u32 = 3;
pub const crypto_password_lifetime: u32 = 4;
pub const archive_ordinal: u32 = 1;
pub const archive_entry_count: u32 = 2;
pub const archive_entry_name: u32 = 3;
pub const archive_entry_size: u32 = 4;
pub const archive_entry: u32 = 5;
pub const archive_entry_data: u32 = 6;
pub const archive_entry_method: u32 = 7;
pub const archive_comment: u32 = 8;
pub const archive_entry_typeflag: u32 = 9;
pub const archive_entry_link_name: u32 = 10;
pub const archive_entry_uid: u32 = 11;
pub const archive_entry_mtime: u32 = 12;
pub const gzip_modification_time: u32 = 1;
pub const gzip_extra_flags: u32 = 2;
pub const gzip_operating_system: u32 = 3;
pub const gzip_text: u32 = 4;
pub const gzip_header_crc: u32 = 5;
pub const gzip_extra: u32 = 6;
pub const gzip_name: u32 = 7;
pub const gzip_comment: u32 = 8;
pub const bzip2_block_size: u32 = 1;
pub const lzma_dictionary: u32 = 1;
pub const zstd_window: u32 = 1;
pub const zstd_dictionary: u32 = 2;
pub const zstd_hash_bits: u32 = 3;
pub const zstd_max_chain: u32 = 4;
pub const zstd_nice_len: u32 = 5;
pub const zstd_search_window: u32 = 6;
pub const zstd_lazy: u32 = 7;
pub const zstd_skip_interior_insert: u32 = 8;
pub const zstd_double_hash: u32 = 9;
pub const zstd_row_match: u32 = 10;
pub const lzma_match_finder_depth: u32 = 2;
pub const lzma_lazy: u32 = 3;
pub const lzma_nice_len: u32 = 4;
pub const lzma_match_finder: u32 = 5;
pub const deflate_good: u32 = 1;
pub const deflate_nice: u32 = 2;
pub const deflate_lazy: u32 = 3;
pub const deflate_chain: u32 = 4;
pub const deflate_optimal: u32 = 5;
pub const xz_check: u32 = 1;
pub const xz_filters: u32 = 2;
pub var ids: catalog.Ids = undefined;
pub var catalog_descriptors: []catalog.DescriptorJson = &.{};
pub var io: std.Io = undefined;

pub fn loadCatalog(path: []const u8) !catalog.Catalog {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, std.heap.page_allocator, .limited(1 << 20));
    const parsed = try catalog.parse(std.heap.page_allocator, bytes);
    ids = try catalog.loadIds(&parsed);
    catalog_descriptors = parsed.descriptors;
    return parsed;
}

pub const Scenario = struct {
    name: []const u8,
    suite: []const u8,
    run: *const fn (r: *Runner) anyerror!void,
    workspace_size: usize,
    output_size: usize,
    encoded_size: usize,
    corpus: usize = 0,
};

pub const Spec = struct {
    label: []const u8,
    run: *const fn (r: *Runner) anyerror!void,
    workspace_size: usize,
    output_size: usize,
    encoded_size: usize,
};

pub const Single = struct {
    name: []const u8,
    run: *const fn (r: *Runner) anyerror!void,
    workspace_size: usize,
    output_size: usize,
    encoded_size: usize,
    suite: ?[]const u8 = null,
    corpus: usize = 0,
};

pub fn scenarios(comptime suite: []const u8, comptime specs: []const Spec, comptime singles: []const Single) [specs.len * 4 + singles.len]Scenario {
    var list: [specs.len * 4 + singles.len]Scenario = undefined;
    var index: usize = 0;
    for (specs) |spec| {
        for (0..4) |i| {
            list[index] = .{
                .name = std.fmt.comptimePrint("{s} corpus_0{d}", .{ spec.label, i + 1 }),
                .suite = suite,
                .run = spec.run,
                .workspace_size = spec.workspace_size,
                .output_size = spec.output_size,
                .encoded_size = spec.encoded_size,
                .corpus = i,
            };
            index += 1;
        }
    }
    for (singles) |single| {
        list[index] = .{
            .name = single.name,
            .suite = single.suite orelse suite,
            .run = single.run,
            .workspace_size = single.workspace_size,
            .output_size = single.output_size,
            .encoded_size = single.encoded_size,
            .corpus = single.corpus,
        };
        index += 1;
    }
    return list;
}

pub const Mode = struct {
    planning: u64,
    delivery_write: u64,
    delivery_read: u64,
    caps_query: u64,
    caps_io: u64,
};

pub const mode_stream = Mode{
    .planning = plan_replay_pass,
    .delivery_write = delivery_provisional,
    .delivery_read = delivery_provisional,
    .caps_query = cap_read | cap_size | cap_replay,
    .caps_io = cap_read | cap_write | cap_size | cap_replay,
};

pub const mode_archive = Mode{
    .planning = plan_metadata_exact,
    .delivery_write = delivery_verified,
    .delivery_read = delivery_provisional,
    .caps_query = cap_read | cap_write | cap_size | cap_replay,
    .caps_io = cap_read | cap_write | cap_size | cap_replay,
};

pub const mode_xz = Mode{
    .planning = plan_replay_pass,
    .delivery_write = delivery_verified,
    .delivery_read = delivery_verified,
    .caps_query = cap_read | cap_size | cap_replay,
    .caps_io = cap_read | cap_write | cap_size | cap_replay,
};

pub const mode_protocol = Mode{
    .planning = plan_metadata_exact,
    .delivery_write = delivery_provisional,
    .delivery_read = delivery_provisional,
    .caps_query = cap_read | cap_write | cap_size | cap_replay | cap_seek | cap_range,
    .caps_io = cap_read | cap_write | cap_size | cap_replay | cap_seek | cap_range,
};

pub fn setup(r: *Runner, profile_id: Id, mode: Mode) void {
    r.profile_id = profile_id;
    r.planning = mode.planning;
    r.delivery_write = mode.delivery_write;
    r.delivery_read = mode.delivery_read;
    r.caps_query = mode.caps_query;
    r.caps_io = mode.caps_io;
}

pub const Runner = struct {
    gpa: std.mem.Allocator,
    scenario_name: []const u8,
    corpus_index: usize = 0,
    corpus_buffer: [32]u8 = undefined,
    workspace: []u8 = &.{},
    output: []u8 = &.{},
    encoded: []u8 = &.{},
    response: Node = Node.init(),
    status: u32 = 0,
    required: usize = 0,
    encoded_len: usize = 0,
    profile_id: Id = .{ .low = 0, .high = 0 },
    extra: u64 = 0,
    extra2: ?u64 = null,
    sink_accept: u64 = 0,
    input: []const u8 = &.{},
    caps_query: u64 = 0,
    caps_io: u64 = 0,
    planning: u64 = 0,
    delivery_write: u64 = 0,
    delivery_read: u64 = 0,
    invalid: []const u8 = &.{},
    invalid_status: u32 = 0,
    corrupt_status: u32 = 0,
    write_exact: bool = false,
};

pub fn node(bytes: ?[*]u8, capacity: u64) Node {
    var value = Node.init();
    value.bytes = bytes;
    value.byte_capacity = capacity;
    return value;
}

pub fn inputNode(bytes: []const u8) Node {
    var value = node(@ptrCast(@constCast(bytes.ptr)), bytes.len);
    value.byte_length = bytes.len;
    return value;
}

pub fn scalarNode(id: Id) Node {
    var result = node(null, 0);
    result.id = id;
    return result;
}

pub fn scalarValue(id: Id, v: u64) Node {
    var result = scalarNode(id);
    result.value_low = v;
    return result;
}

pub fn paramProfile(id: Id) Node {
    var result = scalarNode(ids.profile);
    result.value_low = id.low;
    result.value_high = id.high;
    return result;
}

pub fn paramTargetCommand(id: Id) Node {
    var result = scalarNode(ids.target_command);
    result.value_low = id.low;
    result.value_high = id.high;
    return result;
}

pub fn paramPlanningBound() Node {
    return scalarNode(ids.planning_bound);
}

pub fn paramSelector(family: u16, ordinal: u32, attrs: u8, command_mask: u32) u64 {
    return (@as(u64, family) << 48) | (@as(u64, ordinal) << 16) | (@as(u64, attrs) << 8) | @as(u64, command_mask & 0x07);
}

pub fn paramScalar(family: u16, ordinal: u32, commands: u32, value: u64) Node {
    var result = scalarNode(ids.parameter);
    result.value_high = paramSelector(family, ordinal, 0x11, commands);
    result.value_low = value;
    return result;
}

pub fn paramBytes(family: u16, ordinal: u32, commands: u32, bytes: []const u8) Node {
    return paramBytesFull(family, ordinal, 0x12, commands, bytes);
}

pub fn paramBytesFull(family: u16, ordinal: u32, attrs: u8, commands: u32, bytes: []const u8) Node {
    var result = scalarNode(ids.parameter);
    result.value_high = paramSelector(family, ordinal, attrs, commands);
    result.bytes = @ptrCast(@constCast(bytes.ptr));
    result.byte_capacity = bytes.len;
    result.byte_length = bytes.len;
    return result;
}

pub fn cap(v: u64) Node {
    return paramScalar(param_family_protocol, protocol_resource_capabilities, cmd_all, v);
}

pub fn pln(v: u64) Node {
    return paramScalar(param_family_protocol, protocol_planning_mode, cmd_all, v);
}

pub fn dlv(v: u64) Node {
    return paramScalar(param_family_protocol, protocol_delivery_mode, cmd_all, v);
}

pub fn lim(v: u64) Node {
    return paramScalar(param_family_protocol, protocol_resource_limit, cmd_all, v);
}

pub fn blck(v: u64) Node {
    return paramScalar(param_family_bzip2, bzip2_block_size, cmd_query_write, v);
}

pub fn lzd(v: u64) Node {
    return paramScalar(param_family_lzma, lzma_dictionary, cmd_all, v);
}

pub fn xck(v: u64) Node {
    return paramScalar(param_family_xz, xz_check, cmd_query_write, v);
}

pub fn xflt(v: u64) Node {
    return paramScalar(param_family_xz, xz_filters, cmd_query_write, v);
}

pub fn pw(bytes: []const u8) Node {
    return paramBytes(param_family_crypto, crypto_password, cmd_all, bytes);
}

pub fn algo(v: u64) Node {
    return paramScalar(param_family_crypto, crypto_algorithm, cmd_all, v);
}

pub fn kdf(v: u64) Node {
    return paramScalar(param_family_crypto, crypto_kdf_rounds_limit, cmd_all, v);
}

pub fn plt(v: u64) Node {
    return paramScalar(param_family_crypto, crypto_password_lifetime, cmd_all, v);
}

pub fn mtime(v: u64) Node {
    return paramScalar(param_family_gzip, gzip_modification_time, cmd_query_write, v);
}

pub fn xflags(v: u64) Node {
    return paramScalar(param_family_gzip, gzip_extra_flags, cmd_query_write, v);
}

pub fn os(v: u64) Node {
    return paramScalar(param_family_gzip, gzip_operating_system, cmd_query_write, v);
}

pub fn text(v: u64) Node {
    return paramScalar(param_family_gzip, gzip_text, cmd_query_write, v);
}

pub fn hcrc(v: u64) Node {
    return paramScalar(param_family_gzip, gzip_header_crc, cmd_query_write, v);
}

pub fn gname(bytes: []const u8) Node {
    return paramBytes(param_family_gzip, gzip_name, cmd_query_write, bytes);
}

pub fn gcomment(bytes: []const u8) Node {
    return paramBytes(param_family_gzip, gzip_comment, cmd_query_write, bytes);
}

pub fn gextra(bytes: []const u8) Node {
    return paramBytes(param_family_gzip, gzip_extra, cmd_query_write, bytes);
}

pub fn tflag(v: u64) Node {
    return paramScalar(param_family_archive, archive_entry_typeflag, cmd_query_write, v);
}

pub fn link(bytes: []const u8) Node {
    return paramBytes(param_family_archive, archive_entry_link_name, cmd_query_write, bytes);
}

pub fn uid(v: u64) Node {
    return paramScalar(param_family_archive, archive_entry_uid, cmd_query_write, v);
}

pub fn mt(v: u64) Node {
    return paramScalar(param_family_archive, archive_entry_mtime, cmd_query_write, v);
}

pub fn ord(v: u64) Node {
    return paramScalar(param_family_archive, archive_ordinal, cmd_read, v);
}

pub fn callbackNode(token_low: u64, token_high: u64) Node {
    var value = node(null, 0);
    value.flags = abi.node_flag_callback_resource;
    value.value_low = token_low;
    value.value_high = token_high;
    return value;
}

pub fn sourceSpan(bytes: []const u8) Node {
    var value = inputNode(bytes);
    value.id = ids.source;
    return value;
}

pub fn sinkSpan(bytes: []u8) Node {
    var value = node(bytes.ptr, bytes.len);
    value.id = ids.sink;
    return value;
}

pub fn sourceCallbackNode(token_low: u64, token_high: u64) Node {
    var value = callbackNode(token_low, token_high);
    value.id = ids.source;
    return value;
}

pub fn sinkCallbackNode(token_low: u64, token_high: u64) Node {
    var value = callbackNode(token_low, token_high);
    value.id = ids.sink;
    return value;
}

pub fn archiveEntryNode(name_node: *Node, data_node: *Node, name: []const u8, data: []const u8) Node {
    var entry = node(null, 0);
    entry.id = ids.parameter;
    entry.value_high = paramSelector(param_family_archive, archive_entry, 0x17, cmd_query_write);
    name_node.* = paramBytesFull(param_family_archive, archive_entry_name, 0x32, cmd_all, name);
    data_node.* = paramBytes(param_family_archive, archive_entry_data, cmd_all, data);
    entry.child = name_node;
    name_node.next = data_node;
    return entry;
}

pub fn archiveEntryWithMethod(
    name_node: *Node,
    data_node: *Node,
    method_node: *Node,
    name: []const u8,
    data: []const u8,
    method: u64,
) Node {
    const entry = archiveEntryNode(name_node, data_node, name, data);
    method_node.* = paramScalar(param_family_archive, archive_entry_method, cmd_query_write, method);
    data_node.next = method_node;
    return entry;
}

pub const ArchiveEntryNodes = struct {
    name: Node,
    data: Node,
    method: Node,
};

pub fn archiveEntryMethod(nodes: *ArchiveEntryNodes, name: []const u8, data: []const u8, method: u64) Node {
    return archiveEntryWithMethod(&nodes.name, &nodes.data, &nodes.method, name, data, method);
}

pub fn capacityDiagnostics(required: *Node, available: *Node, diagnostic: *Node) void {
    required.* = scalarNode(ids.diagnostic_required_capacity);
    available.* = scalarNode(ids.diagnostic_available_capacity);
    diagnostic.* = node(null, 0);
    diagnostic.child = required;
    required.next = available;
}

pub fn cryptoDiagnostic(
    wrong_password: *Node,
    kdf_limit: *Node,
    password_lifetime: *Node,
    unsupported_algorithm: *Node,
) Node {
    wrong_password.* = scalarNode(ids.crypto_wrong_password);
    kdf_limit.* = scalarNode(ids.crypto_kdf_limit);
    password_lifetime.* = scalarNode(ids.crypto_password_lifetime);
    unsupported_algorithm.* = scalarNode(ids.crypto_unsupported_algorithm);
    var diagnostic = node(null, 0);
    diagnostic.child = wrong_password;
    wrong_password.next = kdf_limit;
    kdf_limit.next = password_lifetime;
    password_lifetime.next = unsupported_algorithm;
    return diagnostic;
}

pub fn cryptoProfile() Node {
    var result = scalarNode(ids.crypto_profile);
    result.value_low = ids.crypto.low;
    result.value_high = ids.crypto.high;
    return result;
}

pub fn linkNodes(nodes: []Node) void {
    for (nodes[0 .. nodes.len - 1], 1..) |*current, index| {
        current.next = &nodes[index];
    }
}

pub fn invoke(
    operation: Id,
    request: ?*Node,
    response: *Node,
    workspace: ?[*]u8,
    workspace_capacity: usize,
    callback: ?Callback,
    callback_context: ?*anyopaque,
    diagnostic: ?*Node,
) u32 {
    var envelope = Call.init();
    envelope.operation = operation;
    envelope.request = request;
    envelope.response = response;
    envelope.workspace = workspace;
    envelope.workspace_capacity = workspace_capacity;
    envelope.callback = callback;
    envelope.callback_context = callback_context;
    envelope.diagnostic = diagnostic;
    return abi.stdk_call(&envelope);
}

fn linkAndInvoke(
    operation: Id,
    nodes: []Node,
    response: *Node,
    workspace: ?[*]u8,
    workspace_capacity: usize,
    callback: ?Callback,
    callback_context: ?*anyopaque,
    diagnostic: ?*Node,
) u32 {
    linkNodes(nodes);
    return invoke(operation, &nodes[0], response, workspace, workspace_capacity, callback, callback_context, diagnostic);
}

pub const CallOpts = struct {
    profile: bool = true,
    ctx: bool = false,
    workspace: []u8 = &.{},
    callback: ?Callback = null,
    context: ?*anyopaque = null,
    diagnostic: ?*Node = null,
};

pub fn call(r: *Runner, operation: Id, nodes: []const Node, opts: CallOpts) u32 {
    var list: [16]Node = undefined;
    const prefix: usize = if (opts.profile) 1 else 0;
    const suffix: usize = if (opts.ctx) 3 else 0;
    std.debug.assert(nodes.len + prefix + suffix <= list.len);
    var count: usize = 0;
    if (opts.profile) {
        list[count] = paramProfile(r.profile_id);
        count += 1;
    }
    @memcpy(list[count .. count + nodes.len], nodes);
    count += nodes.len;
    if (opts.ctx) {
        list[count] = cap(ctxCap(r, operation));
        count += 1;
        list[count] = pln(r.planning);
        count += 1;
        list[count] = dlv(ctxDelivery(r, operation));
        count += 1;
    }
    const workspace = if (opts.workspace.len != 0) opts.workspace else r.workspace;
    r.status = linkAndInvoke(operation, list[0..count], &r.response, workspace.ptr, workspace.len, opts.callback, opts.context, opts.diagnostic);
    return r.status;
}

fn ctxCap(r: *Runner, operation: Id) u64 {
    return if (abi.idEqual(operation, ids.query)) r.caps_query else r.caps_io;
}

fn ctxDelivery(r: *Runner, operation: Id) u64 {
    return if (abi.idEqual(operation, ids.read)) r.delivery_read else r.delivery_write;
}

pub fn requireStatus(r: *Runner, expected: u32) !void {
    if (r.status != expected) {
        std.debug.print("scenario {s}: unexpected status {d}, expected {d}\n", .{ r.scenario_name, r.status, expected });
        return error.UnexpectedStatus;
    }
}

pub fn expect(r: *Runner, operation: Id, nodes: []const Node, opts: CallOpts, status: u32) !void {
    _ = call(r, operation, nodes, opts);
    try requireStatus(r, status);
}

pub fn reject(r: *Runner, operation: Id, nodes: []const Node, opts: CallOpts, status: u32, unchanged: []u8) !void {
    @memset(unchanged, 0xa5);
    _ = call(r, operation, nodes, opts);
    try requireStatus(r, status);
    if (!allBytesEqual(unchanged, 0xa5)) return error.OutputChanged;
}

pub fn rejectAny(r: *Runner, operation: Id, nodes: []const Node, opts: CallOpts, unchanged: []u8) !void {
    @memset(unchanged, 0xa5);
    _ = call(r, operation, nodes, opts);
    if (r.status == Status.ok or !allBytesEqual(unchanged, 0xa5)) return error.UnexpectedAcceptance;
}

pub fn expectCapacity(
    r: *Runner,
    operation: Id,
    nodes: []const Node,
    opts: CallOpts,
    required_id: Id,
    available_id: Id,
    expected_required: ?u64,
    expected_available: u64,
    unchanged: []u8,
) !void {
    var required = scalarNode(required_id);
    var available = scalarNode(available_id);
    var diagnostic = node(null, 0);
    diagnostic.child = &required;
    required.next = &available;
    @memset(unchanged, 0xa5);
    _ = call(r, operation, nodes, .{ .profile = opts.profile, .ctx = opts.ctx, .workspace = opts.workspace, .diagnostic = &diagnostic });
    try requireStatus(r, Status.insufficient_capacity);
    if (expected_required) |value| {
        if (required.value_low != value) return error.CapacityRequiredMismatch;
    } else if (required.value_low == 0) {
        return error.CapacityRequiredMissing;
    }
    if (available.value_low != expected_available) return error.CapacityAvailableMismatch;
    if (!allBytesEqual(unchanged, 0xa5)) return error.CapacityChangedOutput;
}

pub const SourceCallbackContext = struct {
    data: []const u8,
    offset: usize = 0,
};

pub const SinkCallbackContext = struct {
    accepted_total: usize = 0,
    fail_after: usize,
    last_status: u32 = Status.ok,
};

pub const SinkBufferContext = struct {
    buffer: []u8,
    offset: usize = 0,
    accept_limit: usize,
};

pub fn sourceCallback(c: *Call) callconv(.c) u32 {
    const ctx: *SourceCallbackContext = @ptrCast(@alignCast(c.callback_context orelse return Status.unsupported));
    const response = c.response orelse return Status.unsupported;
    if (abi.idEqual(c.operation, catalog.callback_size)) {
        response.value_low = ctx.data.len;
        return Status.ok;
    }
    if (abi.idEqual(c.operation, catalog.callback_rewind)) {
        ctx.offset = 0;
        return Status.ok;
    }
    if (abi.idEqual(c.operation, catalog.callback_seek)) {
        ctx.offset = @intCast(c.request.?.value_low);
        return Status.ok;
    }
    if (abi.idEqual(c.operation, catalog.callback_read)) {
        const remaining = ctx.data.len - ctx.offset;
        const capacity: usize = @intCast(response.byte_capacity);
        const n = @min(capacity, remaining);
        if (n > 0) {
            const dst = response.bytes orelse return Status.unsupported;
            @memcpy(dst[0..n], ctx.data[ctx.offset .. ctx.offset + n]);
        }
        ctx.offset += n;
        response.byte_length = n;
        return Status.ok;
    }
    return Status.unsupported;
}

pub fn sinkCallback(c: *Call) callconv(.c) u32 {
    const ctx: *SinkCallbackContext = @ptrCast(@alignCast(c.callback_context orelse return Status.unsupported));
    const response = c.response orelse return Status.unsupported;
    if (abi.idEqual(c.operation, catalog.callback_write)) {
        var n: usize = @intCast(c.request.?.byte_length);
        if (n > 2) n = 2;
        const new_total = ctx.accepted_total + n;
        if (new_total >= ctx.fail_after) {
            ctx.last_status = Status.insufficient_capacity;
            return ctx.last_status;
        }
        ctx.accepted_total = new_total;
        response.byte_length = n;
        return Status.ok;
    }
    return Status.unsupported;
}

pub fn sinkBufferCallback(c: *Call) callconv(.c) u32 {
    const ctx: *SinkBufferContext = @ptrCast(@alignCast(c.callback_context orelse return Status.unsupported));
    const response = c.response orelse return Status.unsupported;
    if (abi.idEqual(c.operation, catalog.callback_write)) {
        var n: usize = @intCast(c.request.?.byte_length);
        if (n > ctx.accept_limit) n = ctx.accept_limit;
        if (ctx.offset + n > ctx.buffer.len) n = ctx.buffer.len - ctx.offset;
        if (n > 0) {
            @memcpy(ctx.buffer[ctx.offset .. ctx.offset + n], c.request.?.bytes.?[0..n]);
        }
        ctx.offset += n;
        response.byte_length = n;
        return Status.ok;
    }
    return Status.unsupported;
}

pub fn allBytesEqual(bytes: []const u8, value: u8) bool {
    for (bytes) |byte| {
        if (byte != value) return false;
    }
    return true;
}

pub fn containsBytes(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.mem.eql(u8, haystack[index .. index + needle.len], needle)) return true;
    }
    return false;
}

pub fn crc32Ieee(bytes: []const u8) u32 {
    var crc: u32 = 0xffff_ffff;
    for (bytes) |byte| {
        var value = crc ^ byte;
        var bit: u5 = 0;
        while (bit < 8) : (bit += 1) {
            crc = if ((value & 1) != 0) (value >> 1) ^ 0xedb8_8320 else value >> 1;
            value = crc;
        }
    }
    return ~crc;
}
