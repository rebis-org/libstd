const std = @import("std");

const envelope = @import("../kernel/envelope.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const call = @import("call.zig");
const drivers = @import("drivers.zig");
const executor = @import("executor.zig");
const sessions = @import("sessions.zig");
const Exception = @import("../common/primitive/exception.zig").Exception;

// The handle is the caller's storage pointer, so sessions stay isolated.
// Destroy clears the cookie. Span construction is a no-op.
const Session = sessions.Session;

// Handle identity: live sessions carry the alive cookie, dead storage the
// dead cookie; the boundary never dispatches through garbage ops.
const alive_cookie: u64 = 0x5354_444b_5f31_0001;
const dead_cookie: u64 = 0x5354_444b_5f31_dead;

// Generous but bounded: zip-bomb protection holds without host policing.
// Unbounded streaming needs stdk_session_bounded with maxInt values.
const default_max_encoded: u64 = 16 << 30;
const default_max_decoded: u64 = 16 << 30;
const default_max_work: u64 = 4 << 30;
const default_max_entries: u64 = 1 << 20;

fn exceptionStatus(exception: Exception) u32 {
    return vocabulary.statusFor(exception);
}

// Single-sourced surface for matching, sizing, and the catalog projection.
// Ordering is ABI once released: append only.
const SessionDef = struct {
    component: [:0]const u8,
    verb: [:0]const u8,
    storage: *const fn () usize,
    session: *const fn ([]u8, sessions.Budgets) Exception!Session,
};
// The tar/write boundary gap: fixed-mode framing cannot express typeflags,
// links, modes, or pax names. Full write re-entry waits for v2.
const session_defs = [_]SessionDef{
    .{ .component = "gzip", .verb = "decode", .storage = drivers.gzipDecodeStorage, .session = drivers.gzipDecodeSession },
    .{ .component = "deflate", .verb = "decode", .storage = drivers.deflateDecodeStorage, .session = drivers.deflateDecodeSession },
    .{ .component = "zlib", .verb = "decode", .storage = drivers.zlibDecodeStorage, .session = drivers.zlibDecodeSession },
    .{ .component = "deflate", .verb = "encode", .storage = drivers.deflateEncodeStorage, .session = drivers.deflateEncodeSession },
    .{ .component = "gzip", .verb = "encode", .storage = drivers.gzipEncodeStorage, .session = drivers.gzipEncodeSession },
    .{ .component = "zlib", .verb = "encode", .storage = drivers.zlibEncodeStorage, .session = drivers.zlibEncodeSession },
    .{ .component = "lz4", .verb = "decode", .storage = drivers.lz4DecodeStorage, .session = drivers.lz4DecodeSession },
    .{ .component = "lz4", .verb = "encode", .storage = drivers.lz4EncodeStorage, .session = drivers.lz4EncodeSession },
    .{ .component = "brotli", .verb = "decode", .storage = drivers.brotliDecodeStorage, .session = drivers.brotliDecodeSession },
    .{ .component = "lz4-legacy", .verb = "decode", .storage = drivers.lz4LegacyDecodeStorage, .session = drivers.lz4LegacyDecodeSession },
    .{ .component = "tar", .verb = "encode", .storage = drivers.tarEncodeStorage, .session = drivers.tarEncodeSession },
};

fn matchSessionIndex(component: ?[*:0]const u8, verb: ?[*:0]const u8) ?usize {
    const component_name = if (component) |ptr| std.mem.span(ptr) else return null;
    const verb_name = if (verb) |ptr| std.mem.span(ptr) else return null;
    for (session_defs, 0..) |def, index| {
        if (std.mem.eql(u8, component_name, def.component) and std.mem.eql(u8, verb_name, def.verb)) {
            return index;
        }
    }
    return null;
}

// Poison storage after create failure; later calls see the dead sentinel.
// Undersized storage cannot be poisoned; the contract forbids reuse.
fn markDead(bytes: [*]u8, storage_len: u64) void {
    const len: usize = std.math.cast(usize, storage_len) orelse return;
    if (len < @sizeOf(Session)) return;
    std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]).* = .{
        .state = undefined,
        .ops = &destroyed_ops,
        .alive = false,
        .failed = true,
        .cookie = dead_cookie,
        .storage_len = 0,
    };
}

fn checkAlive(handle: ?*anyopaque) ?*Session {
    const raw = handle orelse return null;
    // Create checks alignment, but step and destroy take opaque handles;
    // refuse a misaligned pointer before the cast.
    if (@intFromPtr(raw) % @alignOf(Session) != 0) return null;
    const session: *Session = @ptrCast(@alignCast(raw));
    if (session.cookie != alive_cookie) return null;
    if (session.ops == &destroyed_ops) return null;
    return session;
}

export fn stdk_session_storage(component: ?[*:0]const u8, verb: ?[*:0]const u8) callconv(.c) u64 {
    const index = matchSessionIndex(component, verb) orelse return 0;
    return driverStateOffset() + session_defs[index].storage();
}

// Layout is [Session record][driver state] so creation never collides with managed state.
fn createWithBudgets(
    component: ?[*:0]const u8,
    verb: ?[*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
    budgets: sessions.Budgets,
) u32 {
    const index = matchSessionIndex(component, verb) orelse return envelope.Status.unsupported;
    const bytes = storage orelse {
        return envelope.Status.invalid_call;
    };
    // The Session record holds pointers and u64 words; misaligned storage would
    // be undefined behavior in release-fast.
    if (@intFromPtr(bytes) % @alignOf(Session) != 0) return envelope.Status.invalid_call;
    if (storage_len < driverStateOffset()) {
        markDead(bytes, storage_len);
        return envelope.Status.insufficient_capacity;
    }
    const state_storage = bytes[driverStateOffset() .. std.math.cast(usize, storage_len) orelse return envelope.Status.insufficient_capacity];
    const session = session_defs[index].session(state_storage, budgets) catch |exception| {
        markDead(bytes, storage_len);
        return exceptionStatus(exception);
    };
    std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]).* = session;
    const live = std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]);
    live.cookie = alive_cookie;
    live.storage_len = storage_len;
    return envelope.Status.ok;
}

export fn stdk_session_create(
    component: ?[*:0]const u8,
    verb: ?[*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
) callconv(.c) u32 {
    return createWithBudgets(component, verb, storage, storage_len, .{
        .max_encoded = default_max_encoded,
        .max_decoded = default_max_decoded,
        .max_work = default_max_work,
        .max_entries = default_max_entries,
    });
}

// Hosts pass zip-bomb limits here instead of policing produced bytes.
// max_entries is reserved: v1 session pairs are entry-less streams.
export fn stdk_session_bounded(
    component: ?[*:0]const u8,
    verb: ?[*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
    max_encoded: u64,
    max_decoded: u64,
    max_work: u64,
    max_entries: u64,
) callconv(.c) u32 {
    return createWithBudgets(component, verb, storage, storage_len, .{
        .max_encoded = max_encoded,
        .max_decoded = max_decoded,
        .max_work = max_work,
        .max_entries = max_entries,
    });
}

fn driverStateOffset() usize {
    return std.mem.alignForward(usize, @sizeOf(Session), 16);
}

// u128 arithmetic keeps end computations overflow-free against hostile
// lengths. The C boundary reports no failure, so the check stays infallible.
fn rangesOverlap(a: ?[*]const u8, a_len: u64, b: ?[*]const u8, b_len: u64) bool {
    const a_start = if (a) |ptr| @as(u128, @intFromPtr(ptr)) else return false;
    const b_start = if (b) |ptr| @as(u128, @intFromPtr(ptr)) else return false;
    return a_start < b_start + b_len and b_start < a_start + a_len;
}

export fn stdk_session_step(
    handle: ?*anyopaque,
    input: ?[*]const u8,
    input_len: u64,
    output: ?[*]u8,
    output_len: u64,
    end_of_input: c_int,
    counts_out: ?*[2]u64,
    state_out: ?*c_int,
) callconv(.c) u32 {
    const session = checkAlive(handle) orelse return envelope.Status.invalid_call;
    const counts = counts_out orelse return envelope.Status.invalid_call;
    // A NULL buffer with a nonzero length is a caller defect; treating it
    // as an empty buffer would silently misreport the transfer.
    if (input == null and input_len != 0) return envelope.Status.invalid_call;
    if (output == null and output_len != 0) return envelope.Status.invalid_call;
    // Aliasing input, output, or the session's own storage silently corrupts
    // state mid-copy, so refuse overlapping ranges up front.
    const storage_start: ?[*]const u8 = @ptrCast(handle.?);
    if (rangesOverlap(input, input_len, output, output_len) or
        rangesOverlap(input, input_len, storage_start, session.storage_len) or
        rangesOverlap(output, output_len, storage_start, session.storage_len))
    {
        return envelope.Status.invalid_call;
    }
    const input_slice: []const u8 = if (input) |ptr| ptr[0 .. std.math.cast(usize, input_len) orelse return envelope.Status.invalid_call] else &.{};
    const output_slice: []u8 = if (output) |ptr| ptr[0 .. std.math.cast(usize, output_len) orelse return envelope.Status.invalid_call] else &.{};
    const result = session.step(input_slice, output_slice, end_of_input != 0);
    counts[0] = result.consumed;
    counts[1] = result.produced;
    if (state_out) |state| state.* = switch (result.status) {
        .open => 0,
        .done => 1,
        .failed => -1,
    };
    if (result.status == .failed) {
        session.failed = true;
        session.failure_status = exceptionStatus(result.exception orelse error.InternalException);
        session.failure_detail = result.required_capacity;
        return exceptionStatus(result.exception orelse error.InternalException);
    }
    return envelope.Status.ok;
}

// The last failed step's status plus a driver-defined scalar: required
// capacity for insufficient_capacity, else 0. Valid while storage is alive.
export fn stdk_session_failure(
    handle: ?*anyopaque,
    status_out: ?*u32,
    detail_out: ?*u64,
) callconv(.c) u32 {
    const session = checkAlive(handle) orelse return envelope.Status.invalid_call;
    if (status_out) |status| status.* = session.failure_status;
    if (detail_out) |detail| detail.* = session.failure_detail;
    return envelope.Status.ok;
}

// "v1:" is the version and retirement mechanism: pairs are append-only
// within a version, and a breaking change bumps the prefix.
export fn stdk_session_catalog() callconv(.c) [*:0]const u8 {
    return session_catalog_text;
}

// The async completion record: caller-owned storage, like session storage.
// The ticket is the record pointer; the library flips it to done once.
pub const Completion = extern struct {
    structure_size: u32,
    state: u32,
    status: u32,
    reserved: u32,

    pub const in_progress: u32 = 0;
    pub const done: u32 = 1;
    // Transient: a cancel request landed; the task observes it at its start.
    pub const cancelling: u32 = 2;

    pub const pending: u32 = std.math.maxInt(u32);

    comptime {
        // The header fixes the same 16 bytes; a drift is a silent host miscompile.
        if (@sizeOf(Completion) != 16) @compileError("stdk_completion layout drifted: the ABI fixes 16 bytes.");
    }

    pub fn init() Completion {
        return .{ .structure_size = @sizeOf(Completion), .state = in_progress, .status = 0, .reserved = 0 };
    }

    fn isValid(self: *const Completion) bool {
        return self.structure_size >= @sizeOf(Completion) and self.reserved == 0 and
            (self.state == in_progress or self.state == done or self.state == cancelling);
    }
};

// The submission descriptor: caller-owned storage, alive until the record
// is done; a threaded executor reads it on its own thread.
pub const Submission = extern struct {
    call: ?*envelope.Call,
    completion: ?*Completion,
};

fn submitTask(context: *anyopaque) callconv(.c) u32 {
    const submission: *Submission = @ptrCast(@alignCast(context));
    const completion = submission.completion orelse return envelope.Status.invalid_call;
    // Cancellation is honored at the task boundary: a record already marked
    // cancelling skips the envelope and completes as cancelled.
    if (@atomicLoad(u32, &completion.state, .seq_cst) == Completion.cancelling) {
        complete(completion, envelope.Status.cancelled);
        return envelope.Status.cancelled;
    }
    const status = if (submission.call) |handle|
        call.run(handle, executor.inline_executor)
    else
        envelope.Status.invalid_call;
    complete(completion, status);
    return status;
}

// Returns the submission verdict; the call's own status lands in the record.
// The inline executor completes before this returns; threaded arms flip it later.
export fn stdk_submit(call_handle: ?*envelope.Call, record: ?*Completion) callconv(.c) u32 {
    const completion = record orelse return envelope.Status.invalid_call;
    if (!completion.isValid()) return envelope.Status.invalid_call;
    if (completion.state != Completion.in_progress) return envelope.Status.invalid_call;
    if (call_handle == null) {
        complete(completion, envelope.Status.invalid_call);
        return envelope.Status.invalid_call;
    }
    var submission = Submission{ .call = call_handle, .completion = completion };
    _ = executor.inline_executor.run(.{ .context = &submission, .invoke = submitTask });
    return envelope.Status.ok;
}

// The general form: N caller-owned submissions through a caller-selected
// executor; a null executor selects the inline default. One malformed
// record fails the group before any task is scheduled.
export fn stdk_group(
    submissions: ?[*]Submission,
    count: u64,
    exec: ?*const executor.Executor,
) callconv(.c) u32 {
    const subs = submissions orelse return envelope.Status.invalid_call;
    const total = std.math.cast(usize, count) orelse return envelope.Status.invalid_call;
    if (total == 0) return envelope.Status.invalid_call;
    for (subs[0..total]) |*submission| {
        const completion = submission.completion orelse return envelope.Status.invalid_call;
        if (!completion.isValid() or completion.state != Completion.in_progress) return envelope.Status.invalid_call;
    }
    const selected = if (exec) |e| e.* else executor.inline_executor;
    for (0..total) |index| {
        _ = selected.run(.{ .context = &subs[index], .invoke = submitTask });
    }
    return envelope.Status.ok;
}

fn complete(completion: *Completion, status: u32) void {
    @atomicStore(u32, &completion.status, status, .seq_cst);
    @atomicStore(u32, &completion.state, Completion.done, .seq_cst);
}

// Idempotent and non-blocking: the envelope status once done, pending
// while a threaded executor still holds the call, invalid_call for a
// malformed record.
export fn stdk_poll(record: ?*Completion) callconv(.c) u32 {
    const completion = record orelse return envelope.Status.invalid_call;
    if (!completion.isValid()) return envelope.Status.invalid_call;
    if (completion.state == Completion.done) return completion.status;
    return Completion.pending;
}

// Idempotent like poll. A pending cancel plants a request the task honors at
// its start boundary; a running envelope always completes with its real
// status, and a done record accepts cancel as a no-op.
export fn stdk_cancel(record: ?*Completion) callconv(.c) u32 {
    const completion = record orelse return envelope.Status.invalid_call;
    if (!completion.isValid()) return envelope.Status.invalid_call;
    while (true) {
        const state = @atomicLoad(u32, &completion.state, .seq_cst);
        switch (state) {
            Completion.done, Completion.cancelling => return envelope.Status.ok,
            Completion.in_progress => {
                if (@cmpxchgStrong(u32, &completion.state, Completion.in_progress, Completion.cancelling, .seq_cst, .seq_cst) == null) return envelope.Status.ok;
            },
            else => return envelope.Status.invalid_call,
        }
    }
}

const session_catalog_text: [:0]const u8 = blk: {
    var text: [:0]const u8 = "v1:";
    for (session_defs, 0..) |def, index| {
        const entry = def.component ++ "/" ++ def.verb;
        text = if (index == 0) text ++ entry else text ++ "," ++ entry;
    }
    break :blk text;
};

// Destroy is idempotent and total: live sessions are destroyed, dead ones
// report ok, and never-created storage is refused, never dispatched.
export fn stdk_session_destroy(handle: ?*anyopaque) callconv(.c) u32 {
    const raw = handle orelse return envelope.Status.invalid_call;
    if (@intFromPtr(raw) % @alignOf(Session) != 0) return envelope.Status.invalid_call;
    const session: *Session = @ptrCast(@alignCast(raw));
    if (session.cookie == dead_cookie or session.ops == &destroyed_ops) return envelope.Status.ok;
    if (session.cookie != alive_cookie) return envelope.Status.invalid_call;
    session.destroy();
    session.cookie = dead_cookie;
    session.ops = &destroyed_ops;
    return envelope.Status.ok;
}

// Sentinel ops for destroyed sessions. Function pointers are never called since callers check first.
const destroyed_ops = sessions.Ops{
    .step = struct {
        fn call(state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) sessions.StepResult {
            _ = state;
            _ = input;
            _ = output;
            _ = end_of_input;
            unreachable;
        }
    }.call,
    .destroy = struct {
        fn call(state: *anyopaque) void {
            _ = state;
        }
    }.call,
};
