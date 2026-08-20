const std = @import("std");

const harness = @import("harness");
const run = @import("run");

const cmd = @import("cmd.zig");
const env_mod = @import("env.zig");
const gate = @import("gate.zig");
const lib = @import("lib.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");
const ours = @import("ours.zig");

// Bound-sized verified staging (xz) peaks near 296 MiB at the largest corpus
// file with the bt4 tuning; 384 MiB keeps every row configuration resident.
const workspace_size = 384 * 1024 * 1024;

fn corpusComplete(env: *env_mod.Env, dir: []const u8) bool {
    for (env_mod.silesia_files) |name| {
        if (!env.existsPath("{s}/{s}", .{ dir, name })) return false;
    }
    return true;
}

fn ensureCorpus(env: *env_mod.Env) ![]const u8 {
    for (env_mod.paths.corpus_candidates) |dir| {
        if (corpusComplete(env, dir)) return dir;
    }
    std.debug.print("Silesia corpus missing; downloading {s}\n", .{env_mod.silesia_url});
    try std.Io.Dir.cwd().createDirPath(env.io, env_mod.paths.corpus_dir);
    const download = try run.output(env.init, &.{ "curl", "-fsSL", "-o", env_mod.paths.corpus_zip, env_mod.silesia_url });
    env.allocator.free(download);
    try run.silent(env.init, &.{ "unzip", "-q", "-o", env_mod.paths.corpus_zip, "-d", env_mod.paths.corpus_dir });
    for (env_mod.paths.corpus_candidates) |dir| {
        if (corpusComplete(env, dir)) return dir;
    }
    return error.SilesiaCorpusMissing;
}

fn produceArchive(env: *env_mod.Env, comptime row: matrix.Row, input_path: []const u8, output_path: []const u8) ![]u8 {
    if (row.kind == .lzma_file) {
        const lzma_cmd = comptime cmd.get(.lzma);
        const bin = try env.makePath("{s}/{s}", .{ env_mod.paths.cmd, lzma_cmd.exe });
        defer env.allocator.free(bin);
        _ = try cmd.encode(env, lzma_cmd, bin, input_path, output_path, "lzma", false, &.{});
        return env.readFile(output_path, 1 << 31);
    }
    const rar_bin = try env.makePath("{s}/rar", .{env_mod.paths.bins});
    defer env.allocator.free(rar_bin);
    const pwd_stdout = try run.output(env.init, &.{"pwd"});
    defer env.allocator.free(pwd_stdout);
    const pwd = std.mem.trim(u8, pwd_stdout, " \n\r");
    const rar_abs = try env.makePath("{s}/{s}", .{ pwd, rar_bin });
    defer env.allocator.free(rar_abs);
    const stdout = try run.outputCwd(env.init, env_mod.paths.work, &.{ rar_abs, "a", "-qo-", "-m0", "-idq", "out.rar", "input.bin" });
    env.allocator.free(stdout);
    return env.readFile(output_path, 1 << 31);
}

fn availability(env: *env_mod.Env, comptime row: matrix.Row) [4]bool {
    return .{
        true,
        if (row.cmd) |id| env.existsPath("{s}/{s}", .{ env_mod.paths.cmd, cmd.get(id).exe }) else false,
        row.lib != null,
        if (row.bin) |id| env.existsPath("{s}/{s}", .{ env_mod.paths.bins, cmd.get(id).exe }) else false,
    };
}

fn measureRow(env: *env_mod.Env, comptime row: matrix.Row, workspace: []u8) !metric.Totals {
    const cmd_bin: ?[]u8 = if (row.cmd) |id| try env.makePath("{s}/{s}", .{ env_mod.paths.cmd, cmd.get(id).exe }) else null;
    defer if (cmd_bin) |p| env.allocator.free(p);
    const bin_bin: ?[]u8 = if (row.bin) |id| try env.makePath("{s}/{s}", .{ env_mod.paths.bins, cmd.get(id).exe }) else null;
    defer if (bin_bin) |p| env.allocator.free(p);
    var totals = metric.Totals{};
    for (env_mod.silesia_files[0..env.limit]) |name| {
        if (env.file) |filter| {
            if (!std.mem.eql(u8, name, filter)) continue;
        }
        const input = try env.readFile(try env.makePath("{s}/{s}", .{ env.corpus, name }), 1 << 27);
        defer env.allocator.free(input);
        const encoded = if (env.bound and !row.archive and !row.decode_only)
            try env.allocator.alloc(u8, try ours.encodedBound(row, input, workspace))
        else
            try env.allocator.alloc(u8, input.len + input.len / 2 + (1 << 20));
        defer env.allocator.free(encoded);
        const decoded = try env.allocator.alloc(u8, input.len);
        defer env.allocator.free(decoded);
        const input_path = try env.makePath("{s}/input.bin", .{env_mod.paths.work});
        defer env.allocator.free(input_path);
        const output_path = try env.makePath("{s}/out.{s}", .{ env_mod.paths.work, row.ext });
        defer env.allocator.free(output_path);
        try std.Io.Dir.cwd().createDirPath(env.io, env_mod.paths.work);
        try env.writeFile(input_path, input);
        totals.input_bytes += input.len;

        if (row.decode_only) {
            const archive = try produceArchive(env, row, input_path, output_path);
            defer env.allocator.free(archive);
            totals.add(.ours, ours.decodeOnly(env, row, archive, input, decoded, workspace));
            if (row.cmd) |id| totals.add(.cmd, cmd.decodeMeasure(env, id, cmd_bin.?, output_path, input));
            if (row.lib != null) totals.add(.lib, lib.decodeOnly(env, lib.refOf(row), archive, input, decoded));
            if (row.bin) |id| totals.add(.bin, cmd.decodeMeasure(env, id, bin_bin.?, output_path, input));
        } else {
            const ours_result = ours.transform(env, row, input, encoded, decoded, workspace);
            totals.add(.ours, ours_result);
            if (!ours_result.ok) {
                std.debug.print("ours {s} failed on {s} (len {d})\n", .{ row.name, name, input.len });
                if (env.row != null) {
                    try env.writeFile(env_mod.paths.debug_ours, encoded[0..@min(ours_result.encoded, encoded.len)]);
                    try env.writeFile(env_mod.paths.debug_input, input);
                }
            }
            var console_ns: u64 = 0;
            if (row.cmd) |id| {
                const m = cmd.measure(env, id, cmd_bin.?, input_path, output_path, row.ext, row.store, row.cmd_args, input);
                totals.add(.cmd, m);
                console_ns = m.encode_ns;
            }
            if (row.lib != null) {
                var ref = lib.refOf(row);
                if (row.lib.? == .lzma7z) ref.console = .{ .path = output_path, .encode_ns = console_ns };
                totals.add(.lib, lib.measure(env, ref, input, encoded, decoded));
            }
            if (row.bin) |id| {
                totals.add(.bin, cmd.measure(env, id, bin_bin.?, input_path, output_path, row.ext, row.store, row.cmd_args, input));
            }
        }
        env.delete(input_path);
        env.delete(output_path);
    }
    return totals;
}

pub fn main(init: std.process.Init) !void {
    @setEvalBranchQuota(10000);
    harness.io = init.io;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const catalog_path = args.next() orelse return error.MissingCatalogArgument;
    if (args.next() != null) return error.UnexpectedArgument;
    _ = try harness.loadCatalog(catalog_path);

    var env = env_mod.Env{
        .io = init.io,
        .init = init,
        .allocator = std.heap.page_allocator,
        .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
        .corpus = env_mod.paths.corpus,
        .row = init.environ_map.get("STDK_BENCH_ROW"),
        .file = init.environ_map.get("STDK_BENCH_FILE"),
        .bound = env_mod.parseDefaultOn(init.environ_map.get("STDK_BENCH_BOUND")),
    };
    defer env.arena.deinit();
    if (init.environ_map.get("STDK_BENCH_FILES")) |value| {
        env.limit = @min(std.fmt.parseInt(usize, value, 10) catch env_mod.silesia_files.len, env_mod.silesia_files.len);
    }
    env.corpus = try ensureCorpus(&env);
    const workspace = try env.allocator.alloc(u8, workspace_size);
    defer env.allocator.free(workspace);

    const runs = env_mod.parseRuns(init.environ_map.get("STDK_BENCH_RUNS"));
    const skip_warmup: usize = if (runs > 1) 1 else 0;

    const gate_cfg = env_mod.gate(init.environ_map);
    const file_filtered = env.file != null or env.limit != env_mod.silesia_files.len;
    const gate_fatal = gate_cfg.fatal and runs >= 3 and env.row == null and !file_filtered;
    if (gate_cfg.enabled) {
        if (runs < 3) std.debug.print("gate: warning: fewer than 3 runs ({d}); fatal mode disabled\n", .{runs});
        if (env.row != null or file_filtered) std.debug.print("gate: warning: row or file filter active; fatal mode disabled\n", .{});
    }

    var per_row: [matrix.rows.len]std.ArrayList(metric.Totals) = undefined;
    inline for (0..matrix.rows.len) |i| per_row[i] = std.ArrayList(metric.Totals).empty;
    defer {
        inline for (0..matrix.rows.len) |i| per_row[i].deinit(env.allocator);
    }

    var run_index: usize = 0;
    while (run_index < runs) : (run_index += 1) {
        var run_report = std.ArrayList(u8).empty;
        defer run_report.deinit(env.allocator);
        try run_report.appendSlice(env.allocator, metric.header);
        inline for (matrix.rows, 0..) |row, idx| {
            const selected = if (env.row) |filter| std.mem.eql(u8, row.name, filter) else true;
            if (selected) {
                if (run_index == 0) std.debug.print("benchmark {s} ...\n", .{row.name});
                const totals = try measureRow(&env, row, workspace);
                try metric.row(&run_report, env.allocator, row, totals, availability(&env, row));
                try per_row[idx].append(env.allocator, totals);
            }
        }
        const run_path = try std.fmt.allocPrint(env.allocator, "zig-out/benchmark/report_{d}.txt", .{run_index});
        defer env.allocator.free(run_path);
        try env.writeFile(run_path, run_report.items);
    }

    var report = std.ArrayList(u8).empty;
    defer report.deinit(env.allocator);
    try report.appendSlice(env.allocator, metric.header);
    var results = std.ArrayList(gate.Result).empty;
    defer results.deinit(env.allocator);
    inline for (matrix.rows, 0..) |row, idx| {
        const selected = if (env.row) |filter| std.mem.eql(u8, row.name, filter) else true;
        if (selected) {
            const list = per_row[idx].items;
            const totals = if (list.len > 0) try metric.medianTotals(env.allocator, list, skip_warmup) else metric.Totals{};
            const available = availability(&env, row);
            try metric.row(&report, env.allocator, row, totals, available);
            if (gate_cfg.enabled) try results.append(env.allocator, gate.classify(row, totals, available, gate_cfg));
        }
    }
    // With the gate on, a row-filtered run must not overwrite the full-matrix baseline.
    const row_report: ?[]u8 = if (gate_cfg.enabled and env.row != null)
        try std.fmt.allocPrint(env.allocator, "zig-out/benchmark/report_{s}.txt", .{env.row.?})
    else
        null;
    defer if (row_report) |path| env.allocator.free(path);
    try env.writeFile(row_report orelse env_mod.paths.report, report.items);

    if (gate_cfg.enabled) {
        gate.sort(results.items);
        var gate_report = std.ArrayList(u8).empty;
        defer gate_report.deinit(env.allocator);
        try gate_report.appendSlice(env.allocator, gate.header);
        for (results.items) |result| try gate.row(&gate_report, env.allocator, result);
        const row_gate: ?[]u8 = if (env.row) |filter|
            try std.fmt.allocPrint(env.allocator, "zig-out/benchmark/gate_{s}.txt", .{filter})
        else
            null;
        defer if (row_gate) |path| env.allocator.free(path);
        const gate_path = row_gate orelse env_mod.paths.gate;
        try env.writeFile(gate_path, gate_report.items);
        const summary = gate.summarize(results.items);
        std.debug.print("gate: {d} pass, {d} fail, {d} noisy, {d} unmeasurable, {d} unhealthy -> {s}\n", .{ summary.pass, summary.fail, summary.noisy, summary.unmeasurable, summary.unhealthy, gate_path });
        if (results.items.len > 0) {
            if (results.items[0].worst_gap) |worst| std.debug.print("gate: worst gap {d:.1}% ({s})\n", .{ worst * 100.0, results.items[0].name });
        }
        if (gate_fatal and summary.fatalRows() > 0) {
            std.debug.print("gate: fatal: {d} row(s) miss parity\n", .{summary.fatalRows()});
            std.process.exit(1);
        }
    }
}
