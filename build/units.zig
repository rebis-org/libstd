const std = @import("std");

const acceptance = @import("acceptance.zig");
const bench_env = @import("acceptance/benchmark/env.zig");
const checks = @import("checks.zig");
const dist = @import("dist.zig");
const common = @import("platform/common.zig");
const vendor = @import("vendor.zig");

pub const Category = enum {
    distribution,
    acceptance,
    vendor,
    checks,
};

pub const registry = .{
    .vendor = .{ .category = Category.vendor, .units = vendor.units, .expand = vendor.expand },
    .acceptance = .{ .category = Category.acceptance, .units = acceptance.units, .expand = acceptance.expand },
    .distribution = .{ .category = Category.distribution, .units = dist.units, .expand = dist.expand },
    .checks = .{ .category = Category.checks, .units = checks.units, .expand = checks.expand },
};

const registry_fields = @typeInfo(@TypeOf(registry)).@"struct";

comptime {
    for (registry_fields.field_names) |name| {
        if (!@hasField(Category, name)) @compileError("registry field is not a category: " ++ name ++ ".");
        const layer = @field(registry, name);
        for (layer.units, 0..) |unit, index| {
            for (layer.units[0..index]) |other| {
                if (std.mem.eql(u8, unit.name, other.name)) @compileError("duplicate unit name: " ++ unit.name ++ ".");
            }
        }
    }
}

pub fn expand(b: *std.Build, ctx: *common.Settings) void {
    addCorpusStep(b);
    inline for (registry_fields.field_names) |name| {
        @field(registry, name).expand(b, ctx);
    }
}

fn renderList() []const u8 {
    comptime {
        var out: []const u8 = "";
        for (registry_fields.field_names) |name| {
            const layer = @field(registry, name);
            out = out ++ @tagName(layer.category) ++ ":\n";
            for (layer.units) |unit| {
                out = out ++ "  " ++ unit.name ++ "\n";
            }
        }
        return out;
    }
}

fn zigStringLiteral(comptime s: []const u8) []const u8 {
    comptime {
        var out: []const u8 = "\"";
        for (s) |c| {
            out = out ++ switch (c) {
                '\n' => "\\n",
                '\\' => "\\\\",
                '"' => "\\\"",
                else => &[1]u8{c},
            };
        }
        return out ++ "\"";
    }
}

pub fn addListingStep(b: *std.Build) *std.Build.Step {
    const listing = comptime renderList();
    const write = b.addWriteFiles();
    const source = write.add("units_main.zig", "const std = @import(\"std\");\n" ++
        "pub fn main(init: std.process.Init) !void {\n" ++
        "    try std.Io.File.stdout().writeStreamingAll(init.io, " ++
        comptime zigStringLiteral(listing) ++ ");\n}\n");
    const exe = b.addExecutable(.{
        .name = "units",
        .root_module = b.createModule(.{
            .root_source_file = source,
            .target = b.graph.host,
        }),
    });
    const run = b.addRunArtifact(exe);
    const step = b.step("units", "List the registered build units");
    step.dependOn(&run.step);
    return step;
}

// CI suite jobs restore no benchmark cache, so the Silesia corpus the
// brotli round-trip needs must be materialized on demand. The download is
// pinned by content exactly as the benchmark harness pins it.
fn addCorpusStep(b: *std.Build) void {
    const root_entry = bench_env.paths.corpus_dir ++ "/mozilla";
    const nested_entry = bench_env.paths.corpus_dir ++ "/silesia/mozilla";
    const corpus_script = b.fmt(
        \\if [ ! -f {s} ] && [ ! -f {s} ]; then
        \\  mkdir -p {s} &&
        \\  curl -fsSL -o {s} {s} &&
        \\  echo "{s}  {s}" | shasum -a 256 -c - &&
        \\  unzip -q -o {s} -d {s}
        \\fi
    , .{
        root_entry,
        nested_entry,
        bench_env.paths.corpus_dir,
        bench_env.paths.corpus_zip,
        bench_env.silesia_url,
        bench_env.silesia_sha256,
        bench_env.paths.corpus_zip,
        bench_env.paths.corpus_zip,
        bench_env.paths.corpus_dir,
    });
    const corpus_run = std.Build.Step.Run.create(b, "corpus download");
    corpus_run.addArgs(&.{ "sh", "-c", corpus_script });
    b.step("corpus", "Materialize the Silesia benchmark corpus").dependOn(&corpus_run.step);
}
