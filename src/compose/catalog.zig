const envelope = @import("../kernel/envelope.zig");
const EnvelopeId = envelope.Id;
const vocabulary = @import("../kernel/vocabulary.zig");
const command_mask_query = vocabulary.command_mask_query;
const command_mask_read = vocabulary.command_mask_read;
const command_mask_write = vocabulary.command_mask_write;
const CommandPolicy = vocabulary.CommandPolicy;
const CommitMode = vocabulary.CommitMode;

// Behavioral dispatch policy only; structural descriptors live in kernel.catalog.

fn idEqual(left: EnvelopeId, right: EnvelopeId) bool {
    return left.low == right.low and left.high == right.high;
}

pub fn profileTagForId(id: EnvelopeId) ?vocabulary.ProfileTag {
    const ids = vocabulary.ids;
    if (idEqual(id, ids.test_echo)) return .test_echo;
    if (idEqual(id, ids.test_read)) return .test_read;
    if (idEqual(id, ids.deflate)) return .deflate;
    if (idEqual(id, ids.gzip)) return .gzip;
    if (idEqual(id, ids.zstd)) return .zstd;
    if (idEqual(id, ids.bzip2)) return .bzip2;
    if (idEqual(id, ids.lzma)) return .lzma;
    if (idEqual(id, ids.lzma2)) return .lzma2;
    if (idEqual(id, ids.lzma_file)) return .lzma_file;
    if (idEqual(id, ids.xz)) return .xz;
    if (idEqual(id, ids.tar)) return .tar;
    if (idEqual(id, ids.zip)) return .zip;
    if (idEqual(id, ids.sevenzip)) return .sevenzip;
    if (idEqual(id, ids.rar)) return .rar;
    return null;
}

const all_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_write | vocabulary.resource_capability_bit_size | vocabulary.resource_capability_bit_replay | vocabulary.resource_capability_bit_seek | vocabulary.resource_capability_bit_range;
const replay_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_replay;
const archive_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_write | vocabulary.resource_capability_bit_size | vocabulary.resource_capability_bit_replay;

fn measuredPolicy(command: u32, target: u32, comptime confirmed: bool) ?CommandPolicy {
    const commit: CommitMode = if (confirmed) .confirmed else .tentative;
    if (command == command_mask_query) {
        if (target != command_mask_read and target != command_mask_write) return null;
        return .{ .command = command_mask_query, .target = target, .capabilities = replay_capabilities, .sizing = .measured, .commit = commit };
    }
    if (command != command_mask_read and command != command_mask_write) return null;
    return .{ .command = command, .capabilities = replay_capabilities, .sizing = .measured, .commit = commit };
}

fn archivePolicy(command: u32, target: u32) ?CommandPolicy {
    if (command == command_mask_query) {
        if (target == command_mask_read) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .tentative };
        if (target == command_mask_write) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .confirmed };
        return null;
    }
    if (command == command_mask_read) return .{ .command = command_mask_read, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .tentative };
    if (command == command_mask_write) return .{ .command = command_mask_write, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .confirmed };
    return null;
}

fn rarPolicy(command: u32, target: u32) ?CommandPolicy {
    if (command == command_mask_query) {
        if (target == command_mask_read) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .tentative };
        if (target == command_mask_write) return .{ .command = command_mask_query, .target = target, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .confirmed };
        return null;
    }
    if (command == command_mask_read) return .{ .command = command_mask_read, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .tentative };
    if (command == command_mask_write) return .{ .command = command_mask_write, .capabilities = archive_capabilities, .sizing = .metadata_exact, .commit = .confirmed };
    return null;
}

fn testEchoPolicy(command: u32) ?CommandPolicy {
    if (command != command_mask_read and command != command_mask_write) return null;
    return .{ .command = command, .capabilities = all_capabilities, .sizing = .metadata_exact, .commit = .tentative };
}

fn testReadPolicy(command: u32, target: u32) ?CommandPolicy {
    if (command == command_mask_query and target == command_mask_read) return .{ .command = command_mask_query, .target = target, .capabilities = all_capabilities, .sizing = .metadata_exact, .commit = .tentative };
    if (command == command_mask_read) return .{ .command = command_mask_read, .capabilities = all_capabilities, .sizing = .metadata_exact, .commit = .tentative };
    return null;
}

pub fn commandPolicyFor(id: EnvelopeId, command: u32, target: u32) ?CommandPolicy {
    const tag = profileTagForId(id) orelse return null;
    return switch (tag) {
        .test_echo => testEchoPolicy(command),
        .test_read => testReadPolicy(command, target),
        .deflate, .gzip, .bzip2, .lzma, .lzma2, .lzma_file => measuredPolicy(command, target, false),
        .zstd, .xz => measuredPolicy(command, target, true),
        .tar, .zip, .sevenzip => archivePolicy(command, target),
        .rar => rarPolicy(command, target),
    };
}
