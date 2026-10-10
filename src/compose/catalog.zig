const envelope = @import("../kernel/envelope.zig");
const EnvelopeId = envelope.Id;
const contract = @import("interface").contract;
const vocabulary = @import("../kernel/vocabulary.zig");
const discovery = @import("../kernel/discovery.zig");
const components = @import("components");
const command_mask_query = vocabulary.command_mask_query;
const command_mask_read = vocabulary.command_mask_read;
const command_mask_write = vocabulary.command_mask_write;
const CommandPolicy = vocabulary.CommandPolicy;
const CommitMode = vocabulary.CommitMode;

// Dispatch answers how a profile runs, not what it is.
pub fn toContractId(id: EnvelopeId) contract.Id {
    return .{ .low = id.low, .high = id.high };
}

pub fn profileTagForId(id: EnvelopeId) ?components.ProfileTag {
    const descriptor = discovery.findById(toContractId(id)) orelse return null;
    return components.tagForName(descriptor.name);
}

const all_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_write | vocabulary.resource_capability_bit_size | vocabulary.resource_capability_bit_replay | vocabulary.resource_capability_bit_seek | vocabulary.resource_capability_bit_range;
const replay_capabilities = vocabulary.resource_capability_bit_read | vocabulary.resource_capability_bit_replay;
const archive_capabilities = all_capabilities & ~(vocabulary.resource_capability_bit_seek | vocabulary.resource_capability_bit_range);

fn ioPolicy(command: u32, target: u32, capabilities: u32, sizing: vocabulary.SizingMode, read_commit: CommitMode, write_commit: CommitMode) ?CommandPolicy {
    if (command == command_mask_query) {
        if (target != command_mask_read and target != command_mask_write) return null;
        const commit = if (target == command_mask_read) read_commit else write_commit;
        return .{ .command = command_mask_query, .target = target, .capabilities = capabilities, .sizing = sizing, .commit = commit };
    }
    if (command != command_mask_read and command != command_mask_write) return null;
    const commit = if (command == command_mask_read) read_commit else write_commit;
    return .{ .command = command, .capabilities = capabilities, .sizing = sizing, .commit = commit };
}

fn measuredPolicy(command: u32, target: u32, confirmed: bool) ?CommandPolicy {
    const commit: CommitMode = if (confirmed) .confirmed else .tentative;
    return ioPolicy(command, target, replay_capabilities, .measured, commit, commit);
}

fn archivePolicy(command: u32, target: u32) ?CommandPolicy {
    return ioPolicy(command, target, archive_capabilities, .metadata_exact, .tentative, .confirmed);
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
    // Fixtures accept every capability and both sizing modes, which no descriptor-derived rule expresses.
    if (vocabulary.eql(id, vocabulary.ids.test_echo)) return testEchoPolicy(command);
    if (vocabulary.eql(id, vocabulary.ids.test_read)) return testReadPolicy(command, target);
    if (discovery.findById(toContractId(id))) |descriptor| {
        return switch (descriptor.class) {
            // Filters are ingredients, not callable profiles.
            .filter => null,
            .slice, .streaming, .grammar => if (descriptor.sizing == .metadata_exact)
                archivePolicy(command, target)
            else
                measuredPolicy(command, target, descriptor.commit == .confirmed),
        };
    }
    return null;
}
