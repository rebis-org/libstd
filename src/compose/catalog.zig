const components = @import("components");
const contract = @import("interface").contract;

const discovery = @import("../kernel/discovery.zig");
const envelope = @import("../kernel/envelope.zig");
const vocabulary = @import("../kernel/vocabulary.zig");

const EnvelopeId = envelope.Id;
const CommandPolicy = vocabulary.CommandPolicy;
const CommitMode = vocabulary.CommitMode;
const command_mask_read = vocabulary.command_mask_read;
const command_mask_write = vocabulary.command_mask_write;

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

// Read and write commit differently, so a direction's policy resolves here
// once instead of at every reader of it.
fn io(direction: u32, capabilities: u32, sizing: vocabulary.SizingMode, read_commit: CommitMode, write_commit: CommitMode) CommandPolicy {
    return .{
        .capabilities = capabilities,
        .sizing = sizing,
        .commit = if (direction == command_mask_read) read_commit else write_commit,
    };
}

const fixture_io = io(command_mask_read, all_capabilities, .metadata_exact, .tentative, .tentative);

pub fn commandPolicyFor(id: EnvelopeId, direction: u32) ?CommandPolicy {
    if (direction != command_mask_read and direction != command_mask_write) return null;
    // Fixtures accept every capability and both sizing modes, which no descriptor-derived rule expresses.
    if (vocabulary.eql(id, vocabulary.ids.test_echo)) return fixture_io;
    // The fixture's query verb names the read direction only.
    if (vocabulary.eql(id, vocabulary.ids.test_read)) return if (direction == command_mask_read) fixture_io else null;
    const descriptor = discovery.findById(toContractId(id)) orelse return null;
    // Filters are ingredients, not callable profiles.
    if (descriptor.class == .filter) return null;
    if (descriptor.sizing == .metadata_exact) return io(direction, archive_capabilities, .metadata_exact, .tentative, .confirmed);
    const commit: CommitMode = if (descriptor.commit == .confirmed) .confirmed else .tentative;
    return io(direction, replay_capabilities, .measured, commit, commit);
}
