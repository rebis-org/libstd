pub const discovery = @import("discovery.zig");
pub const envelope = @import("envelope.zig");

test "root re-exports kernel discovery fixtures with pinned identities" {
    const std = @import("std");
    const root = @This();
    const echo = root.discovery.findByName("test_echo") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0401), echo.id.low);
    try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_4001), echo.id.high);
    const read = root.discovery.findByName("test_read") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x6e6b_82f0_8d91_0402), read.id.low);
    try std.testing.expectEqual(@as(u64, 0xa7a3_5105_3d6d_4002), read.id.high);
    // An unknown fixture name resolves to no descriptor.
    try std.testing.expect(root.discovery.findByName("no_such_fixture") == null);
}

test "root re-exports kernel envelope constants and frame builders" {
    const std = @import("std");
    const root = @This();
    try std.testing.expectEqual(@as(u32, 0), root.envelope.Status.ok);
    try std.testing.expectEqual(@as(u32, 9), root.envelope.Status.cancelled);
    var call = root.envelope.Call.init();
    try std.testing.expectEqual(@as(u32, 112), call.structure_size);
    try std.testing.expect(call.isValid());
    // A set flag breaks the frame contract that init established.
    call.flags = 1;
    try std.testing.expect(!call.isValid());
}
