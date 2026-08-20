const Call = @import("abi/contract.zig").Call;
const invoke = @import("adapter/call.zig").invoke;

pub export fn stdk_call(call: ?*Call) callconv(.c) u32 {
    return invoke(call);
}
