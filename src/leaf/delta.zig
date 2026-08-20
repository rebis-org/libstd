const std = @import("std");

pub const max_distance: u8 = 255;

pub fn decode(data: []u8, distance: u8) void {
    var history = [_]u8{0} ** 256;
    var pos: u8 = 0;
    for (data, 0..) |byte, index| {
        const history_index = distance +% 1 +% pos;
        const out = byte +% history[history_index];
        history[pos] = out;
        data[index] = out;
        pos -%= 1;
    }
}

pub fn encode(data: []u8, distance: u8) void {
    var history = [_]u8{0} ** 256;
    var pos: u8 = 0;
    for (data, 0..) |byte, index| {
        const history_index = distance +% 1 +% pos;
        const out = byte -% history[history_index];
        history[pos] = byte;
        data[index] = out;
        pos -%= 1;
    }
}
