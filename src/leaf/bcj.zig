const std = @import("std");

pub const Kind = enum(u8) {
    x86 = 0x04,
    ppc = 0x05,
    ia64 = 0x06,
    arm = 0x07,
    armt = 0x08,
    sparc = 0x09,
    arm64 = 0x0A,
    riscv = 0x0B,
};

pub fn alignment(kind: Kind) u32 {
    return switch (kind) {
        .x86 => 1,
        .ppc => 4,
        .ia64 => 16,
        .arm => 4,
        .armt => 2,
        .sparc => 4,
        .arm64 => 4,
        .riscv => 2,
    };
}

pub fn decode(kind: Kind, start_offset: u32, data: []u8) void {
    switch (kind) {
        .x86 => x86Code(data, start_offset, false),
        .ppc => ppcCode(data, start_offset, false),
        .ia64 => ia64Code(data, start_offset, false),
        .arm => armCode(data, start_offset, false),
        .armt => armThumbCode(data, start_offset, false),
        .sparc => sparcCode(data, start_offset, false),
        .arm64 => arm64Code(data, start_offset, false),
        .riscv => riscvDecode(data, start_offset),
    }
}

pub fn encode(kind: Kind, start_offset: u32, data: []u8) void {
    switch (kind) {
        .x86 => x86Code(data, start_offset, true),
        .ppc => ppcCode(data, start_offset, true),
        .ia64 => ia64Code(data, start_offset, true),
        .arm => armCode(data, start_offset, true),
        .armt => armThumbCode(data, start_offset, true),
        .sparc => sparcCode(data, start_offset, true),
        .arm64 => arm64Code(data, start_offset, true),
        .riscv => riscvEncode(data, start_offset),
    }
}

const mask_to_bit_number = [_]u8{ 0, 1, 2, 2, 3 };

fn test86MSByte(byte: u8) bool {
    return byte == 0 or byte == 0xFF;
}

fn x86Code(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    if (data.len < 5) return;
    var prev_mask: u32 = 0;
    var prev_pos: u32 = start_offset -% 5;
    var buffer_pos: usize = 0;
    const limit = data.len - 5;
    while (buffer_pos <= limit) {
        const byte = data[buffer_pos];
        if (byte != 0xE8 and byte != 0xE9) {
            buffer_pos += 1;
            continue;
        }
        const now: u32 = start_offset +% @as(u32, @truncate(buffer_pos));
        const offset = now -% prev_pos;
        prev_pos = now;
        if (offset > 5) {
            prev_mask = 0;
        } else {
            for (0..offset) |_| {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }
        var ms_byte = data[buffer_pos + 4];
        if (test86MSByte(ms_byte) and (prev_mask >> 1) <= 4 and (prev_mask >> 1) != 3) {
            var src = (@as(u32, ms_byte) << 24) |
                (@as(u32, data[buffer_pos + 3]) << 16) |
                (@as(u32, data[buffer_pos + 2]) << 8) |
                @as(u32, data[buffer_pos + 1]);
            var dest: u32 = undefined;
            while (true) {
                if (is_encoder) {
                    dest = src +% (now +% 5);
                } else {
                    dest = src -% (now +% 5);
                }
                if (prev_mask == 0) break;
                const bit = mask_to_bit_number[prev_mask >> 1];
                ms_byte = @truncate(dest >> @as(u5, @intCast(24 - bit * 8)));
                if (!test86MSByte(ms_byte)) break;
                src = dest ^ ((@as(u32, 1) << @as(u5, @intCast(32 - bit * 8))) -% 1);
            }
            data[buffer_pos + 4] = @truncate(~((dest >> 24 & 1) -% 1));
            data[buffer_pos + 3] = @truncate(dest >> 16);
            data[buffer_pos + 2] = @truncate(dest >> 8);
            data[buffer_pos + 1] = @truncate(dest);
            buffer_pos += 5;
            prev_mask = 0;
        } else {
            buffer_pos += 1;
            prev_mask |= 1;
            if (test86MSByte(ms_byte)) prev_mask |= 0x10;
        }
    }
}

fn ppcCode(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    const size = data.len & ~@as(usize, 3);
    var index: usize = 0;
    while (index < size) : (index += 4) {
        if ((data[index] >> 2) == 0x12 and (data[index + 3] & 3) == 1) {
            const src = (@as(u32, data[index] & 3) << 24) |
                (@as(u32, data[index + 1]) << 16) |
                (@as(u32, data[index + 2]) << 8) |
                @as(u32, data[index + 3] & ~@as(u8, 3));
            const now = start_offset +% @as(u32, @truncate(index));
            const dest = if (is_encoder) now +% src else src -% now;
            data[index] = 0x48 | (@as(u8, @truncate(dest >> 24)) & 0x03);
            data[index + 1] = @truncate(dest >> 16);
            data[index + 2] = @truncate(dest >> 8);
            data[index + 3] = (data[index + 3] & 3) | @as(u8, @truncate(dest));
        }
    }
}

fn ia64Code(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    const branch_table = [_]u32{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        4, 4, 6, 6, 0, 0, 7, 7,
        4, 4, 0, 0, 4, 4, 0, 0,
    };
    const size = data.len & ~@as(usize, 15);
    var index: usize = 0;
    while (index < size) : (index += 16) {
        const instr_template = data[index] & 0x1F;
        const mask = branch_table[instr_template];
        var bit_pos: u32 = 5;
        for (0..3) |slot| {
            if (((mask >> @intCast(slot)) & 1) == 0) {
                bit_pos += 41;
                continue;
            }
            const byte_pos: usize = bit_pos >> 3;
            const bit_res = bit_pos & 7;
            var instruction: u64 = 0;
            for (0..6) |byte_index| {
                instruction |= @as(u64, data[index + byte_index + byte_pos]) << @as(u6, @intCast(8 * byte_index));
            }
            var inst_norm = instruction >> @as(u6, @intCast(bit_res));
            if (((inst_norm >> 37) & 0xF) == 0x5 and ((inst_norm >> 9) & 0x7) == 0) {
                const src = (((@as(u32, @truncate(inst_norm >> 13)) & 0xFFFFF) |
                    ((@as(u32, @truncate(inst_norm >> 36)) & 1) << 20)) << 4);
                const now = start_offset +% @as(u32, @truncate(index));
                var dest = if (is_encoder) now +% src else src -% now;
                dest >>= 4;
                inst_norm &= ~(@as(u64, 0x8FFFFF) << 13);
                inst_norm |= (@as(u64, dest & 0xFFFFF) << 13);
                inst_norm |= (@as(u64, dest & 0x100000) << (36 - 20));
                const shift: u6 = @intCast(bit_res);
                instruction = (instruction & ((@as(u64, 1) << shift) - 1)) | (inst_norm << shift);
                for (0..6) |byte_index| {
                    data[index + byte_index + byte_pos] = @truncate(instruction >> @as(u6, @intCast(8 * byte_index)));
                }
            }
            bit_pos += 41;
        }
    }
}

fn armCode(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    const size = data.len & ~@as(usize, 3);
    var index: usize = 0;
    while (index < size) : (index += 4) {
        if (data[index + 3] == 0xEB) {
            const src = (@as(u32, data[index + 2]) << 16 |
                @as(u32, data[index + 1]) << 8 |
                @as(u32, data[index])) << 2;
            const now = start_offset +% @as(u32, @truncate(index));
            var dest = if (is_encoder) now +% 8 +% src else src -% (now +% 8);
            dest >>= 2;
            data[index + 2] = @truncate(dest >> 16);
            data[index + 1] = @truncate(dest >> 8);
            data[index] = @truncate(dest);
        }
    }
}

fn armThumbCode(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    if (data.len < 4) return;
    const size = data.len - 4;
    var index: usize = 0;
    while (index <= size) : (index += 2) {
        if ((data[index + 1] & 0xF8) == 0xF0 and (data[index + 3] & 0xF8) == 0xF8) {
            const src = ((@as(u32, data[index + 1]) & 7) << 19) |
                (@as(u32, data[index]) << 11) |
                ((@as(u32, data[index + 3]) & 7) << 8) |
                @as(u32, data[index + 2]);
            const shifted = src << 1;
            const now = start_offset +% @as(u32, @truncate(index));
            var dest = if (is_encoder) now +% 4 +% shifted else shifted -% (now +% 4);
            dest >>= 1;
            data[index + 1] = 0xF0 | (@as(u8, @truncate(dest >> 19)) & 0x7);
            data[index] = @truncate(dest >> 11);
            data[index + 3] = 0xF8 | (@as(u8, @truncate(dest >> 8)) & 0x7);
            data[index + 2] = @truncate(dest);
            index += 2;
        }
    }
}

fn sparcCode(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    const size = data.len & ~@as(usize, 3);
    var index: usize = 0;
    while (index < size) : (index += 4) {
        const call = (data[index] == 0x40 and (data[index + 1] & 0xC0) == 0x00) or
            (data[index] == 0x7F and (data[index + 1] & 0xC0) == 0xC0);
        if (!call) continue;
        const src = ((@as(u32, data[index]) << 24) |
            (@as(u32, data[index + 1]) << 16) |
            (@as(u32, data[index + 2]) << 8) |
            @as(u32, data[index + 3])) << 2;
        const now = start_offset +% @as(u32, @truncate(index));
        var dest = if (is_encoder) now +% src else src -% now;
        dest >>= 2;
        dest = ((0 -% ((dest >> 22) & 1)) << 22 & 0x3FFFFFFF) |
            (dest & 0x3FFFFF) |
            0x40000000;
        data[index] = @truncate(dest >> 24);
        data[index + 1] = @truncate(dest >> 16);
        data[index + 2] = @truncate(dest >> 8);
        data[index + 3] = @truncate(dest);
    }
}

fn arm64Code(data: []u8, start_offset: u32, comptime is_encoder: bool) void {
    const size = data.len & ~@as(usize, 3);
    var index: usize = 0;
    while (index < size) : (index += 4) {
        var instr = read32le(data[index..][0..4]);
        const pc = start_offset +% @as(u32, @truncate(index));
        if ((instr >> 26) == 0x25) {
            const src = instr;
            instr = 0x94000000;
            var converted_pc = pc >> 2;
            if (!is_encoder) converted_pc = 0 -% converted_pc;
            instr |= (src +% converted_pc) & 0x03FFFFFF;
            write32le(data[index..][0..4], instr);
        } else if ((instr & 0x9F000000) == 0x90000000) {
            const src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001FFFFC);
            if ((src +% 0x00020000) & 0x001C0000 != 0) continue;
            instr &= 0x9000001F;
            var converted_pc = pc >> 12;
            if (!is_encoder) converted_pc = 0 -% converted_pc;
            const dest = src +% converted_pc;
            instr |= (dest & 3) << 29;
            instr |= (dest & 0x0003FFFC) << 3;
            instr |= (0 -% (dest & 0x00020000)) & 0x00E00000;
            write32le(data[index..][0..4], instr);
        }
    }
}

fn riscvEncode(data: []u8, start_offset: u32) void {
    if (data.len < 8) return;
    const size = data.len - 8;
    var index: usize = 0;
    while (index <= size) : (index += 2) {
        var inst: u32 = data[index];
        if (inst == 0xEF) {
            const b1 = data[index + 1];
            if ((b1 & 0x0D) != 0) continue;
            const b2 = data[index + 2];
            const b3 = data[index + 3];
            const pc = start_offset +% @as(u32, @truncate(index));
            var addr = ((@as(u32, b1) & 0xF0) << 8) |
                ((@as(u32, b2) & 0x0F) << 16) |
                ((@as(u32, b2) & 0x10) << 7) |
                ((@as(u32, b2) & 0xE0) >> 4) |
                ((@as(u32, b3) & 0x7F) << 4) |
                ((@as(u32, b3) & 0x80) << 13);
            addr +%= pc;
            data[index + 1] = (b1 & 0x0F) | @as(u8, @truncate((addr >> 13) & 0xF0));
            data[index + 2] = @truncate(addr >> 9);
            data[index + 3] = @truncate(addr >> 1);
            index += 4 - 2;
        } else if ((inst & 0x7F) == 0x17) {
            inst |= @as(u32, data[index + 1]) << 8;
            inst |= @as(u32, data[index + 2]) << 16;
            inst |= @as(u32, data[index + 3]) << 24;
            if (inst & 0xE80 != 0) {
                const inst2 = read32le(data[index + 4 ..][0..4]);
                if (notAuipcPair(inst, inst2)) {
                    index += 6 - 2;
                    continue;
                }
                var addr = inst & 0xFFFFF000;
                addr +%= (inst2 >> 20) -% ((inst2 >> 19) & 0x1000);
                addr +%= start_offset +% @as(u32, @truncate(index));
                inst = 0x17 | (2 << 7) | (inst2 << 12);
                write32le(data[index..][0..4], inst);
                write32be(data[index + 4 ..][0..4], addr);
                index += 8 - 2;
            } else {
                const fake_rs1 = inst >> 27;
                if (notSpecialAuipc(inst, fake_rs1)) {
                    index += 4 - 2;
                    continue;
                }
                const fake_addr = read32le(data[index + 4 ..][0..4]);
                const fake_inst2 = (inst >> 12) | (fake_addr << 20);
                inst = 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFFF000);
                write32le(data[index..][0..4], inst);
                write32le(data[index + 4 ..][0..4], fake_inst2);
                index += 8 - 2;
            }
        }
    }
}

fn riscvDecode(data: []u8, start_offset: u32) void {
    if (data.len < 8) return;
    const size = data.len - 8;
    var index: usize = 0;
    while (index <= size) : (index += 2) {
        var inst: u32 = data[index];
        if (inst == 0xEF) {
            const b1 = data[index + 1];
            const b2 = data[index + 2];
            const b3 = data[index + 3];
            const pc = start_offset +% @as(u32, @truncate(index));
            var addr = ((@as(u32, b1) & 0xF0) << 13) |
                (@as(u32, b2) << 9) |
                (@as(u32, b3) << 1);
            addr -%= pc;
            data[index + 1] = (b1 & 0x0F) | @as(u8, @truncate((addr >> 8) & 0xF0));
            data[index + 2] = @as(u8, @truncate(((addr >> 16) & 0x0F) |
                ((addr >> 7) & 0x10) |
                ((addr << 4) & 0xE0)));
            data[index + 3] = @as(u8, @truncate(((addr >> 4) & 0x7F) |
                ((addr >> 13) & 0x80)));
            index += 4 - 2;
        } else if ((inst & 0x7F) == 0x17) {
            inst |= @as(u32, data[index + 1]) << 8;
            inst |= @as(u32, data[index + 2]) << 16;
            inst |= @as(u32, data[index + 3]) << 24;
            var inst2: u32 = 0;
            if (inst & 0xE80 != 0) {
                inst2 = read32le(data[index + 4 ..][0..4]);
                if (notAuipcPair(inst, inst2)) {
                    index += 6 - 2;
                    continue;
                }
                var addr = inst & 0xFFFFF000;
                addr +%= inst2 >> 20;
                inst = 0x17 | (2 << 7) | (inst2 << 12);
                inst2 = addr;
            } else {
                const inst2_rs1 = inst >> 27;
                if (notSpecialAuipc(inst, inst2_rs1)) {
                    index += 4 - 2;
                    continue;
                }
                var addr = read32be(data[index + 4 ..][0..4]);
                addr -%= start_offset +% @as(u32, @truncate(index));
                inst2 = (inst >> 12) | (addr << 20);
                inst = 0x17 | (inst2_rs1 << 7) | ((addr +% 0x800) & 0xFFFFF000);
            }
            write32le(data[index..][0..4], inst);
            write32le(data[index + 4 ..][0..4], inst2);
            index += 8 - 2;
        }
    }
}

fn notAuipcPair(auipc: u32, inst2: u32) bool {
    return (((auipc << 8) ^ (inst2 -% 3)) & 0xF8003) != 0;
}

fn notSpecialAuipc(auipc: u32, inst2_rs1: u32) bool {
    return ((auipc -% 0x3117) << 18) >= (inst2_rs1 & 0x1D);
}

fn read32le(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn read32be(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn write32le(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

fn write32be(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}
