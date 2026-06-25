//! eBPF instruction representation and the BPF ISA opcode constants.
//!
//! The in-memory encoding of [`BpfInsn`] matches the kernel's `struct bpf_insn`:
//! a little-endian `u64` laid out as `code:8 | dst_reg:4 | src_reg:4 | off:16 | imm:32`.
//! This lets us round-trip the "dump" format (one `u64` per instruction) exactly
//! like the C tool does.

/// Instruction classes (low 3 bits of `code`).
pub mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

/// Size modifiers for load/store (bits 3-4 of `code`).
pub mod size {
    pub const W: u8 = 0x00; // word, 32-bit
    pub const H: u8 = 0x08; // half-word, 16-bit
    pub const B: u8 = 0x10; // byte, 8-bit
    pub const DW: u8 = 0x18; // double word, 64-bit
}

/// Mode modifiers for load/store (bits 5-7 of `code`).
pub mod mode {
    pub const IMM: u8 = 0x00;
    pub const ABS: u8 = 0x20;
    pub const IND: u8 = 0x40;
    pub const MEM: u8 = 0x60;
    pub const MEMSX: u8 = 0x80;
    pub const ATOMIC: u8 = 0xc0;
}

/// Source operand selector (bit 3 of `code` for ALU/JMP).
pub mod src {
    pub const K: u8 = 0x00; // use 32-bit immediate
    pub const X: u8 = 0x08; // use source register
}

/// ALU / JMP operation codes (high 4 bits of `code`).
pub mod op {
    // ALU
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const ARSH: u8 = 0xc0;
    pub const END: u8 = 0xd0;

    // JMP
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
}

/// Endianness sub-codes for `BPF_END` (carried in `src`).
pub mod end {
    pub const TO_LE: u8 = 0x00;
    pub const TO_BE: u8 = 0x08;
}

/// `src_reg` value marking an ePass `ecall` extension instruction.
pub const EPASS_CALL: u8 = 6;

pub const MAX_BPF_REG: usize = 11;
pub const BPF_REG_0: u8 = 0;
pub const BPF_REG_1: u8 = 1;
pub const BPF_REG_6: u8 = 6;
pub const BPF_REG_10: u8 = 10;

/// The maximum number of arguments an eBPF helper call accepts (r1..=r5).
pub const MAX_FUNC_ARG: usize = 5;

#[inline]
pub const fn class_of(code: u8) -> u8 {
    code & 0x07
}
#[inline]
pub const fn op_of(code: u8) -> u8 {
    code & 0xf0
}
#[inline]
pub const fn src_of(code: u8) -> u8 {
    code & 0x08
}
#[inline]
pub const fn size_of(code: u8) -> u8 {
    code & 0x18
}
#[inline]
pub const fn mode_of(code: u8) -> u8 {
    code & 0xe0
}

/// A single eBPF instruction, bit-compatible with the kernel `struct bpf_insn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_reg,
            src_reg,
            off,
            imm,
        }
    }

    /// Decode a `bpf_insn` from its packed little-endian `u64` representation.
    pub fn from_u64(raw: u64) -> Self {
        let code = (raw & 0xff) as u8;
        let regs = ((raw >> 8) & 0xff) as u8;
        let dst_reg = regs & 0x0f;
        let src_reg = (regs >> 4) & 0x0f;
        let off = ((raw >> 16) & 0xffff) as u16 as i16;
        let imm = ((raw >> 32) & 0xffff_ffff) as u32 as i32;
        Self {
            code,
            dst_reg,
            src_reg,
            off,
            imm,
        }
    }

    /// Encode this instruction into its packed little-endian `u64` representation.
    pub fn to_u64(self) -> u64 {
        let regs = (self.dst_reg & 0x0f) | ((self.src_reg & 0x0f) << 4);
        (self.code as u64)
            | ((regs as u64) << 8)
            | ((self.off as u16 as u64) << 16)
            | ((self.imm as u32 as u64) << 32)
    }

    /// `true` if this is the second slot of a 64-bit immediate load (all-zero `code`).
    pub fn is_imm64_continuation(self) -> bool {
        self.code == 0
    }
}

/// Combine the `imm` of two consecutive instruction slots into a 64-bit immediate.
pub fn join_imm64(low_imm: i32, high_imm: i32) -> i64 {
    let low = (low_imm as u32) as u64;
    ((high_imm as i64) << 32) | (low as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u64() {
        let insn = BpfInsn::new(class::ALU64 | op::ADD | src::X, 1, 2, -3, 0x1234_5678);
        assert_eq!(BpfInsn::from_u64(insn.to_u64()), insn);
    }

    #[test]
    fn decode_known_layout() {
        // code=0x07, dst=1, src=2, off=0, imm=0  ->  add64 r1, r2
        let raw = 0x0000_0000_0000_2107u64;
        let insn = BpfInsn::from_u64(raw);
        assert_eq!(insn.code, 0x07);
        assert_eq!(insn.dst_reg, 1);
        assert_eq!(insn.src_reg, 2);
    }
}
