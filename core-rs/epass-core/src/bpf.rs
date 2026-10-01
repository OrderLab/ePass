//! eBPF instruction encoding (RFC 9669).

/// One instruction slot, bit-compatible with `struct bpf_insn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct BpfInsn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        BpfInsn {
            code,
            dst,
            src,
            off,
            imm,
        }
    }

    /// Decode the packed little-endian `u64` form.
    pub const fn from_u64(raw: u64) -> Self {
        BpfInsn {
            code: raw as u8,
            dst: ((raw >> 8) & 0xf) as u8,
            src: ((raw >> 12) & 0xf) as u8,
            off: (raw >> 16) as u16 as i16,
            imm: (raw >> 32) as u32 as i32,
        }
    }

    pub const fn to_u64(self) -> u64 {
        (self.code as u64)
            | ((((self.dst & 0xf) | ((self.src & 0xf) << 4)) as u64) << 8)
            | ((self.off as u16 as u64) << 16)
            | ((self.imm as u32 as u64) << 32)
    }

    pub const fn class(self) -> u8 {
        self.code & 0x07
    }
    pub const fn op(self) -> u8 {
        self.code & 0xf0
    }
    pub const fn uses_reg(self) -> bool {
        self.code & 0x08 != 0
    }
    pub const fn size(self) -> u8 {
        self.code & 0x18
    }
    pub const fn mode(self) -> u8 {
        self.code & 0xe0
    }
}

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

pub mod size {
    pub const W: u8 = 0x00;
    pub const H: u8 = 0x08;
    pub const B: u8 = 0x10;
    pub const DW: u8 = 0x18;
}

pub mod mode {
    pub const IMM: u8 = 0x00;
    pub const ABS: u8 = 0x20;
    pub const IND: u8 = 0x40;
    pub const MEM: u8 = 0x60;
    pub const MEMSX: u8 = 0x80;
    pub const ATOMIC: u8 = 0xc0;
}

pub mod alu {
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
}

pub mod jmp {
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
    /// `may_goto` (JMP | JCOND).
    pub const JCOND: u8 = 0xe0;
}

/// `src_reg` of a BPF_CALL.
pub mod call {
    pub const HELPER: u8 = 0;
    pub const LOCAL: u8 = 1;
    pub const KFUNC: u8 = 2;
    /// ePass extension call (reserved).
    pub const ECALL: u8 = 6;
}

/// libbpf poison encodings for calls that must stay dead.
pub mod poison {
    /// `bpf_core_poison_insn`: an unresolvable CO-RE relocation.
    pub const CORE_RELO: i32 = 0xbad2310;
    /// `poison_map_ldimm64`: base of `2001000000 + map_idx` (two slots).
    pub const LDIMM64_MAP_BASE: i32 = 2_001_000_000;
    /// `poison_kfunc_call`: base of `2002000000 + ext_idx`.
    pub const KFUNC_BASE: i32 = 2_002_000_000;

    pub fn is_poison(imm: i32) -> bool {
        imm == CORE_RELO || (LDIMM64_MAP_BASE..KFUNC_BASE + 1_000_000).contains(&imm)
    }
}

pub const R0: u8 = 0;
pub const R6: u8 = 6;
pub const R10: u8 = 10;
/// Registers r0..=r10.
pub const NREGS: usize = 11;
