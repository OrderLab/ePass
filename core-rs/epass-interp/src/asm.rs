//! A tiny eBPF assembler for tests: each function returns encoded slots.

use crate::Insn;

pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R4: u8 = 4;
pub const R5: u8 = 5;
pub const R6: u8 = 6;
pub const R7: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;
pub const R10: u8 = 10;

/// ALU operation codes (high nibble).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alu {
    Add = 0x00,
    Sub = 0x10,
    Mul = 0x20,
    Div = 0x30,
    Or = 0x40,
    And = 0x50,
    Lsh = 0x60,
    Rsh = 0x70,
    Neg = 0x80,
    Mod = 0x90,
    Xor = 0xa0,
    Mov = 0xb0,
    Arsh = 0xc0,
}

/// Conditional jump codes (high nibble).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Jmp {
    Jeq = 0x10,
    Jgt = 0x20,
    Jge = 0x30,
    Jset = 0x40,
    Jne = 0x50,
    Jsgt = 0x60,
    Jsge = 0x70,
    Jlt = 0xa0,
    Jle = 0xb0,
    Jslt = 0xc0,
    Jsle = 0xd0,
}

/// Memory access sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Size {
    W = 0x00,
    H = 0x08,
    B = 0x10,
    DW = 0x18,
}

fn raw(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    Insn { code, dst, src, off, imm }.encode()
}

pub fn alu64_imm(op: Alu, dst: u8, imm: i32) -> u64 {
    raw(0x07 | op as u8, dst, 0, 0, imm)
}
pub fn alu64_reg(op: Alu, dst: u8, src: u8) -> u64 {
    raw(0x07 | 0x08 | op as u8, dst, src, 0, 0)
}
pub fn alu32_imm(op: Alu, dst: u8, imm: i32) -> u64 {
    raw(0x04 | op as u8, dst, 0, 0, imm)
}
pub fn alu32_reg(op: Alu, dst: u8, src: u8) -> u64 {
    raw(0x04 | 0x08 | op as u8, dst, src, 0, 0)
}
/// Signed div/mod (off = 1).
pub fn sdiv64_reg(dst: u8, src: u8) -> u64 {
    raw(0x07 | 0x08 | Alu::Div as u8, dst, src, 1, 0)
}
pub fn smod64_reg(dst: u8, src: u8) -> u64 {
    raw(0x07 | 0x08 | Alu::Mod as u8, dst, src, 1, 0)
}
pub fn sdiv32_imm(dst: u8, imm: i32) -> u64 {
    raw(0x04 | Alu::Div as u8, dst, 0, 1, imm)
}
/// `dst = (sN) src` (64-bit movsx).
pub fn movsx64(dst: u8, src: u8, bits: i16) -> u64 {
    raw(0x07 | 0x08 | Alu::Mov as u8, dst, src, bits, 0)
}
/// `wdst = (sN) wsrc` (32-bit movsx).
pub fn movsx32(dst: u8, src: u8, bits: i16) -> u64 {
    raw(0x04 | 0x08 | Alu::Mov as u8, dst, src, bits, 0)
}
pub fn mov64_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(Alu::Mov, dst, imm)
}
pub fn mov64_reg(dst: u8, src: u8) -> u64 {
    alu64_reg(Alu::Mov, dst, src)
}
pub fn mov32_imm(dst: u8, imm: i32) -> u64 {
    alu32_imm(Alu::Mov, dst, imm)
}
pub fn mov32_reg(dst: u8, src: u8) -> u64 {
    alu32_reg(Alu::Mov, dst, src)
}
pub fn neg64(dst: u8) -> u64 {
    raw(0x07 | Alu::Neg as u8, dst, 0, 0, 0)
}
/// `dst = htobe{16,32,64}(dst)` (ALU class, TO_BE).
pub fn be(dst: u8, bits: i32) -> u64 {
    raw(0x04 | 0xd0 | 0x08, dst, 0, 0, bits)
}
/// `dst = htole{16,32,64}(dst)` (ALU class, TO_LE).
pub fn le(dst: u8, bits: i32) -> u64 {
    raw(0x04 | 0xd0, dst, 0, 0, bits)
}
/// `dst = bswap{16,32,64}(dst)` (ALU64 class, v4).
pub fn bswap(dst: u8, bits: i32) -> u64 {
    raw(0x07 | 0xd0, dst, 0, 0, bits)
}

/// Two slots: `dst = imm64`.
pub fn ld_imm64(dst: u8, imm: u64) -> [u64; 2] {
    ld_imm64_src(dst, 0, imm)
}
/// Two slots: `ld_imm64` with a pseudo source.
pub fn ld_imm64_src(dst: u8, src: u8, imm: u64) -> [u64; 2] {
    [
        raw(0x18, dst, src, 0, imm as u32 as i32),
        raw(0, 0, 0, 0, (imm >> 32) as u32 as i32),
    ]
}
pub fn ld_map_fd(dst: u8, fd: u32) -> [u64; 2] {
    ld_imm64_src(dst, 1, fd as u64)
}

pub fn ldx(size: Size, dst: u8, src: u8, off: i16) -> u64 {
    raw(0x01 | 0x60 | size as u8, dst, src, off, 0)
}
pub fn ldxs(size: Size, dst: u8, src: u8, off: i16) -> u64 {
    raw(0x01 | 0x80 | size as u8, dst, src, off, 0)
}
pub fn st(size: Size, dst: u8, off: i16, imm: i32) -> u64 {
    raw(0x02 | 0x60 | size as u8, dst, 0, off, imm)
}
pub fn stx(size: Size, dst: u8, src: u8, off: i16) -> u64 {
    raw(0x03 | 0x60 | size as u8, dst, src, off, 0)
}
/// Atomic op on `[dst + off]` with `src`; `op` is the imm (e.g. 0x00 add,
/// 0x01 fetch-add, 0xe1 xchg, 0xf1 cmpxchg).
pub fn atomic(size: Size, dst: u8, src: u8, off: i16, op: i32) -> u64 {
    raw(0x03 | 0xc0 | size as u8, dst, src, off, op)
}
pub fn ld_abs(size: Size, imm: i32) -> u64 {
    raw(0x20 | size as u8, 0, 0, 0, imm)
}
pub fn ld_ind(size: Size, src: u8, imm: i32) -> u64 {
    raw(0x40 | size as u8, 0, src, 0, imm)
}

pub fn ja(off: i16) -> u64 {
    raw(0x05, 0, 0, off, 0)
}
/// `gotol` (JMP32 | JA, offset in imm).
pub fn gotol(off: i32) -> u64 {
    raw(0x06, 0, 0, 0, off)
}
pub fn jmp_imm(op: Jmp, dst: u8, imm: i32, off: i16) -> u64 {
    raw(0x05 | op as u8, dst, 0, off, imm)
}
pub fn jmp_reg(op: Jmp, dst: u8, src: u8, off: i16) -> u64 {
    raw(0x05 | 0x08 | op as u8, dst, src, off, 0)
}
pub fn jmp32_imm(op: Jmp, dst: u8, imm: i32, off: i16) -> u64 {
    raw(0x06 | op as u8, dst, 0, off, imm)
}
pub fn jmp32_reg(op: Jmp, dst: u8, src: u8, off: i16) -> u64 {
    raw(0x06 | 0x08 | op as u8, dst, src, off, 0)
}
pub fn call(helper: i32) -> u64 {
    raw(0x85, 0, 0, 0, helper)
}
/// bpf-to-bpf call to `pc + off + 1`.
pub fn call_local(off: i32) -> u64 {
    raw(0x85, 0, 1, 0, off)
}
pub fn exit() -> u64 {
    raw(0x95, 0, 0, 0, 0)
}

/// Flatten slot groups into one program.
#[macro_export]
macro_rules! prog {
    ($($e:expr),* $(,)?) => {{
        let mut v: ::std::vec::Vec<u64> = ::std::vec::Vec::new();
        $( $crate::asm::Emit::emit($e, &mut v); )*
        v
    }};
}

/// Anything that can be appended to a program.
pub trait Emit {
    fn emit(self, out: &mut Vec<u64>);
}
impl Emit for u64 {
    fn emit(self, out: &mut Vec<u64>) {
        out.push(self);
    }
}
impl Emit for [u64; 2] {
    fn emit(self, out: &mut Vec<u64>) {
        out.extend_from_slice(&self);
    }
}
impl Emit for Vec<u64> {
    fn emit(self, out: &mut Vec<u64>) {
        out.extend(self);
    }
}
