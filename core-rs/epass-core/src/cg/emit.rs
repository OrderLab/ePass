//! Frame layout, block layout, encoding and branch relaxation.

use super::mir::{Base, MFunc, MOp, MSlot, Src, VReg};
use super::ra::{Alloc, NOCOLOR};
use super::ssaout::{EdgeMoves, Loc, PMove, PSrc};
use crate::analysis::Extent;
use crate::bpf::{alu, class, jmp, mode, size as bsz, BpfInsn};
use crate::ctx::Ctx;
use crate::error::{Error, ErrorKind, Result};
use crate::facts::Isa;
use crate::ir::{BinOp, BlockId, Callee, Cond, Size, SwapKind, Width};
use crate::mem::{FVec, Idx, IdxVec};

/// Placement of ePass's own stack slots, below the original frame.
#[derive(Debug)]
pub struct Frame<'h> {
    pub ir: FVec<'h, i16>,
    pub spill: FVec<'h, i16>,
    pub scratch: i16,
    pub scratch2: i16,
    /// Lowest offset ePass uses (0 if none).
    pub lowest: i32,
}

impl Frame<'_> {
    fn offset(&self, s: MSlot) -> Result<i32> {
        Ok(match s {
            MSlot::Ir(id) => *self.ir.get(id.index()).ok_or(Error::internal("ir slot"))? as i32,
            MSlot::Spill(k) => *self.spill.get(k as usize).ok_or(Error::internal("spill slot"))? as i32,
            MSlot::Scratch => self.scratch as i32,
            MSlot::Scratch2 => self.scratch2 as i32,
        })
    }
}

/// Place slots below the original frame (whose lowest access is
/// `ext.lowest`); fails with NoStack beyond 512 bytes.
pub fn layout_frame<'h>(m: &MFunc<'h>, ext: Extent, scratch: bool) -> Result<Frame<'h>> {
    let heap = m.heap;
    let base: i32 = if ext.unknown {
        -512
    } else {
        let low = i32::try_from(ext.lowest).map_err(|_| Error::invalid_input("frame extent"))?;
        // Round down to a multiple of 8.
        low.div_euclid(8) * 8
    };
    let mut cur = base;
    let mut take = |size: u32, align: u32| -> Result<i16> {
        let align = align.clamp(1, 8) as i32;
        let next = cur - size as i32;
        let aligned = next.div_euclid(align) * align;
        if aligned < -512 {
            return Err(Error::new(ErrorKind::NoStack, "no stack space for ePass slots"));
        }
        cur = aligned;
        Ok(aligned as i16)
    };
    let mut ir = FVec::new(heap);
    for s in m.ir_slots.iter() {
        ir.push(take(s.size, s.align)?)?;
    }
    let mut spill = FVec::new(heap);
    for _ in 0..m.spill_slots {
        spill.push(take(8, 8)?)?;
    }
    let scratch_off = if scratch { take(8, 8)? } else { 0 };
    let scratch2_off = if scratch { take(8, 8)? } else { 0 };
    let lowest = if cur == base && !scratch && m.spill_slots == 0 && m.ir_slots.is_empty() {
        0
    } else {
        cur
    };
    Ok(Frame {
        ir,
        spill,
        scratch: scratch_off,
        scratch2: scratch2_off,
        lowest,
    })
}

// ------------------------------------------------------------- block order

/// Chain layout: follow fallthrough preferences (`CondBr` false edge, `Br`
/// target) from each unplaced block in RPO.
pub fn block_order<'h>(m: &MFunc<'h>, rpo: &[BlockId]) -> Result<FVec<'h, BlockId>> {
    let heap = m.heap;
    let mut placed: IdxVec<'h, BlockId, bool> = IdxVec::filled(heap, m.blocks.len(), false)?;
    let mut out = FVec::new(heap);
    for &start in rpo {
        let mut cur = start;
        while !*placed.at(cur)? {
            *placed.at_mut(cur)? = true;
            out.push(cur)?;
            let next = match m.block(cur)?.insns.last().map(|i| i.op) {
                Some(MOp::Br { t }) => Some(t),
                Some(MOp::CondBr { t, f, .. }) => {
                    if !*placed.at(f)? {
                        Some(f)
                    } else {
                        Some(t)
                    }
                }
                _ => None,
            };
            match next {
                Some(n) if !*placed.at(n)? => cur = n,
                _ => break,
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- encoding

/// One emitted instruction before branch resolution.
#[derive(Clone, Copy, Debug)]
struct Item {
    insn: BpfInsn,
    /// Second slot of an ld_imm64.
    wide: Option<i32>,
    /// Branch target block (resolved later).
    target: Option<BlockId>,
    /// A long (gotol) form is needed.
    long: bool,
    origin: Option<u32>,
}

fn plain(insn: BpfInsn, origin: Option<u32>) -> Item {
    Item {
        insn,
        wide: None,
        target: None,
        long: false,
        origin,
    }
}

fn binop_code(op: BinOp) -> (u8, i16) {
    match op {
        BinOp::Add => (alu::ADD, 0),
        BinOp::Sub => (alu::SUB, 0),
        BinOp::Mul => (alu::MUL, 0),
        BinOp::UDiv => (alu::DIV, 0),
        BinOp::SDiv => (alu::DIV, 1),
        BinOp::UMod => (alu::MOD, 0),
        BinOp::SMod => (alu::MOD, 1),
        BinOp::And => (alu::AND, 0),
        BinOp::Or => (alu::OR, 0),
        BinOp::Xor => (alu::XOR, 0),
        BinOp::Shl => (alu::LSH, 0),
        BinOp::LShr => (alu::RSH, 0),
        BinOp::AShr => (alu::ARSH, 0),
    }
}

fn cond_code(c: Cond) -> u8 {
    match c {
        Cond::Eq => jmp::JEQ,
        Cond::Ne => jmp::JNE,
        Cond::Ugt => jmp::JGT,
        Cond::Uge => jmp::JGE,
        Cond::Ult => jmp::JLT,
        Cond::Ule => jmp::JLE,
        Cond::Sgt => jmp::JSGT,
        Cond::Sge => jmp::JSGE,
        Cond::Slt => jmp::JSLT,
        Cond::Sle => jmp::JSLE,
        Cond::Set => jmp::JSET,
    }
}

fn size_code(s: Size) -> u8 {
    match s {
        Size::B1 => bsz::B,
        Size::B2 => bsz::H,
        Size::B4 => bsz::W,
        Size::B8 => bsz::DW,
    }
}

fn wclass(w: Width) -> u8 {
    match w {
        Width::W32 => class::ALU,
        Width::W64 => class::ALU64,
    }
}

struct Enc<'a, 'h> {
    m: &'a MFunc<'h>,
    color: &'a IdxVec<'h, VReg, u8>,
    frame: &'a Frame<'h>,
    out: FVec<'h, Item>,
    origin: Option<u32>,
}

impl<'a, 'h> Enc<'a, 'h> {
    fn r(&self, v: VReg) -> Result<u8> {
        match self.color.get(v).copied() {
            Some(c) if c != NOCOLOR => Ok(c),
            _ => Err(Error::internal("emitting an uncolored register")),
        }
    }

    fn put(&mut self, i: BpfInsn) -> Result<()> {
        let o = self.origin;
        self.out.push(plain(i, o))
    }

    fn mov64(&mut self, dst: u8, src: u8) -> Result<()> {
        if dst != src {
            self.put(BpfInsn::new(class::ALU64 | alu::MOV | 0x08, dst, src, 0, 0))?;
        }
        Ok(())
    }

    fn ld64(&mut self, dst: u8, imm: u64, src_reg: u8) -> Result<()> {
        let o = self.origin;
        self.out.push(Item {
            insn: BpfInsn::new(class::LD | mode::IMM | bsz::DW, dst, src_reg, 0, imm as u32 as i32),
            wide: Some((imm >> 32) as u32 as i32),
            target: None,
            long: false,
            origin: o,
        })
    }

    fn src_imm(&self, s: Src) -> Result<(bool, u8, i32)> {
        Ok(match s {
            Src::V(v) => (true, self.r(v)?, 0),
            Src::Imm(i) => (false, 0, i),
            Src::Fp => (true, 10, 0),
        })
    }

    fn base(&self, b: Base) -> Result<u8> {
        match b {
            Base::V(v) => self.r(v),
            Base::Fp => Ok(10),
        }
    }

    fn pmove(&mut self, mv: PMove) -> Result<()> {
        match mv {
            PMove::Mov { dst, src } => match src {
                PSrc::Loc(Loc::Reg(r)) => self.mov64(dst, r),
                PSrc::Loc(Loc::Slot(sl)) => {
                    let off = self.frame.offset(sl)? as i16;
                    self.put(BpfInsn::new(class::LDX | mode::MEM | bsz::DW, dst, 10, off, 0))
                }
                PSrc::Imm(i) => self.put(BpfInsn::new(class::ALU64 | alu::MOV, dst, 0, 0, i)),
                PSrc::Imm32(i) => self.put(BpfInsn::new(class::ALU | alu::MOV, dst, 0, 0, i)),
                PSrc::Ld64(c) => self.ld64(dst, c, 0),
                PSrc::Fp => self.mov64(dst, 10),
            },
            PMove::Store { slot, src } => {
                let off = self.frame.offset(slot)? as i16;
                self.put(BpfInsn::new(class::STX | mode::MEM | bsz::DW, 10, src, off, 0))
            }
            PMove::StoreImm { slot, imm } => {
                let off = self.frame.offset(slot)? as i16;
                self.put(BpfInsn::new(class::ST | mode::MEM | bsz::DW, 10, 0, off, imm))
            }
        }
    }

    /// `dst = a; dst op= b` with the two-address rule.
    fn two_addr(&mut self, w: Width, op: BinOp, dst: u8, a: u8, b: Src) -> Result<()> {
        let (code, off) = binop_code(op);
        let (is_reg, br, imm) = self.src_imm(b)?;
        let (a, br) = if dst != a && is_reg && br == dst && op.is_commutative() {
            (br, a)
        } else {
            (a, br)
        };
        if is_reg && br == dst && dst != a {
            return Err(Error::internal("two-address constraint violated"));
        }
        self.mov64(dst, a)?;
        let x = if is_reg { 0x08 } else { 0 };
        self.put(BpfInsn::new(wclass(w) | code | x, dst, br, off, imm))
    }

    fn insn(&mut self, op: MOp, origin: Option<u32>, isa: Isa, big_endian: bool) -> Result<()> {
        self.origin = origin;
        match op {
            MOp::Copy { dst, src } => {
                let d = self.r(dst)?;
                match src {
                    Src::V(s) => {
                        let s = self.r(s)?;
                        self.mov64(d, s)?;
                    }
                    Src::Imm(i) => self.put(BpfInsn::new(class::ALU64 | alu::MOV, d, 0, 0, i))?,
                    Src::Fp => self.mov64(d, 10)?,
                }
            }
            MOp::Imm32 { dst, imm } => {
                let d = self.r(dst)?;
                self.put(BpfInsn::new(class::ALU | alu::MOV, d, 0, 0, imm))?;
            }
            MOp::Ld64 { dst, imm, src_reg } => {
                let d = self.r(dst)?;
                self.ld64(d, imm, src_reg)?;
            }
            MOp::Alu { op, w, dst, a, b } => {
                let (d, ra) = (self.r(dst)?, self.r(a)?);
                self.two_addr(w, op, d, ra, b)?;
            }
            MOp::Neg { w, dst, a } => {
                let (d, ra) = (self.r(dst)?, self.r(a)?);
                self.mov64(d, ra)?;
                self.put(BpfInsn::new(wclass(w) | alu::NEG, d, 0, 0, 0))?;
            }
            MOp::Ext { from, signed, w, dst, a } => {
                let (d, ra) = (self.r(dst)?, self.r(a)?);
                match (signed, from) {
                    // zext32, and sext from 32 at width 32 (also a zext32).
                    (false, 32) => self.put(BpfInsn::new(class::ALU | alu::MOV | 0x08, d, ra, 0, 0))?,
                    (true, 32) if w == Width::W32 => {
                        self.put(BpfInsn::new(class::ALU | alu::MOV | 0x08, d, ra, 0, 0))?
                    }
                    (false, _) => {
                        let mask = if from == 8 { 0xff } else { 0xffff };
                        self.mov64(d, ra)?;
                        self.put(BpfInsn::new(class::ALU64 | alu::AND, d, 0, 0, mask))?;
                    }
                    (true, _) if isa >= Isa::V4 => {
                        let c = if w == Width::W32 && from < 32 { class::ALU } else { class::ALU64 };
                        self.put(BpfInsn::new(c | alu::MOV | 0x08, d, ra, from as i16, 0))?;
                    }
                    (true, _) => {
                        // Below v4: 64-bit shifts, then truncate for w32.
                        let sh = 64 - from as i32;
                        self.mov64(d, ra)?;
                        self.put(BpfInsn::new(class::ALU64 | alu::LSH, d, 0, 0, sh))?;
                        self.put(BpfInsn::new(class::ALU64 | alu::ARSH, d, 0, 0, sh))?;
                        if w == Width::W32 {
                            self.put(BpfInsn::new(class::ALU | alu::MOV | 0x08, d, d, 0, 0))?;
                        }
                    }
                }
            }
            MOp::Bswap { bits, kind, dst, a } => {
                let (d, ra) = (self.r(dst)?, self.r(a)?);
                self.mov64(d, ra)?;
                let enc = match kind {
                    SwapKind::ToLe => class::ALU | alu::END,
                    SwapKind::ToBe => class::ALU | alu::END | 0x08,
                    SwapKind::Swap if isa >= Isa::V4 => class::ALU64 | alu::END,
                    // An unconditional swap is "to the other byte order".
                    SwapKind::Swap if big_endian => class::ALU | alu::END,
                    SwapKind::Swap => class::ALU | alu::END | 0x08,
                };
                self.put(BpfInsn::new(enc, d, 0, 0, bits as i32))?;
            }
            MOp::Load { size, signed, dst, base, off } => {
                let (d, b) = (self.r(dst)?, self.base(base)?);
                if signed && isa < Isa::V4 {
                    let sh = 64 - size.bits() as i32;
                    self.put(BpfInsn::new(class::LDX | mode::MEM | size_code(size), d, b, off, 0))?;
                    self.put(BpfInsn::new(class::ALU64 | alu::LSH, d, 0, 0, sh))?;
                    self.put(BpfInsn::new(class::ALU64 | alu::ARSH, d, 0, 0, sh))?;
                } else {
                    let md = if signed { mode::MEMSX } else { mode::MEM };
                    self.put(BpfInsn::new(class::LDX | md | size_code(size), d, b, off, 0))?;
                }
            }
            MOp::Store { size, base, off, val } => {
                let b = self.base(base)?;
                match val {
                    Src::Imm(i) => self.put(BpfInsn::new(class::ST | mode::MEM | size_code(size), b, 0, off, i))?,
                    Src::V(v) => {
                        let s = self.r(v)?;
                        self.put(BpfInsn::new(class::STX | mode::MEM | size_code(size), b, s, off, 0))?;
                    }
                    Src::Fp => self.put(BpfInsn::new(class::STX | mode::MEM | size_code(size), b, 10, off, 0))?,
                }
            }
            MOp::FrameAddr { dst, slot, off } => {
                let d = self.r(dst)?;
                let o = self
                    .frame
                    .offset(slot)?
                    .checked_add(off)
                    .ok_or(Error::internal("frame address"))?;
                self.mov64(d, 10)?;
                self.put(BpfInsn::new(class::ALU64 | alu::ADD, d, 0, 0, o))?;
            }
            MOp::SlotStore { slot, src } => {
                let s = self.r(src)?;
                let o = self.frame.offset(slot)? as i16;
                self.put(BpfInsn::new(class::STX | mode::MEM | bsz::DW, 10, s, o, 0))?;
            }
            MOp::SlotLoad { dst, slot } => {
                let d = self.r(dst)?;
                let o = self.frame.offset(slot)? as i16;
                self.put(BpfInsn::new(class::LDX | mode::MEM | bsz::DW, d, 10, o, 0))?;
            }
            MOp::Call { callee, .. } => match callee {
                Callee::Helper(id) => self.put(BpfInsn::new(class::JMP | jmp::CALL, 0, 0, 0, id))?,
                Callee::Kfunc { btf_id, fd_idx } => {
                    self.put(BpfInsn::new(class::JMP | jmp::CALL, 0, 2, fd_idx, btf_id))?
                }
                Callee::Local(_) => return Err(Error::unsupported("bpf-to-bpf calls")),
            },
            MOp::Opaque { raw, .. } => self.put(BpfInsn::from_u64(raw))?,
            MOp::Exit => self.put(BpfInsn::new(class::JMP | jmp::EXIT, 0, 0, 0, 0))?,
            MOp::Poison { imm } => self.put(BpfInsn::new(class::JMP | jmp::CALL, 0, 0, 0, imm))?,
            MOp::Br { .. } | MOp::CondBr { .. } => {
                return Err(Error::internal("terminator emitted as a body instruction"))
            }
        }
        Ok(())
    }

    fn jump(&mut self, code: u8, dst: u8, src: u8, imm: i32, target: BlockId) -> Result<()> {
        let o = self.origin;
        self.out.push(Item {
            insn: BpfInsn::new(code, dst, src, 0, imm),
            wide: None,
            target: Some(target),
            long: false,
            origin: o,
        })
    }
}

/// Result of encoding.
#[derive(Debug)]
pub struct Encoded<'h> {
    pub insns: FVec<'h, BpfInsn>,
    /// (original bytecode index, first emitted index), ascending by origin.
    pub offsets: FVec<'h, (u32, u32)>,
}

#[allow(clippy::too_many_arguments)]
pub fn encode<'h>(
    m: &MFunc<'h>,
    a: &Alloc<'h>,
    moves: &EdgeMoves<'h>,
    frame: &Frame<'h>,
    order: &[BlockId],
    max_insns: u32,
    ctx: &Ctx<'_>,
) -> Result<Encoded<'h>> {
    let heap = m.heap;
    let mut e = Enc {
        m,
        color: &a.color,
        frame,
        out: FVec::new(heap),
        origin: None,
    };
    // Item index where each block starts.
    let mut start: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, m.blocks.len(), u32::MAX)?;
    for (k, &b) in order.iter().enumerate() {
        ctx.tick()?;
        *start.at_mut(b)? = e.out.len() as u32;
        let next = order.get(k + 1).copied();
        for &mv in moves.at_start.at(b)?.iter() {
            e.origin = None;
            e.pmove(mv)?;
        }
        let mb = e.m.block(b)?;
        let n = mb.insns.len();
        for (j, ins) in mb.insns.iter().enumerate() {
            if j + 1 == n && ins.op.is_terminator() {
                break;
            }
            e.insn(ins.op, ins.origin, m.isa, m.big_endian)?;
        }
        for &mv in moves.at_end.at(b)?.iter() {
            e.origin = None;
            e.pmove(mv)?;
        }
        let term = mb.insns.last().copied().ok_or(Error::internal("block without terminator"))?;
        e.origin = term.origin;
        match term.op {
            MOp::Br { t } => {
                if Some(t) != next {
                    e.jump(class::JMP | jmp::JA, 0, 0, 0, t)?;
                }
            }
            MOp::CondBr { cond, w, a: av, b: bv, t, f } => {
                let jc = match w {
                    Width::W32 => class::JMP32,
                    Width::W64 => class::JMP,
                };
                let ra = e.r(av)?;
                let (is_reg, rb, imm) = e.src_imm(bv)?;
                let x = if is_reg { 0x08 } else { 0 };
                if t == f {
                    if Some(t) != next {
                        e.jump(class::JMP | jmp::JA, 0, 0, 0, t)?;
                    }
                } else if Some(f) == next {
                    e.jump(jc | cond_code(cond) | x, ra, rb, imm, t)?;
                } else if let (Some(nc), true) = (cond.negated(), Some(t) == next) {
                    e.jump(jc | cond_code(nc) | x, ra, rb, imm, f)?;
                } else {
                    e.jump(jc | cond_code(cond) | x, ra, rb, imm, t)?;
                    e.jump(class::JMP | jmp::JA, 0, 0, 0, f)?;
                }
            }
            op => e.insn(op, term.origin, m.isa, m.big_endian)?,
        }
    }

    // Relaxation: give out-of-range jumps the long form until stable.
    let mut items = e.out;
    loop {
        ctx.tick()?;
        // Slot position of each item.
        let mut pos: FVec<'h, u32> = FVec::with_capacity(heap, items.len() + 1)?;
        let mut p = 0u32;
        for it in items.iter() {
            pos.push(p)?;
            p += match (it.wide, it.long, it.insn.class()) {
                (Some(_), _, _) => 2,
                (None, true, c) if c != class::JMP || it.insn.op() != jmp::JA => 2,
                _ => 1,
            };
        }
        pos.push(p)?;
        if p > max_insns {
            return Err(Error::limit("program too large after code generation"));
        }
        let block_pos = |b: BlockId| -> Result<u32> {
            let i = *start.at(b)?;
            pos.get(i as usize).copied().ok_or(Error::internal("block position"))
        };
        let mut changed = false;
        for k in 0..items.len() {
            let it = *items.get(k).ok_or(Error::internal("item"))?;
            let Some(t) = it.target else { continue };
            if it.long {
                continue;
            }
            let from = *pos.get(k).ok_or(Error::internal("pos"))? as i64;
            let off = block_pos(t)? as i64 - from - 1;
            if i16::try_from(off).is_err() {
                if m.isa < Isa::V4 {
                    return Err(Error::unsupported("jump out of range below ISA v4"));
                }
                if let Some(x) = items.get_mut(k) {
                    x.long = true;
                }
                changed = true;
            }
        }
        if !changed {
            // Final encoding.
            let mut insns: FVec<'h, BpfInsn> = FVec::with_capacity(heap, p as usize)?;
            let mut offsets: FVec<'h, (u32, u32)> = FVec::new(heap);
            for (k, it) in items.iter().enumerate() {
                let here = *pos.get(k).ok_or(Error::internal("pos"))?;
                if let Some(o) = it.origin {
                    offsets.push((o, here))?;
                }
                match (it.target, it.long) {
                    (None, _) => {
                        insns.push(it.insn)?;
                        if let Some(hi) = it.wide {
                            insns.push(BpfInsn::new(0, 0, 0, 0, hi))?;
                        }
                    }
                    (Some(t), false) => {
                        let off = block_pos(t)? as i64 - here as i64 - 1;
                        let mut i = it.insn;
                        i.off = i16::try_from(off).map_err(|_| Error::internal("jump offset"))?;
                        insns.push(i)?;
                    }
                    (Some(t), true) => {
                        let is_ja = it.insn.class() == class::JMP && it.insn.op() == jmp::JA;
                        if is_ja {
                            let off = block_pos(t)? as i64 - here as i64 - 1;
                            let imm = i32::try_from(off).map_err(|_| Error::internal("gotol"))?;
                            insns.push(BpfInsn::new(class::JMP32 | jmp::JA, 0, 0, 0, imm))?;
                        } else {
                            // Inverted short jump over a gotol.
                            let inv = invert(it.insn)?;
                            insns.push(inv)?;
                            let off = block_pos(t)? as i64 - (here as i64 + 1) - 1;
                            let imm = i32::try_from(off).map_err(|_| Error::internal("gotol"))?;
                            insns.push(BpfInsn::new(class::JMP32 | jmp::JA, 0, 0, 0, imm))?;
                        }
                    }
                }
            }
            // Keep the first emitted index per origin.
            offsets.as_mut_slice().sort_unstable();
            let mut w = 0usize;
            for r in 0..offsets.len() {
                let cur = *offsets.get(r).ok_or(Error::internal("offsets"))?;
                if w == 0 || offsets.get(w - 1).map(|x| x.0) != Some(cur.0) {
                    if let Some(s) = offsets.get_mut(w) {
                        *s = cur;
                    }
                    w += 1;
                }
            }
            offsets.truncate(w);
            return Ok(Encoded { insns, offsets });
        }
    }
}

/// Negate a conditional jump and make it skip one instruction.
fn invert(i: BpfInsn) -> Result<BpfInsn> {
    let c = match i.op() {
        jmp::JEQ => jmp::JNE,
        jmp::JNE => jmp::JEQ,
        jmp::JGT => jmp::JLE,
        jmp::JLE => jmp::JGT,
        jmp::JGE => jmp::JLT,
        jmp::JLT => jmp::JGE,
        jmp::JSGT => jmp::JSLE,
        jmp::JSLE => jmp::JSGT,
        jmp::JSGE => jmp::JSLT,
        jmp::JSLT => jmp::JSGE,
        _ => return Err(Error::unsupported("out-of-range JSET")),
    };
    Ok(BpfInsn::new((i.code & !0xf0) | c, i.dst, i.src, 1, i.imm))
}
