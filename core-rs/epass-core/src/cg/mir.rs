//! MIR: eBPF-level machine IR with virtual registers, and lowering from the
//! SSA IR. Legalization happens here: immediates that do not fit their
//! encoding are materialized, constant left operands are swapped or
//! materialized, ISA levels gate the forms used, and every register
//! constraint (call arguments/results, opaque registers, the return value)
//! becomes an explicit copy to a fixed register.

use crate::define_idx;
use crate::error::{Error, Result};
use crate::facts::Isa;
use crate::ir::{
    BinOp, BlockId, Callee, Cond, Function, InsnId, Op, Size, SlotId, SwapKind, Value, Width,
};
use crate::mem::{FVec, Heap, Idx, IdxVec};

define_idx! {
    /// A virtual register. `VReg(0..=9)` are the fixed registers r0..r9.
    pub struct VReg;
}

/// Number of allocatable (and fixed) registers.
pub const NREG: u32 = 10;

pub fn fixed(r: u8) -> VReg {
    VReg(r as u32)
}

impl VReg {
    pub fn is_fixed(self) -> bool {
        self.0 < NREG
    }
}

/// An operand that may be encoded as a 32-bit immediate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    V(VReg),
    Imm(i32),
    Fp,
}

/// A memory base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    V(VReg),
    Fp,
}

/// Stack slots owned by ePass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MSlot {
    /// A frame slot declared in the IR.
    Ir(SlotId),
    /// A register-allocation spill slot.
    Spill(u32),
    /// Scratch slot for breaking parallel-copy cycles.
    Scratch,
    /// Scratch slot for saving a temporary register inside a copy.
    Scratch2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MOp {
    /// `dst = src` (`Imm` is a sign-extended 64-bit move; `Fp` copies r10).
    Copy { dst: VReg, src: Src },
    /// `wdst = imm` (zero-extended).
    Imm32 { dst: VReg, imm: i32 },
    /// `dst = imm64` (two slots; `src_reg` is the ld_imm64 pseudo source).
    Ld64 { dst: VReg, imm: u64, src_reg: u8 },
    Alu { op: BinOp, w: Width, dst: VReg, a: VReg, b: Src },
    Neg { w: Width, dst: VReg, a: VReg },
    Ext { from: u8, signed: bool, w: Width, dst: VReg, a: VReg },
    Bswap { bits: u8, kind: SwapKind, dst: VReg, a: VReg },
    Load { size: Size, signed: bool, dst: VReg, base: Base, off: i16 },
    Store { size: Size, base: Base, off: i16, val: Src },
    /// `dst = r10 + offset(slot) + off`.
    FrameAddr { dst: VReg, slot: MSlot, off: i32 },
    SlotStore { slot: MSlot, src: VReg },
    SlotLoad { dst: VReg, slot: MSlot },
    /// Reads fixed r1..r(nargs), clobbers r0..r5, result in r0.
    Call { callee: Callee, nargs: u8 },
    /// A raw instruction on fixed registers.
    Opaque { raw: u64, def: Option<u8>, uses: u16, clobbers: u16 },
    // ---- terminators ----
    Br { t: BlockId },
    CondBr { cond: Cond, w: Width, a: VReg, b: Src, t: BlockId, f: BlockId },
    /// Return r0.
    Exit,
    Poison { imm: i32 },
}

impl MOp {
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            MOp::Br { .. } | MOp::CondBr { .. } | MOp::Exit | MOp::Poison { .. }
        )
    }

    /// Defined registers (at most one virtual def; calls/opaque define fixed
    /// registers).
    pub fn defs(&self, out: &mut [VReg; 8]) -> usize {
        let mut n = 0usize;
        let mut put = |v: VReg| {
            if let Some(s) = out.get_mut(n) {
                *s = v;
            }
            n += 1;
        };
        match *self {
            MOp::Copy { dst, .. }
            | MOp::Imm32 { dst, .. }
            | MOp::Ld64 { dst, .. }
            | MOp::Alu { dst, .. }
            | MOp::Neg { dst, .. }
            | MOp::Ext { dst, .. }
            | MOp::Bswap { dst, .. }
            | MOp::Load { dst, .. }
            | MOp::FrameAddr { dst, .. }
            | MOp::SlotLoad { dst, .. } => put(dst),
            MOp::Call { .. } => {
                for r in 0..=5u8 {
                    put(fixed(r));
                }
            }
            MOp::Opaque { def, clobbers, .. } => {
                for r in 0..NREG as u8 {
                    if def == Some(r) || clobbers & (1 << r) != 0 {
                        put(fixed(r));
                    }
                }
            }
            _ => {}
        }
        n.min(8)
    }

    /// Used registers.
    pub fn uses(&self, out: &mut [VReg; 8]) -> usize {
        let mut n = 0usize;
        let mut put = |v: VReg| {
            if let Some(s) = out.get_mut(n) {
                *s = v;
            }
            n += 1;
        };
        let src = |s: Src, put: &mut dyn FnMut(VReg)| {
            if let Src::V(v) = s {
                put(v);
            }
        };
        let base = |b: Base, put: &mut dyn FnMut(VReg)| {
            if let Base::V(v) = b {
                put(v);
            }
        };
        match *self {
            MOp::Copy { src: s, .. } => src(s, &mut put),
            MOp::Alu { a, b, .. } => {
                put(a);
                src(b, &mut put);
            }
            MOp::Neg { a, .. } | MOp::Ext { a, .. } | MOp::Bswap { a, .. } => put(a),
            MOp::Load { base: b, .. } => base(b, &mut put),
            MOp::Store { base: b, val, .. } => {
                base(b, &mut put);
                src(val, &mut put);
            }
            MOp::SlotStore { src: s, .. } => put(s),
            MOp::Call { nargs, .. } => {
                for r in 1..=nargs.min(5) {
                    put(fixed(r));
                }
            }
            MOp::Opaque { uses, .. } => {
                for r in 0..NREG as u8 {
                    if uses & (1 << r) != 0 {
                        put(fixed(r));
                    }
                }
            }
            MOp::CondBr { a, b, .. } => {
                put(a);
                src(b, &mut put);
            }
            MOp::Exit => put(fixed(0)),
            _ => {}
        }
        n.min(8)
    }

    /// Rewrite every use of `from` to `to`.
    pub fn replace_use(&mut self, from: VReg, to: VReg) {
        let fs = |s: &mut Src| {
            if *s == Src::V(from) {
                *s = Src::V(to);
            }
        };
        let fb = |b: &mut Base| {
            if *b == Base::V(from) {
                *b = Base::V(to);
            }
        };
        let fv = |v: &mut VReg| {
            if *v == from {
                *v = to;
            }
        };
        match self {
            MOp::Copy { src, .. } => fs(src),
            MOp::Alu { a, b, .. } => {
                fv(a);
                fs(b);
            }
            MOp::Neg { a, .. } | MOp::Ext { a, .. } | MOp::Bswap { a, .. } => fv(a),
            MOp::Load { base, .. } => fb(base),
            MOp::Store { base, val, .. } => {
                fb(base);
                fs(val);
            }
            MOp::SlotStore { src, .. } => fv(src),
            MOp::CondBr { a, b, .. } => {
                fv(a);
                fs(b);
            }
            _ => {}
        }
    }

    pub fn successors(&self) -> crate::ir::Succs {
        match *self {
            MOp::Br { t } => crate::ir::Succs::one(t),
            MOp::CondBr { t, f, .. } => crate::ir::Succs::two(t, f),
            _ => crate::ir::Succs::none(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MInsn {
    pub op: MOp,
    /// Source bytecode index of the IR instruction this came from.
    pub origin: Option<u32>,
}

/// A phi input value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PVal {
    V(VReg),
    Const(u64),
    Fp,
    Undef,
    /// A spilled input, loaded straight from its slot by the edge copy.
    Slot(MSlot),
}

#[derive(Debug)]
pub struct MPhi<'h> {
    pub dst: VReg,
    pub inputs: FVec<'h, (BlockId, PVal)>,
    /// A spilled ("memory") phi: its value lives only in this slot, the
    /// edge copies store to it, and every use reloads from it.
    pub slot: Option<MSlot>,
}

#[derive(Debug)]
pub struct MBlock<'h> {
    pub live: bool,
    pub phis: FVec<'h, MPhi<'h>>,
    pub insns: FVec<'h, MInsn>,
    pub preds: FVec<'h, BlockId>,
}

/// Per-vreg allocation info.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct VInfo {
    /// Preferred color (the register the original program used).
    pub hint: Option<u8>,
    /// Reload temporaries and other tiny ranges are never spilled.
    pub unspillable: bool,
    /// Spill slot index, once spilled.
    pub spilled: Option<u32>,
}

#[derive(Debug)]
pub struct MFunc<'h> {
    pub heap: &'h Heap<'h>,
    pub blocks: IdxVec<'h, BlockId, MBlock<'h>>,
    pub entry: BlockId,
    pub vregs: IdxVec<'h, VReg, VInfo>,
    pub ir_slots: FVec<'h, crate::ir::FrameSlot>,
    pub spill_slots: u32,
    pub needs_scratch: bool,
    pub isa: Isa,
    pub big_endian: bool,
}

impl<'h> MFunc<'h> {
    pub fn new_vreg(&mut self) -> Result<VReg> {
        self.vregs.push(VInfo::default())
    }

    pub fn nvregs(&self) -> usize {
        self.vregs.len()
    }

    pub fn block(&self, b: BlockId) -> Result<&MBlock<'h>> {
        let mb = self.blocks.at(b)?;
        if mb.live {
            Ok(mb)
        } else {
            Err(Error::internal("dead MIR block"))
        }
    }

    pub fn block_mut(&mut self, b: BlockId) -> Result<&mut MBlock<'h>> {
        self.blocks.at_mut(b)
    }

    /// Live blocks in id order.
    pub fn block_ids(&self) -> impl Iterator<Item = BlockId> + '_ {
        self.blocks.iter().filter(|(_, b)| b.live).map(|(id, _)| id)
    }

    pub fn successors(&self, b: BlockId) -> Result<crate::ir::Succs> {
        Ok(match self.block(b)?.insns.last() {
            Some(t) => t.op.successors(),
            None => crate::ir::Succs::none(),
        })
    }
}

// ------------------------------------------------------------------ lowering

fn fits_sext32(c: u64) -> bool {
    c == c as i32 as i64 as u64
}

struct Lower<'a, 'h> {
    f: &'a Function<'h>,
    m: MFunc<'h>,
    vreg_of: IdxVec<'h, InsnId, u32>,
    params: [Option<VReg>; 6],
    cur: BlockId,
    origin: Option<u32>,
}

const NOV: u32 = u32::MAX;

impl<'a, 'h> Lower<'a, 'h> {
    fn push(&mut self, op: MOp) -> Result<()> {
        let o = self.origin;
        self.m.blocks.at_mut(self.cur)?.insns.push(MInsn { op, origin: o })
    }

    fn vreg(&self, i: InsnId) -> Result<VReg> {
        match *self.vreg_of.at(i)? {
            NOV => Err(Error::internal("value without a vreg")),
            v => Ok(VReg(v)),
        }
    }

    /// Materialize a 64-bit constant into a new vreg.
    fn constant(&mut self, c: u64) -> Result<VReg> {
        let t = self.m.new_vreg()?;
        if fits_sext32(c) {
            self.push(MOp::Copy {
                dst: t,
                src: Src::Imm(c as i32),
            })?;
        } else if c >> 32 == 0 {
            self.push(MOp::Imm32 {
                dst: t,
                imm: c as u32 as i32,
            })?;
        } else {
            self.push(MOp::Ld64 {
                dst: t,
                imm: c,
                src_reg: 0,
            })?;
        }
        Ok(t)
    }

    /// A value in a register.
    fn reg(&mut self, v: Value) -> Result<VReg> {
        match v {
            Value::Insn(i) => self.vreg(i),
            Value::Const(c) => self.constant(c),
            Value::Param(k) => self
                .params
                .get(k as usize)
                .copied()
                .flatten()
                .ok_or(Error::internal("param vreg")),
            Value::FramePtr => {
                let t = self.m.new_vreg()?;
                self.push(MOp::Copy { dst: t, src: Src::Fp })?;
                Ok(t)
            }
            Value::Undef => Err(Error::internal("undef in a register context")),
            Value::Builtin(_) => Err(Error::unsupported("builtin constants are not lowered in v2")),
        }
    }

    /// A value as an ALU/JMP source operand of width `w`.
    fn src(&mut self, v: Value, w: Width) -> Result<Src> {
        if let Value::Const(c) = v {
            match w {
                Width::W32 => return Ok(Src::Imm(c as u32 as i32)),
                Width::W64 if fits_sext32(c) => return Ok(Src::Imm(c as i32)),
                Width::W64 => {}
            }
        }
        Ok(Src::V(self.reg(v)?))
    }

    fn base(&mut self, v: Value) -> Result<Base> {
        match v {
            Value::FramePtr => Ok(Base::Fp),
            v => Ok(Base::V(self.reg(v)?)),
        }
    }

    /// Copy `v` into fixed register `r` (no-op for undef).
    fn move_to_fixed(&mut self, r: u8, v: Value) -> Result<()> {
        let dst = fixed(r);
        match v {
            Value::Undef => Ok(()),
            Value::Const(c) if fits_sext32(c) => self.push(MOp::Copy {
                dst,
                src: Src::Imm(c as i32),
            }),
            Value::Const(c) if c >> 32 == 0 => self.push(MOp::Imm32 {
                dst,
                imm: c as u32 as i32,
            }),
            Value::Const(c) => self.push(MOp::Ld64 {
                dst,
                imm: c,
                src_reg: 0,
            }),
            Value::FramePtr => self.push(MOp::Copy { dst, src: Src::Fp }),
            v => {
                let s = self.reg(v)?;
                self.push(MOp::Copy { dst, src: Src::V(s) })
            }
        }
    }

    fn pval(&self, v: Value) -> Result<PVal> {
        Ok(match v {
            Value::Insn(i) => PVal::V(self.vreg(i)?),
            Value::Const(c) => PVal::Const(c),
            Value::Param(k) => PVal::V(
                self.params
                    .get(k as usize)
                    .copied()
                    .flatten()
                    .ok_or(Error::internal("param vreg"))?,
            ),
            Value::FramePtr => PVal::Fp,
            Value::Undef => PVal::Undef,
            Value::Builtin(_) => return Err(Error::unsupported("builtin constants")),
        })
    }

    fn insn(&mut self, i: InsnId) -> Result<()> {
        let d = self.f.insn(i)?;
        self.origin = d.origin;
        let opnd = |k: usize| self.f.operand(i, k);
        match d.op {
            Op::Phi => {} // handled with the block
            Op::Bin { op, w } => {
                let dst = self.vreg(i)?;
                let (mut a, mut b) = (opnd(0)?, opnd(1)?);
                if a.as_const().is_some() && op.is_commutative() && b.as_const().is_none() {
                    core::mem::swap(&mut a, &mut b);
                }
                let ra = self.reg(a)?;
                let sb = self.src(b, w)?;
                self.push(MOp::Alu { op, w, dst, a: ra, b: sb })?;
                if matches!(op, BinOp::SDiv | BinOp::SMod) && self.m.isa < Isa::V4 {
                    return Err(Error::unsupported("sdiv/smod need ISA v4").at(i.0));
                }
            }
            Op::Neg { w } => {
                let dst = self.vreg(i)?;
                let a = self.reg(opnd(0)?)?;
                self.push(MOp::Neg { w, dst, a })?;
            }
            Op::Ext { from, signed, w } => {
                let dst = self.vreg(i)?;
                let a = self.reg(opnd(0)?)?;
                self.push(MOp::Ext { from, signed, w, dst, a })?;
            }
            Op::Bswap { bits, kind } => {
                let dst = self.vreg(i)?;
                let a = self.reg(opnd(0)?)?;
                self.push(MOp::Bswap { bits, kind, dst, a })?;
            }
            Op::Load { size, signed, off } => {
                let dst = self.vreg(i)?;
                let base = self.base(opnd(0)?)?;
                self.push(MOp::Load {
                    size,
                    signed,
                    dst,
                    base,
                    off,
                })?;
            }
            Op::Store { size, off } => {
                let base = self.base(opnd(0)?)?;
                let val = match opnd(1)? {
                    // `st` sign-extends its immediate to the access size.
                    Value::Const(c) if size != Size::B8 || fits_sext32(c) => Src::Imm(c as i32),
                    v => Src::V(self.reg(v)?),
                };
                self.push(MOp::Store {
                    size,
                    base,
                    off,
                    val,
                })?;
            }
            Op::LdSym { kind, imm } => {
                let dst = self.vreg(i)?;
                self.push(MOp::Ld64 {
                    dst,
                    imm,
                    src_reg: kind.src_reg(),
                })?;
            }
            Op::SlotAddr { slot, off } => {
                let dst = self.vreg(i)?;
                self.push(MOp::FrameAddr {
                    dst,
                    slot: MSlot::Ir(slot),
                    off,
                })?;
            }
            Op::SlotLoad { slot } => {
                let dst = self.vreg(i)?;
                self.push(MOp::SlotLoad {
                    dst,
                    slot: MSlot::Ir(slot),
                })?;
            }
            Op::SlotStore { slot } => {
                let src = self.reg(opnd(0)?)?;
                self.push(MOp::SlotStore {
                    slot: MSlot::Ir(slot),
                    src,
                })?;
            }
            Op::Call { callee, .. } => {
                if let Callee::Local(_) = callee {
                    return Err(Error::unsupported("bpf-to-bpf calls").at(i.0));
                }
                let n = self.f.operand_count(i)?;
                for k in 0..n {
                    let v = opnd(k)?;
                    self.move_to_fixed((k + 1) as u8, v)?;
                }
                self.push(MOp::Call {
                    callee,
                    nargs: n as u8,
                })?;
                if self.f.use_count(i)? > 0 {
                    let dst = self.vreg(i)?;
                    self.push(MOp::Copy {
                        dst,
                        src: Src::V(fixed(0)),
                    })?;
                }
            }
            Op::Ecall { .. } => return Err(Error::unsupported("ecall has no lowering in v2").at(i.0)),
            Op::Opaque(o) => {
                let mut k = 0usize;
                for r in 0..=10u8 {
                    if o.uses & (1 << r) == 0 {
                        continue;
                    }
                    let v = opnd(k)?;
                    k += 1;
                    if r == 10 {
                        if v != Value::FramePtr {
                            return Err(Error::internal("opaque r10 operand"));
                        }
                    } else {
                        self.move_to_fixed(r, v)?;
                    }
                }
                self.push(MOp::Opaque {
                    raw: o.raw,
                    def: o.def,
                    uses: o.uses & 0x3ff,
                    clobbers: o.clobbers,
                })?;
                if let Some(r) = o.def {
                    if self.f.use_count(i)? > 0 {
                        let dst = self.vreg(i)?;
                        self.push(MOp::Copy {
                            dst,
                            src: Src::V(fixed(r)),
                        })?;
                    }
                }
            }
            Op::Br { target } => self.push(MOp::Br { t: target })?,
            Op::CondBr { cond, w, t, f } => {
                let (a, b) = (opnd(0)?, opnd(1)?);
                let swappable = cond.is_symmetric() || self.m.isa >= Isa::V2;
                let (cond, a, b) = if a.as_const().is_some() && b.as_const().is_none() && swappable {
                    (cond.swapped(), b, a)
                } else {
                    (cond, a, b)
                };
                let ra = self.reg(a)?;
                let sb = self.src(b, w)?;
                self.push(MOp::CondBr {
                    cond,
                    w,
                    a: ra,
                    b: sb,
                    t,
                    f,
                })?;
            }
            Op::Ret => {
                let v = opnd(0)?;
                self.move_to_fixed(0, v)?;
                self.push(MOp::Exit)?;
            }
            Op::Poison { imm } => self.push(MOp::Poison { imm })?,
            Op::Throw => return Err(Error::internal("throw survived lower_throw")),
        }
        Ok(())
    }
}

/// Lower a validated IR function (with critical edges split) to MIR.
pub fn lower<'h>(f: &Function<'h>, isa: Isa, big_endian: bool) -> Result<MFunc<'h>> {
    let heap = f.heap();
    let mut blocks: IdxVec<'h, BlockId, MBlock<'h>> = IdxVec::new(heap);
    for _ in 0..f.block_id_bound() {
        blocks.push(MBlock {
            live: false,
            phis: FVec::new(heap),
            insns: FVec::new(heap),
            preds: FVec::new(heap),
        })?;
    }
    let mut m = MFunc {
        heap,
        blocks,
        entry: f.entry(),
        vregs: IdxVec::new(heap),
        ir_slots: FVec::new(heap),
        spill_slots: 0,
        needs_scratch: false,
        isa,
        big_endian,
    };
    for _ in 0..NREG {
        m.new_vreg()?;
    }
    for (_, s) in f.slots() {
        m.ir_slots.push(s)?;
    }
    // A vreg per result-producing instruction.
    let mut vreg_of: IdxVec<'h, InsnId, u32> = IdxVec::filled(heap, f.insn_id_bound(), NOV)?;
    let mut uses_param = [false; 6];
    for b in f.blocks() {
        for i in f.iter_block(b) {
            if f.insn(i)?.op.has_result() {
                let v = m.new_vreg()?;
                m.vregs.at_mut(v)?.hint = f.insn(i)?.hint;
                *vreg_of.at_mut(i)? = v.to_u32();
            }
            for v in f.operands(i) {
                if let Value::Param(k) = v {
                    if let Some(u) = uses_param.get_mut(k as usize) {
                        *u = true;
                    }
                }
            }
        }
    }
    let mut lw = Lower {
        f,
        m,
        vreg_of,
        params: [None; 6],
        cur: f.entry(),
        origin: None,
    };
    // Parameters arrive in r1..r5.
    for (k, &used) in uses_param.iter().enumerate() {
        if used && k >= 1 {
            let v = lw.m.new_vreg()?;
            if let Some(p) = lw.params.get_mut(k) {
                *p = Some(v);
            }
            lw.cur = f.entry();
            lw.push(MOp::Copy {
                dst: v,
                src: Src::V(fixed(k as u8)),
            })?;
        }
    }
    for b in f.blocks() {
        lw.cur = b;
        {
            let mb = lw.m.blocks.at_mut(b)?;
            mb.live = true;
            for &p in f.preds(b)? {
                mb.preds.push(p)?;
            }
        }
        for i in f.iter_block(b) {
            if matches!(f.op(i)?, Op::Phi) {
                let dst = lw.vreg(i)?;
                let mut inputs = FVec::new(heap);
                for (v, pb) in f.phi_inputs(i) {
                    inputs.push((pb, lw.pval(v)?))?;
                }
                lw.m.blocks.at_mut(b)?.phis.push(MPhi { dst, inputs, slot: None })?;
            } else {
                lw.insn(i)?;
            }
        }
    }
    Ok(lw.m)
}

/// Debug dump of MIR into the compilation log (Debug level).
pub fn dump(m: &MFunc<'_>, ctx: &crate::ctx::Ctx<'_>) {
    use crate::ctx_log;
    use crate::log::Level;
    if !ctx.log_enabled(Level::Debug) {
        return;
    }
    for b in m.block_ids() {
        let Ok(mb) = m.block(b) else { continue };
        ctx_log!(ctx, Level::Debug, "mbb{}: preds={:?}\n", b.0, mb.preds.as_slice());
        for p in mb.phis.iter() {
            ctx_log!(ctx, Level::Debug, "  v{} = phi {:?}\n", p.dst.0, p.inputs.as_slice());
        }
        for i in mb.insns.iter() {
            ctx_log!(ctx, Level::Debug, "  {:?}\n", i.op);
        }
    }
}
