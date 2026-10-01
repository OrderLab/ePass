//! Value facts derived from the IR (never declared by it):
//! - stack provenance and the original frame extent,
//! - value class (scalar vs. pointer kinds, nullability),
//! - known zero-extension of the upper 32 bits.
//!
//! All three are forward dataflow over SSA values, solved by iterating
//! instructions in reverse postorder until no fact changes (phis are the
//! only instructions whose inputs can come from later blocks).

use crate::analysis::{Cfg, DomTree};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::facts::RetClass;
use crate::ir::{BinOp, BlockId, Cond, Function, InsnId, Op, Value, Width};
use crate::mem::IdxVec;

// ------------------------------------------------------------- provenance

/// Whether a value may point into the frame (r10-relative).
///
/// `Stack { lo, exact }` means "possibly a frame pointer, and if so at
/// offset >= lo"; `exact` means "definitely the frame pointer plus exactly
/// `lo`". Only the lowest reachable frame address matters for placing ePass
/// slots below the program's frame, so joins keep the minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackFact {
    /// Not yet computed (optimistic bottom for phis).
    Unseen,
    NotStack,
    Stack { lo: i64, exact: bool },
    /// Possibly a frame pointer at an unbounded offset.
    Unknown,
}

impl StackFact {
    const FP: StackFact = StackFact::Stack { lo: 0, exact: true };

    fn join(self, o: StackFact) -> StackFact {
        use StackFact::*;
        match (self, o) {
            (Unseen, x) | (x, Unseen) => x,
            (Unknown, _) | (_, Unknown) => Unknown,
            (NotStack, NotStack) => NotStack,
            (Stack { lo: a, exact: ea }, Stack { lo: b, exact: eb }) => Stack {
                lo: a.min(b),
                exact: ea && eb && a == b,
            },
            (Stack { lo, .. }, NotStack) | (NotStack, Stack { lo, .. }) => Stack { lo, exact: false },
        }
    }

    fn shift(self, by: i64, exact: bool) -> StackFact {
        match self {
            StackFact::Stack { lo, exact: e } => match lo.checked_add(by) {
                Some(v) if v >= -(1 << 20) => StackFact::Stack {
                    lo: v,
                    exact: e && exact,
                },
                _ => StackFact::Unknown,
            },
            x => x,
        }
    }

    pub fn lowest(self) -> Option<i64> {
        match self {
            StackFact::Stack { lo, .. } => Some(lo),
            _ => None,
        }
    }

    fn may_be_stack(self) -> bool {
        !matches!(self, StackFact::NotStack)
    }
}

/// Stack provenance of every instruction result, including frame pointers
/// that the program spills to (exact) stack slots and reloads.
///
/// SSA values have one fact each; the contents of exact stack slots are
/// tracked flow-sensitively (per block, joined at merges) because compilers
/// reuse spill slots for unrelated values.
#[derive(Debug)]
pub struct Provenance<'h> {
    facts: IdxVec<'h, InsnId, StackFact>,
    /// A frame pointer was stored somewhere other than an exact stack slot.
    pub escaped: bool,
}

/// Phi facts that keep lowering past this many updates are widened to
/// `Unknown` (a loop that decrements a frame pointer).
const WIDEN_AFTER: u8 = 4;

/// Slot contents: sorted (offset, fact) for slots that may hold a frame
/// pointer; absent slots hold scalars.
type SlotState<'h> = crate::mem::FVec<'h, (i64, StackFact)>;

fn state_get(st: &SlotState<'_>, at: i64) -> StackFact {
    match st.binary_search_by_key(&at, |e| e.0) {
        Ok(i) => st.get(i).map_or(StackFact::NotStack, |e| e.1),
        Err(_) => StackFact::NotStack,
    }
}

fn state_set(st: &mut SlotState<'_>, at: i64, v: StackFact) -> Result<()> {
    match st.binary_search_by_key(&at, |e| e.0) {
        Ok(i) => {
            if v == StackFact::NotStack {
                st.remove(i);
            } else if let Some(e) = st.get_mut(i) {
                e.1 = v;
            }
            Ok(())
        }
        Err(i) => {
            if v == StackFact::NotStack {
                Ok(())
            } else {
                st.insert(i, (at, v))
            }
        }
    }
}

/// Kill pointer facts in slots overlapping `[at, at + len)`.
fn state_clobber(st: &mut SlotState<'_>, at: i64, len: i64) {
    st.retain(|e| e.0 + 8 <= at || e.0 >= at + len);
}

fn state_join_into(dst: &mut SlotState<'_>, src: &SlotState<'_>) -> Result<()> {
    for &(k, v) in src.iter() {
        let j = state_get(dst, k).join(v);
        state_set(dst, k, j)?;
    }
    Ok(())
}

impl<'h> Provenance<'h> {
    pub fn compute(f: &Function<'h>, cfg: &Cfg<'h>, mag: &Magnitude<'h>, ctx: &Ctx<'_>) -> Result<Self> {
        let heap = f.heap();
        let mut p = Provenance {
            facts: IdxVec::filled(heap, f.insn_id_bound(), StackFact::Unseen)?,
            escaped: false,
        };
        let mut updates: IdxVec<'h, InsnId, u8> = IdxVec::filled(heap, f.insn_id_bound(), 0)?;
        let nb = f.block_id_bound();
        let mut out: IdxVec<'h, crate::ir::BlockId, SlotState<'h>> = IdxVec::new(heap);
        for _ in 0..nb {
            out.push(crate::mem::FVec::new(heap))?;
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &b in cfg.rpo() {
                // Slot state at block entry: join of the predecessors.
                let mut st: SlotState<'h> = crate::mem::FVec::new(heap);
                for &pb in f.preds(b)? {
                    if cfg.is_reachable(pb) {
                        state_join_into(&mut st, out.at(pb)?)?;
                    }
                }
                for i in f.iter_block(b) {
                    ctx.tick()?;
                    let op = f.insn(i)?.op;
                    let mut new = match op {
                        // Reloading a spilled frame pointer.
                        Op::Load { size: crate::ir::Size::B8, off, .. } => {
                            match p.of(f.operand(i, 0)?) {
                                StackFact::Stack { lo, exact: true } => state_get(&st, lo.saturating_add(off as i64)),
                                StackFact::Unseen => StackFact::Unseen,
                                StackFact::Stack { .. } | StackFact::Unknown => {
                                    if p.escaped {
                                        StackFact::Unknown
                                    } else {
                                        st.iter().fold(StackFact::NotStack, |a, e| a.join(e.1))
                                    }
                                }
                                StackFact::NotStack => {
                                    if p.escaped {
                                        StackFact::Unknown
                                    } else {
                                        StackFact::NotStack
                                    }
                                }
                            }
                        }
                        _ => p.transfer(f, i, mag)?,
                    };
                    if let Op::Store { size, off } = op {
                        let val = p.of(f.operand(i, 1)?);
                        let base = p.of(f.operand(i, 0)?);
                        let len = size.bytes() as i64;
                        match base {
                            StackFact::Stack { lo, exact: true } => {
                                let at = lo.saturating_add(off as i64);
                                state_clobber(&mut st, at, len);
                                if size == crate::ir::Size::B8 && val.may_be_stack() && val != StackFact::Unseen {
                                    state_set(&mut st, at, val)?;
                                }
                            }
                            StackFact::Unseen => {}
                            _ => {
                                // Facts still being computed are revisited. A
                                // store narrower than 8 bytes cannot leave a
                                // usable frame pointer in memory.
                                if size == crate::ir::Size::B8
                                    && val.may_be_stack()
                                    && val != StackFact::Unseen
                                    && !p.escaped
                                {
                                    crate::ctx_log!(
                                        ctx,
                                        crate::Level::Debug,
                                        "provenance: frame pointer escapes at {:?} (base {:?}, value {:?})\n",
                                        f.insn(i)?.origin,
                                        base,
                                        val
                                    );
                                    p.escaped = true;
                                    changed = true;
                                }
                            }
                        }
                    }
                    let cur = *p.facts.at(i)?;
                    if cur == new {
                        continue;
                    }
                    if matches!(op, Op::Phi) {
                        let n = updates.at_mut(i)?;
                        *n = n.saturating_add(1);
                        if *n > WIDEN_AFTER {
                            new = StackFact::Unknown;
                        }
                    }
                    if cur != new {
                        *p.facts.at_mut(i)? = new;
                        changed = true;
                    }
                }
                let o = out.at_mut(b)?;
                if o.as_slice() != st.as_slice() {
                    *o = st;
                    changed = true;
                }
            }
        }
        Ok(p)
    }

    pub fn of(&self, v: Value) -> StackFact {
        match v {
            Value::FramePtr => StackFact::FP,
            Value::Insn(i) => self.facts.get(i).copied().unwrap_or(StackFact::Unknown),
            _ => StackFact::NotStack,
        }
    }

    fn transfer(&self, f: &Function<'_>, i: InsnId, mag: &Magnitude<'_>) -> Result<StackFact> {
        let d = f.insn(i)?;
        Ok(match d.op {
            Op::Bin { op, w } => {
                let (va, vb) = (f.operand(i, 0)?, f.operand(i, 1)?);
                let (x, y) = (self.of(va), self.of(vb));
                use StackFact::*;
                match (x, y) {
                    (Unseen, _) | (_, Unseen) => Unseen,
                    (NotStack, NotStack) => NotStack,
                    (Unknown, _) | (_, Unknown) => Unknown,
                    _ if w == Width::W32 => Unknown,
                    // A pointer difference is a scalar.
                    (Stack { .. }, Stack { .. }) if op == BinOp::Sub => NotStack,
                    (Stack { .. }, Stack { .. }) => Unknown,
                    (Stack { .. }, NotStack) => match (op, vb.as_const()) {
                        (BinOp::Add, Some(c)) => x.shift(c as i64, true),
                        (BinOp::Sub, Some(c)) => x.shift((c as i64).wrapping_neg(), true),
                        // Adding a provably non-negative value can only raise
                        // the offset.
                        (BinOp::Add, None) if mag.non_negative(vb) => x.shift(0, false),
                        _ => Unknown,
                    },
                    (NotStack, Stack { .. }) => match (op, va.as_const()) {
                        (BinOp::Add, Some(c)) => y.shift(c as i64, true),
                        (BinOp::Add, None) if mag.non_negative(va) => y.shift(0, false),
                        _ => Unknown,
                    },
                }
            }
            Op::Neg { .. } | Op::Ext { .. } | Op::Bswap { .. } => match self.of(f.operand(i, 0)?) {
                StackFact::NotStack => StackFact::NotStack,
                StackFact::Unseen => StackFact::Unseen,
                _ => StackFact::Unknown,
            },
            Op::Phi => {
                let mut acc = StackFact::Unseen;
                for (v, _) in f.phi_inputs(i) {
                    acc = acc.join(self.of(v));
                }
                acc
            }
            // Calls, symbols, slot reads, narrow loads and opaque results are
            // not frame pointers. Slot addresses are ePass's own.
            _ => StackFact::NotStack,
        })
    }
}

/// The part of the frame the original program can touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// Lowest r10-relative byte offset accessed (<= 0).
    pub lowest: i64,
    /// A frame pointer escaped or had an unknown offset: assume the whole
    /// 512-byte frame is in use.
    pub unknown: bool,
}

/// Compute the original program's frame extent.
///
/// Accesses through a frame pointer `r10 + c` touch `[c + off, c + off +
/// size)`; helper memory arguments touch `[c, c + n)` upward, and the
/// verifier keeps both within `[-512, 0)`. So the lowest touched address is
/// the minimum of `c + off` over dereferences and of `c` over call arguments.
pub fn frame_extent(f: &Function<'_>, prov: &Provenance<'_>, cfg: &Cfg<'_>, ctx: &Ctx<'_>) -> Result<Extent> {
    let mut ext = Extent {
        lowest: 0,
        unknown: prov.escaped,
    };
    let note = |fact: StackFact, off: i64, ext: &mut Extent| match fact {
        StackFact::Stack { lo, .. } => ext.lowest = ext.lowest.min(lo.saturating_add(off)),
        StackFact::Unknown | StackFact::Unseen => ext.unknown = true,
        StackFact::NotStack => {}
    };
    for &b in cfg.rpo() {
        for i in f.iter_block(b) {
            ctx.tick()?;
            let d = f.insn(i)?;
            match d.op {
                Op::Load { off, .. } => note(prov.of(f.operand(i, 0)?), off as i64, &mut ext),
                Op::Store { off, .. } => {
                    // Stored frame pointers are tracked by `Provenance`.
                    note(prov.of(f.operand(i, 0)?), off as i64, &mut ext);
                }
                Op::Call { .. } | Op::Ecall { .. } => {
                    for v in f.operands(i) {
                        note(prov.of(v), 0, &mut ext);
                    }
                }
                Op::Opaque(o) => {
                    // Operands in ascending register order; the address
                    // register is the raw dst for atomics.
                    let raw = crate::bpf::BpfInsn::from_u64(o.raw);
                    let mut k = 0usize;
                    for r in 0..=10u8 {
                        if o.uses & (1 << r) == 0 {
                            continue;
                        }
                        let v = f.operand(i, k)?;
                        k += 1;
                        let fact = prov.of(v);
                        if raw.class() == crate::bpf::class::STX && r == raw.dst {
                            note(fact, raw.off as i64, &mut ext);
                        } else if fact.may_be_stack() {
                            ext.unknown = true;
                        }
                    }
                }
                Op::SlotStore { .. } | Op::Ret if prov.of(f.operand(i, 0)?).may_be_stack() => {
                    ext.unknown = true;
                }
                _ => {}
            }
        }
    }
    if ext.lowest < -512 {
        return Err(Error::invalid_input("stack access below the 512-byte frame"));
    }
    Ok(ext)
}

// -------------------------------------------------------------- magnitude

/// An upper bound on the number of significant bits of each value
/// (`value < 2^bits` as an unsigned 64-bit number). A value with at most 63
/// bits is non-negative as a signed number.
#[derive(Debug)]
pub struct Magnitude<'h> {
    bits: IdxVec<'h, InsnId, u8>,
    /// Bound from [`iv_range`] for counted-loop phis (64 = none).
    iv: IdxVec<'h, InsnId, u8>,
}

impl<'h> Magnitude<'h> {
    pub fn compute(f: &Function<'h>, cfg: &Cfg<'h>, ctx: &Ctx<'_>) -> Result<Self> {
        let heap = f.heap();
        // Optimistic for phis: start at 0 and only grow; widen loops.
        let mut m = Magnitude {
            bits: IdxVec::filled(heap, f.insn_id_bound(), 0)?,
            iv: IdxVec::filled(heap, f.insn_id_bound(), 64)?,
        };
        let dom = DomTree::compute(f, cfg, ctx)?;
        for &b in cfg.rpo() {
            for i in f.iter_block(b) {
                if !matches!(f.insn(i)?.op, Op::Phi) {
                    break;
                }
                ctx.tick()?;
                if let Some((lo, hi)) = iv_range(f, &dom, i)? {
                    if lo >= 0 {
                        *m.iv.at_mut(i)? = (64 - (hi as u64).leading_zeros()) as u8;
                    }
                }
            }
        }
        let mut updates: IdxVec<'h, InsnId, u8> = IdxVec::filled(heap, f.insn_id_bound(), 0)?;
        let mut changed = true;
        while changed {
            changed = false;
            for &b in cfg.rpo() {
                for i in f.iter_block(b) {
                    ctx.tick()?;
                    let mut new = m.transfer(f, i)?;
                    let cur = *m.bits.at(i)?;
                    if new <= cur {
                        continue;
                    }
                    if matches!(f.insn(i)?.op, Op::Phi) {
                        let n = updates.at_mut(i)?;
                        *n = n.saturating_add(1);
                        if *n > WIDEN_AFTER {
                            new = 64;
                        }
                    }
                    *m.bits.at_mut(i)? = new;
                    changed = true;
                }
            }
        }
        Ok(m)
    }

    pub fn bits(&self, v: Value) -> u8 {
        match v {
            Value::Const(c) => (64 - c.leading_zeros()) as u8,
            Value::Insn(i) => self.bits.get(i).copied().unwrap_or(64),
            _ => 64,
        }
    }

    pub fn non_negative(&self, v: Value) -> bool {
        self.bits(v) <= 63
    }

    fn transfer(&self, f: &Function<'_>, i: InsnId) -> Result<u8> {
        let d = f.insn(i)?;
        let b = |k: usize| f.operand(i, k).map(|v| self.bits(v));
        let shift_amount = |k: usize| f.operand(i, k).ok().and_then(Value::as_const);
        Ok(match d.op {
            Op::Bin { op, w } => {
                let (x, y) = (b(0)?, b(1)?);
                let r: u32 = match op {
                    BinOp::And => x.min(y) as u32,
                    BinOp::Or | BinOp::Xor => x.max(y) as u32,
                    BinOp::Add => x.max(y) as u32 + 1,
                    BinOp::Mul => x as u32 + y as u32,
                    BinOp::UDiv => x as u32,
                    BinOp::UMod => x.min(y) as u32,
                    BinOp::Shl => match shift_amount(1) {
                        Some(s) => x as u32 + (s & (w.bits() as u64 - 1)) as u32,
                        None => 64,
                    },
                    BinOp::LShr => match shift_amount(1) {
                        Some(s) => (x as u32).saturating_sub((s & (w.bits() as u64 - 1)) as u32),
                        None => x as u32,
                    },
                    BinOp::AShr if x <= 63 && w == Width::W64 => x as u32,
                    _ => 64,
                };
                let cap = if w == Width::W32 { 32 } else { 64 };
                r.min(cap) as u8
            }
            Op::Neg { w: Width::W32 } => 32,
            Op::Ext { from, signed: false, w } => {
                let cap = if w == Width::W32 { 32 } else { 64 };
                b(0)?.min(from).min(cap)
            }
            Op::Ext { from, signed: true, w } => {
                let x = b(0)?;
                let cap = if w == Width::W32 { 32 } else { 64 };
                if x < from {
                    x
                } else {
                    cap
                }
            }
            Op::Bswap { bits, .. } => bits,
            Op::Load { size, signed: false, .. } if size.bytes() < 8 => (size.bits()) as u8,
            Op::Opaque(o) => {
                let raw = crate::bpf::BpfInsn::from_u64(o.raw);
                match raw.class() {
                    crate::bpf::class::LD => 32,
                    crate::bpf::class::STX if raw.size() == crate::bpf::size::W => 32,
                    _ => 64,
                }
            }
            Op::Phi => {
                let mut acc = 0u8;
                for (v, _) in f.phi_inputs(i) {
                    if v != Value::Undef && v != Value::Insn(i) {
                        acc = acc.max(self.bits(v));
                    }
                }
                acc.min(self.iv.get(i).copied().unwrap_or(64))
            }
            _ => 64,
        })
    }
}

/// Signed range of a counted-loop induction variable.
///
/// Recognizes `p = phi(c0, n)` in a block `h`, where `n = p + s` (64-bit,
/// `s` constant) and the back edge carrying `n` is reached only through
/// the "not equal" edge of a 64-bit `g == e` / `g != e` test, with `g`
/// being `p` or `n` and `e` constant. Within one iteration `p` is fixed,
/// so the tested `n` is the one that flows back. If `e - c0` is an exact
/// positive multiple `k` of `s` (as integers), `p` walks from `c0` toward
/// `e` without wrapping and stops at `e` (`g = p`, `k >= 0`) or one step
/// before it (`g = n`, `k >= 1`).
fn iv_range(f: &Function<'_>, dom: &DomTree<'_>, p: InsnId) -> Result<Option<(i64, i64)>> {
    let h = f.insn(p)?.block();
    let mut init = None;
    let mut back = None;
    let mut count = 0;
    for (v, from) in f.phi_inputs(p) {
        count += 1;
        match v {
            Value::Const(c) => init = Some(c as i64),
            Value::Insn(n) => back = Some((n, from)),
            _ => return Ok(None),
        }
    }
    let (Some(c0), Some((n, latch)), 2) = (init, back, count) else {
        return Ok(None);
    };
    let s = match f.op(n)? {
        Op::Bin { op: BinOp::Add, w: Width::W64 } => match (f.operand(n, 0)?, f.operand(n, 1)?) {
            (Value::Insn(x), Value::Const(c)) | (Value::Const(c), Value::Insn(x)) if x == p => c as i64,
            _ => return Ok(None),
        },
        Op::Bin { op: BinOp::Sub, w: Width::W64 } => match (f.operand(n, 0)?, f.operand(n, 1)?) {
            (Value::Insn(x), Value::Const(c)) if x == p => (c as i64).wrapping_neg(),
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    if s == 0 {
        return Ok(None);
    }
    // The guard edge `g -> q` must dominate the back edge: either it is the
    // back edge itself, or `q` is entered only from `g` and dominates the
    // latch. Candidates for `q` are the latch's dominators below `h`.
    let guard = |g: BlockId, q: BlockId| -> Result<Option<(InsnId, i64)>> {
        let Some(t) = f.terminator(g)? else { return Ok(None) };
        let Op::CondBr { cond, w: Width::W64, t: bt, f: bf } = f.op(t)? else {
            return Ok(None);
        };
        let ne = match cond {
            Cond::Eq => bf,
            Cond::Ne => bt,
            _ => return Ok(None),
        };
        if bt == bf || ne != q {
            return Ok(None);
        }
        Ok(match (f.operand(t, 0)?, f.operand(t, 1)?) {
            (Value::Insn(x), Value::Const(e)) | (Value::Const(e), Value::Insn(x)) if x == p || x == n => {
                Some((x, e as i64))
            }
            _ => None,
        })
    };
    let mut found = guard(latch, h)?;
    let mut q = latch;
    let mut steps = 0u32;
    while found.is_none() && q != h && steps < 256 {
        steps += 1;
        if let [g] = f.preds(q)? {
            found = guard(*g, q)?;
        }
        match dom.idom(q) {
            Some(d) if d != q => q = d,
            _ => break,
        }
    }
    let Some((x, e)) = found else { return Ok(None) };
    // Exact integer arithmetic without i128 (the kernel has no 128-bit
    // division): give up whenever an i64 step would overflow.
    let (k_min, last) = if x == p { (0, Some(e)) } else { (1, e.checked_sub(s)) };
    let (Some(last), Some(span)) = (last, e.checked_sub(c0)) else {
        return Ok(None);
    };
    match (span.checked_rem(s), span.checked_div(s)) {
        (Some(0), Some(k)) if k >= k_min => Ok(Some((c0.min(last), c0.max(last)))),
        _ => Ok(None),
    }
}

// ------------------------------------------------------------ value class

/// Coarse value classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Unseen,
    Scalar,
    Ctx,
    Stack,
    Map,
    MapValue,
    Mem,
    /// A pointer of unknown kind, or possibly a pointer.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassFact {
    pub class: Class,
    pub nullable: bool,
}

impl ClassFact {
    const UNSEEN: ClassFact = ClassFact {
        class: Class::Unseen,
        nullable: false,
    };
    const SCALAR: ClassFact = ClassFact {
        class: Class::Scalar,
        nullable: false,
    };
    fn ptr(class: Class) -> ClassFact {
        ClassFact {
            class,
            nullable: false,
        }
    }
    fn join(self, o: ClassFact) -> ClassFact {
        match (self.class, o.class) {
            (Class::Unseen, _) => o,
            (_, Class::Unseen) => self,
            (a, b) if a == b => ClassFact {
                class: a,
                nullable: self.nullable || o.nullable,
            },
            _ => ClassFact {
                class: Class::Unknown,
                nullable: true,
            },
        }
    }
    pub fn is_pointer(self) -> bool {
        !matches!(self.class, Class::Scalar | Class::Unseen)
    }
}

/// Value class of every instruction result. `ret_class` maps a call to its
/// return class (from the host facts).
#[derive(Debug)]
pub struct Classes<'h> {
    facts: IdxVec<'h, InsnId, ClassFact>,
}

impl<'h> Classes<'h> {
    pub fn compute(
        f: &Function<'h>,
        cfg: &Cfg<'h>,
        ctx: &Ctx<'_>,
        ret_class: &dyn Fn(&Op) -> RetClass,
    ) -> Result<Self> {
        let mut c = Classes {
            facts: IdxVec::filled(f.heap(), f.insn_id_bound(), ClassFact::UNSEEN)?,
        };
        let mut changed = true;
        while changed {
            changed = false;
            for &b in cfg.rpo() {
                for i in f.iter_block(b) {
                    ctx.tick()?;
                    let new = c.transfer(f, i, ret_class)?;
                    let cur = c.facts.at_mut(i)?;
                    if *cur != new {
                        *cur = new;
                        changed = true;
                    }
                }
            }
        }
        Ok(c)
    }

    pub fn of(&self, v: Value) -> ClassFact {
        match v {
            Value::Insn(i) => self.facts.get(i).copied().unwrap_or(ClassFact {
                class: Class::Unknown,
                nullable: true,
            }),
            Value::Param(1) => ClassFact::ptr(Class::Ctx),
            Value::FramePtr => ClassFact::ptr(Class::Stack),
            _ => ClassFact::SCALAR,
        }
    }

    fn transfer(&self, f: &Function<'_>, i: InsnId, ret_class: &dyn Fn(&Op) -> RetClass) -> Result<ClassFact> {
        let d = f.insn(i)?;
        Ok(match d.op {
            Op::Bin { op, w } => {
                let x = self.of(f.operand(i, 0)?);
                let y = self.of(f.operand(i, 1)?);
                if x.class == Class::Unseen || y.class == Class::Unseen {
                    ClassFact::UNSEEN
                } else if w == Width::W32 {
                    ClassFact::SCALAR
                } else {
                    match (x.is_pointer(), y.is_pointer(), op) {
                        (false, false, _) => ClassFact::SCALAR,
                        (true, false, BinOp::Add | BinOp::Sub) => x,
                        (false, true, BinOp::Add) => y,
                        (true, true, BinOp::Sub) => ClassFact::SCALAR,
                        _ => ClassFact {
                            class: Class::Unknown,
                            nullable: true,
                        },
                    }
                }
            }
            Op::Neg { .. } | Op::Ext { .. } | Op::Bswap { .. } => ClassFact::SCALAR,
            Op::LdSym { kind, .. } => match kind {
                crate::ir::SymKind::MapFd | crate::ir::SymKind::MapIdx => ClassFact::ptr(Class::Map),
                crate::ir::SymKind::MapValueFd | crate::ir::SymKind::MapValueIdx => {
                    ClassFact::ptr(Class::MapValue)
                }
                _ => ClassFact {
                    class: Class::Unknown,
                    nullable: false,
                },
            },
            Op::SlotAddr { .. } => ClassFact::ptr(Class::Stack),
            // A load can yield a pointer (e.g. skb->data from the context).
            Op::Load { .. } | Op::SlotLoad { .. } | Op::Opaque(_) => ClassFact {
                class: Class::Unknown,
                nullable: true,
            },
            Op::Call { .. } | Op::Ecall { .. } => match ret_class(&d.op) {
                RetClass::Scalar => ClassFact::SCALAR,
                RetClass::MapValueOrNull => ClassFact {
                    class: Class::MapValue,
                    nullable: true,
                },
                RetClass::MemOrNull => ClassFact {
                    class: Class::Mem,
                    nullable: true,
                },
                RetClass::Ptr => ClassFact {
                    class: Class::Unknown,
                    nullable: true,
                },
            },
            Op::Phi => {
                let mut acc = ClassFact::UNSEEN;
                for (v, _) in f.phi_inputs(i) {
                    acc = acc.join(self.of(v));
                }
                acc
            }
            _ => ClassFact::SCALAR,
        })
    }
}

// ------------------------------------------------------ known zero-extend

/// Which values are known to have their upper 32 bits zero.
#[derive(Debug)]
pub struct UpperZero<'h> {
    facts: IdxVec<'h, InsnId, bool>,
}

impl<'h> UpperZero<'h> {
    pub fn compute(f: &Function<'h>, cfg: &Cfg<'h>, ctx: &Ctx<'_>) -> Result<Self> {
        // Optimistic for phis (start true), so loops of zero-extended values
        // are recognized; the iteration only ever lowers facts to false.
        let mut z = UpperZero {
            facts: IdxVec::filled(f.heap(), f.insn_id_bound(), true)?,
        };
        let mut changed = true;
        while changed {
            changed = false;
            for &b in cfg.rpo() {
                for i in f.iter_block(b) {
                    ctx.tick()?;
                    let new = z.transfer(f, i)?;
                    let cur = z.facts.at_mut(i)?;
                    if *cur && !new {
                        *cur = false;
                        changed = true;
                    }
                }
            }
        }
        Ok(z)
    }

    pub fn of(&self, v: Value) -> bool {
        match v {
            Value::Const(c) => c >> 32 == 0,
            Value::Insn(i) => self.facts.get(i).copied().unwrap_or(false),
            _ => false,
        }
    }

    fn transfer(&self, f: &Function<'_>, i: InsnId) -> Result<bool> {
        let d = f.insn(i)?;
        Ok(match d.op {
            Op::Bin { w: Width::W32, .. } | Op::Neg { w: Width::W32 } => true,
            Op::Ext { w: Width::W32, .. } => true,
            Op::Ext { signed: false, from, .. } => from <= 32,
            Op::Bswap { bits, .. } => bits <= 32,
            Op::Load { size, signed: false, .. } => size.bytes() <= 4,
            Op::Opaque(o) => {
                // LD_ABS/IND load at most 4 bytes; 32-bit atomics fetch a
                // zero-extended old value.
                let raw = crate::bpf::BpfInsn::from_u64(o.raw);
                match raw.class() {
                    crate::bpf::class::LD => raw.size() != crate::bpf::size::DW,
                    crate::bpf::class::STX => raw.size() == crate::bpf::size::W,
                    _ => false,
                }
            }
            Op::Phi => f.phi_inputs(i).all(|(v, _)| v == Value::Undef || self.of(v)),
            _ => false,
        })
    }
}
