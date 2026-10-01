//! Value facts derived from the IR (never declared by it):
//! - stack provenance and the original frame extent,
//! - value class (scalar vs. pointer kinds, nullability),
//! - known zero-extension of the upper 32 bits.
//!
//! All three are forward dataflow over SSA values, solved by iterating
//! instructions in reverse postorder until no fact changes (phis are the
//! only instructions whose inputs can come from later blocks).

use crate::analysis::Cfg;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::facts::RetClass;
use crate::ir::{BinOp, Function, InsnId, Op, Value, Width};
use crate::mem::IdxVec;

// ------------------------------------------------------------- provenance

/// Whether a value may point into the frame (r10-relative).
///
/// `Stack(lo)` means "possibly a frame pointer, and if so at offset >= lo".
/// Only the lowest reachable frame address matters for placing ePass slots
/// below the program's frame, so joins keep the minimum and a join with a
/// non-stack value stays `Stack`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackFact {
    /// Not yet computed (optimistic bottom for phis).
    Unseen,
    NotStack,
    Stack(i64),
    /// Possibly a frame pointer at an unbounded offset.
    Unknown,
}

impl StackFact {
    fn join(self, o: StackFact) -> StackFact {
        use StackFact::*;
        match (self, o) {
            (Unseen, x) | (x, Unseen) => x,
            (Unknown, _) | (_, Unknown) => Unknown,
            (NotStack, NotStack) => NotStack,
            (Stack(a), Stack(b)) => Stack(a.min(b)),
            (Stack(a), NotStack) | (NotStack, Stack(a)) => Stack(a),
        }
    }

    fn shift(self, by: i64) -> StackFact {
        match self {
            StackFact::Stack(lo) => match lo.checked_add(by) {
                Some(v) if v >= -(1 << 20) => StackFact::Stack(v),
                _ => StackFact::Unknown,
            },
            x => x,
        }
    }
}

/// Stack provenance of every instruction result.
#[derive(Debug)]
pub struct Provenance<'h> {
    facts: IdxVec<'h, InsnId, StackFact>,
}

/// Phi facts that keep lowering past this many updates are widened to
/// `Unknown` (a loop that decrements a frame pointer).
const WIDEN_AFTER: u8 = 4;

impl<'h> Provenance<'h> {
    pub fn compute(f: &Function<'h>, cfg: &Cfg<'h>, uz: &UpperZero<'h>, ctx: &Ctx<'_>) -> Result<Self> {
        let heap = f.heap();
        let mut p = Provenance {
            facts: IdxVec::filled(heap, f.insn_id_bound(), StackFact::Unseen)?,
        };
        let mut updates: IdxVec<'h, InsnId, u8> = IdxVec::filled(heap, f.insn_id_bound(), 0)?;
        let mut changed = true;
        while changed {
            changed = false;
            for &b in cfg.rpo() {
                for i in f.iter_block(b) {
                    ctx.tick()?;
                    let mut new = p.transfer(f, i, uz)?;
                    let cur = *p.facts.at(i)?;
                    if cur == new {
                        continue;
                    }
                    if matches!(f.insn(i)?.op, Op::Phi) {
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
            }
        }
        Ok(p)
    }

    pub fn of(&self, v: Value) -> StackFact {
        match v {
            Value::FramePtr => StackFact::Stack(0),
            Value::Insn(i) => self.facts.get(i).copied().unwrap_or(StackFact::Unknown),
            _ => StackFact::NotStack,
        }
    }

    fn transfer(&self, f: &Function<'_>, i: InsnId, uz: &UpperZero<'_>) -> Result<StackFact> {
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
                    (Stack(_), Stack(_)) if op == BinOp::Sub => NotStack,
                    (Stack(_), Stack(_)) => Unknown,
                    (Stack(_), NotStack) => match (op, vb.as_const()) {
                        (BinOp::Add, Some(c)) => x.shift(c as i64),
                        (BinOp::Sub, Some(c)) => x.shift((c as i64).wrapping_neg()),
                        // Adding a value below 2^32 can only raise the offset.
                        (BinOp::Add, None) if uz.of(vb) => x,
                        _ => Unknown,
                    },
                    (NotStack, Stack(_)) => match (op, va.as_const()) {
                        (BinOp::Add, Some(c)) => y.shift(c as i64),
                        (BinOp::Add, None) if uz.of(va) => y,
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
            // Loads, calls, symbols, slot reads and opaque results are not
            // frame pointers (frame pointers stored to memory are escapes,
            // handled by `frame_extent`). Slot addresses are ePass's own.
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
        unknown: false,
    };
    let note = |fact: StackFact, off: i64, ext: &mut Extent| match fact {
        StackFact::Stack(c) => ext.lowest = ext.lowest.min(c.saturating_add(off)),
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
                    note(prov.of(f.operand(i, 0)?), off as i64, &mut ext);
                    if prov.of(f.operand(i, 1)?) != StackFact::NotStack {
                        ext.unknown = true; // a frame pointer stored to memory
                    }
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
                        } else if fact != StackFact::NotStack {
                            ext.unknown = true;
                        }
                    }
                }
                Op::SlotStore { .. } | Op::Ret
                    if prov.of(f.operand(i, 0)?) != StackFact::NotStack =>
                {
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
