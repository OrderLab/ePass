//! The `.epir` v2 text printer. Output is canonical: blocks are numbered in
//! print order (entry first, then creation order) and instructions are
//! numbered in print order, so `print(parse(print(f))) == print(f)`.

use core::fmt::{self, Write};

use super::{
    BlockId, BuiltinKind, Callee, Function, InsnId, Op, Size, SwapKind, Value, Width,
};
use crate::error::{Error, Result};
use crate::mem::{FVec, Idx, IdxVec};

const NONE: u32 = u32::MAX;

/// Print-order numbering of blocks and instructions.
pub struct Names<'h> {
    blocks: IdxVec<'h, BlockId, u32>,
    insns: IdxVec<'h, InsnId, u32>,
    order: FVec<'h, BlockId>,
}

impl fmt::Debug for Names<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Names").field("order", &self.order).finish()
    }
}

impl<'h> Names<'h> {
    pub fn new(f: &Function<'h>) -> Result<Self> {
        let heap = f.heap();
        let mut blocks = IdxVec::filled(heap, f.block_id_bound(), NONE)?;
        let mut insns = IdxVec::filled(heap, f.insn_id_bound(), NONE)?;
        let mut order = FVec::new(heap);
        order.push(f.entry())?;
        for b in f.blocks() {
            if b != f.entry() {
                order.push(b)?;
            }
        }
        let mut n = 0u32;
        for (k, &b) in order.iter().enumerate() {
            *blocks.at_mut(b)? = k as u32;
            for i in f.iter_block(b) {
                if f.insn(i)?.op.has_result() {
                    *insns.at_mut(i)? = n;
                    n += 1;
                }
            }
        }
        Ok(Names {
            blocks,
            insns,
            order,
        })
    }

    pub fn block(&self, b: BlockId) -> u32 {
        self.blocks.get(b).copied().unwrap_or(NONE)
    }

    pub fn insn(&self, i: InsnId) -> u32 {
        self.insns.get(i).copied().unwrap_or(NONE)
    }

    /// Blocks in print order.
    pub fn order(&self) -> &[BlockId] {
        self.order.as_slice()
    }
}

/// Format a constant: small values as signed decimal, others as hex.
pub fn fmt_const(w: &mut dyn Write, c: u64) -> fmt::Result {
    let s = c as i64;
    if (-65536..=65536).contains(&s) {
        write!(w, "{s}")
    } else {
        write!(w, "{c:#x}")
    }
}

fn width(w: Width) -> &'static str {
    match w {
        Width::W32 => "32",
        Width::W64 => "64",
    }
}

fn size_name(s: Size, signed: bool) -> &'static str {
    match (s, signed) {
        (Size::B1, false) => "u8",
        (Size::B2, false) => "u16",
        (Size::B4, false) => "u32",
        (Size::B8, false) => "u64",
        (Size::B1, true) => "s8",
        (Size::B2, true) => "s16",
        (Size::B4, true) => "s32",
        (Size::B8, true) => "s64",
    }
}

pub fn builtin_name(k: BuiltinKind) -> &'static str {
    match k {
        BuiltinKind::BbInsnCount => "builtin.bb_insn_cnt",
        BuiltinKind::BbInsnCriticalCount => "builtin.bb_insn_critical_cnt",
    }
}

pub fn fmt_value(w: &mut dyn Write, n: &Names<'_>, v: Value) -> fmt::Result {
    match v {
        Value::Insn(i) => write!(w, "%{}", n.insn(i)),
        Value::Const(c) => fmt_const(w, c),
        Value::Param(k) => write!(w, "%arg{k}"),
        Value::FramePtr => w.write_str("%fp"),
        Value::Undef => w.write_str("undef"),
        Value::Builtin(k) => w.write_str(builtin_name(k)),
    }
}

fn fmt_addr(w: &mut dyn Write, n: &Names<'_>, base: Value, off: i16) -> fmt::Result {
    w.write_char('[')?;
    fmt_value(w, n, base)?;
    write!(w, "{off:+}]")
}

/// Print one instruction (without indentation or newline).
pub fn fmt_insn(w: &mut dyn Write, f: &Function<'_>, n: &Names<'_>, i: InsnId) -> fmt::Result {
    let Ok(d) = f.insn(i) else {
        return w.write_str("<dead>");
    };
    let op = d.op;
    if op.has_result() {
        write!(w, "%{} = ", n.insn(i))?;
    }
    let ops = |k: usize| f.operand(i, k).unwrap_or(Value::Undef);
    let list = |w: &mut dyn Write| -> fmt::Result {
        w.write_char('(')?;
        for (k, v) in f.operands(i).enumerate() {
            if k > 0 {
                w.write_str(", ")?;
            }
            fmt_value(w, n, v)?;
        }
        w.write_char(')')
    };
    match op {
        Op::Bin { op, w: wd } => {
            write!(w, "{}.{} ", op.name(), width(wd))?;
            fmt_value(w, n, ops(0))?;
            w.write_str(", ")?;
            fmt_value(w, n, ops(1))
        }
        Op::Neg { w: wd } => {
            write!(w, "neg.{} ", width(wd))?;
            fmt_value(w, n, ops(0))
        }
        Op::Ext { from, signed, w: wd } => {
            let k = if signed { "sext" } else { "zext" };
            write!(w, "{k}.{from}.{} ", width(wd))?;
            fmt_value(w, n, ops(0))
        }
        Op::Bswap { bits, kind } => {
            let k = match kind {
                SwapKind::ToLe => "le",
                SwapKind::ToBe => "be",
                SwapKind::Swap => "swap",
            };
            write!(w, "bswap.{k}.{bits} ")?;
            fmt_value(w, n, ops(0))
        }
        Op::Load { size, signed, off } => {
            write!(w, "load.{} ", size_name(size, signed))?;
            fmt_addr(w, n, ops(0), off)
        }
        Op::Store { size, off } => {
            write!(w, "store.{} ", size_name(size, false))?;
            fmt_addr(w, n, ops(0), off)?;
            w.write_str(", ")?;
            fmt_value(w, n, ops(1))
        }
        Op::LdSym { kind, imm } => {
            write!(w, "ldsym.{} ", kind.name())?;
            fmt_const(w, imm)
        }
        Op::SlotAddr { slot, off } => write!(w, "slotaddr ${}{:+}", slot.to_u32(), off),
        Op::SlotLoad { slot } => write!(w, "slotload ${}", slot.to_u32()),
        Op::SlotStore { slot } => {
            write!(w, "slotstore ${}, ", slot.to_u32())?;
            fmt_value(w, n, ops(0))
        }
        Op::Call {
            callee,
            unknown_arity,
        } => {
            w.write_str(if unknown_arity { "call.unknown " } else { "call " })?;
            match callee {
                Callee::Helper(id) => write!(w, "helper#{id}")?,
                Callee::Kfunc { btf_id, fd_idx } => write!(w, "kfunc#{btf_id}:{fd_idx}")?,
                Callee::Local(fid) => write!(w, "local#{}", fid.to_u32())?,
            }
            list(w)
        }
        Op::Ecall { id } => {
            write!(w, "ecall#{id}")?;
            list(w)
        }
        Op::Opaque(o) => {
            write!(w, "opaque {:#018x}", o.raw)?;
            list(w)
        }
        Op::Phi => {
            w.write_str("phi ")?;
            for (k, (v, b)) in f.phi_inputs(i).enumerate() {
                if k > 0 {
                    w.write_str(", ")?;
                }
                w.write_char('[')?;
                fmt_value(w, n, v)?;
                write!(w, ", bb{}]", n.block(b))?;
            }
            Ok(())
        }
        Op::Br { target } => write!(w, "br bb{}", n.block(target)),
        Op::CondBr { cond, w: wd, t, f: fb } => {
            write!(w, "condbr.{}.{} ", width(wd), cond.name())?;
            fmt_value(w, n, ops(0))?;
            w.write_str(", ")?;
            fmt_value(w, n, ops(1))?;
            write!(w, ", bb{}, bb{}", n.block(t), n.block(fb))
        }
        Op::Ret => {
            w.write_str("ret ")?;
            fmt_value(w, n, ops(0))
        }
        Op::Throw => w.write_str("throw"),
        Op::Poison { imm } => write!(w, "poison {imm}"),
    }
}

/// Print a whole function.
pub fn print(w: &mut dyn Write, f: &Function<'_>) -> Result<()> {
    let names = Names::new(f)?;
    let e = |_| Error::internal("format error");
    w.write_str("; epir v2\nfunc main {\n").map_err(e)?;
    for (s, slot) in f.slots() {
        write!(w, "  slot ${} size={} align={}", s.to_u32(), slot.size, slot.align).map_err(e)?;
        if slot.may_hold_ptr {
            w.write_str(" ptr").map_err(e)?;
        }
        w.write_char('\n').map_err(e)?;
    }
    for &b in names.order() {
        write!(w, "bb{}:", names.block(b)).map_err(e)?;
        let preds = f.preds(b)?;
        if !preds.is_empty() {
            w.write_str(" ; preds").map_err(e)?;
            for &p in preds {
                write!(w, " bb{}", names.block(p)).map_err(e)?;
            }
        }
        w.write_char('\n').map_err(e)?;
        for i in f.iter_block(b) {
            w.write_str("  ").map_err(e)?;
            fmt_insn(w, f, &names, i).map_err(e)?;
            w.write_char('\n').map_err(e)?;
        }
    }
    w.write_str("}\n").map_err(e)?;
    Ok(())
}
