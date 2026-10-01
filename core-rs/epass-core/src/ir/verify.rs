//! The IR validator.
//!
//! Because the kernel accepts IR from userspace, this is a security boundary:
//! it must reject any malformed function with an error, never panic, and run
//! in time linear in the function size (plus the dominator computation). It
//! runs after loading, after lifting, before codegen, and after every pass in
//! debug builds.

use super::{BlockId, Callee, Function, InsnId, Op, OpaqueInsn, Value};
use crate::analysis::{Cfg, DomTree};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::mem::{FVec, Idx, IdxVec};

/// Largest eBPF stack frame.
pub const MAX_FRAME: u32 = 512;

fn bad(msg: &'static str, at: InsnId) -> Error {
    Error::invalid_ir(msg).at(at.to_u32())
}

fn bad_block(msg: &'static str, b: BlockId) -> Error {
    Error::invalid_ir(msg).at(b.to_u32())
}

/// Derive the register signature of an instruction that ePass passes
/// through as [`Op::Opaque`]: atomics and LD_ABS/IND. Returns `None` for any
/// other instruction.
pub fn opaque_signature(raw: u64) -> Option<OpaqueInsn> {
    let code = raw as u8;
    let dst = ((raw >> 8) & 0xf) as u8;
    let src = ((raw >> 12) & 0xf) as u8;
    let imm = (raw >> 32) as u32 as i32;
    if dst > 10 || src > 10 {
        return None;
    }
    const R1_R5: u16 = 0b11_1110;
    let bit = |r: u8| 1u16 << r;
    match code {
        // LD | ABS | {W,H,B}
        0x20 | 0x28 | 0x30 => Some(OpaqueInsn {
            raw,
            def: Some(0),
            uses: bit(6),
            clobbers: R1_R5,
        }),
        // LD | IND | {W,H,B}
        0x40 | 0x48 | 0x50 => Some(OpaqueInsn {
            raw,
            def: Some(0),
            uses: bit(6) | bit(src),
            clobbers: R1_R5,
        }),
        // STX | ATOMIC | {W,DW}
        0xc3 | 0xdb => {
            let fetch = imm & 0x01 != 0;
            let (def, uses) = match imm & !0x01 {
                0x00 | 0x40 | 0x50 | 0xa0 => {
                    (if fetch { Some(src) } else { None }, bit(dst) | bit(src))
                }
                0xe0 if fetch => (Some(src), bit(dst) | bit(src)),
                0xf0 if fetch => (Some(0), bit(dst) | bit(src) | bit(0)),
                _ => return None,
            };
            if def == Some(10) {
                return None;
            }
            Some(OpaqueInsn {
                raw,
                def,
                uses,
                clobbers: 0,
            })
        }
        _ => None,
    }
}

/// Validate a function. `allow_ecall` comes from the policy.
pub fn verify(f: &Function<'_>, ctx: &Ctx<'_>, allow_ecall: bool) -> Result<()> {
    let heap = f.heap();
    if f.insn_count() > ctx.limits.max_insns as usize {
        return Err(Error::limit("too many IR instructions"));
    }
    let entry = f.entry();
    if !f.is_block(entry) {
        return Err(Error::invalid_ir("entry block missing"));
    }
    if !f.preds(entry)?.is_empty() {
        return Err(bad_block("entry block has predecessors", entry));
    }

    // Ordinal of each instruction within its block, for same-block dominance.
    let mut ord: IdxVec<'_, InsnId, u32> = IdxVec::filled(heap, f.insn_id_bound(), u32::MAX)?;
    // Recomputed predecessor counts, to check stored predecessor lists.
    let mut pred_seen: IdxVec<'_, BlockId, u32> = IdxVec::filled(heap, f.block_id_bound(), 0)?;

    for b in f.blocks() {
        ctx.tick()?;
        let mut n = 0u32;
        let mut seen_non_phi = false;
        let mut prev: Option<InsnId> = None;
        let last = f.block(b)?.last();
        if last.is_none() {
            return Err(bad_block("empty block", b));
        }
        for i in f.iter_block(b) {
            ctx.tick()?;
            let d = f.insn(i)?;
            if d.block() != b || f.prev(i)? != prev {
                return Err(bad("corrupt instruction list", i));
            }
            prev = Some(i);
            *ord.at_mut(i)? = n;
            n = n.saturating_add(1);
            if n > ctx.limits.max_insns {
                return Err(Error::limit("block too long"));
            }
            if matches!(d.op, Op::Phi) {
                if seen_non_phi {
                    return Err(bad("phi after a non-phi instruction", i));
                }
            } else {
                seen_non_phi = true;
            }
            if d.op.is_terminator() && Some(i) != last {
                return Err(bad("terminator in the middle of a block", i));
            }
            check_shape(f, i, allow_ecall)?;
        }
        let term = f
            .terminator(b)?
            .ok_or(bad_block("block does not end in a terminator", b))?;
        for &s in f.insn(term)?.op.successors().as_slice() {
            if !f.is_block(s) {
                return Err(bad("branch to unknown block", term));
            }
            if s == entry {
                return Err(bad("branch to the entry block", term));
            }
            if !f.preds(s)?.contains(&b) {
                return Err(bad("predecessor list out of date", term));
            }
            let c = pred_seen.at_mut(s)?;
            *c = c.saturating_add(1);
        }
    }
    for b in f.blocks() {
        let preds = f.preds(b)?;
        if preds.len() as u32 != *pred_seen.at(b)? {
            return Err(bad_block("predecessor list has stale entries", b));
        }
        for &p in preds {
            if !f.is_block(p) {
                return Err(bad_block("predecessor is not a block", b));
            }
        }
    }

    // Phi inputs match predecessors exactly.
    for b in f.blocks() {
        let preds = f.preds(b)?;
        for i in f.iter_block(b) {
            if !matches!(f.insn(i)?.op, Op::Phi) {
                break;
            }
            ctx.tick()?;
            let mut count = 0usize;
            for (_, ib) in f.phi_inputs(i) {
                count += 1;
                if !preds.contains(&ib) {
                    return Err(bad("phi input from a non-predecessor", i));
                }
            }
            if count != f.operand_count(i)? || count != preds.len() {
                return Err(bad("phi inputs do not match predecessors", i));
            }
            // Duplicates: with count == preds.len() and every input a pred,
            // any duplicate implies a missing pred.
            let mut tmp: FVec<'_, BlockId> = FVec::new(heap);
            for (_, ib) in f.phi_inputs(i) {
                if !tmp.push_unique(ib)? {
                    return Err(bad("duplicate phi input", i));
                }
            }
        }
    }

    // SSA: definitions dominate uses (reachable blocks only).
    let cfg = Cfg::compute(f, ctx)?;
    let dom = DomTree::compute(f, &cfg, ctx)?;
    for &b in cfg.rpo() {
        for i in f.iter_block(b) {
            ctx.tick()?;
            let is_phi = matches!(f.insn(i)?.op, Op::Phi);
            for (k, v) in f.operands(i).enumerate() {
                let Value::Insn(def) = v else { continue };
                let db = f.insn(def)?.block();
                if !cfg.is_reachable(db) {
                    return Err(bad("use of an unreachable definition", i));
                }
                if is_phi {
                    let o = f.operand_ids(i)?.nth(k).ok_or(bad("phi operand", i))?;
                    let ib = f.opnd(o)?.block.ok_or(bad("phi operand without block", i))?;
                    if cfg.is_reachable(ib) && !dom.dominates(db, ib) {
                        return Err(bad("phi input not dominated by its definition", i));
                    }
                } else if db == b {
                    if *ord.at(def)? >= *ord.at(i)? {
                        return Err(bad("use before definition", i));
                    }
                } else if !dom.dominates(db, b) {
                    return Err(bad("use not dominated by its definition", i));
                }
            }
        }
    }

    // Frame slots fit the eBPF stack.
    let mut total: u32 = 0;
    for (_, s) in f.slots() {
        if s.size == 0 || s.size > MAX_FRAME || !s.align.is_power_of_two() || s.align > 8 {
            return Err(Error::invalid_ir("bad frame slot"));
        }
        if s.may_hold_ptr && (s.size != 8 || s.align != 8) {
            return Err(Error::invalid_ir("pointer slot must be 8 bytes, 8-aligned"));
        }
        total = total
            .checked_add(s.size.next_multiple_of(s.align.max(1)))
            .ok_or(Error::invalid_ir("frame too large"))?;
        if total > MAX_FRAME {
            return Err(Error::invalid_ir("frame slots exceed 512 bytes"));
        }
    }
    Ok(())
}

/// Per-opcode operand shape checks.
fn check_shape(f: &Function<'_>, i: InsnId, allow_ecall: bool) -> Result<()> {
    let op = f.insn(i)?.op;
    let n = f.operand_count(i)?;
    let want = |k: usize| -> Result<()> {
        if n == k {
            Ok(())
        } else {
            Err(bad("wrong operand count", i))
        }
    };
    match op {
        Op::Bin { .. } | Op::Store { .. } | Op::CondBr { .. } => want(2)?,
        Op::Neg { .. } | Op::Load { .. } | Op::Ret | Op::SlotStore { .. } => want(1)?,
        Op::Ext { from, w, .. } => {
            want(1)?;
            let _ = w;
            if !matches!(from, 8 | 16 | 32) {
                return Err(bad("bad extension width", i));
            }
        }
        Op::Bswap { bits, .. } => {
            want(1)?;
            if !matches!(bits, 16 | 32 | 64) {
                return Err(bad("bad swap width", i));
            }
        }
        Op::LdSym { .. } | Op::Br { .. } | Op::Throw | Op::Poison { .. } => want(0)?,
        Op::SlotAddr { slot, off } => {
            want(0)?;
            let s = f.slot(slot).map_err(|_| bad("unknown frame slot", i))?;
            if off < 0 || off as u32 > s.size {
                return Err(bad("slot address out of range", i));
            }
        }
        Op::SlotLoad { slot } => {
            want(0)?;
            let s = f.slot(slot).map_err(|_| bad("unknown frame slot", i))?;
            if s.size != 8 {
                return Err(bad("slot load needs an 8-byte slot", i));
            }
        }
        Op::Call { callee, unknown_arity } => {
            if n > 5 || (unknown_arity && n != 5) {
                return Err(bad("bad call argument count", i));
            }
            if let Callee::Local(_) = callee {
                return Err(Error::unsupported("bpf-to-bpf calls").at(i.to_u32()));
            }
        }
        Op::Ecall { .. } => {
            if !allow_ecall {
                return Err(bad("ecall not allowed by policy", i));
            }
            if n > 5 {
                return Err(bad("bad ecall argument count", i));
            }
        }
        Op::Opaque(o) => {
            let sig = opaque_signature(o.raw).ok_or(bad("opaque instruction not passable", i))?;
            if sig != o {
                return Err(bad("opaque register signature does not match", i));
            }
            want(o.uses.count_ones() as usize)?;
        }
        Op::Phi => {}
    }
    // Operand value kinds.
    let undef_ok = matches!(op, Op::Phi | Op::Call { .. } | Op::Ecall { .. });
    for v in f.operands(i) {
        match v {
            Value::Insn(def) => {
                let d = f.insn(def).map_err(|_| bad("use of a dead instruction", i))?;
                if !d.op.has_result() {
                    return Err(bad("use of an instruction without a result", i));
                }
                if def == i && !matches!(op, Op::Phi) {
                    return Err(bad("instruction uses itself", i));
                }
            }
            Value::Param(k) if !(1..=5).contains(&k) => {
                return Err(bad("bad parameter register", i));
            }
            Value::Undef if !undef_ok => return Err(bad("undef operand", i)),
            _ => {}
        }
    }
    Ok(())
}
