//! `lower_throw` (mandatory, Finalize): a `throw` becomes `ret <code>`
//! (gopt `throw_ret`, default 0) after discarding every ringbuf reservation
//! that is still outstanding on all paths to it. The verifier rejects
//! programs that exit holding a reference, so the release is required.
//!
//! The reservation analysis is the must-analysis of the C core's
//! `translate_throw_df`: IN(b) = ∩ OUT(preds), OUT(b) = (IN(b) ∪ GEN(b)) −
//! KILL(b), where GEN are `bpf_ringbuf_reserve` calls and KILL the
//! reservations passed directly to `bpf_ringbuf_submit`/`_discard`.

use crate::analysis::Cfg;
use crate::error::{Error, Result};
use crate::ir::func::At;
use crate::ir::{BlockId, Callee, Function, InsnId, Op, Value};
use crate::mem::{BitSet, FVec, IdxVec};
use crate::pm::{no_args, PassCx, PassInfo, Phase};

pub const INFO: PassInfo = PassInfo {
    name: "lower_throw",
    phase: Phase::Finalize,
    after: &[],
    before: &[],
    default_on: true,
    user_controllable: false,
    mandatory: true,
    check_args: no_args,
    run,
};

const RINGBUF_RESERVE: i32 = 131;
const RINGBUF_SUBMIT: i32 = 132;
const RINGBUF_DISCARD: i32 = 133;

fn helper(op: Op) -> Option<i32> {
    match op {
        Op::Call {
            callee: Callee::Helper(id),
            ..
        } => Some(id),
        _ => None,
    }
}

fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    let heap = f.heap();
    let mut throws: FVec<'h, InsnId> = FVec::new(heap);
    let mut reserves: FVec<'h, InsnId> = FVec::new(heap);
    for b in f.blocks() {
        for i in f.iter_block(b) {
            match f.op(i)? {
                Op::Throw => throws.push(i)?,
                op if helper(op) == Some(RINGBUF_RESERVE) => reserves.push(i)?,
                _ => {}
            }
        }
    }
    if throws.is_empty() {
        return Ok(());
    }
    let ret = Value::Const(cx.opts.throw_ret as i64 as u64);
    if reserves.is_empty() {
        for &t in throws.iter() {
            f.set_terminator_with(t, Op::Ret, &[ret])?;
        }
        return Ok(());
    }
    // Reservation index of each reserve call.
    let mut rindex: IdxVec<'h, InsnId, u32> = IdxVec::filled(heap, f.insn_id_bound(), u32::MAX)?;
    for (k, &r) in reserves.iter().enumerate() {
        *rindex.at_mut(r)? = k as u32;
    }
    let n = reserves.len();
    let nb = f.block_id_bound();
    let mut gen: IdxVec<'h, BlockId, BitSet<'h>> = IdxVec::new(heap);
    let mut kill: IdxVec<'h, BlockId, BitSet<'h>> = IdxVec::new(heap);
    let mut out: IdxVec<'h, BlockId, BitSet<'h>> = IdxVec::new(heap);
    for _ in 0..nb {
        gen.push(BitSet::new(heap, n)?)?;
        kill.push(BitSet::new(heap, n)?)?;
        out.push(BitSet::new(heap, n)?)?;
    }
    for b in f.blocks() {
        for i in f.iter_block(b) {
            let op = f.op(i)?;
            match helper(op) {
                Some(RINGBUF_RESERVE) => {
                    gen.at_mut(b)?.insert(*rindex.at(i)? as usize)?;
                }
                Some(RINGBUF_SUBMIT | RINGBUF_DISCARD) => {
                    let arg = f.operand(i, 0)?;
                    let k = match arg {
                        Value::Insn(d) if *rindex.at(d)? != u32::MAX => *rindex.at(d)?,
                        _ => {
                            return Err(Error::unsupported(
                                "throw with a ringbuf release of an indirect reservation",
                            )
                            .at(i.0))
                        }
                    };
                    kill.at_mut(b)?.insert(k as usize)?;
                }
                _ => {}
            }
        }
    }
    let cfg = Cfg::compute(f, cx.ctx)?;
    // Must-analysis: start OUT at "all" for non-entry blocks.
    for &b in cfg.rpo() {
        if b != f.entry() {
            let o = out.at_mut(b)?;
            for k in 0..n {
                o.insert(k)?;
            }
        }
    }
    let mut inb = BitSet::new(heap, n)?;
    let mut changed = true;
    while changed {
        changed = false;
        for &b in cfg.rpo() {
            cx.ctx.tick()?;
            inb.clear();
            let preds = f.preds(b)?;
            let mut first = true;
            for &p in preds {
                if !cfg.is_reachable(p) {
                    continue;
                }
                if first {
                    inb.copy_from(out.at(p)?)?;
                    first = false;
                } else {
                    inb.intersect_with(out.at(p)?)?;
                }
            }
            // OUT = (IN ∪ GEN) − KILL
            let mut new = BitSet::new(heap, n)?;
            new.copy_from(&inb)?;
            new.union_with(gen.at(b)?)?;
            for k in kill.at(b)?.iter() {
                new.remove(k)?;
            }
            let cur = out.at_mut(b)?;
            let mut same = true;
            for k in 0..n {
                if cur.contains(k) != new.contains(k) {
                    same = false;
                    break;
                }
            }
            if !same {
                cur.copy_from(&new)?;
                changed = true;
            }
        }
    }
    for &t in throws.iter() {
        let b = f.insn(t)?.block();
        let outstanding: FVec<'h, usize> = {
            let mut v = FVec::new(heap);
            for k in out.at(b)?.iter() {
                v.push(k)?;
            }
            v
        };
        for &k in outstanding.iter() {
            let r = *reserves.get(k).ok_or(Error::internal("reservation"))?;
            f.insert(
                At::Before(t),
                Op::Call {
                    callee: Callee::Helper(RINGBUF_DISCARD),
                    unknown_arity: false,
                },
                &[Value::Insn(r), Value::Const(0)],
            )?;
        }
        f.set_terminator_with(t, Op::Ret, &[ret])?;
    }
    Ok(())
}
