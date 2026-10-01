//! `dce`: dead-code elimination.
//!
//! Mark-and-sweep from the roots (terminators and instructions with side
//! effects), so dead phi cycles are removed too; then unreachable blocks are
//! deleted.

use crate::error::Result;
use crate::ir::cleanup::remove_unreachable;
use crate::ir::{Function, InsnId, Value};
use crate::mem::{FVec, IdxVec};
use crate::pm::{no_args, PassCx, PassInfo, Phase};

pub const INFO: PassInfo = PassInfo {
    name: "dce",
    phase: Phase::Optimize,
    after: &["const_prop", "phi", "zext_elim"],
    before: &[],
    default_on: true,
    user_controllable: true,
    mandatory: false,
    check_args: no_args,
    run,
};

fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    run_on(f, cx).map(|_| ())
}

pub fn run_on<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>) -> Result<bool> {
    let mut changed = remove_unreachable(f, cx.ctx)?;
    let heap = f.heap();
    let mut live: IdxVec<'h, InsnId, bool> = IdxVec::filled(heap, f.insn_id_bound(), false)?;
    let mut work: FVec<'h, InsnId> = FVec::new(heap);
    for b in f.blocks() {
        for i in f.iter_block(b) {
            if !f.op(i)?.is_pure() {
                *live.at_mut(i)? = true;
                work.push(i)?;
            }
        }
    }
    while let Some(i) = work.pop() {
        cx.ctx.tick()?;
        for v in f.operands(i) {
            if let Value::Insn(d) = v {
                if !*live.at(d)? {
                    *live.at_mut(d)? = true;
                    work.push(d)?;
                }
            }
        }
    }
    let mut dead: FVec<'h, InsnId> = FVec::new(heap);
    for b in f.blocks() {
        for i in f.iter_block(b) {
            if !*live.at(i)? {
                dead.push(i)?;
            }
        }
    }
    // Break use links among dead instructions, then delete them.
    for &i in dead.iter() {
        for k in 0..f.operand_count(i)? {
            f.set_operand(i, k, Value::Undef)?;
        }
    }
    for &i in dead.iter() {
        f.remove(i)?;
        changed = true;
    }
    Ok(changed)
}
