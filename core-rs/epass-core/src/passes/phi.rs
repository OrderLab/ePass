//! `phi`: remove trivial phis.
//!
//! A phi whose inputs are all the same value `v` (ignoring self-references
//! and `undef`) is replaced by `v`, provided `v` dominates the phi's block
//! (an `undef` input stands for "any value", so choosing `v` is sound).

use crate::analysis::{Cfg, DomTree};
use crate::error::Result;
use crate::ir::{Function, InsnId, Op, Value};
use crate::mem::FVec;
use crate::pm::{no_args, PassCx, PassInfo, Phase};

pub const INFO: PassInfo = PassInfo {
    name: "phi",
    phase: Phase::Optimize,
    after: &["const_prop"],
    before: &[],
    default_on: true,
    user_controllable: true,
    mandatory: false,
    check_args: no_args,
    run,
};

/// The unique non-self, non-undef input of a phi, if there is one.
fn trivial_value(f: &Function<'_>, phi: InsnId) -> Option<Value> {
    let mut same: Option<Value> = None;
    for (v, _) in f.phi_inputs(phi) {
        if v == Value::Insn(phi) || v == Value::Undef {
            continue;
        }
        match same {
            None => same = Some(v),
            Some(s) if s == v => {}
            Some(_) => return None,
        }
    }
    Some(same.unwrap_or(Value::Undef))
}

fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    run_on(f, cx).map(|_| ())
}

/// Returns whether anything changed.
pub fn run_on<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>) -> Result<bool> {
    let mut any = false;
    loop {
        let cfg = Cfg::compute(f, cx.ctx)?;
        let dom = DomTree::compute(f, &cfg, cx.ctx)?;
        let mut phis: FVec<'h, InsnId> = FVec::new(f.heap());
        for &b in cfg.rpo() {
            for i in f.iter_block(b) {
                if matches!(f.op(i)?, Op::Phi) {
                    phis.push(i)?;
                } else {
                    break;
                }
            }
        }
        let mut changed = false;
        for &phi in phis.iter() {
            cx.ctx.tick()?;
            if !f.is_insn(phi) {
                continue;
            }
            let Some(v) = trivial_value(f, phi) else { continue };
            let pb = f.insn(phi)?.block();
            let ok = match v {
                Value::Insn(d) => {
                    let db = f.insn(d)?.block();
                    db != pb && dom.dominates(db, pb)
                }
                // Replacing with undef is only valid where undef is legal.
                Value::Undef => f
                    .uses(phi)
                    .filter_map(|o| f.opnd(o).ok().map(|o| o.user))
                    .all(|u| matches!(f.op(u), Ok(Op::Phi | Op::Call { .. }))),
                _ => true,
            };
            if !ok {
                continue;
            }
            // Drop self-references first so the phi becomes removable.
            let n = f.operand_count(phi)?;
            for k in 0..n {
                if f.operand(phi, k)? == Value::Insn(phi) {
                    f.set_operand(phi, k, Value::Undef)?;
                }
            }
            f.replace_all_uses(phi, v)?;
            for k in 0..n {
                f.set_operand(phi, k, Value::Undef)?;
            }
            f.remove(phi)?;
            changed = true;
        }
        if !changed {
            return Ok(any);
        }
        any = true;
    }
}
