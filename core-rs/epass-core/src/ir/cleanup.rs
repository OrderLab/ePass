//! CFG cleanup shared by passes.

use super::{Function, Op, Value};
use crate::analysis::Cfg;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::mem::FVec;

/// Delete blocks unreachable from the entry. Returns true if any were removed.
pub fn remove_unreachable(f: &mut Function<'_>, ctx: &Ctx<'_>) -> Result<bool> {
    let cfg = Cfg::compute(f, ctx)?;
    let mut dead: FVec<'_, super::BlockId> = FVec::new(f.heap());
    for b in f.blocks() {
        if !cfg.is_reachable(b) {
            dead.push(b)?;
        }
    }
    if dead.is_empty() {
        return Ok(false);
    }
    // 1. Drop dead blocks' phi inputs in their (live) successors.
    for &b in dead.iter() {
        for &s in f.successors(b)?.as_slice() {
            for i in f.block_insns(s)?.iter() {
                if !matches!(f.op(*i)?, Op::Phi) {
                    break;
                }
                f.remove_phi_input(*i, b)?;
            }
        }
    }
    // 2. Clear every operand in dead blocks so no use links remain.
    for &b in dead.iter() {
        for i in f.block_insns(b)?.iter() {
            ctx.tick()?;
            for k in 0..f.operand_count(*i)? {
                f.set_operand(*i, k, Value::Undef)?;
            }
        }
    }
    // 3. Remove the instructions (terminators drop their edges) and blocks.
    for &b in dead.iter() {
        let insns = f.block_insns(b)?;
        for &i in insns.iter().rev() {
            ctx.tick()?;
            // Uses from live code are impossible (dominance), and uses from
            // dead code were cleared above.
            f.replace_all_uses(i, Value::Undef)?;
            f.remove(i)?;
        }
    }
    for &b in dead.iter() {
        f.remove_block(b)?;
    }
    Ok(true)
}
