//! IR validity checker, run after lifting and after each pass (unless disabled).
//!
//! Verifies structural invariants the rest of the pipeline relies on:
//! - conditional jumps have exactly two successors with `bb1` being the
//!   physically-next block in the layout;
//! - `ja` has exactly one successor;
//! - every operand referencing an instruction points to a live instruction;
//! - def-use chains are consistent.

use std::collections::HashSet;

use crate::env::Env;
use crate::error::Result;
use crate::internal;
use crate::ir::{Function, InsnKind, Value};

/// Run the structural checker over a function.
pub fn prog_check(env: &Env, func: &Function) -> Result<()> {
    if env.opts.disable_prog_check {
        return Ok(());
    }

    // Build the set of live instruction ids for operand validation.
    let mut live: HashSet<u32> = HashSet::new();
    for &bb in &func.reachable_bbs {
        for &id in &func.bb(bb).insns {
            live.insert(id.0);
        }
    }
    live.insert(func.sp.0);
    for a in func.args {
        live.insert(a.0);
    }

    for (layout_idx, &bb) in func.reachable_bbs.iter().enumerate() {
        let block = func.bb(bb);

        // Terminator checks.
        if let Some(last) = block.last() {
            let insn = func.insn(last);
            match &insn.kind {
                InsnKind::CondJmp { .. } => {
                    if block.succs.len() != 2 {
                        return Err(internal!(
                            "conditional jump in bb{} has {} successors (expected 2)",
                            bb.0,
                            block.succs.len()
                        ));
                    }
                    // bb1 (fallthrough) must be the physically next block.
                    let next = func.reachable_bbs.get(layout_idx + 1).copied();
                    if insn.bb1 != next {
                        return Err(internal!(
                            "conditional jump fallthrough bb1 is not the next block in bb{}",
                            bb.0
                        ));
                    }
                }
                InsnKind::Ja => {
                    if block.succs.len() != 1 {
                        return Err(internal!(
                            "ja in bb{} has {} successors (expected 1)",
                            bb.0,
                            block.succs.len()
                        ));
                    }
                }
                _ => {}
            }
        }

        // Operand liveness + def-use consistency.
        for &id in &block.insns {
            let insn = func.insn(id);
            for v in insn.operand_values() {
                if let Value::Insn(def) = v {
                    if !live.contains(&def.0) {
                        return Err(internal!(
                            "instruction %{} uses a dead/unknown def %{}",
                            id.0,
                            def.0
                        ));
                    }
                    // The def must list `id` as a user.
                    if !func.insn(def).users.contains(&id) {
                        return Err(internal!(
                            "broken def-use: %{} uses %{} but is not in its user list",
                            id.0,
                            def.0
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
