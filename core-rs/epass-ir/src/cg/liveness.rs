//! SSA liveness analysis and interference-graph construction.
//!
//! Follows the path-exploration scheme of the Pereira & Palsberg chordal-graph
//! allocator: for each SSA value, walk backwards from each use to the def,
//! marking live-in/out and recording interferences with the live values that
//! are killed along the way.

use std::collections::HashSet;

use crate::bytecode::{BPF_REG_0, BPF_REG_6};
use crate::env::Env;
use crate::error::Result;
use crate::ir::insn::InsnKind;
use crate::ir::{BbId, Function, InsnId};

use super::{CgState, RA_COLORS};

/// Reset per-iteration liveness/interference data.
pub fn clean(func: &Function, cg: &mut CgState) {
    cg.all_var.clear();
    let regs = cg.regs;
    for reg in regs {
        let e = cg.extra_mut(reg);
        e.adj.clear();
        e.live_in.clear();
        e.live_out.clear();
        e.lambda = 0;
        e.w = 0;
        cg.all_var.push(reg);
    }
    for &bb in &func.reachable_bbs {
        for &id in &func.bb(bb).insns {
            let e = cg.extra_mut(id);
            e.adj.clear();
            e.live_in.clear();
            e.live_out.clear();
            e.lambda = 0;
            e.w = 0;
            if !e.finalized {
                e.vr_pos.allocated = false;
            }
        }
    }
}

fn push_unique(v: &mut Vec<InsnId>, id: InsnId) {
    if !v.contains(&id) {
        v.push(id);
    }
}

/// Liveness analysis: populate `live_in`/`live_out` for every statement.
pub fn analyze(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let _ = env;
    // Collect all virtual registers (instructions with a non-finalized dst).
    let mut vars: Vec<InsnId> = Vec::new();
    for &bb in &func.reachable_bbs {
        for &id in &func.bb(bb).insns {
            let e = cg.extra(id);
            if e.dst == Some(id) && !e.finalized {
                vars.push(id);
            }
        }
    }
    for &v in &vars {
        push_unique(&mut cg.all_var, v);
        let users = func.insn(v).users.clone();
        let mut visited: HashSet<BbId> = HashSet::new();
        for s in users {
            if matches!(func.insn(s).kind, InsnKind::Phi) {
                // For a phi user, liveness propagates from the predecessor block
                // corresponding to each operand equal to `v`.
                let phi = func.insn(s).phi.clone();
                for entry in phi {
                    if entry.value == crate::ir::Value::Insn(v) {
                        live_out_at_block(func, cg, &mut visited, entry.bb, v);
                    }
                }
            } else {
                live_in_at_statement(func, cg, &mut visited, s, v);
            }
        }
    }
    Ok(())
}

fn live_out_at_block(
    func: &Function,
    cg: &mut CgState,
    visited: &mut HashSet<BbId>,
    n: BbId,
    v: InsnId,
) {
    if visited.contains(&n) {
        return;
    }
    visited.insert(n);
    if let Some(last) = func.bb(n).last() {
        live_out_at_statement(func, cg, visited, last, v);
    } else {
        let preds = func.bb(n).preds.clone();
        for p in preds {
            live_out_at_block(func, cg, visited, p, v);
        }
    }
}

fn live_out_at_statement(
    func: &Function,
    cg: &mut CgState,
    visited: &mut HashSet<BbId>,
    s: InsnId,
    v: InsnId,
) {
    push_unique(&mut cg.extra_mut(s).live_out, v);
    let dst = cg.extra(s).dst;
    match dst {
        Some(d) => {
            if d != v {
                // `s` kills `d` (not `v`); `v` and `d` interfere, keep going up.
                make_conflict(func, cg, v, d);
                live_in_at_statement(func, cg, visited, s, v);
            }
            // If `d == v`, this statement defines `v`: stop propagating upward.
        }
        None => {
            // `s` has no destination (no kill): keep propagating.
            live_in_at_statement(func, cg, visited, s, v);
        }
    }
}

fn live_in_at_statement(
    func: &Function,
    cg: &mut CgState,
    visited: &mut HashSet<BbId>,
    s: InsnId,
    v: InsnId,
) {
    push_unique(&mut cg.extra_mut(s).live_in, v);
    match func.prev_insn(s) {
        None => {
            let preds = func.insn(s).parent_bb;
            let preds = func.bb(preds).preds.clone();
            for p in preds {
                live_out_at_block(func, cg, visited, p, v);
            }
        }
        Some(prev) => live_out_at_statement(func, cg, visited, prev, v),
    }
}

/// Record an interference edge between two values, resolving pre-colored /
/// pre-spilled values to their physical registers (or dropping if spilled).
fn make_conflict(func: &Function, cg: &mut CgState, v1: InsnId, v2: InsnId) {
    if v1 == v2 {
        return;
    }
    let r1 = match resolve_conflict_node(cg, v1) {
        Some(r) => r,
        None => return,
    };
    let r2 = match resolve_conflict_node(cg, v2) {
        Some(r) => r,
        None => return,
    };
    if r1 == r2 {
        return;
    }
    let _ = func;
    push_unique(&mut cg.extra_mut(r1).adj, r2);
    push_unique(&mut cg.extra_mut(r2).adj, r1);
}

/// Map a value to its interference node: itself, or its physical register if
/// pre-colored. Returns `None` for pre-spilled values (no register conflict).
fn resolve_conflict_node(cg: &CgState, v: InsnId) -> Option<InsnId> {
    let e = cg.extra(v);
    if e.vr_pos.allocated {
        if e.vr_pos.spilled != 0 {
            None
        } else {
            Some(cg.regs[e.vr_pos.alloc_reg as usize])
        }
    } else {
        Some(v)
    }
}

/// Build the interference graph: physical-register clique, phi conflicts,
/// caller-saved constraints across calls, and ALU operand constraints.
pub fn build_interference(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let _ = env;

    // All physical registers conflict pairwise.
    for i in 0..RA_COLORS {
        for j in (i + 1)..RA_COLORS {
            let (a, b) = (cg.regs[i], cg.regs[j]);
            make_conflict(func, cg, a, b);
        }
    }

    let bbs = func.reachable_bbs.clone();
    for bb in bbs {
        let insns = func.bb(bb).insns.clone();
        for id in insns {
            match func.insn(id).kind.clone() {
                InsnKind::Phi => {
                    let phi = func.insn(id).phi.clone();
                    for entry in phi {
                        phi_conflict_at_block(func, cg, entry.bb, id);
                    }
                }
                InsnKind::Call { .. } | InsnKind::Ecall => {
                    // Values live across the call conflict with caller-saved R0..R5.
                    let live_in = cg.extra(id).live_in.clone();
                    let live_out: HashSet<InsnId> = cg.extra(id).live_out.iter().copied().collect();
                    for v in live_in {
                        if live_out.contains(&v) {
                            for r in BPF_REG_0..BPF_REG_6 {
                                let reg = cg.regs[r as usize];
                                make_conflict(func, cg, reg, v);
                            }
                        }
                    }
                }
                _ => {
                    if func.insn(id).is_bin_alu() {
                        // a = ALU b c : dst conflicts with the second operand.
                        if let crate::ir::Value::Insn(c) = func.insn(id).values[1] {
                            make_conflict(func, cg, id, c);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// A phi value conflicts with the live-out (or live-in for jumps) of each
/// predecessor block's terminator.
fn phi_conflict_at_block(func: &Function, cg: &mut CgState, n: BbId, v: InsnId) {
    if let Some(last) = func.bb(n).last() {
        let set = if func.insn(last).is_jmp() {
            cg.extra(last).live_in.clone()
        } else {
            cg.extra(last).live_out.clone()
        };
        for u in set {
            if u != v {
                make_conflict(func, cg, u, v);
            }
        }
    } else {
        let preds = func.bb(n).preds.clone();
        for p in preds {
            phi_conflict_at_block(func, cg, p, v);
        }
    }
}
