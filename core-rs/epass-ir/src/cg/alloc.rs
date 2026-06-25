//! Register allocation core: maximum-cardinality search, pre-spilling, the
//! spill transform, greedy coloring, copy coalescing, and SSA-out (phi removal).

use crate::env::Env;
use crate::error::Result;
use crate::ir::insn::InsnKind;
use crate::ir::value::VrType;
use crate::ir::{Function, InsnId, InsertPos, Value};
use crate::{internal, invalid};

use super::prepare::{create_alloc, ensure_extra};
use super::{liveness, CgState, RA_COLORS};

/// Reset state at the start of an RA iteration.
pub fn clean_iteration(func: &Function, cg: &mut CgState) {
    liveness::clean(func, cg);
}

/// Maximum cardinality search: produce a simplicial elimination order (SEO).
fn mcs(cg: &mut CgState) {
    cg.seo.clear();
    let mut remaining: Vec<InsnId> = cg.all_var.clone();
    // Reset lambda.
    for &v in &remaining {
        cg.extra_mut(v).lambda = 0;
    }
    while !remaining.is_empty() {
        // Pick the vertex with maximum lambda (first wins ties, matching C `>=`).
        let mut max_l = 0u32;
        let mut max_i = remaining[0];
        for &v in &remaining {
            let l = cg.extra(v).lambda;
            if l >= max_l {
                max_l = l;
                max_i = v;
            }
        }
        cg.seo.push(max_i);
        let adj = cg.extra(max_i).adj.clone();
        for u in adj {
            if remaining.contains(&u) {
                cg.extra_mut(u).lambda += 1;
            }
        }
        remaining.retain(|&x| x != max_i);
    }
}

/// Pre-spill pass: find maximal cliques exceeding `RA_COLORS` and select the
/// highest-weight virtual registers to spill. Returns the spill set.
pub fn pre_spill(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<Vec<InsnId>> {
    let _ = (env, func);
    mcs(cg);

    // Build the maximal cliques (eps[i]) along the SEO.
    let seo = cg.seo.clone();
    let mut eps: Vec<Vec<InsnId>> = Vec::with_capacity(seo.len());
    for &v in &seo {
        cg.extra_mut(v).w += 1;
    }
    // Reset w then recompute per the clique structure.
    for &v in &seo {
        cg.extra_mut(v).w = 0;
    }
    for (i, &v) in seo.iter().enumerate() {
        let mut q = vec![v];
        cg.extra_mut(v).w += 1;
        let adj = cg.extra(v).adj.clone();
        for u in adj {
            // u is in the clique if it appears earlier in the SEO.
            if seo[..i].contains(&u) {
                q.push(u);
                cg.extra_mut(u).w += 1;
            }
        }
        eps.push(q);
    }

    // Greedily spill the heaviest VR from any oversized clique.
    let mut to_spill: Vec<InsnId> = Vec::new();
    loop {
        let over = eps.iter().position(|c| c.len() > RA_COLORS);
        let Some(idx) = over else { break };
        // Choose the max-weight virtual register in this clique.
        let mut max_w = 0u32;
        let mut max_i: Option<InsnId> = None;
        for &v in &eps[idx] {
            let e = cg.extra(v);
            if e.w >= max_w && !e.nonvr && !e.spilled_once {
                max_w = e.w;
                max_i = Some(v);
            }
        }
        let chosen = max_i.ok_or_else(|| internal!("oversized clique with no spillable VR"))?;
        to_spill.push(chosen);
        for c in &mut eps {
            c.retain(|&x| x != chosen);
        }
    }
    Ok(to_spill)
}

/// Spill every selected value everywhere (spill-everywhere): allocate a stack
/// slot, store the def, and reload at each use.
pub fn spill(
    env: &mut Env,
    func: &mut Function,
    cg: &mut CgState,
    to_spill: &[InsnId],
) -> Result<()> {
    let _ = env;
    for &v in to_spill {
        if matches!(func.insn(v).kind, InsnKind::Call { .. } | InsnKind::AllocArray { .. }) {
            return Err(internal!("attempted to spill a call/allocarray"));
        }
        let users = func.insn(v).users.clone();

        let alloc = if matches!(func.insn(v).kind, InsnKind::Alloc { .. }) {
            v
        } else {
            let entry = func.entry;
            let alloc = create_alloc(cg, func, entry, VrType::B64, InsertPos::FrontAfterPhi);
            // store alloc, v  (placed right after v's def)
            let store = func.build_store_at(v, alloc, Value::Insn(v), InsertPos::Back);
            ensure_extra(cg, func, store);
            alloc
        };

        // Finalize the stack slot.
        let off = cg.new_spill(8);
        {
            let e = cg.extra_mut(alloc);
            e.finalized = true;
            e.vr_pos.allocated = true;
            e.vr_pos.spilled = off;
            e.vr_pos.spilled_size = 8;
        }

        if !matches!(func.insn(v).kind, InsnKind::Alloc { .. }) {
            for user in users {
                spill_one_use(func, cg, user, alloc, v)?;
            }
            // The def now has a tiny live range (def -> store); never re-spill it.
            cg.extra_mut(v).spilled_once = true;
        }
    }
    Ok(())
}

/// Rewrite a single user of a spilled value to reload from the stack.
fn spill_one_use(
    func: &mut Function,
    cg: &mut CgState,
    user: InsnId,
    alloc: InsnId,
    v: InsnId,
) -> Result<()> {
    match func.insn(user).kind.clone() {
        // A store of the spilled value into its own slot: nothing to do.
        InsnKind::Store
            if func.insn(user).values.first() == Some(&Value::Insn(user)) =>
        {
            Ok(())
        }
        InsnKind::Phi => {
            // Reload at the end of each predecessor block contributing v.
            let entries = func.insn(user).phi.clone();
            for (idx, entry) in entries.iter().enumerate() {
                if entry.value == Value::Insn(v) {
                    let load = func.build_load_bb(entry.bb, alloc, InsertPos::BackBeforeJmp);
                    ensure_extra(cg, func, load);
                    // Update the phi operand.
                    func.remove_use(entry.value, user);
                    func.insn_mut(user).phi[idx].value = Value::Insn(load);
                    func.add_use(Value::Insn(load), user);
                }
            }
            Ok(())
        }
        _ => {
            let load = func.build_load_at(user, alloc, InsertPos::Front);
            ensure_extra(cg, func, load);
            func.change_value(user, Value::Insn(v), Value::Insn(load));
            Ok(())
        }
    }
}

/// Greedy coloring along the SEO (optimal for chordal graphs).
pub fn coloring(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let _ = (env, func);
    let seo = cg.seo.clone();
    for v in seo {
        if cg.extra(v).vr_pos.allocated {
            continue;
        }
        let mut used = [false; RA_COLORS];
        let adj = cg.extra(v).adj.clone();
        for a in adj {
            let ae = cg.extra(a);
            if ae.vr_pos.allocated && ae.vr_pos.spilled == 0 {
                used[ae.vr_pos.alloc_reg as usize] = true;
            }
        }
        let mut assigned = false;
        for (i, &u) in used.iter().enumerate() {
            if !u {
                let e = cg.extra_mut(v);
                e.vr_pos.allocated = true;
                e.vr_pos.alloc_reg = i as u8;
                assigned = true;
                break;
            }
        }
        if !assigned {
            return Err(crate::error::Error::RegAlloc(
                "no register available during coloring".into(),
            ));
        }
    }
    Ok(())
}

/// Best-effort copy coalescing for assign / store / load chains.
pub fn coalesce(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let _ = env;
    let insns: Vec<_> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .collect();
    for id in insns {
        match func.insn(id).kind.clone() {
            InsnKind::Assign => {
                if let Value::Insn(src) = func.insn(id).values[0] {
                    try_coalesce(cg, id, src);
                }
            }
            InsnKind::Store => {
                let v0 = func.insn(id).values[0];
                let v1 = func.insn(id).values[1];
                if let (Value::Insn(alloc), Value::Insn(src)) = (v0, v1) {
                    try_coalesce(cg, alloc, src);
                }
            }
            InsnKind::Load => {
                if let Value::Insn(alloc) = func.insn(id).values[0] {
                    try_coalesce(cg, id, alloc);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Try to give `v1` and `v2` the same register if it does not break coloring.
fn try_coalesce(cg: &mut CgState, v1: InsnId, v2: InsnId) {
    let (s1, s2) = (cg.extra(v1).vr_pos.spilled, cg.extra(v2).vr_pos.spilled);
    let (r1, r2) = (cg.extra(v1).vr_pos.alloc_reg, cg.extra(v2).vr_pos.alloc_reg);
    if s1 != 0 || s2 != 0 || r1 == r2 {
        return;
    }
    // Colors used by both neighborhoods.
    let mut used = [false; RA_COLORS];
    for v in [v1, v2] {
        let adj = cg.extra(v).adj.clone();
        for a in adj {
            let ae = cg.extra(a);
            if ae.vr_pos.allocated && ae.vr_pos.spilled == 0 {
                used[ae.vr_pos.alloc_reg as usize] = true;
            }
        }
    }
    let f1 = cg.extra(v1).finalized;
    let f2 = cg.extra(v2).finalized;
    if f1 {
        if !used[r1 as usize] {
            cg.extra_mut(v2).vr_pos.alloc_reg = r1;
        }
    } else if f2 {
        if !used[r2 as usize] {
            cg.extra_mut(v1).vr_pos.alloc_reg = r2;
        }
    } else if let Some(free) = (0..RA_COLORS).find(|&i| !used[i]) {
        cg.extra_mut(v1).vr_pos.alloc_reg = free as u8;
        cg.extra_mut(v2).vr_pos.alloc_reg = free as u8;
    }
}

/// SSA-out: replace each phi with copies in its predecessor blocks.
pub fn remove_phi(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let _ = env;
    let phis: Vec<InsnId> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .filter(|&id| matches!(func.insn(id).kind, InsnKind::Phi))
        .collect();

    for phi in phis {
        let vrpos = cg.extra(phi).vr_pos;
        if vrpos.spilled != 0 {
            return Err(invalid!("phi cannot be spilled"));
        }
        let entries = func.insn(phi).phi.clone();
        for entry in entries {
            // assign(entry.value) in the predecessor block, sharing phi's reg.
            let assign = func.build_assign_bb(entry.bb, entry.value, InsertPos::BackBeforeJmp);
            ensure_extra(cg, func, assign);
            cg.extra_mut(assign).vr_pos = vrpos;
            cg.extra_mut(assign).finalized = true;
            func.remove_use(entry.value, phi);
        }
        func.insn_mut(phi).phi.clear();
        let reg = cg.regs[vrpos.alloc_reg as usize];
        func.replace_all_uses(phi, Value::Insn(reg));
        func.erase_insn(phi);
        cg.extra.remove(&phi);
    }
    Ok(())
}
