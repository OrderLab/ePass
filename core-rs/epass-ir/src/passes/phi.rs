//! `remove_trivial_phi`: iteratively delete phi nodes whose operands are all
//! identical (ignoring self-references), replacing uses with that single value.

use crate::env::Env;
use crate::error::Result;
use crate::invalid;
use crate::ir::{Function, InsnId, InsnKind, Value};
use crate::pass::{FnPass, Pass};

/// Try to remove one trivial phi. Returns `Ok(true)` if it was removed.
fn try_remove(func: &mut Function, phi: InsnId) -> Result<bool> {
    let mut same: Option<Value> = None;
    for entry in func.insn(phi).phi.clone() {
        let v = entry.value;
        // Skip self-references and operands equal to the running unique value.
        if let Value::Insn(def) = v {
            if def == phi {
                continue;
            }
        }
        if Some(v) == same {
            continue;
        }
        if same.is_some() {
            // Two distinct non-self operands: not trivial.
            return Ok(false);
        }
        same = Some(v);
    }

    let Some(rep) = same else {
        return Err(invalid!("phi instruction %{} has no operands", phi.0));
    };

    // Drop our own uses of the phi operands before replacing/erasing.
    for entry in func.insn(phi).phi.clone() {
        func.remove_use(entry.value, phi);
    }
    func.insn_mut(phi).phi.clear();

    func.replace_all_uses_except(phi, rep, Some(phi));
    func.erase_insn(phi);
    Ok(true)
}

/// Remove all trivial phis to a fixpoint.
pub fn remove_trivial_phi(_env: &mut Env, func: &mut Function) -> Result<()> {
    let mut changed = true;
    while changed {
        changed = false;
        let phis: Vec<InsnId> = func
            .reachable_bbs
            .iter()
            .flat_map(|&bb| func.bb(bb).insns.clone())
            .filter(|&id| matches!(func.insn(id).kind, InsnKind::Phi))
            .collect();
        for phi in phis {
            if func.is_alive(phi) {
                changed |= try_remove(func, phi)?;
            }
        }
    }
    Ok(())
}

/// Construct the pass object.
pub fn pass() -> impl Pass {
    FnPass::new("remove_trivial_phi", remove_trivial_phi)
}
