//! The pass framework: a [`Pass`] trait plus a [`PassManager`] that runs the
//! pre / custom / post pipeline, re-validating and re-laying-out the CFG after
//! each pass (matching the C `run_single_pass` / `bpf_ir_pass_postprocess`).

use crate::env::{Env, LogLevel, Timer};
use crate::error::Result;
use crate::ir::Function;
use crate::{cfg, check, log_debug};

/// A transformation or analysis over a function.
pub trait Pass {
    /// A short, stable name (used for logging and per-run enable/disable).
    fn name(&self) -> &str;

    /// Run the pass. Mutating the function is allowed.
    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()>;
}

/// Allow plain closures to be used as passes.
pub struct FnPass<F> {
    name: &'static str,
    f: F,
}

impl<F> FnPass<F>
where
    F: Fn(&mut Env, &mut Function) -> Result<()>,
{
    pub fn new(name: &'static str, f: F) -> Self {
        FnPass { name, f }
    }
}

impl<F> Pass for FnPass<F>
where
    F: Fn(&mut Env, &mut Function) -> Result<()>,
{
    fn name(&self) -> &str {
        self.name
    }
    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()> {
        (self.f)(env, func)
    }
}

/// Recompute CFG metadata and validate the IR after a pass mutated it.
pub fn postprocess(env: &mut Env, func: &mut Function) -> Result<()> {
    // Recompute successors from terminators, then chain layout + end blocks.
    recompute_succs(func)?;
    cfg::finalize(env, func)?;
    drop_unreachable_edges(func);
    prune_phi_inputs(func);
    check::prog_check(env, func)?;
    Ok(())
}

/// Re-derive each block's `succs` from its terminator's jump targets.
///
/// Insertion/erasure during a pass can leave `succs` stale; the terminator's
/// `bb1`/`bb2` are the source of truth.
fn recompute_succs(func: &mut Function) -> Result<()> {
    use crate::ir::InsnKind;
    let bbs: Vec<_> = func.all_bbs.clone();
    for bb in bbs {
        let Some(last) = func.bb(bb).last() else {
            continue;
        };
        let (b1, b2) = {
            let insn = func.insn(last);
            match &insn.kind {
                InsnKind::CondJmp { .. } => (insn.bb1, insn.bb2),
                InsnKind::Ja => (insn.bb1, None),
                _ => continue,
            }
        };
        // Disconnect old successors, then reconnect from the terminator.
        let old: Vec<_> = func.bb(bb).succs.clone();
        for s in old {
            func.disconnect(bb, s);
        }
        if let Some(b1) = b1 {
            func.connect(bb, b1);
        }
        if let Some(b2) = b2 {
            func.connect(bb, b2);
        }
    }
    Ok(())
}

/// Drop predecessor/successor edges that cross from the reachable subgraph to an
/// unreachable block after a CFG rewrite. The BB arena keeps unreachable blocks
/// around, but later analyses walk `preds`, so reachable blocks must not retain
/// stale predecessors from dead blocks.
fn drop_unreachable_edges(func: &mut Function) {
    let reachable: std::collections::HashSet<_> = func.reachable_bbs.iter().copied().collect();
    let bbs = func.all_bbs.clone();
    for bb in bbs {
        func.bb_mut(bb).preds.retain(|p| reachable.contains(p));
        if reachable.contains(&bb) {
            func.bb_mut(bb).succs.retain(|s| reachable.contains(s));
        }
    }
}

/// Remove phi operands whose incoming block is no longer a predecessor after a
/// CFG rewrite. This keeps SSA edge uses aligned with the current CFG and lets
/// later phi-simplification see constants/trivial phis exposed by branch folding.
fn prune_phi_inputs(func: &mut Function) {
    use crate::ir::InsnKind;
    let bbs = func.reachable_bbs.clone();
    let reachable: std::collections::HashSet<_> = bbs.iter().copied().collect();
    for bb in bbs {
        let preds: Vec<_> = func
            .bb(bb)
            .preds
            .iter()
            .copied()
            .filter(|p| reachable.contains(p))
            .collect();
        let phis: Vec<_> = func
            .bb(bb)
            .insns
            .iter()
            .copied()
            .take_while(|&id| matches!(func.insn(id).kind, InsnKind::Phi))
            .collect();
        for phi in phis {
            let old = func.insn(phi).phi.clone();
            let mut new_phi = Vec::with_capacity(old.len());
            let mut removed_values = Vec::new();
            for entry in old {
                if preds.contains(&entry.bb) {
                    new_phi.push(entry);
                } else {
                    removed_values.push(entry.value);
                }
            }
            for value in removed_values {
                if !new_phi.iter().any(|entry| entry.value == value) {
                    func.remove_use(value, phi);
                }
            }
            func.insn_mut(phi).phi = new_phi;
        }
    }
}

/// Runs an ordered list of passes.
#[derive(Default)]
pub struct PassManager {
    pub pre: Vec<Box<dyn Pass>>,
    pub custom: Vec<Box<dyn Pass>>,
    pub post: Vec<Box<dyn Pass>>,
}

impl PassManager {
    pub fn new() -> Self {
        PassManager::default()
    }

    fn run_one(&self, env: &mut Env, func: &mut Function, pass: &dyn Pass) -> Result<()> {
        log_debug!(env, "------ Running Pass: {} ------\n", pass.name());
        pass.run(env, func)?;
        postprocess(env, func)?;
        if env.opts.verbose >= 2 {
            let txt = crate::ir::print::print_function(func);
            env.log(LogLevel::Debug, format_args!("{txt}"));
        }
        Ok(())
    }

    /// Run pre, then custom, then post passes.
    pub fn run(&self, env: &mut Env, func: &mut Function) -> Result<()> {
        let timer = Timer::start();
        for p in &self.pre {
            self.run_one(env, func, p.as_ref())?;
        }
        for p in &self.custom {
            self.run_one(env, func, p.as_ref())?;
        }
        for p in &self.post {
            self.run_one(env, func, p.as_ref())?;
        }
        env.run_time_ns += timer.elapsed_ns();
        Ok(())
    }
}
