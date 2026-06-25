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
