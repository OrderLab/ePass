//! `optimize_ir`: light-weight dead-code elimination over the IR.
//!
//! Two transforms (ported from the C `optimization.c`):
//! 1. `remove_no_user_insn` — iteratively erase value-producing instructions
//!    (not void, not calls) that have no users.
//! 2. `remove_unused_alloc` — erase `alloc`s that are only ever stored to
//!    (never loaded), together with those stores.
//!
//! In the Rust pipeline this is a default pass ordered after phi cleanup and
//! before code generation.

use crate::env::Env;
use crate::error::Result;
use crate::ir::insn::InsnKind;
use crate::ir::{Function, InsnId};
use crate::pass::Pass;

/// Options controlling the optimizer (parsed from a pass-option string).
#[derive(Debug, Clone, Copy, Default)]
pub struct OptimizeOpts {
    /// Skip dead-code (no-user) elimination.
    pub no_dead_elim: bool,
    /// Skip the whole pass.
    pub no_opt: bool,
}

impl OptimizeOpts {
    /// Parse a pass-option string (`"no_dead_elim,noopt"` or `"no_dead_elim noopt"`).
    pub fn parse(s: &str) -> Self {
        let mut o = OptimizeOpts::default();
        for tok in s.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
            match tok {
                "no_dead_elim" => o.no_dead_elim = true,
                "noopt" => o.no_opt = true,
                _ => {}
            }
        }
        o
    }
}

/// Iteratively erase value-producing instructions with no users.
fn remove_no_user_insn(func: &mut Function) {
    loop {
        let mut changed = false;
        let candidates: Vec<InsnId> = func
            .reachable_bbs
            .iter()
            .flat_map(|&bb| func.bb(bb).insns.clone())
            .collect();
        for id in candidates {
            if !func.is_alive(id) {
                continue;
            }
            let insn = func.insn(id);
            if insn.is_void() || matches!(insn.kind, InsnKind::Call { .. } | InsnKind::Ecall) {
                continue;
            }
            // A self-reference (e.g. an unsimplified phi) does not count as a use.
            let live_users = insn.users.iter().any(|&u| u != id);
            if !live_users {
                func.erase_insn(id);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

/// Erase `alloc`s that are never loaded (only stored), and their stores.
fn remove_unused_alloc(func: &mut Function) {
    let allocs: Vec<InsnId> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .filter(|&id| matches!(func.insn(id).kind, InsnKind::Alloc { .. }))
        .collect();

    for alloc in allocs {
        if !func.is_alive(alloc) {
            continue;
        }
        let users = func.insn(alloc).users.clone();
        let has_load = users
            .iter()
            .any(|&u| matches!(func.insn(u).kind, InsnKind::Load));
        if has_load {
            continue;
        }
        // No loads: drop every store (the only remaining users), then the alloc.
        for user in users {
            if func.is_alive(user) {
                // Detach the store's operand uses first so erase_insn's
                // "no users" invariant holds.
                func.erase_insn(user);
            }
        }
        func.erase_insn(alloc);
    }
}

/// Run the optimizer with the given options.
pub fn optimize_ir_opts(env: &mut Env, func: &mut Function, opts: OptimizeOpts) -> Result<()> {
    if opts.no_opt {
        crate::log_debug!(env, "skip optimization\n");
        return Ok(());
    }
    if !opts.no_dead_elim {
        remove_no_user_insn(func);
    } else {
        crate::log_debug!(env, "skip remove_no_user_insn\n");
    }
    remove_unused_alloc(func);
    Ok(())
}

/// Run the optimizer with default options.
pub fn optimize_ir(env: &mut Env, func: &mut Function) -> Result<()> {
    optimize_ir_opts(env, func, OptimizeOpts::default())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OptimizeIrPass {
    opts: OptimizeOpts,
}

impl Pass for OptimizeIrPass {
    fn name(&self) -> &str {
        "optimize_ir"
    }

    fn enabled_by_default(&self) -> bool {
        true
    }

    fn allow_disable(&self) -> bool {
        true
    }

    fn init(&mut self, arg: Option<&str>) -> Result<()> {
        self.opts = arg.map(OptimizeOpts::parse).unwrap_or_default();
        Ok(())
    }

    fn register_pass(&self, mut order: Vec<String>) -> Result<Vec<String>> {
        let name = self.name();
        if let Some(pos) = order.iter().position(|p| p == name) {
            let own = order.remove(pos);
            // The optimizer should run after phi cleanup, and after const_prop if
            // phi was disabled in a custom build. Put it behind the latest known
            // cleanup pass, otherwise keep it at the end.
            let insert_after = order
                .iter()
                .rposition(|p| p == "phi" || p == "const_prop")
                .map(|i| i + 1)
                .unwrap_or(order.len());
            order.insert(insert_after, own);
        }
        Ok(order)
    }

    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()> {
        optimize_ir_opts(env, func, self.opts)
    }
}

/// Construct the pass object.
pub fn pass() -> impl Pass {
    OptimizeIrPass::default()
}
