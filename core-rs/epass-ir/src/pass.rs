//! The pass framework: a [`Pass`] trait plus a [`PassManager`] that runs the
//! pre / custom / post pipeline, re-validating and re-laying-out the CFG after
//! each pass (matching the C `run_single_pass` / `bpf_ir_pass_postprocess`).

use crate::env::{Env, LogLevel, Timer};
use crate::error::Result;
use crate::ir::Function;
use crate::{cfg, check, internal, invalid, log_debug};
use indexmap::IndexMap;

/// A transformation or analysis over a function.
pub trait Pass {
    /// A short, stable name (used for logging and pass options).
    fn name(&self) -> &str;

    /// Whether this pass runs when absent from `--popt`.
    fn enabled_by_default(&self) -> bool {
        false
    }

    /// Whether the pass can be disabled with `!pass_name`.
    fn allow_disable(&self) -> bool {
        true
    }

    /// Initialize/configure this pass from its pass-option argument.
    ///
    /// Called once while building the pass manager, before ordering and before
    /// any IR mutation. Most passes take no options and inherit this default.
    fn init(&mut self, arg: Option<&str>) -> Result<()> {
        if arg.is_some() {
            return Err(invalid!("pass '{}' takes no options", self.name()));
        }
        Ok(())
    }

    /// Adjust this pass's position in the pass list.
    ///
    /// The pass manager verifies that the returned list only inserted, removed,
    /// or moved entries with this pass's own name. Other passes' relative order
    /// and multiplicity must remain unchanged.
    fn register_pass(&self, order: Vec<String>) -> Result<Vec<String>> {
        Ok(order)
    }

    /// Run the pass. Mutating the function is allowed.
    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()>;
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

/// Parsed pass-option entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPassOpt {
    name: String,
    disabled: bool,
    arg: Option<String>,
}

/// Runs an ordered list of passes.
#[derive(Default)]
pub struct PassManager {
    passes: IndexMap<String, Box<dyn Pass>>,
    order: Vec<String>,
}

impl PassManager {
    pub fn new() -> Self {
        PassManager::default()
    }

    /// Build a pass manager from available pass objects and a `--popt` string.
    pub fn from_passes(mut passes: Vec<Box<dyn Pass>>, popt: &str) -> Result<Self> {
        let mut map: IndexMap<String, Box<dyn Pass>> = IndexMap::new();
        for pass in passes.drain(..) {
            let name = pass.name().to_string();
            if map.contains_key(&name) {
                return Err(invalid!("duplicate pass registration '{name}'"));
            }
            map.insert(name, pass);
        }

        let parsed = parse_popt(popt)?;
        let mut enabled: IndexMap<String, bool> = map
            .iter()
            .map(|(name, pass)| (name.clone(), pass.enabled_by_default()))
            .collect();
        let mut args: IndexMap<String, Option<String>> = map.keys().map(|name| (name.clone(), None)).collect();
        let mut explicit: IndexMap<String, bool> = map.keys().map(|name| (name.clone(), false)).collect();

        for opt in parsed {
            let Some(pass) = map.get(opt.name.as_str()) else {
                return Err(invalid!("unknown pass '{}'", opt.name));
            };
            if opt.disabled {
                if opt.arg.is_some() {
                    return Err(invalid!("disabled pass '{}' cannot have options", opt.name));
                }
                if !pass.allow_disable() {
                    return Err(invalid!("pass '{}' cannot be disabled", opt.name));
                }
                enabled.insert(opt.name.clone(), false);
                explicit.insert(opt.name, true);
            } else {
                enabled.insert(opt.name.clone(), true);
                args.insert(opt.name.clone(), opt.arg);
                explicit.insert(opt.name, true);
            }
        }

        // Initialize enabled passes (default-enabled passes get None unless the
        // user supplied an explicit option).
        let keys: Vec<String> = map.keys().cloned().collect();
        for name in &keys {
            if *enabled.get(name).unwrap_or(&false) {
                let arg = args.get(name).and_then(|x| x.as_deref());
                map.get_mut(name).unwrap().init(arg)?;
            }
        }

        let mut order: Vec<String> = keys
            .iter()
            .filter(|name| *enabled.get(*name).unwrap_or(&false))
            .cloned()
            .collect();

        const MAX_ORDER_ITERS: usize = 32;
        let enabled_names = order.clone();
        let mut stable = false;
        for _ in 0..MAX_ORDER_ITERS {
            let before_iter = order.clone();
            for name in &enabled_names {
                if !order.iter().any(|n| n == name) {
                    // The pass removed itself; don't ask it to order again.
                    continue;
                }
                let pass = map.get(name).unwrap();
                let old = order.clone();
                let new = pass.register_pass(order)?;
                verify_only_own_changes(pass.name(), &old, &new)?;
                order = new;
            }
            if order == before_iter {
                stable = true;
                break;
            }
        }
        if !stable {
            return Err(internal!("pass registration order did not converge after {MAX_ORDER_ITERS} iterations"));
        }

        Ok(PassManager { passes: map, order })
    }

    /// Add a pass directly to this manager, enabled at the end of the current order.
    /// Useful for tests or custom callers that construct their own pipeline.
    pub fn add_pass(&mut self, pass: Box<dyn Pass>) -> Result<()> {
        let name = pass.name().to_string();
        if self.passes.contains_key(&name) {
            return Err(invalid!("duplicate pass '{name}'"));
        }
        self.order.push(name.clone());
        self.passes.insert(name, pass);
        Ok(())
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

    /// Run passes in the finalized order.
    pub fn run(&self, env: &mut Env, func: &mut Function) -> Result<()> {
        let timer = Timer::start();
        for name in &self.order {
            let pass = self
                .passes
                .get(name.as_str())
                .ok_or_else(|| internal!("pass order references unknown pass '{name}'"))?;
            self.run_one(env, func, pass.as_ref())?;
        }
        env.run_time_ns += timer.elapsed_ns();
        Ok(())
    }
}

fn verify_only_own_changes(own: &str, old: &[String], new: &[String]) -> Result<()> {
    let old_without: Vec<_> = old.iter().filter(|n| n.as_str() != own).cloned().collect();
    let new_without: Vec<_> = new.iter().filter(|n| n.as_str() != own).cloned().collect();
    if old_without != new_without {
        return Err(internal!("pass '{own}' illegally modified other passes during registration"));
    }
    let own_count = new.iter().filter(|n| n.as_str() == own).count();
    if own_count > 1 {
        return Err(internal!("pass '{own}' duplicated itself; duplicate pass instances are not supported yet"));
    }
    Ok(())
}

fn parse_popt(popt: &str) -> Result<Vec<ParsedPassOpt>> {
    let mut out = Vec::new();
    for item in split_top_level_commas(popt)? {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (disabled, rest) = match item.strip_prefix('!') {
            Some(r) => (true, r.trim()),
            None => (false, item),
        };
        let (name, arg) = if let Some(open) = rest.find('(') {
            if !rest.ends_with(')') {
                return Err(invalid!("unterminated pass option parentheses in '{item}'"));
            }
            let name = rest[..open].trim();
            let arg = rest[open + 1..rest.len() - 1].to_string();
            (name, Some(arg))
        } else {
            (rest, None)
        };
        if name.is_empty() {
            return Err(invalid!("empty pass name in '{item}'"));
        }
        out.push(ParsedPassOpt { name: name.to_string(), disabled, arg });
    }
    Ok(out)
}

fn split_top_level_commas(s: &str) -> Result<Vec<&str>> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (idx, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(invalid!("unmatched ')' in pass options"));
                }
            }
            ',' if depth == 0 => {
                parts.push(&s[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(invalid!("unterminated pass option parentheses"));
    }
    parts.push(&s[start..]);
    Ok(parts)
}
