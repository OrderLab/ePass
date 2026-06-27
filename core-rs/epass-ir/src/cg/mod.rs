//! Code generator: SSA-based register allocation (chordal-graph coloring) and
//! lowering of the IR back to eBPF bytecode.
//!
//! Algorithm reference: Pereira & Palsberg, "Register Allocation via the
//! Coloring of Chordal Graphs" (APLAS 2005). The register-allocation state for
//! each instruction lives in a side-table ([`CgState::extra`]) keyed by
//! [`InsnId`], keeping the IR node itself stage-agnostic.

mod alloc;
mod liveness;
mod norm;
mod prepare;

use std::collections::HashMap;

use crate::env::{Env, Timer};
use crate::error::Result;
use crate::ir::value::VrPos;
use crate::ir::{Function, InsnId};
use crate::{internal, log_debug};

/// Number of allocatable physical registers (R0..R9).
pub const RA_COLORS: usize = 10;

/// Per-instruction register-allocation metadata.
#[derive(Debug, Clone)]
pub struct CgExtra {
    /// The instruction whose allocation represents this value's location
    /// (`Some(self)` for value-producing insns, `None` for void insns).
    pub dst: Option<InsnId>,
    /// Liveness: values live-in / live-out at this statement.
    pub live_in: Vec<InsnId>,
    pub live_out: Vec<InsnId>,
    /// Interference-graph adjacency.
    pub adj: Vec<InsnId>,
    /// MCS weight (lambda) and clique weight (w).
    pub lambda: u32,
    pub w: u32,
    /// Whether `vr_pos` is fixed (pre-colored / pre-spilled).
    pub finalized: bool,
    pub vr_pos: VrPos,
    /// A non-virtual pseudo (physical register / stack pointer).
    pub nonvr: bool,
    /// Whether this value has already been spilled-everywhere (its def now has
    /// a tiny live range; never re-select it for spilling).
    pub spilled_once: bool,
}

impl CgExtra {
    fn new(dst: Option<InsnId>) -> Self {
        CgExtra {
            dst,
            live_in: Vec::new(),
            live_out: Vec::new(),
            adj: Vec::new(),
            lambda: 0,
            w: 0,
            finalized: false,
            vr_pos: VrPos::default(),
            nonvr: false,
            spilled_once: false,
        }
    }
}

/// Code-generation state for a function.
pub struct CgState {
    /// Per-instruction RA metadata, keyed by instruction id.
    pub extra: HashMap<InsnId, CgExtra>,
    /// Physical-register pseudo-instructions R0..R9.
    pub regs: [InsnId; RA_COLORS],
    /// Simplicial elimination order (from MCS).
    pub seo: Vec<InsnId>,
    /// All virtual registers in the interference graph.
    pub all_var: Vec<InsnId>,
    /// Current (negative) stack offset for spills/arrays.
    pub stack_offset: i32,
}

impl CgState {
    pub fn extra(&self, id: InsnId) -> &CgExtra {
        self.extra.get(&id).expect("missing CG extra")
    }
    pub fn extra_mut(&mut self, id: InsnId) -> &mut CgExtra {
        self.extra.get_mut(&id).expect("missing CG extra")
    }

    /// Allocate `size` bytes of stack and return the new (negative) offset.
    pub fn new_spill(&mut self, size: u32) -> i32 {
        self.stack_offset -= size as i32;
        self.stack_offset
    }
}

/// Compile a function: run CG prep, register allocation, SSA-out, and lower to
/// bytecode (written into `env.insns`).
pub fn compile(env: &mut Env, func: &mut Function) -> Result<()> {
    let timer = Timer::start();

    // The normal pass pipeline runs optimize_ir before codegen. CG prep starts
    // from the post-pass IR and only performs lowering required for allocation.
    let mut cg = prepare::init_cg(env, func)?;

    prepare::change_call(env, func, &mut cg)?;
    log_ir(env, func, "after change_call");

    prepare::change_fun_arg(env, func, &mut cg)?;
    log_ir(env, func, "after change_fun_arg");

    prepare::spill_array(env, func, &mut cg)?;
    prepare::spill_const(env, func, &mut cg)?;
    log_ir(env, func, "after spill prep");

    // Register-allocation fixpoint. Each iteration:
    //   1. (re)build liveness + interference,
    //   2. pre-spill any clique larger than the register count, and
    //   3. greedily color along the MCS order.
    //
    // On a chordal graph this converges in one pass (pre-spilling guarantees a
    // K-colorable graph, Pereira & Palsberg Theorem 2). The RA interference
    // graph here is *not* chordal — the caller-saved / two-address / phi
    // constraint edges break the SSA dominance property the chordality proof
    // relies on — so the MCS order is not a perfect elimination order and greedy
    // coloring can fail even when the graph is K-colorable. When that happens we
    // post-spill the offending value (paper's "post-spilling" fallback) and
    // re-run. Each value is spilled at most once, so this terminates.
    let max_iter = 64;
    let mut iteration = 0;
    loop {
        if iteration > max_iter {
            return Err(internal!("register allocation did not converge"));
        }
        log_debug!(env, "----- RA iteration {} -----\n", iteration);
        alloc::clean_iteration(func, &mut cg);
        liveness::analyze(env, func, &mut cg)?;
        liveness::build_interference(env, func, &mut cg)?;

        let to_spill = alloc::pre_spill(env, func, &mut cg)?;
        log_debug!(env, "RA iteration {} pre-spills {}\n", iteration, to_spill.len());
        if !to_spill.is_empty() {
            alloc::spill(env, func, &mut cg, &to_spill)?;
            iteration += 1;
            continue;
        }

        // No oversized clique: attempt to color. On a non-chordal graph this can
        // still fail; if so, post-spill the failing value and retry.
        match alloc::coloring(env, func, &mut cg)? {
            None => break,
            Some(failed) => {
                let victim = alloc::pick_spill_victim(func, &cg, failed)?;
                log_debug!(
                    env,
                    "RA iteration {} coloring failed at %{}, post-spilling %{}\n",
                    iteration,
                    failed.0,
                    victim.0
                );
                alloc::spill(env, func, &mut cg, &[victim])?;
                iteration += 1;
            }
        }
    }
    log_debug!(env, "RA converged in {} iterations\n", iteration);

    log_ir(env, func, "after coloring");

    if !env.opts.disable_coalesce {
        alloc::coalesce(env, func, &mut cg)?;
        log_ir(env, func, "after coalescing");
    }

    let offset = cg.stack_offset;
    prepare::add_stack_offset(func, offset);

    alloc::remove_phi(env, func, &mut cg)?;
    log_ir(env, func, "after SSA-out");

    norm::normalize_and_emit(env, func, &mut cg)?;

    env.cg_time_ns += timer.elapsed_ns();
    Ok(())
}

fn log_ir(env: &mut Env, func: &Function, msg: &str) {
    if env.opts.verbose >= 2 {
        log_debug!(env, "----- CG: {} -----\n", msg);
        let txt = crate::ir::print::print_function(func);
        log_debug!(env, "{}", txt);
    }
}
