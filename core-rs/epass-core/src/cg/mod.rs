//! Code generation: IR → MIR → register allocation → SSA-out → frame
//! layout → block layout → bytecode (plus an old→new instruction map).

pub mod emit;
pub mod mir;
pub mod ra;
pub mod ssaout;

use crate::analysis::{frame_extent, Cfg, Magnitude, Provenance};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::facts::Isa;
use crate::ir::verify::verify;
use crate::ir::{Function, Op};
use crate::mem::FVec;

pub use emit::Encoded;

/// Codegen options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CgOptions {
    pub isa: Isa,
    pub big_endian: bool,
    /// Registers available to virtual registers (10; tests use fewer to
    /// force spilling).
    pub ra_colors: u8,
    /// Run the post-allocation checker.
    pub check: bool,
}

impl Default for CgOptions {
    fn default() -> Self {
        CgOptions {
            isa: Isa::V4,
            big_endian: false,
            ra_colors: 10,
            check: cfg!(debug_assertions),
        }
    }
}

/// Split every critical edge into a block that has phis, so that parallel
/// copies have a place on each edge.
pub fn split_critical_edges(f: &mut Function<'_>, ctx: &Ctx<'_>) -> Result<()> {
    let mut edges: FVec<'_, (crate::ir::BlockId, crate::ir::BlockId)> = FVec::new(f.heap());
    for p in f.blocks() {
        let succs = f.successors(p)?;
        if succs.len() < 2 {
            continue;
        }
        for &s in succs.as_slice() {
            ctx.tick()?;
            let has_phi = f
                .block(s)?
                .first()
                .is_some_and(|i| matches!(f.op(i), Ok(Op::Phi)));
            if has_phi && f.preds(s)?.len() >= 2 {
                edges.push((p, s))?;
            }
        }
    }
    for &(p, s) in edges.iter() {
        f.split_edge(p, s)?;
    }
    Ok(())
}

/// Compile a validated, finalized function to bytecode.
pub fn compile<'h>(f: &mut Function<'h>, ctx: &Ctx<'_>, o: &CgOptions) -> Result<Encoded<'h>> {
    split_critical_edges(f, ctx)?;
    verify(f, ctx, false)?;
    let cfg = Cfg::compute(f, ctx)?;
    let mag = Magnitude::compute(f, &cfg, ctx)?;
    let prov = Provenance::compute(f, &cfg, &mag, ctx)?;
    let ext = frame_extent(f, &prov, &cfg, ctx)?;
    let mut m = mir::lower(f, o.isa, o.big_endian)?;
    let alloc = ra::allocate(&mut m, o.ra_colors, ctx)?;
    if o.check {
        ra::check(&m, &alloc, ctx)?;
    }
    let moves = ssaout::build(&m, &alloc)?;
    let frame = emit::layout_frame(&m, ext, moves.uses_scratch)?;
    let order = emit::block_order(&m, alloc.order.as_slice())?;
    emit::encode(&m, &alloc, &moves, &frame, order.as_slice(), ctx.limits.max_insns, ctx)
}
