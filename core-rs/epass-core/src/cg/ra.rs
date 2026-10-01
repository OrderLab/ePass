//! Liveness, interference and register allocation on MIR.
//!
//! The allocator is the v1 design kept for v2: an interference graph,
//! maximum-cardinality-search (MCS) order, greedy coloring, and a
//! post-spill fallback (spill everywhere, then rebuild and recolor) because
//! fixed-register and two-address constraints make the graph non-chordal.
//! Every structure is iterative and bounded; a failure to converge is
//! `Error::RegAlloc`, never an internal panic.

use super::mir::{MFunc, MOp, PVal, Src, VReg, NREG};
use crate::ctx::Ctx;
use crate::error::{Error, ErrorKind, Result};
use crate::ir::BlockId;
use crate::mem::{FVec, IdxVec, SparseSet};

/// "No color".
pub const NOCOLOR: u8 = u8::MAX;

/// Per-block liveness (sorted vreg ids).
pub struct Liveness<'h> {
    pub live_in: IdxVec<'h, BlockId, FVec<'h, u32>>,
    pub live_out: IdxVec<'h, BlockId, FVec<'h, u32>>,
}

impl core::fmt::Debug for Liveness<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Liveness").finish()
    }
}

fn sorted_union(dst: &mut FVec<'_, u32>, src: &[u32]) -> Result<bool> {
    let mut changed = false;
    for &v in src {
        if let Err(pos) = dst.as_slice().binary_search(&v) {
            dst.insert(pos, v)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Blocks in reverse postorder of the MIR CFG.
pub fn rpo<'h>(m: &MFunc<'h>, ctx: &Ctx<'_>) -> Result<FVec<'h, BlockId>> {
    let heap = m.heap;
    let n = m.blocks.len();
    let mut state: IdxVec<'h, BlockId, u8> = IdxVec::filled(heap, n, 0)?;
    let mut post: FVec<'h, BlockId> = FVec::new(heap);
    let mut stack: FVec<'h, (BlockId, u8)> = FVec::new(heap);
    stack.push((m.entry, 0))?;
    *state.at_mut(m.entry)? = 1;
    while let Some(&(b, k)) = stack.last() {
        ctx.tick()?;
        let s = m.successors(b)?;
        if let Some(&x) = s.as_slice().get(k as usize) {
            if let Some(t) = stack.last_mut() {
                t.1 = k + 1;
            }
            if *state.at(x)? == 0 {
                *state.at_mut(x)? = 1;
                stack.push((x, 0))?;
            }
        } else {
            stack.pop();
            post.push(b)?;
        }
    }
    let mut out = FVec::with_capacity(heap, post.len())?;
    for &b in post.iter().rev() {
        out.push(b)?;
    }
    Ok(out)
}

impl<'h> Liveness<'h> {
    pub fn compute(m: &MFunc<'h>, order: &[BlockId], ctx: &Ctx<'_>) -> Result<Self> {
        let heap = m.heap;
        let nb = m.blocks.len();
        let mut gen: IdxVec<'h, BlockId, FVec<'h, u32>> = IdxVec::new(heap);
        let mut kill: IdxVec<'h, BlockId, FVec<'h, u32>> = IdxVec::new(heap);
        let mut live_in: IdxVec<'h, BlockId, FVec<'h, u32>> = IdxVec::new(heap);
        let mut live_out: IdxVec<'h, BlockId, FVec<'h, u32>> = IdxVec::new(heap);
        for _ in 0..nb {
            gen.push(FVec::new(heap))?;
            kill.push(FVec::new(heap))?;
            live_in.push(FVec::new(heap))?;
            live_out.push(FVec::new(heap))?;
        }
        let mut defs = [VReg(0); 8];
        let mut uses = [VReg(0); 8];
        for &b in order {
            let mb = m.block(b)?;
            let g = gen.at_mut(b)?;
            let mut killed: FVec<'h, u32> = FVec::new(heap);
            for p in mb.phis.iter().filter(|p| p.slot.is_none()) {
                sorted_union(&mut killed, &[p.dst.0])?;
            }
            for ins in mb.insns.iter() {
                ctx.tick()?;
                let nu = ins.op.uses(&mut uses);
                for &u in uses.get(..nu).unwrap_or(&[]) {
                    if killed.as_slice().binary_search(&u.0).is_err() {
                        sorted_union(g, &[u.0])?;
                    }
                }
                let nd = ins.op.defs(&mut defs);
                for &d in defs.get(..nd).unwrap_or(&[]) {
                    sorted_union(&mut killed, &[d.0])?;
                }
            }
            *kill.at_mut(b)? = killed;
        }
        // Backward dataflow in reverse RPO until stable.
        let mut changed = true;
        let mut tmp: FVec<'h, u32> = FVec::new(heap);
        while changed {
            changed = false;
            for &b in order.iter().rev() {
                ctx.tick()?;
                tmp.clear();
                for &s in m.successors(b)?.as_slice() {
                    let sb = m.block(s)?;
                    // live_in(s) minus s's phi defs, plus s's phi inputs from b.
                    for &v in live_in.at(s)?.iter() {
                        if !sb.phis.iter().any(|p| p.slot.is_none() && p.dst.0 == v) {
                            sorted_union(&mut tmp, &[v])?;
                        }
                    }
                    for p in sb.phis.iter() {
                        for &(pb, pv) in p.inputs.iter() {
                            if pb == b {
                                if let PVal::V(v) = pv {
                                    sorted_union(&mut tmp, &[v.0])?;
                                }
                            }
                        }
                    }
                }
                let out = live_out.at_mut(b)?;
                if out.as_slice() != tmp.as_slice() {
                    out.clear();
                    out.extend_from_slice(tmp.as_slice())?;
                    changed = true;
                }
                // in = gen ∪ (out − kill) ∪ phi defs
                let mut inn: FVec<'h, u32> = gen.at(b)?.try_clone()?;
                let k = kill.at(b)?;
                let mb = m.block(b)?;
                for &v in tmp.iter() {
                    if k.as_slice().binary_search(&v).is_err() {
                        sorted_union(&mut inn, &[v])?;
                    }
                }
                for p in mb.phis.iter().filter(|p| p.slot.is_none()) {
                    sorted_union(&mut inn, &[p.dst.0])?;
                }
                let li = live_in.at_mut(b)?;
                if li.as_slice() != inn.as_slice() {
                    *li = inn;
                    changed = true;
                }
            }
        }
        Ok(Liveness { live_in, live_out })
    }
}

/// The interference graph.
pub struct Graph<'h> {
    pub adj: IdxVec<'h, VReg, FVec<'h, u32>>,
}

impl core::fmt::Debug for Graph<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Graph").field("nodes", &self.adj.len()).finish()
    }
}

impl<'h> Graph<'h> {
    fn edge(&mut self, a: VReg, b: VReg) -> Result<()> {
        if a == b || (a.is_fixed() && b.is_fixed()) {
            return Ok(());
        }
        self.adj.at_mut(a)?.push(b.0)?;
        self.adj.at_mut(b)?.push(a.0)
    }

    pub fn build(m: &MFunc<'h>, live: &Liveness<'h>, order: &[BlockId], ctx: &Ctx<'_>) -> Result<Self> {
        let heap = m.heap;
        let n = m.nvregs();
        let mut g = Graph {
            adj: IdxVec::new(heap),
        };
        for _ in 0..n {
            g.adj.push(FVec::new(heap))?;
        }
        let mut cur = SparseSet::new(heap, n)?;
        let mut defs = [VReg(0); 8];
        let mut uses = [VReg(0); 8];
        let mut tmp: FVec<'h, u32> = FVec::new(heap);
        for &b in order {
            cur.clear();
            for &v in live.live_out.at(b)?.iter() {
                cur.insert(v)?;
            }
            let mb = m.block(b)?;
            for ins in mb.insns.iter().rev() {
                ctx.tick()?;
                let nd = ins.op.defs(&mut defs);
                let nu = ins.op.uses(&mut uses);
                // A copy's destination does not interfere with its source
                // (they hold the same value; any later redefinition of
                // either creates the edge there).
                let copy_src = match ins.op {
                    MOp::Copy { src: Src::V(s), .. } => Some(s),
                    _ => None,
                };
                tmp.clear();
                for v in cur.iter() {
                    tmp.push(v)?;
                }
                for &d in defs.get(..nd).unwrap_or(&[]) {
                    for &l in tmp.iter() {
                        let lv = VReg(l);
                        if Some(lv) != copy_src {
                            g.edge(d, lv)?;
                        }
                    }
                }
                // Two-address: `dst = a op b` is emitted `dst = a; dst op= b`,
                // so for a non-commutative op dst must differ from b.
                if let MOp::Alu { op, dst, a, b: Src::V(bv), .. } = ins.op {
                    if !op.is_commutative() && bv != a {
                        g.edge(dst, bv)?;
                    }
                }
                for &d in defs.get(..nd).unwrap_or(&[]) {
                    cur.remove(d.0);
                }
                for &u in uses.get(..nu).unwrap_or(&[]) {
                    cur.insert(u.0)?;
                }
            }
            // Phi defs at block entry: simultaneous with each other and
            // with everything live there.
            tmp.clear();
            for v in cur.iter() {
                tmp.push(v)?;
            }
            for p in mb.phis.iter().filter(|p| p.slot.is_none()) {
                if !tmp.as_slice().contains(&p.dst.0) {
                    tmp.push(p.dst.0)?;
                }
            }
            for p in mb.phis.iter().filter(|p| p.slot.is_none()) {
                for &l in tmp.iter() {
                    g.edge(p.dst, VReg(l))?;
                }
            }
        }
        for v in 0..n as u32 {
            let a = g.adj.at_mut(VReg(v))?;
            a.as_mut_slice().sort_unstable();
            dedup(a);
        }
        Ok(g)
    }

    pub fn neighbors(&self, v: VReg) -> &[u32] {
        self.adj.get(v).map_or(&[], |a| a.as_slice())
    }
}

fn dedup(v: &mut FVec<'_, u32>) {
    let mut w = 0usize;
    let n = v.len();
    let s = v.as_mut_slice();
    for r in 0..n {
        let x = *s.get(r).unwrap_or(&0);
        if w == 0 || s.get(w - 1) != Some(&x) {
            if let Some(slot) = s.get_mut(w) {
                *slot = x;
            }
            w += 1;
        }
    }
    v.truncate(w);
}

/// Maximum cardinality search order over non-fixed vregs, O(V + E) with a
/// bucket queue.
fn mcs<'h>(m: &MFunc<'h>, g: &Graph<'h>, ctx: &Ctx<'_>) -> Result<FVec<'h, VReg>> {
    let heap = m.heap;
    let n = m.nvregs();
    let mut weight: IdxVec<'h, VReg, u32> = IdxVec::filled(heap, n, 0)?;
    let mut done: IdxVec<'h, VReg, bool> = IdxVec::filled(heap, n, false)?;
    // Bucket lists: head[w], next/prev per node.
    let none = u32::MAX;
    let maxw = n + 1;
    let mut head: IdxVec<'h, VReg, u32> = IdxVec::filled(heap, maxw, none)?;
    let mut next: IdxVec<'h, VReg, u32> = IdxVec::filled(heap, n, none)?;
    let mut prev: IdxVec<'h, VReg, u32> = IdxVec::filled(heap, n, none)?;
    let link = |head: &mut IdxVec<'h, VReg, u32>, next: &mut IdxVec<'h, VReg, u32>, prev: &mut IdxVec<'h, VReg, u32>, v: u32, w: u32| -> Result<()> {
        let h = *head.at(VReg(w))?;
        *next.at_mut(VReg(v))? = h;
        *prev.at_mut(VReg(v))? = none;
        if h != none {
            *prev.at_mut(VReg(h))? = v;
        }
        *head.at_mut(VReg(w))? = v;
        Ok(())
    };
    let unlink = |head: &mut IdxVec<'h, VReg, u32>, next: &mut IdxVec<'h, VReg, u32>, prev: &mut IdxVec<'h, VReg, u32>, v: u32, w: u32| -> Result<()> {
        let (nx, pv) = (*next.at(VReg(v))?, *prev.at(VReg(v))?);
        if pv != none {
            *next.at_mut(VReg(pv))? = nx;
        } else {
            *head.at_mut(VReg(w))? = nx;
        }
        if nx != none {
            *prev.at_mut(VReg(nx))? = pv;
        }
        Ok(())
    };
    let mut count = 0usize;
    for v in NREG..n as u32 {
        link(&mut head, &mut next, &mut prev, v, 0)?;
        count += 1;
    }
    // Fixed registers are "already ordered": their neighbors start heavier.
    for r in 0..NREG {
        *done.at_mut(VReg(r))? = true;
        for &u in g.neighbors(VReg(r)) {
            if !*done.at(VReg(u))? {
                let w = *weight.at(VReg(u))?;
                unlink(&mut head, &mut next, &mut prev, u, w)?;
                *weight.at_mut(VReg(u))? = w + 1;
                link(&mut head, &mut next, &mut prev, u, w + 1)?;
            }
        }
    }
    let mut out = FVec::with_capacity(heap, count)?;
    let mut top = maxw.saturating_sub(1) as u32;
    while out.len() < count {
        ctx.tick()?;
        while top > 0 && *head.at(VReg(top))? == none {
            top -= 1;
        }
        let v = *head.at(VReg(top))?;
        if v == none {
            return Err(Error::internal("mcs bucket underflow"));
        }
        unlink(&mut head, &mut next, &mut prev, v, top)?;
        *done.at_mut(VReg(v))? = true;
        out.push(VReg(v))?;
        for &u in g.neighbors(VReg(v)) {
            if !*done.at(VReg(u))? {
                let w = *weight.at(VReg(u))?;
                unlink(&mut head, &mut next, &mut prev, u, w)?;
                *weight.at_mut(VReg(u))? = w + 1;
                link(&mut head, &mut next, &mut prev, u, w + 1)?;
                if w + 1 > top {
                    top = w + 1;
                }
            }
        }
    }
    Ok(out)
}

/// Spill `v` everywhere: store after its def, reload before each use.
fn spill(m: &mut MFunc<'_>, v: VReg, order: &[BlockId], ctx: &Ctx<'_>) -> Result<()> {
    let slot = m.spill_slots;
    m.spill_slots = m
        .spill_slots
        .checked_add(1)
        .ok_or(Error::new(ErrorKind::NoStack, "too many spill slots"))?;
    m.vregs.at_mut(v)?.spilled = Some(slot);
    let sslot = super::mir::MSlot::Spill(slot);
    let heap = m.heap;
    let mut defs = [VReg(0); 8];
    let mut uses = [VReg(0); 8];
    for &b in order {
        ctx.tick()?;
        // A spilled phi becomes a memory phi: no register at all.
        for p in m.block_mut(b)?.phis.iter_mut() {
            if p.dst == v {
                p.slot = Some(sslot);
            }
        }
        let mut out: FVec<'_, super::mir::MInsn> = FVec::new(heap);
        let old = core::mem::replace(&mut m.block_mut(b)?.insns, FVec::new(heap));
        for ins in old.iter() {
            let nu = ins.op.uses(&mut uses);
            let mut op = ins.op;
            if uses.get(..nu).unwrap_or(&[]).contains(&v) {
                let t = m.new_vreg()?;
                m.vregs.at_mut(t)?.unspillable = true;
                out.push(super::mir::MInsn {
                    op: MOp::SlotLoad { dst: t, slot: sslot },
                    origin: ins.origin,
                })?;
                op.replace_use(v, t);
            }
            out.push(super::mir::MInsn { op, origin: ins.origin })?;
            let nd = ins.op.defs(&mut defs);
            if defs.get(..nd).unwrap_or(&[]).contains(&v) {
                out.push(super::mir::MInsn {
                    op: MOp::SlotStore { slot: sslot, src: v },
                    origin: ins.origin,
                })?;
            }
        }
        m.block_mut(b)?.insns = out;
    }
    // Phi inputs: the edge copy loads straight from the slot (no reload
    // temporary, so many spilled inputs on one edge need no registers).
    for &s in order {
        let mb = m.block_mut(s)?;
        for p in mb.phis.iter_mut() {
            for inp in p.inputs.iter_mut() {
                if inp.1 == PVal::V(v) {
                    inp.1 = PVal::Slot(sslot);
                }
            }
        }
    }
    Ok(())
}

/// Allocation result.
pub struct Alloc<'h> {
    pub color: IdxVec<'h, VReg, u8>,
    pub live: Liveness<'h>,
    pub order: FVec<'h, BlockId>,
    pub rounds: u32,
}

impl core::fmt::Debug for Alloc<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Alloc").field("rounds", &self.rounds).finish()
    }
}

/// Color all vregs, spilling as needed. `colors` limits the registers
/// available to virtual registers (10 normally; tests force spills).
pub fn allocate<'h>(m: &mut MFunc<'h>, colors: u8, ctx: &Ctx<'_>) -> Result<Alloc<'h>> {
    let heap = m.heap;
    let colors = colors.clamp(1, NREG as u8);
    let max_rounds = 64u32;
    let mut rounds = 0u32;
    // The first round's graph: a spilled value's slot is live exactly where
    // the value was live originally, so it decides which slots may be shared.
    let mut first: Option<Graph<'h>> = None;
    loop {
        rounds += 1;
        if rounds > max_rounds {
            return Err(Error::new(ErrorKind::RegAlloc, "register allocation did not converge"));
        }
        let order = rpo(m, ctx)?;
        let live = Liveness::compute(m, order.as_slice(), ctx)?;
        let g = Graph::build(m, &live, order.as_slice(), ctx)?;
        if first.is_none() {
            first = Some(Graph::build(m, &live, order.as_slice(), ctx)?);
        }
        let seo = mcs(m, &g, ctx)?;
        let n = m.nvregs();
        let mut color: IdxVec<'h, VReg, u8> = IdxVec::filled(heap, n, NOCOLOR)?;
        for r in 0..NREG {
            *color.at_mut(VReg(r))? = r as u8;
        }
        let mut failed: FVec<'h, VReg> = FVec::new(heap);
        for &v in seo.iter() {
            ctx.tick()?;
            let mut used = 0u16;
            for &u in g.neighbors(v) {
                let c = *color.at(VReg(u))?;
                if c != NOCOLOR {
                    used |= 1 << c;
                }
            }
            let hint = m
                .vregs
                .get(v)
                .and_then(|i| i.hint)
                .filter(|&h| h < colors && used & (1 << h) == 0);
            let free = hint.or_else(|| (0..colors).find(|&c| used & (1 << c) == 0));
            match free {
                Some(c) => *color.at_mut(v)? = c,
                None => failed.push(v)?,
            }
        }
        if failed.is_empty() {
            coalesce(m, &g, &mut color, colors, ctx)?;
            if let Some(g1) = first.as_ref() {
                share_slots(m, g1, ctx)?;
            }
            return Ok(Alloc {
                color,
                live,
                order,
                rounds,
            });
        }
        // Post-spill: each failed node, or its heaviest spillable neighbor.
        let mut victims: FVec<'h, VReg> = FVec::new(heap);
        for &v in failed.iter() {
            let spillable = |x: VReg, m: &MFunc<'_>| -> bool {
                !x.is_fixed()
                    && m.vregs.get(x).is_some_and(|i| !i.unspillable && i.spilled.is_none())
            };
            let pick = if spillable(v, m) {
                Some(v)
            } else {
                let mut best: Option<(usize, VReg)> = None;
                for &u in g.neighbors(v) {
                    let uv = VReg(u);
                    if spillable(uv, m) && !victims.as_slice().contains(&uv) {
                        let deg = g.neighbors(uv).len();
                        if best.is_none_or(|(d, _)| deg > d) {
                            best = Some((deg, uv));
                        }
                    }
                }
                best.map(|(_, u)| u)
            };
            let neighbor_already_chosen = g
                .neighbors(v)
                .iter()
                .any(|&u| victims.as_slice().contains(&VReg(u)));
            match pick {
                Some(x) => {
                    victims.push_unique(x)?;
                }
                // A neighbor is already being spilled this round; that frees
                // a color for `v` next round.
                None if neighbor_already_chosen => {}
                None => {
                    crate::ctx_log!(
                        ctx,
                        crate::Level::Debug,
                        "ra: v{} uncolorable (unspillable={}), {} neighbors:",
                        v.0,
                        m.vregs.get(v).is_some_and(|i| i.unspillable),
                        g.neighbors(v).len()
                    );
                    for &u in g.neighbors(v) {
                        crate::ctx_log!(
                            ctx,
                            crate::Level::Debug,
                            " v{}:c{}:{}",
                            u,
                            color.get(VReg(u)).copied().unwrap_or(NOCOLOR),
                            if m.vregs.get(VReg(u)).is_some_and(|i| i.unspillable) { "u" } else { "s" }
                        );
                    }
                    crate::ctx_log!(ctx, crate::Level::Debug, "\n");
                    super::mir::dump(m, ctx);
                    return Err(Error::new(
                        ErrorKind::RegAlloc,
                        "coloring failed and no value can be spilled",
                    ));
                }
            }
        }
        for &x in victims.iter() {
            spill(m, x, order.as_slice(), ctx)?;
        }
    }
}

/// Color spill slots: spilled values that never interfered share a slot.
fn share_slots<'h>(m: &mut MFunc<'h>, g1: &Graph<'h>, ctx: &Ctx<'_>) -> Result<()> {
    use super::mir::MSlot;
    let heap = m.heap;
    let old_n = m.spill_slots as usize;
    if old_n == 0 {
        return Ok(());
    }
    // old slot -> vreg, and the new assignment.
    let mut owner: IdxVec<'h, VReg, u32> = IdxVec::filled(heap, old_n, u32::MAX)?;
    for v in 0..m.nvregs() as u32 {
        if let Some(k) = m.vregs.get(VReg(v)).and_then(|i| i.spilled) {
            *owner.at_mut(VReg(k))? = v;
        }
    }
    let mut new_of: IdxVec<'h, VReg, u32> = IdxVec::filled(heap, old_n, u32::MAX)?;
    let mut new_n = 0u32;
    let mut used: FVec<'h, bool> = FVec::new(heap);
    for k in 0..old_n as u32 {
        ctx.tick()?;
        let v = *owner.at(VReg(k))?;
        used.clear();
        used.resize(new_n as usize, false)?;
        for &u in g1.neighbors(VReg(v)) {
            if let Some(ku) = m.vregs.get(VReg(u)).and_then(|i| i.spilled) {
                let nu = *new_of.at(VReg(ku))?;
                if let Some(x) = used.get_mut(nu as usize) {
                    *x = true;
                }
            }
        }
        let pick = (0..new_n).find(|&c| !*used.get(c as usize).unwrap_or(&true)).unwrap_or(new_n);
        if pick == new_n {
            new_n += 1;
        }
        *new_of.at_mut(VReg(k))? = pick;
    }
    let remap = |s: MSlot, new_of: &IdxVec<'h, VReg, u32>| -> Result<MSlot> {
        Ok(match s {
            MSlot::Spill(k) => MSlot::Spill(*new_of.at(VReg(k))?),
            other => other,
        })
    };
    for b in m.block_ids().collect_ids(heap)?.iter() {
        let mb = m.block_mut(*b)?;
        for ins in mb.insns.iter_mut() {
            match &mut ins.op {
                MOp::SlotLoad { slot, .. } | MOp::SlotStore { slot, .. } | MOp::FrameAddr { slot, .. } => {
                    *slot = remap(*slot, &new_of)?;
                }
                _ => {}
            }
        }
        for p in mb.phis.iter_mut() {
            if let Some(sl) = p.slot {
                p.slot = Some(remap(sl, &new_of)?);
            }
            for inp in p.inputs.iter_mut() {
                if let PVal::Slot(sl) = inp.1 {
                    inp.1 = PVal::Slot(remap(sl, &new_of)?);
                }
            }
        }
    }
    for v in 0..m.nvregs() as u32 {
        if let Some(info) = m.vregs.get_mut(VReg(v)) {
            if let Some(k) = info.spilled {
                info.spilled = Some(*new_of.at(VReg(k))?);
            }
        }
    }
    m.spill_slots = new_n;
    Ok(())
}

trait CollectIds {
    fn collect_ids<'h>(self, heap: &'h crate::mem::Heap<'h>) -> Result<FVec<'h, BlockId>>;
}

impl<I: Iterator<Item = BlockId>> CollectIds for I {
    fn collect_ids<'h>(self, heap: &'h crate::mem::Heap<'h>) -> Result<FVec<'h, BlockId>> {
        let mut v = FVec::new(heap);
        for b in self {
            v.push(b)?;
        }
        Ok(v)
    }
}

/// Give copy-related vregs the same color when no neighbor forbids it.
fn coalesce<'h>(m: &MFunc<'h>, g: &Graph<'h>, color: &mut IdxVec<'h, VReg, u8>, colors: u8, ctx: &Ctx<'_>) -> Result<()> {
    let mut pairs: FVec<'h, (VReg, VReg)> = FVec::new(m.heap);
    for b in m.block_ids() {
        let mb = m.block(b)?;
        for ins in mb.insns.iter() {
            match ins.op {
                MOp::Copy { dst, src: Src::V(s) } => pairs.push((dst, s))?,
                MOp::Alu { dst, a, .. }
                | MOp::Neg { dst, a, .. }
                | MOp::Bswap { dst, a, .. } => pairs.push((dst, a))?,
                _ => {}
            }
        }
        for p in mb.phis.iter().filter(|p| p.slot.is_none()) {
            for &(_, v) in p.inputs.iter() {
                if let PVal::V(v) = v {
                    pairs.push((p.dst, v))?;
                }
            }
        }
    }
    for _round in 0..2 {
        for &(a, b) in pairs.iter() {
            ctx.tick()?;
            let (ca, cb) = (*color.at(a)?, *color.at(b)?);
            if ca == cb || ca == NOCOLOR || cb == NOCOLOR {
                continue;
            }
            if g.neighbors(a).contains(&b.0) {
                continue;
            }
            let free_for = |x: VReg, c: u8, color: &IdxVec<'h, VReg, u8>| -> bool {
                c < colors
                    && g
                        .neighbors(x)
                        .iter()
                        .all(|&u| color.get(VReg(u)).copied() != Some(c))
            };
            if !a.is_fixed() && free_for(a, cb, color) {
                *color.at_mut(a)? = cb;
            } else if !b.is_fixed() && free_for(b, ca, color) {
                *color.at_mut(b)? = ca;
            }
        }
    }
    Ok(())
}

/// Post-allocation checker: no interfering pair shares a color, every
/// referenced vreg is colored, and the two-address constraint holds.
pub fn check<'h>(m: &MFunc<'h>, a: &Alloc<'h>, ctx: &Ctx<'_>) -> Result<()> {
    let g = Graph::build(m, &a.live, a.order.as_slice(), ctx)?;
    for v in 0..m.nvregs() as u32 {
        let cv = *a.color.at(VReg(v))?;
        for &u in g.neighbors(VReg(v)) {
            let cu = *a.color.at(VReg(u))?;
            if cv != NOCOLOR && cv == cu {
                return Err(Error::internal("allocation check: interfering values share a register"));
            }
        }
    }
    let mut uses = [VReg(0); 8];
    for b in m.block_ids() {
        for ins in m.block(b)?.insns.iter() {
            let nu = ins.op.uses(&mut uses);
            for &u in uses.get(..nu).unwrap_or(&[]) {
                if *a.color.at(u)? == NOCOLOR {
                    return Err(Error::internal("allocation check: use of an uncolored value"));
                }
            }
        }
    }
    Ok(())
}
