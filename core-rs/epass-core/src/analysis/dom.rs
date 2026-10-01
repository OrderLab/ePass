//! Reverse postorder and dominators (Cooper, Harvey, Kennedy: "A Simple,
//! Fast Dominance Algorithm"), all iterative.

use core::fmt;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::ir::{BlockId, Function};
use crate::mem::{FVec, Idx, IdxVec};

const UNREACHED: u32 = u32::MAX;

/// Reachability and reverse postorder from the entry block.
pub struct Cfg<'h> {
    rpo: FVec<'h, BlockId>,
    /// Position in `rpo`, or UNREACHED.
    index: IdxVec<'h, BlockId, u32>,
}

impl fmt::Debug for Cfg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cfg").field("rpo", &self.rpo).finish()
    }
}

impl<'h> Cfg<'h> {
    pub fn compute(f: &Function<'h>, ctx: &Ctx<'h>) -> Result<Self> {
        let heap = f.heap();
        let n = f.block_id_bound();
        let mut index = IdxVec::filled(heap, n, UNREACHED)?;
        // state: 0 = new, 1 = on stack, 2 = done
        let mut state: IdxVec<'h, BlockId, u8> = IdxVec::filled(heap, n, 0)?;
        let mut post: FVec<'h, BlockId> = FVec::new(heap);
        // Explicit DFS stack of (block, next successor index).
        let mut stack: FVec<'h, (BlockId, u8)> = FVec::new(heap);
        let entry = f.entry();
        *state.at_mut(entry)? = 1;
        stack.push((entry, 0))?;
        while let Some(&(b, k)) = stack.last() {
            ctx.tick()?;
            let succs = f.successors(b)?;
            if let Some(&s) = succs.as_slice().get(k as usize) {
                if let Some(top) = stack.last_mut() {
                    top.1 = k.saturating_add(1);
                }
                if !f.is_block(s) {
                    return Err(Error::invalid_ir("branch to unknown block"));
                }
                if *state.at(s)? == 0 {
                    *state.at_mut(s)? = 1;
                    stack.push((s, 0))?;
                }
            } else {
                stack.pop();
                *state.at_mut(b)? = 2;
                post.push(b)?;
            }
        }
        let mut rpo = FVec::with_capacity(heap, post.len())?;
        for (i, &b) in post.iter().rev().enumerate() {
            rpo.push(b)?;
            *index.at_mut(b)? = i as u32;
        }
        Ok(Cfg { rpo, index })
    }

    /// Reachable blocks in reverse postorder (entry first).
    pub fn rpo(&self) -> &[BlockId] {
        self.rpo.as_slice()
    }

    pub fn is_reachable(&self, b: BlockId) -> bool {
        self.index.get(b).is_some_and(|&i| i != UNREACHED)
    }

    pub fn rpo_index(&self, b: BlockId) -> Option<u32> {
        self.index.get(b).copied().filter(|&i| i != UNREACHED)
    }
}

/// The dominator tree of the reachable blocks.
pub struct DomTree<'h> {
    idom: IdxVec<'h, BlockId, u32>,
    /// Pre/post numbers in the dominator tree, for O(1) dominance queries.
    pre: IdxVec<'h, BlockId, u32>,
    post: IdxVec<'h, BlockId, u32>,
}

impl fmt::Debug for DomTree<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomTree").finish()
    }
}

impl<'h> DomTree<'h> {
    pub fn compute(f: &Function<'h>, cfg: &Cfg<'h>, ctx: &Ctx<'h>) -> Result<Self> {
        let heap = f.heap();
        let n = f.block_id_bound();
        // idom by rpo index; UNREACHED = undefined.
        let rpo = cfg.rpo();
        let mut idom: FVec<'h, u32> = FVec::with_capacity(heap, rpo.len())?;
        idom.resize(rpo.len(), UNREACHED)?;
        if let Some(e) = idom.get_mut(0) {
            *e = 0;
        }
        let mut changed = true;
        while changed {
            changed = false;
            for (bi, &b) in rpo.iter().enumerate().skip(1) {
                ctx.tick()?;
                let mut new = UNREACHED;
                for &p in f.preds(b)? {
                    let Some(pi) = cfg.rpo_index(p) else { continue };
                    if *idom.get(pi as usize).ok_or(Error::internal("idom"))? == UNREACHED {
                        continue;
                    }
                    new = if new == UNREACHED {
                        pi
                    } else {
                        intersect(&idom, pi, new, ctx)?
                    };
                }
                let slot = idom.get_mut(bi).ok_or(Error::internal("idom"))?;
                if new != UNREACHED && *slot != new {
                    *slot = new;
                    changed = true;
                }
            }
        }
        // Store idom as block ids.
        let mut idom_b: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, n, UNREACHED)?;
        for (bi, &b) in rpo.iter().enumerate() {
            let d = *idom.get(bi).ok_or(Error::internal("idom"))?;
            let db = rpo.get(d as usize).ok_or(Error::internal("idom"))?;
            *idom_b.at_mut(b)? = db.to_u32();
        }
        // Children lists in CSR form, then an iterative DFS for pre/post.
        let mut child_count: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, n, 0)?;
        for &b in rpo.iter().skip(1) {
            let d = BlockId(*idom_b.at(b)?);
            let c = child_count.at_mut(d)?;
            *c = c.saturating_add(1);
        }
        let mut start: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, n + 1, 0)?;
        let mut acc = 0u32;
        for i in 0..n {
            *start.at_mut(BlockId(i as u32))? = acc;
            acc = acc.saturating_add(*child_count.at(BlockId(i as u32))?);
        }
        *start.at_mut(BlockId(n as u32))? = acc;
        let mut fill: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, n, 0)?;
        let mut children: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, acc as usize, 0)?;
        for &b in rpo.iter().skip(1) {
            let d = BlockId(*idom_b.at(b)?);
            let pos = *start.at(d)? + *fill.at(d)?;
            *children.at_mut(BlockId(pos))? = b.to_u32();
            *fill.at_mut(d)? += 1;
        }
        let mut pre = IdxVec::filled(heap, n, UNREACHED)?;
        let mut post = IdxVec::filled(heap, n, UNREACHED)?;
        let mut counter = 0u32;
        let mut stack: FVec<'h, (BlockId, u32)> = FVec::new(heap);
        if let Some(&e) = rpo.first() {
            *pre.at_mut(e)? = counter;
            counter += 1;
            stack.push((e, 0))?;
        }
        while let Some(&(b, k)) = stack.last() {
            ctx.tick()?;
            let s = *start.at(b)?;
            let end = *start.at(BlockId(b.to_u32() + 1))?;
            if s + k < end {
                if let Some(top) = stack.last_mut() {
                    top.1 = k + 1;
                }
                let c = BlockId(*children.at(BlockId(s + k))?);
                *pre.at_mut(c)? = counter;
                counter += 1;
                stack.push((c, 0))?;
            } else {
                stack.pop();
                *post.at_mut(b)? = counter;
                counter += 1;
            }
        }
        Ok(DomTree {
            idom: idom_b,
            pre,
            post,
        })
    }

    /// Immediate dominator (the entry block is its own).
    pub fn idom(&self, b: BlockId) -> Option<BlockId> {
        self.idom
            .get(b)
            .copied()
            .filter(|&d| d != UNREACHED)
            .map(BlockId)
    }

    /// Whether `a` dominates `b` (reflexive). False if either is
    /// unreachable.
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        match (
            self.pre.get(a),
            self.post.get(a),
            self.pre.get(b),
            self.post.get(b),
        ) {
            (Some(&pa), Some(&qa), Some(&pb), Some(&qb)) => {
                pa != UNREACHED && pb != UNREACHED && pa <= pb && qb <= qa
            }
            _ => false,
        }
    }
}

fn intersect(idom: &FVec<'_, u32>, mut a: u32, mut b: u32, ctx: &Ctx<'_>) -> Result<u32> {
    while a != b {
        ctx.tick()?;
        while a > b {
            a = *idom.get(a as usize).ok_or(Error::internal("idom"))?;
        }
        while b > a {
            b = *idom.get(b as usize).ok_or(Error::internal("idom"))?;
        }
    }
    Ok(a)
}
