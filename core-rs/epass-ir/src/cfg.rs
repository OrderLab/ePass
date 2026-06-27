//! CFG postprocessing: compute the reachable-block chain layout and end blocks.
//!
//! ePass lays out basic blocks as *chains* so that conditional-jump
//! fallthrough targets (`bb1`) are physically adjacent, which the normalizer
//! relies on. This mirrors the C `add_reach` / `find_chain_head` logic.

use crate::env::Env;
use crate::error::Result;
use crate::internal;
use crate::ir::{BbId, Function, InsnKind};

/// Recompute `reachable_bbs` (chain layout) and `end_bbs`.
pub fn finalize(env: &mut Env, func: &mut Function) -> Result<()> {
    let _ = env;
    let order = reachable_chain_layout(func)?;
    func.reachable_bbs = order;
    func.end_bbs = func
        .reachable_bbs
        .iter()
        .copied()
        .filter(|&bb| func.bb(bb).succs.is_empty())
        .collect();
    Ok(())
}

/// Walk from a block back to the head of its fallthrough chain.
fn find_chain_head(func: &Function, mut bb: BbId) -> Result<BbId> {
    loop {
        let preds = &func.bb(bb).preds;
        if preds.is_empty() {
            return Ok(bb);
        }
        let mut chain_pred: Option<BbId> = None;
        for &p in preds.iter() {
            let succs = &func.bb(p).succs;
            match succs.len() {
                1 => {
                    // A `ja` edge is not a fallthrough chain edge.
                    let is_ja = func
                        .bb(p)
                        .last()
                        .map(|l| matches!(func.insn(l).kind, InsnKind::Ja))
                        .unwrap_or(false);
                    if !is_ja {
                        if chain_pred.is_some() {
                            return Err(internal!("multiple chain predecessors"));
                        }
                        chain_pred = Some(p);
                    }
                }
                2 => {
                    // Only the first successor (fallthrough) chains.
                    if func.bb(p).succs[0] == bb {
                        if chain_pred.is_some() {
                            return Err(internal!("multiple chain predecessors"));
                        }
                        chain_pred = Some(p);
                    }
                }
                _ => return Err(internal!("block has >2 successors")),
            }
        }
        match chain_pred {
            None => return Ok(bb),
            Some(p) => bb = p,
        }
    }
}

fn reachable_chain_layout(func: &Function) -> Result<Vec<BbId>> {
    let n = func.all_bbs.len();
    let mut visited = vec![false; func.bb_arena_len()];
    let mut layout = Vec::new();
    let mut todo = vec![func.entry];
    let mut head = 0;

    let _ = n;
    while head < todo.len() {
        let mut bb = todo[head];
        head += 1;
        if visited[bb.index()] {
            continue;
        }
        bb = find_chain_head(func, bb)?;
        if visited[bb.index()] {
            continue;
        }
        // Walk this chain.
        loop {
            visited[bb.index()] = true;
            layout.push(bb);
            let succs = &func.bb(bb).succs;
            match succs.len() {
                0 => break,
                1 => {
                    let is_ja = func
                        .bb(bb)
                        .last()
                        .map(|l| matches!(func.insn(l).kind, InsnKind::Ja))
                        .unwrap_or(false);
                    if is_ja {
                        todo.push(succs[0]);
                        break;
                    } else {
                        bb = succs[0];
                    }
                }
                2 => {
                    let s0 = succs[0];
                    let s1 = succs[1];
                    todo.push(s1);
                    bb = s0;
                }
                _ => return Err(internal!(">2 successors, invalid CFG")),
            }
        }
    }
    Ok(layout)
}
