//! SSA destruction after register allocation.
//!
//! For every edge P→S into a block with phis, the phi copies form one
//! parallel copy `{loc(φ) ← input}` where a location is a register or, for
//! a spilled ("memory") phi, a stack slot. Critical edges are split before
//! lowering, so the copy goes either at the end of P (P has one successor)
//! or at the start of S (S has one predecessor).
//!
//! Sequentialization: emit a move whose destination no pending move still
//! reads; when only cycles remain, save one destination (in a free register,
//! else in the `Scratch` slot) and redirect its readers. Slot-to-slot and
//! wide-constant-to-slot moves go through a temporary register; if none is
//! free, one register is saved in `Scratch2` around the move. XOR swaps are
//! never used (the verifier forbids them on pointers).

use super::mir::{MFunc, MSlot, PVal};
use super::ra::{Alloc, NOCOLOR};
use crate::error::{Error, Result};
use crate::ir::BlockId;
use crate::mem::{FVec, Heap, IdxVec};

/// A copy location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loc {
    Reg(u8),
    Slot(MSlot),
}

/// Source of a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PSrc {
    Loc(Loc),
    /// `mov64 dst, imm` (sign-extended).
    Imm(i32),
    /// `mov32 dst, imm` (zero-extended).
    Imm32(i32),
    /// `lddw dst, imm64`.
    Ld64(u64),
    Fp,
}

/// One emitted machine move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PMove {
    /// Register destination: `mov`, `mov32`, `lddw`, or `ldxdw` from a slot.
    Mov { dst: u8, src: PSrc },
    /// `stxdw [slot], src`.
    Store { slot: MSlot, src: u8 },
    /// `stdw [slot], imm`.
    StoreImm { slot: MSlot, imm: i32 },
}

/// Moves to emit at the start and at the end (before the terminator) of
/// each block.
#[derive(Debug)]
pub struct EdgeMoves<'h> {
    pub at_start: IdxVec<'h, BlockId, FVec<'h, PMove>>,
    pub at_end: IdxVec<'h, BlockId, FVec<'h, PMove>>,
    /// The scratch slots are needed.
    pub uses_scratch: bool,
}

fn const_src(c: u64) -> PSrc {
    if c == c as i32 as i64 as u64 {
        PSrc::Imm(c as i32)
    } else if c >> 32 == 0 {
        PSrc::Imm32(c as u32 as i32)
    } else {
        PSrc::Ld64(c)
    }
}

struct Seq<'o, 'h> {
    out: &'o mut FVec<'h, PMove>,
    busy: u16,
    scratch: bool,
}

impl Seq<'_, '_> {
    fn free_reg(&self) -> Option<u8> {
        (0..10u8).find(|&r| self.busy & (1 << r) == 0)
    }

    /// Emit `dst ← src` for a destination no pending move reads.
    fn emit(&mut self, dst: Loc, src: PSrc) -> Result<()> {
        match dst {
            Loc::Reg(d) => self.out.push(PMove::Mov { dst: d, src }),
            Loc::Slot(s) => match src {
                PSrc::Loc(Loc::Reg(r)) => self.out.push(PMove::Store { slot: s, src: r }),
                PSrc::Imm(i) => self.out.push(PMove::StoreImm { slot: s, imm: i }),
                PSrc::Fp => self.out.push(PMove::Store { slot: s, src: 10 }),
                PSrc::Loc(Loc::Slot(_)) | PSrc::Imm32(_) | PSrc::Ld64(_) => {
                    if let Some(t) = self.free_reg() {
                        self.out.push(PMove::Mov { dst: t, src })?;
                        self.out.push(PMove::Store { slot: s, src: t })
                    } else {
                        // Borrow r0 around the move.
                        self.scratch = true;
                        self.out.push(PMove::Store {
                            slot: MSlot::Scratch2,
                            src: 0,
                        })?;
                        self.out.push(PMove::Mov { dst: 0, src })?;
                        self.out.push(PMove::Store { slot: s, src: 0 })?;
                        self.out.push(PMove::Mov {
                            dst: 0,
                            src: PSrc::Loc(Loc::Slot(MSlot::Scratch2)),
                        })
                    }
                }
            },
        }
    }
}

/// Sequentialize a parallel copy. `busy` marks registers holding live
/// values (they must not be used as temporaries). Returns whether a scratch
/// slot is needed.
pub fn sequentialize<'h>(
    heap: &'h Heap<'h>,
    moves: &[(Loc, PSrc)],
    busy: u16,
    out: &mut FVec<'h, PMove>,
) -> Result<bool> {
    // Every register the copy mentions (identity moves included) holds a
    // value that is needed: none may serve as a temporary.
    let mut busy = busy;
    for &(d, s) in moves {
        if let Loc::Reg(r) = d {
            busy |= 1 << r;
        }
        if let PSrc::Loc(Loc::Reg(r)) = s {
            busy |= 1 << r;
        }
    }
    let mut pending: FVec<'h, (Loc, PSrc)> = FVec::new(heap);
    for &(d, s) in moves {
        if pending.iter().any(|&(pd, _)| pd == d) {
            return Err(Error::internal("parallel copy writes a location twice"));
        }
        if s == PSrc::Loc(d) {
            continue;
        }
        pending.push((d, s))?;
    }
    let mut seq = Seq {
        out,
        busy,
        scratch: false,
    };
    let mut guard = 0usize;
    while !pending.is_empty() {
        guard += 1;
        if guard > 4 * moves.len() + 8 {
            return Err(Error::internal("parallel copy did not terminate"));
        }
        let ready = (0..pending.len()).find(|&i| {
            let d = pending.get(i).map(|m| m.0);
            !pending
                .iter()
                .enumerate()
                .any(|(j, &(_, s))| j != i && Some(s) == d.map(PSrc::Loc))
        });
        if let Some(i) = ready {
            if let Some((d, s)) = pending.swap_remove(i) {
                seq.emit(d, s)?;
                // A register destination now holds a pending-free value.
                if let PSrc::Loc(Loc::Reg(r)) = s {
                    if !pending.iter().any(|&(_, s2)| s2 == PSrc::Loc(Loc::Reg(r)))
                        && !pending.iter().any(|&(d2, _)| d2 == Loc::Reg(r))
                        && busy & (1 << r) == 0
                    {
                        seq.busy &= !(1 << r);
                    }
                }
            }
            continue;
        }
        // Only cycles remain: save one destination's current value.
        let (d, _) = *pending.first().ok_or(Error::internal("parallel copy"))?;
        if pending
            .iter()
            .any(|&(_, s)| s == PSrc::Loc(Loc::Slot(MSlot::Scratch)))
        {
            return Err(Error::internal("scratch slot still in use"));
        }
        let saved = match seq.free_reg() {
            Some(t) => {
                seq.out.push(PMove::Mov {
                    dst: t,
                    src: PSrc::Loc(d),
                })?;
                seq.busy |= 1 << t;
                Loc::Reg(t)
            }
            None => {
                seq.scratch = true;
                seq.emit(Loc::Slot(MSlot::Scratch), PSrc::Loc(d))?;
                Loc::Slot(MSlot::Scratch)
            }
        };
        for m in pending.iter_mut() {
            if m.1 == PSrc::Loc(d) {
                m.1 = PSrc::Loc(saved);
            }
        }
    }
    Ok(seq.scratch)
}

pub fn build<'h>(m: &MFunc<'h>, a: &Alloc<'h>) -> Result<EdgeMoves<'h>> {
    let heap = m.heap;
    let nb = m.blocks.len();
    let mut at_start: IdxVec<'h, BlockId, FVec<'h, PMove>> = IdxVec::new(heap);
    let mut at_end: IdxVec<'h, BlockId, FVec<'h, PMove>> = IdxVec::new(heap);
    for _ in 0..nb {
        at_start.push(FVec::new(heap))?;
        at_end.push(FVec::new(heap))?;
    }
    let mut uses_scratch = false;
    let color = |v: super::mir::VReg| -> Result<u8> {
        match a.color.get(v).copied() {
            Some(c) if c != NOCOLOR => Ok(c),
            _ => Err(Error::internal("uncolored phi operand")),
        }
    };
    let mut moves: FVec<'h, (Loc, PSrc)> = FVec::new(heap);
    for s in m.block_ids() {
        let sb = m.block(s)?;
        if sb.phis.is_empty() {
            continue;
        }
        for &p in sb.preds.iter() {
            moves.clear();
            for phi in sb.phis.iter() {
                let dst = match phi.slot {
                    Some(sl) => Loc::Slot(sl),
                    None => Loc::Reg(color(phi.dst)?),
                };
                let input = phi
                    .inputs
                    .iter()
                    .find(|(pb, _)| *pb == p)
                    .map(|(_, v)| *v)
                    .ok_or(Error::internal("phi lacks an input for a predecessor"))?;
                let src = match input {
                    PVal::Undef => continue,
                    PVal::V(v) => PSrc::Loc(Loc::Reg(color(v)?)),
                    PVal::Const(c) => const_src(c),
                    PVal::Fp => PSrc::Fp,
                    PVal::Slot(sl) => PSrc::Loc(Loc::Slot(sl)),
                };
                moves.push((dst, src))?;
            }
            let at_p_end = m.successors(p)?.len() == 1;
            if !at_p_end && sb.preds.len() != 1 {
                return Err(Error::internal("critical edge was not split"));
            }
            // Registers live across the copy point.
            let live = if at_p_end {
                a.live.live_out.at(p)?
            } else {
                a.live.live_in.at(s)?
            };
            let mut busy = 0u16;
            for &v in live.iter() {
                let c = *a.color.at(super::mir::VReg(v))?;
                if c != NOCOLOR {
                    busy |= 1 << c;
                }
            }
            // Register phi destinations are live after the copy.
            for phi in sb.phis.iter().filter(|p| p.slot.is_none()) {
                busy |= 1 << color(phi.dst)?;
            }
            let target = if at_p_end {
                at_end.at_mut(p)?
            } else {
                at_start.at_mut(s)?
            };
            if sequentialize(heap, moves.as_slice(), busy, target)? {
                uses_scratch = true;
            }
        }
    }
    Ok(EdgeMoves {
        at_start,
        at_end,
        uses_scratch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::test_support::TestHost;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    /// Simulated machine: 11 registers and a slot map.
    #[derive(Clone, PartialEq, Debug)]
    struct M {
        regs: [u64; 11],
        slots: BTreeMap<u32, u64>,
    }

    fn key(s: MSlot) -> u32 {
        match s {
            MSlot::Spill(k) => k,
            MSlot::Scratch => 1000,
            MSlot::Scratch2 => 1001,
            MSlot::Ir(i) => 2000 + i.0,
        }
    }

    impl M {
        fn read(&self, s: PSrc) -> u64 {
            match s {
                PSrc::Loc(Loc::Reg(r)) => self.regs[r as usize],
                PSrc::Loc(Loc::Slot(sl)) => *self.slots.get(&key(sl)).unwrap_or(&0),
                PSrc::Imm(i) => i as i64 as u64,
                PSrc::Imm32(i) => i as u32 as u64,
                PSrc::Ld64(c) => c,
                PSrc::Fp => 0xf00,
            }
        }
        fn run(&mut self, out: &[PMove]) {
            for m in out {
                match *m {
                    PMove::Mov { dst, src } => self.regs[dst as usize] = self.read(src),
                    PMove::Store { slot, src } => {
                        let v = if src == 10 { 0xf00 } else { self.regs[src as usize] };
                        self.slots.insert(key(slot), v);
                    }
                    PMove::StoreImm { slot, imm } => {
                        self.slots.insert(key(slot), imm as i64 as u64);
                    }
                }
            }
        }
    }

    fn perms(n: usize) -> Vec<Vec<usize>> {
        if n == 0 {
            return std::vec![std::vec![]];
        }
        let mut out = Vec::new();
        for p in perms(n - 1) {
            for i in 0..=p.len() {
                let mut q = p.clone();
                q.insert(i, n - 1);
                out.push(q);
            }
        }
        out
    }

    /// Every permutation of up to 5 locations, where each location may be a
    /// register or a slot, with and without free registers, simulates equal
    /// to the parallel copy.
    #[test]
    fn sequentializer_matches_parallel_semantics_exhaustively() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 26);
        let mut cases = 0u32;
        // Miri is ~1000x slower; 3 locations still cover cycles through slots.
        let max = if cfg!(miri) { 3 } else { 5 };
        for n in 1..=max {
            for p in perms(n) {
                for mask in 0..(1u32 << n) {
                    for &all_busy in &[false, true] {
                        let loc = |i: usize| {
                            if mask & (1 << i) != 0 {
                                Loc::Slot(MSlot::Spill(i as u32))
                            } else {
                                Loc::Reg(i as u8)
                            }
                        };
                        let moves: Vec<(Loc, PSrc)> =
                            (0..n).map(|i| (loc(i), PSrc::Loc(loc(p[i])))).collect();
                        let busy = if all_busy { 0x3ff } else { 0 };
                        let mut out = FVec::new(&heap);
                        sequentialize(&heap, &moves, busy, &mut out).unwrap();
                        let mut mach = M {
                            regs: [0; 11],
                            slots: BTreeMap::new(),
                        };
                        for i in 0..11 {
                            mach.regs[i] = 100 + i as u64;
                        }
                        for i in 0..n {
                            mach.slots.insert(i as u32, 200 + i as u64);
                        }
                        let before = mach.clone();
                        mach.run(out.as_slice());
                        for i in 0..n {
                            let want = before.read(PSrc::Loc(loc(p[i])));
                            let got = mach.read(PSrc::Loc(loc(i)));
                            assert_eq!(got, want, "perm {p:?} mask {mask:b} busy={all_busy}");
                        }
                        if all_busy {
                            // Registers outside the copy keep their values.
                            for r in 0..10 {
                                let involved = (0..n).any(|i| loc(i) == Loc::Reg(r as u8));
                                if !involved {
                                    assert_eq!(mach.regs[r], before.regs[r], "r{r} clobbered");
                                }
                            }
                        }
                        cases += 1;
                    }
                }
            }
        }
        // sum over n of n! * 2^n * 2
        let want: u32 = (1..=max as u32).map(|n| (1..=n).product::<u32>() << n).sum();
        assert_eq!(cases, 2 * want);
        // Constants into slots and fan-out.
        let moves = [
            (Loc::Reg(0), PSrc::Loc(Loc::Reg(1))),
            (Loc::Reg(2), PSrc::Loc(Loc::Reg(1))),
            (Loc::Reg(1), PSrc::Imm(-1)),
            (Loc::Slot(MSlot::Spill(0)), PSrc::Ld64(1 << 40)),
            (Loc::Slot(MSlot::Spill(1)), PSrc::Loc(Loc::Reg(1))),
        ];
        let mut out = FVec::new(&heap);
        sequentialize(&heap, &moves, 0x3ff, &mut out).unwrap();
        let mut mach = M {
            regs: [0; 11],
            slots: BTreeMap::new(),
        };
        mach.regs[1] = 7;
        mach.regs[5] = 55;
        mach.run(out.as_slice());
        assert_eq!((mach.regs[0], mach.regs[1], mach.regs[2]), (7, u64::MAX, 7));
        assert_eq!(mach.slots.get(&0), Some(&(1 << 40)));
        assert_eq!(mach.slots.get(&1), Some(&7));
        assert_eq!(mach.regs[5], 55);
    }
}
