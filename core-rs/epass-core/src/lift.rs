//! Bytecode → SSA lifter.
//!
//! Iterative throughout (no recursion in the input size):
//! 1. decode slots (joining `ld_imm64` pairs), find block leaders and the
//!    bytecode CFG, keep the blocks reachable from pc 0;
//! 2. create IR blocks behind a synthetic entry block (pc 0 may be a loop
//!    header) with placeholder terminators, so IR CFG analyses apply;
//! 3. compute register liveness per block (11-bit masks) and place pruned
//!    phis at iterated dominance frontiers (Cytron et al.);
//! 4. rename in one dominator-tree walk with an explicit stack, translating
//!    each instruction with canonical constants (`mov32 K` zero-extends,
//!    64-bit immediates sign-extend, `w = w` is a zero extension).
//!
//! Unsupported instructions are hard errors; nothing is silently dropped.
//! libbpf-poisoned calls become `Poison` terminators and atomics/LD_ABS/IND
//! become `Opaque` pass-throughs.

use crate::analysis::{Cfg, DomTree};
use crate::bpf::{self, alu, class, jmp, mode, BpfInsn};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::facts::Facts;
use crate::ir::func::At;
use crate::ir::verify::{opaque_signature, verify};
use crate::ir::{
    BinOp, BlockId, Builder, Callee, Cond, Function, InsnId, Op, Size, SwapKind, SymKind, Value,
    Width,
};
use crate::mem::{ChunkVec, FVec, Idx, IdxVec};

const NONE: u32 = u32::MAX;
/// Registers that can be redefined (r10 is read-only).
const NVARS: usize = 10;

fn bad(msg: &'static str, pc: usize) -> Error {
    Error::invalid_input(msg).at(pc as u32)
}

fn unsupported(msg: &'static str, pc: usize) -> Error {
    Error::unsupported(msg).at(pc as u32)
}

/// How a bytecode block ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// Falls through to the next leader.
    Fall,
    /// Unconditional jump to pc.
    Jump(usize),
    /// Conditional jump: taken pc, fallthrough pc.
    Cond(usize, usize),
    Exit,
    Poison(i32),
}

#[derive(Clone, Copy, Debug)]
struct BBlock {
    start: usize,
    /// One past the last slot.
    end: usize,
    /// pc of the terminating instruction (if `end` is not `Fall`).
    last: usize,
    kind: End,
    reachable: bool,
    ir: BlockId,
    uses: u16,
    defs: u16,
    live_in: u16,
}

fn jump_target(pc: usize, off: i64, n: usize) -> Option<usize> {
    let t = (pc as i64).checked_add(off)?.checked_add(1)?;
    if t < 0 || t as usize >= n {
        None
    } else {
        Some(t as usize)
    }
}

fn is_cond(op: u8) -> bool {
    matches!(
        op,
        jmp::JEQ
            | jmp::JGT
            | jmp::JGE
            | jmp::JSET
            | jmp::JNE
            | jmp::JSGT
            | jmp::JSGE
            | jmp::JLT
            | jmp::JLE
            | jmp::JSLT
            | jmp::JSLE
    )
}

fn cond_of(op: u8) -> Option<Cond> {
    Some(match op {
        jmp::JEQ => Cond::Eq,
        jmp::JNE => Cond::Ne,
        jmp::JGT => Cond::Ugt,
        jmp::JGE => Cond::Uge,
        jmp::JLT => Cond::Ult,
        jmp::JLE => Cond::Ule,
        jmp::JSGT => Cond::Sgt,
        jmp::JSGE => Cond::Sge,
        jmp::JSLT => Cond::Slt,
        jmp::JSLE => Cond::Sle,
        jmp::JSET => Cond::Set,
        _ => return None,
    })
}

fn bit(r: u8) -> u16 {
    if (r as usize) < NVARS {
        1 << r
    } else {
        0
    }
}

const R1_R5: u16 = 0b11_1110;

/// Registers read and written by one instruction (r10 excluded).
fn regs_rw(i: BpfInsn, facts: &dyn Facts) -> (u16, u16) {
    let (d, s) = (bit(i.dst), bit(i.src));
    match i.class() {
        class::ALU | class::ALU64 => match i.op() {
            alu::MOV => (if i.uses_reg() { s } else { 0 }, d),
            alu::NEG | alu::END => (d, d),
            _ => (d | if i.uses_reg() { s } else { 0 }, d),
        },
        class::LD => match i.mode() {
            mode::IMM => (0, d),
            mode::ABS => (bit(6), 1 | R1_R5),
            mode::IND => (bit(6) | s, 1 | R1_R5),
            _ => (0, 0),
        },
        class::LDX => (s, d),
        class::ST => (d, 0),
        class::STX => {
            if i.mode() == mode::ATOMIC {
                let sig = opaque_signature(i.to_u64());
                match sig {
                    Some(o) => (o.uses & 0x3ff, o.def.map_or(0, bit)),
                    None => (d | s, 0),
                }
            } else {
                (d | s, 0)
            }
        }
        class::JMP | class::JMP32 => match i.op() {
            jmp::JA => (0, 0),
            jmp::EXIT => (1, 0),
            jmp::CALL => {
                let n = match i.src {
                    bpf::call::HELPER => facts.helper(i.imm).map_or(5, |s| s.nargs),
                    bpf::call::KFUNC => facts.kfunc(i.imm, i.off).map_or(5, |s| s.nargs),
                    _ => 5,
                };
                let reads = ((1u16 << n.min(5)) - 1) << 1;
                (reads, 1 | R1_R5)
            }
            _ => (d | if i.uses_reg() { s } else { 0 }, 0),
        },
        _ => (0, 0),
    }
}

/// Lift a program (one `BpfInsn` per slot) to a validated SSA function.
pub fn lift<'h>(prog: &[BpfInsn], facts: &dyn Facts, ctx: &Ctx<'h>) -> Result<Function<'h>> {
    let heap = ctx.heap;
    let n = prog.len();
    if n == 0 {
        return Err(Error::invalid_input("empty program"));
    }
    if n > ctx.limits.max_insns as usize {
        return Err(Error::limit("program too large"));
    }
    let insn = |pc: usize| prog.get(pc).copied().ok_or(bad("pc out of range", pc));

    // ---- 1. slots, leaders, bytecode blocks ----
    // 0: normal, 1: ld_imm64 head, 2: ld_imm64 tail.
    let mut slot_kind: ChunkVec<'h, u8> = ChunkVec::filled(heap, n, 0)?;
    let mut leader: ChunkVec<'h, bool> = ChunkVec::filled(heap, n, false)?;
    let set = |v: &mut ChunkVec<'h, bool>, pc: usize| -> Result<()> {
        *v.get_mut(pc).ok_or(Error::internal("leader index"))? = true;
        Ok(())
    };
    set(&mut leader, 0)?;
    let mut pc = 0usize;
    while pc < n {
        ctx.tick()?;
        let i = insn(pc)?;
        if i.code == (class::LD | mode::IMM | bpf::size::DW) {
            let t = prog.get(pc + 1).ok_or(bad("truncated ld_imm64", pc))?;
            if t.code != 0 || t.dst != 0 || t.src != 0 || t.off != 0 {
                return Err(bad("malformed ld_imm64", pc));
            }
            *slot_kind.get_mut(pc).ok_or(Error::internal("slot"))? = 1;
            *slot_kind.get_mut(pc + 1).ok_or(Error::internal("slot"))? = 2;
            pc += 2;
            continue;
        }
        if matches!(i.class(), class::JMP | class::JMP32) {
            let op = i.op();
            let ends = match op {
                jmp::JA => {
                    let off = if i.class() == class::JMP32 { i.imm as i64 } else { i.off as i64 };
                    let t = jump_target(pc, off, n).ok_or(bad("jump out of range", pc))?;
                    set(&mut leader, t)?;
                    true
                }
                _ if is_cond(op) => {
                    let t = jump_target(pc, i.off as i64, n).ok_or(bad("jump out of range", pc))?;
                    set(&mut leader, t)?;
                    true
                }
                jmp::EXIT => true,
                jmp::CALL => i.src == bpf::call::HELPER && bpf::poison::is_poison(i.imm),
                _ => false,
            };
            if ends && pc + 1 < n {
                set(&mut leader, pc + 1)?;
            }
        }
        pc += 1;
    }
    // A jump into the second slot of an ld_imm64 is invalid.
    for pc in 0..n {
        if *leader.get(pc).unwrap_or(&false) && *slot_kind.get(pc).unwrap_or(&0) == 2 {
            return Err(bad("jump into the middle of ld_imm64", pc));
        }
    }

    let mut blocks: FVec<'h, BBlock> = FVec::new(heap);
    // pc -> bytecode block index (leaders only).
    let mut block_at: ChunkVec<'h, u32> = ChunkVec::filled(heap, n, NONE)?;
    let mut start = 0usize;
    while start < n {
        ctx.tick()?;
        let mut end = start + 1;
        while end < n && !*leader.get(end).unwrap_or(&true) {
            end += 1;
        }
        // Find the last instruction head in [start, end).
        let mut last = end - 1;
        if *slot_kind.get(last).unwrap_or(&0) == 2 {
            last -= 1;
        }
        let li = insn(last)?;
        let kind = if matches!(li.class(), class::JMP | class::JMP32) {
            match li.op() {
                jmp::JA => {
                    let off = if li.class() == class::JMP32 { li.imm as i64 } else { li.off as i64 };
                    End::Jump(jump_target(last, off, n).ok_or(bad("jump out of range", last))?)
                }
                op if is_cond(op) => End::Cond(
                    jump_target(last, li.off as i64, n).ok_or(bad("jump out of range", last))?,
                    last + 1,
                ),
                jmp::EXIT => End::Exit,
                jmp::CALL if li.src == bpf::call::HELPER && bpf::poison::is_poison(li.imm) => {
                    End::Poison(li.imm)
                }
                _ => End::Fall,
            }
        } else {
            End::Fall
        };
        let idx = blocks.len() as u32;
        *block_at.get_mut(start).ok_or(Error::internal("block_at"))? = idx;
        blocks.push(BBlock {
            start,
            end,
            last,
            kind,
            reachable: false,
            ir: BlockId(0),
            uses: 0,
            defs: 0,
            live_in: 0,
        })?;
        start = end;
    }
    let bidx = |pc: usize| -> Result<usize> {
        match block_at.get(pc) {
            Some(&b) if b != NONE => Ok(b as usize),
            _ => Err(Error::internal("not a leader")),
        }
    };
    // Successor block indices of a bytecode block.
    let succs_of = |b: &BBlock| -> Result<([usize; 2], usize)> {
        Ok(match b.kind {
            End::Fall => {
                if b.end >= n {
                    return Err(bad("program falls off the end", b.last));
                }
                ([bidx(b.end)?, 0], 1)
            }
            End::Jump(t) => ([bidx(t)?, 0], 1),
            End::Cond(t, f) => {
                if f >= n {
                    return Err(bad("program falls off the end", b.last));
                }
                ([bidx(t)?, bidx(f)?], 2)
            }
            End::Exit | End::Poison(_) => ([0, 0], 0),
        })
    };

    // Reachability from pc 0.
    let mut work: FVec<'h, usize> = FVec::new(heap);
    work.push(0)?;
    if let Some(b0) = blocks.get_mut(0) {
        b0.reachable = true;
    }
    while let Some(b) = work.pop() {
        ctx.tick()?;
        let bb = *blocks.get(b).ok_or(Error::internal("block"))?;
        let (ss, k) = succs_of(&bb)?;
        for &s in ss.get(..k).unwrap_or(&[]) {
            let sb = blocks.get_mut(s).ok_or(Error::internal("block"))?;
            if !sb.reachable {
                sb.reachable = true;
                work.push(s)?;
            }
        }
    }

    // ---- 2. IR blocks with placeholder terminators ----
    let mut f = Function::new(heap)?;
    let entry = f.entry();
    for k in 0..blocks.len() {
        let b = blocks.get_mut(k).ok_or(Error::internal("block"))?;
        if b.reachable {
            let id = f.add_block()?;
            f.set_block_origin(id, Some(b.start as u32))?;
            if let Some(b) = blocks.get_mut(k) {
                b.ir = id;
            }
        }
    }
    let ir_of = |blocks: &FVec<'h, BBlock>, k: usize| -> Result<BlockId> {
        blocks.get(k).map(|b| b.ir).ok_or(Error::internal("block"))
    };
    let first = ir_of(&blocks, 0)?;
    f.insert(At::End(entry), Op::Br { target: first }, &[])?;
    for k in 0..blocks.len() {
        ctx.tick()?;
        let b = *blocks.get(k).ok_or(Error::internal("block"))?;
        if !b.reachable {
            continue;
        }
        let (op, nops) = match b.kind {
            End::Fall => (
                Op::Br {
                    target: ir_of(&blocks, bidx(b.end)?)?,
                },
                0,
            ),
            End::Jump(t) => (
                Op::Br {
                    target: ir_of(&blocks, bidx(t)?)?,
                },
                0,
            ),
            End::Cond(t, fpc) => {
                let tb = ir_of(&blocks, bidx(t)?)?;
                let fb = ir_of(&blocks, bidx(fpc)?)?;
                let li = insn(b.last)?;
                if tb == fb {
                    (Op::Br { target: tb }, 0)
                } else {
                    let cond = cond_of(li.op()).ok_or(bad("bad condition", b.last))?;
                    let w = if li.class() == class::JMP32 { Width::W32 } else { Width::W64 };
                    (Op::CondBr { cond, w, t: tb, f: fb }, 2)
                }
            }
            End::Exit => (Op::Ret, 1),
            End::Poison(imm) => (Op::Poison { imm }, 0),
        };
        let placeholder = [Value::Undef; 2];
        let t = f.insert(At::End(b.ir), op, placeholder.get(..nops).unwrap_or(&[]))?;
        if !matches!(b.kind, End::Fall) {
            f.set_origin(t, Some(b.last as u32))?;
        }
    }

    // ---- 3. liveness and phi placement ----
    for k in 0..blocks.len() {
        ctx.tick()?;
        let b = *blocks.get(k).ok_or(Error::internal("block"))?;
        if !b.reachable {
            continue;
        }
        let (mut uses, mut defs) = (0u16, 0u16);
        let mut pc = b.start;
        while pc < b.end {
            let i = insn(pc)?;
            let (r, w) = regs_rw(i, facts);
            uses |= r & !defs;
            defs |= w;
            pc += if *slot_kind.get(pc).unwrap_or(&0) == 1 { 2 } else { 1 };
        }
        if let Some(bm) = blocks.get_mut(k) {
            bm.uses = uses;
            bm.defs = defs;
            bm.live_in = uses;
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for k in (0..blocks.len()).rev() {
            ctx.tick()?;
            let b = *blocks.get(k).ok_or(Error::internal("block"))?;
            if !b.reachable {
                continue;
            }
            let (ss, cnt) = succs_of(&b)?;
            let mut out = 0u16;
            for &s in ss.get(..cnt).unwrap_or(&[]) {
                out |= blocks.get(s).map_or(0, |x| x.live_in);
            }
            let li = b.uses | (out & !b.defs);
            if li != b.live_in {
                if let Some(bm) = blocks.get_mut(k) {
                    bm.live_in = li;
                }
                changed = true;
            }
        }
    }
    // IR block -> bytecode block (entry: NONE).
    let mut bc_of: IdxVec<'h, BlockId, u32> = IdxVec::filled(heap, f.block_id_bound(), NONE)?;
    for (k, b) in blocks.iter().enumerate() {
        if b.reachable {
            *bc_of.at_mut(b.ir)? = k as u32;
        }
    }

    let cfg = Cfg::compute(&f, ctx)?;
    let dom = DomTree::compute(&f, &cfg, ctx)?;
    // Dominance frontiers.
    let nb = f.block_id_bound();
    let mut df: IdxVec<'h, BlockId, FVec<'h, BlockId>> = IdxVec::new(heap);
    for _ in 0..nb {
        df.push(FVec::new(heap))?;
    }
    for &b in cfg.rpo() {
        let preds = f.preds(b)?;
        if preds.len() < 2 {
            continue;
        }
        let idom = dom.idom(b).ok_or(Error::internal("idom"))?;
        for &p in preds {
            let mut runner = p;
            while runner != idom {
                ctx.tick()?;
                df.at_mut(runner)?.push_unique(b)?;
                if runner == entry {
                    // idom(b) dominates every predecessor, so the walk must
                    // meet it before the root.
                    return Err(Error::internal("dominance frontier walk"));
                }
                runner = dom.idom(runner).ok_or(Error::internal("idom"))?;
            }
        }
    }
    // phi_of[block][reg]
    let mut phi_of: IdxVec<'h, BlockId, [u32; NVARS]> = IdxVec::filled(heap, nb, [NONE; NVARS])?;
    let mut inputs: FVec<'h, (Value, BlockId)> = FVec::new(heap);
    let mut in_work: IdxVec<'h, BlockId, u8> = IdxVec::filled(heap, nb, 0)?;
    for r in 0..NVARS {
        let mask = 1u16 << r;
        let mut wl: FVec<'h, BlockId> = FVec::new(heap);
        wl.push(entry)?;
        for b in blocks.iter() {
            if b.reachable && b.defs & mask != 0 {
                wl.push(b.ir)?;
            }
        }
        for &b in wl.iter() {
            *in_work.at_mut(b)? = 1;
        }
        while let Some(x) = wl.pop() {
            ctx.tick()?;
            let frontier = df.at(x)?.try_clone()?;
            for &y in frontier.iter() {
                let k = *bc_of.at(y)?;
                let live = blocks.get(k as usize).is_some_and(|b| b.live_in & mask != 0);
                let slot = phi_of.at_mut(y)?;
                let cell = slot.get_mut(r).ok_or(Error::internal("phi_of"))?;
                if live && *cell == NONE {
                    inputs.clear();
                    for &p in f.preds(y)? {
                        inputs.push((Value::Undef, p))?;
                    }
                    let phi = f.insert_phi(y, inputs.as_slice())?;
                    f.set_origin(phi, f.block(y)?.origin)?;
                    f.set_hint(phi, Some(r as u8))?;
                    if let Some(c) = phi_of.at_mut(y)?.get_mut(r) {
                        *c = phi.to_u32();
                    }
                    if *in_work.at(y)? == 0 {
                        *in_work.at_mut(y)? = 1;
                        wl.push(y)?;
                    }
                }
            }
        }
        for b in f.blocks() {
            *in_work.at_mut(b)? = 0;
        }
    }

    // ---- 4. renaming over the dominator tree ----
    // Children lists.
    let mut kids: IdxVec<'h, BlockId, FVec<'h, BlockId>> = IdxVec::new(heap);
    for _ in 0..nb {
        kids.push(FVec::new(heap))?;
    }
    for &b in cfg.rpo().iter().skip(1) {
        let d = dom.idom(b).ok_or(Error::internal("idom"))?;
        kids.at_mut(d)?.push(b)?;
    }
    let mut stacks: [FVec<'h, Value>; NVARS] = [
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
        FVec::new(heap),
    ];
    for (r, st) in stacks.iter_mut().enumerate() {
        st.push(if (1..=5).contains(&r) {
            Value::Param(r as u8)
        } else {
            Value::Undef
        })?;
    }
    // Walk frames: (block, entered, saved stack heights).
    let mut walk: FVec<'h, (BlockId, bool, [u32; NVARS])> = FVec::new(heap);
    walk.push((entry, false, [0; NVARS]))?;
    while let Some(&(b, entered, saved)) = walk.last() {
        ctx.tick()?;
        if entered {
            walk.pop();
            for (st, &h) in stacks.iter_mut().zip(saved.iter()) {
                st.truncate(h as usize);
            }
            continue;
        }
        let mut heights = [0u32; NVARS];
        for (h, st) in heights.iter_mut().zip(stacks.iter()) {
            *h = st.len() as u32;
        }
        if let Some(top) = walk.last_mut() {
            *top = (b, true, heights);
        }
        let phis = *phi_of.at(b)?;
        for (r, &p) in phis.iter().enumerate() {
            if p != NONE {
                stacks.get_mut(r).ok_or(Error::internal("stack"))?.push(Value::Insn(InsnId(p)))?;
            }
        }
        let k = *bc_of.at(b)?;
        if k != NONE {
            let bb = *blocks.get(k as usize).ok_or(Error::internal("block"))?;
            let mut before = [0usize; NVARS];
            for (h, st) in before.iter_mut().zip(stacks.iter()) {
                *h = st.len();
            }
            translate_block(&mut f, b, &bb, prog, &slot_kind, &mut stacks, facts, ctx)?;
            hint_writes(&mut f, &stacks, &before)?;
        }
        // Fill successor phi inputs for the edge from b.
        for &s in f.successors(b)?.as_slice() {
            let sp = *phi_of.at(s)?;
            for (r, &p) in sp.iter().enumerate() {
                if p == NONE {
                    continue;
                }
                let v = *stacks
                    .get(r)
                    .and_then(|st| st.last())
                    .ok_or(Error::internal("stack"))?;
                let phi = InsnId(p);
                let mut idx = None;
                for (j, o) in f.operand_ids(phi)?.enumerate() {
                    if f.opnd(o)?.block == Some(b) {
                        idx = Some(j);
                        break;
                    }
                }
                let j = idx.ok_or(Error::internal("phi input for edge"))?;
                f.set_operand(phi, j, v)?;
            }
        }
        for &c in kids.at(b)?.iter().rev() {
            walk.push((c, false, [0; NVARS]))?;
        }
    }
    verify(&f, ctx, false)?;
    Ok(f)
}

/// Read register `r` for a strict use (undefined is an input error).
fn read(stacks: &[FVec<'_, Value>; NVARS], r: u8, pc: usize) -> Result<Value> {
    let v = read_any(stacks, r)?;
    if v == Value::Undef {
        return Err(bad("read of an uninitialized register", pc));
    }
    Ok(v)
}

fn read_any(stacks: &[FVec<'_, Value>; NVARS], r: u8) -> Result<Value> {
    if r == bpf::R10 {
        return Ok(Value::FramePtr);
    }
    stacks
        .get(r as usize)
        .and_then(|s| s.last())
        .copied()
        .ok_or(Error::invalid_input("bad register"))
}

fn write(stacks: &mut [FVec<'_, Value>; NVARS], r: u8, v: Value, pc: usize) -> Result<()> {
    stacks
        .get_mut(r as usize)
        .ok_or(bad("write to r10 or an invalid register", pc))?
        .push(v)
}

/// Record the original register of every instruction result defined while
/// translating a block (the allocator tries it first).
fn hint_writes(f: &mut Function<'_>, stacks: &[FVec<'_, Value>; NVARS], before: &[usize; NVARS]) -> Result<()> {
    for (r, st) in stacks.iter().enumerate() {
        let from = before.get(r).copied().unwrap_or(0);
        for &v in st.as_slice().get(from..).unwrap_or(&[]) {
            if let Value::Insn(i) = v {
                if f.insn(i)?.hint.is_none() {
                    f.set_hint(i, Some(r as u8))?;
                }
            }
        }
    }
    Ok(())
}

fn sext32(imm: i32) -> u64 {
    imm as i64 as u64
}

fn zext32(imm: i32) -> u64 {
    imm as u32 as u64
}

#[allow(clippy::too_many_arguments)]
fn translate_block(
    f: &mut Function<'_>,
    b: BlockId,
    bb: &BBlock,
    prog: &[BpfInsn],
    slot_kind: &ChunkVec<'_, u8>,
    stacks: &mut [FVec<'_, Value>; NVARS],
    facts: &dyn Facts,
    ctx: &Ctx<'_>,
) -> Result<()> {
    let mut pc = bb.start;
    let body_end = if matches!(bb.kind, End::Fall) { bb.end } else { bb.last };
    while pc < body_end {
        ctx.tick()?;
        let i = prog.get(pc).copied().ok_or(bad("pc", pc))?;
        let wide = *slot_kind.get(pc).unwrap_or(&0) == 1;
        let mut bld = Builder::new(f, At::BeforeTerminator(b));
        bld.set_origin(Some(pc as u32));
        if i.dst > 10 || i.src > 10 {
            return Err(bad("bad register number", pc));
        }
        match i.class() {
            class::ALU | class::ALU64 => lift_alu(&mut bld, i, pc, stacks)?,
            class::LD => {
                if wide {
                    let hi = prog.get(pc + 1).map_or(0, |t| t.imm);
                    let imm64 = zext32(i.imm) | ((hi as u32 as u64) << 32);
                    let v = if i.src == 0 {
                        Value::Const(imm64)
                    } else {
                        let kind = SymKind::from_src_reg(i.src).ok_or(bad("bad ld_imm64 source", pc))?;
                        if kind == SymKind::Func {
                            return Err(unsupported("ld_imm64 of a function (callbacks)", pc));
                        }
                        bld.ldsym(kind, imm64)?
                    };
                    write(stacks, i.dst, v, pc)?;
                } else {
                    lift_opaque(&mut bld, i, pc, stacks)?;
                }
            }
            class::LDX => {
                let signed = match i.mode() {
                    mode::MEM => false,
                    mode::MEMSX => true,
                    _ => return Err(bad("bad load mode", pc)),
                };
                let size = size_of(i)?;
                if signed && size == Size::B8 {
                    return Err(bad("sign-extending 8-byte load", pc));
                }
                let base = read(stacks, i.src, pc)?;
                let v = bld.load(size, signed, base, i.off)?;
                write(stacks, i.dst, v, pc)?;
            }
            class::ST => {
                if i.mode() != mode::MEM {
                    return Err(bad("bad store mode", pc));
                }
                let base = read(stacks, i.dst, pc)?;
                bld.store(size_of(i)?, base, i.off, Value::Const(sext32(i.imm)))?;
            }
            class::STX => match i.mode() {
                mode::MEM => {
                    let base = read(stacks, i.dst, pc)?;
                    let v = read(stacks, i.src, pc)?;
                    bld.store(size_of(i)?, base, i.off, v)?;
                }
                mode::ATOMIC => lift_opaque(&mut bld, i, pc, stacks)?,
                _ => return Err(bad("bad store mode", pc)),
            },
            class::JMP | class::JMP32 => match i.op() {
                jmp::CALL if i.class() == class::JMP => lift_call(&mut bld, i, pc, stacks, facts)?,
                jmp::JCOND => return Err(unsupported("may_goto", pc)),
                _ => return Err(bad("unexpected jump in block body", pc)),
            },
            _ => return Err(bad("unknown instruction class", pc)),
        }
        pc += if wide { 2 } else { 1 };
    }
    // Terminator operands.
    if let Some(t) = f.terminator(b)? {
        match f.op(t)? {
            Op::CondBr { w, .. } => {
                let li = prog.get(bb.last).copied().ok_or(bad("pc", bb.last))?;
                let a = read(stacks, li.dst, bb.last)?;
                let c = if li.uses_reg() {
                    read(stacks, li.src, bb.last)?
                } else {
                    Value::Const(match w {
                        Width::W64 => sext32(li.imm),
                        Width::W32 => zext32(li.imm),
                    })
                };
                f.set_operand(t, 0, a)?;
                f.set_operand(t, 1, c)?;
            }
            Op::Ret => {
                let r0 = read(stacks, bpf::R0, bb.last)?;
                f.set_operand(t, 0, r0)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn size_of(i: BpfInsn) -> Result<Size> {
    Ok(match i.size() {
        bpf::size::B => Size::B1,
        bpf::size::H => Size::B2,
        bpf::size::W => Size::B4,
        _ => Size::B8,
    })
}

fn lift_alu(
    bld: &mut Builder<'_, '_>,
    i: BpfInsn,
    pc: usize,
    stacks: &mut [FVec<'_, Value>; NVARS],
) -> Result<()> {
    let w = if i.class() == class::ALU64 { Width::W64 } else { Width::W32 };
    let imm = match w {
        Width::W64 => sext32(i.imm),
        Width::W32 => zext32(i.imm),
    };
    let op = i.op();
    match op {
        alu::MOV => {
            if !i.uses_reg() {
                if i.off != 0 || i.src != 0 {
                    return Err(bad("reserved fields in mov", pc));
                }
                return write(stacks, i.dst, Value::Const(imm), pc);
            }
            if i.imm != 0 {
                return Err(bad("reserved fields in mov", pc));
            }
            let s = read(stacks, i.src, pc)?;
            let v = match (i.off, w) {
                (0, Width::W64) => s,
                (0, Width::W32) => match s {
                    Value::Const(c) => Value::Const(c & 0xffff_ffff),
                    _ => bld.ext(32, false, Width::W64, s)?,
                },
                (8, _) | (16, _) | (32, Width::W64) => bld.ext(i.off as u8, true, w, s)?,
                _ => return Err(bad("bad movsx width", pc)),
            };
            write(stacks, i.dst, v, pc)
        }
        alu::NEG => {
            if i.uses_reg() || i.off != 0 {
                return Err(bad("reserved fields in neg", pc));
            }
            let a = read(stacks, i.dst, pc)?;
            let v = bld.neg(w, a)?;
            write(stacks, i.dst, v, pc)
        }
        alu::END => {
            let bits = match i.imm {
                16 | 32 | 64 => i.imm as u8,
                _ => return Err(bad("bad byte-swap width", pc)),
            };
            let kind = match (w, i.uses_reg()) {
                (Width::W32, false) => SwapKind::ToLe,
                (Width::W32, true) => SwapKind::ToBe,
                (Width::W64, false) => SwapKind::Swap,
                (Width::W64, true) => return Err(bad("reserved byte-swap encoding", pc)),
            };
            let a = read(stacks, i.dst, pc)?;
            let v = bld.bswap(bits, kind, a)?;
            write(stacks, i.dst, v, pc)
        }
        _ => {
            let bop = match (op, i.off) {
                (alu::ADD, 0) => BinOp::Add,
                (alu::SUB, 0) => BinOp::Sub,
                (alu::MUL, 0) => BinOp::Mul,
                (alu::DIV, 0) => BinOp::UDiv,
                (alu::DIV, 1) => BinOp::SDiv,
                (alu::MOD, 0) => BinOp::UMod,
                (alu::MOD, 1) => BinOp::SMod,
                (alu::OR, 0) => BinOp::Or,
                (alu::AND, 0) => BinOp::And,
                (alu::LSH, 0) => BinOp::Shl,
                (alu::RSH, 0) => BinOp::LShr,
                (alu::ARSH, 0) => BinOp::AShr,
                (alu::XOR, 0) => BinOp::Xor,
                _ => return Err(bad("unknown or reserved ALU operation", pc)),
            };
            let a = read(stacks, i.dst, pc)?;
            let b = if i.uses_reg() {
                read(stacks, i.src, pc)?
            } else {
                Value::Const(imm)
            };
            let v = bld.bin(bop, w, a, b)?;
            write(stacks, i.dst, v, pc)
        }
    }
}

fn lift_opaque(
    bld: &mut Builder<'_, '_>,
    i: BpfInsn,
    pc: usize,
    stacks: &mut [FVec<'_, Value>; NVARS],
) -> Result<()> {
    let sig = opaque_signature(i.to_u64()).ok_or(unsupported("unsupported instruction", pc))?;
    let mut args = [Value::Undef; 11];
    let mut n = 0usize;
    for r in 0..=10u8 {
        if sig.uses & (1 << r) != 0 {
            if let Some(slot) = args.get_mut(n) {
                *slot = read(stacks, r, pc)?;
            }
            n += 1;
        }
    }
    let id = bld.emit(Op::Opaque(sig), args.get(..n).unwrap_or(&[]))?;
    for r in 1..=5u8 {
        if sig.clobbers & (1 << r) != 0 {
            write(stacks, r, Value::Undef, pc)?;
        }
    }
    if let Some(d) = sig.def {
        write(stacks, d, Value::Insn(id), pc)?;
    }
    Ok(())
}

fn lift_call(
    bld: &mut Builder<'_, '_>,
    i: BpfInsn,
    pc: usize,
    stacks: &mut [FVec<'_, Value>; NVARS],
    facts: &dyn Facts,
) -> Result<()> {
    let (callee, sig) = match i.src {
        bpf::call::HELPER => (Callee::Helper(i.imm), facts.helper(i.imm)),
        bpf::call::KFUNC => (
            Callee::Kfunc {
                btf_id: i.imm,
                fd_idx: i.off,
            },
            facts.kfunc(i.imm, i.off),
        ),
        bpf::call::LOCAL => return Err(unsupported("bpf-to-bpf call", pc)),
        bpf::call::ECALL => return Err(unsupported("ecall", pc)),
        _ => return Err(bad("bad call source", pc)),
    };
    let mut args = [Value::Undef; 5];
    let (n, unknown) = match sig {
        Some(s) => {
            let n = (s.nargs as usize).min(5);
            for k in 0..n {
                let v = read_any(stacks, (k + 1) as u8)?;
                if v == Value::Undef && k < s.optional_from as usize {
                    return Err(bad("call argument register is uninitialized", pc));
                }
                if let Some(a) = args.get_mut(k) {
                    *a = v;
                }
            }
            (n, false)
        }
        None if facts.allow_unknown_calls() => {
            for (k, a) in args.iter_mut().enumerate() {
                *a = read_any(stacks, (k + 1) as u8)?;
            }
            (5, true)
        }
        None => return Err(unsupported("call with an unknown signature", pc)),
    };
    let id = bld.emit(
        Op::Call {
            callee,
            unknown_arity: unknown,
        },
        args.get(..n).unwrap_or(&[]),
    )?;
    for r in 1..=5u8 {
        write(stacks, r, Value::Undef, pc)?;
    }
    write(stacks, bpf::R0, Value::Insn(id), pc)
}
