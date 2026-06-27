//! The IR data model: arena-allocated instructions and basic blocks referenced
//! by typed index handles ([`InsnId`], [`BbId`]). This avoids the cyclic raw
//! pointers used by the C implementation while keeping cheap, `Copy` references.
//!
//! Mutation discipline: because a `&mut Function` cannot be aliased, passes that
//! iterate and mutate must first collect the handles they care about, then
//! apply changes. Helper methods on [`Function`] encapsulate the common cases
//! (insertion, def-use maintenance, value replacement).

pub mod builder;
pub mod insn;
pub mod print;
pub mod text;
pub mod value;

pub use builder::{InsertPoint, IrBuilder};
pub use insn::{BinOp, Cond, EndKind, Insn, InsnKind};
pub use value::{
    AddrValue, AluOp, BuiltinConst, ConstKind, LoadImmExtra, PhiValue, RawPos, RawPosKind, Value,
    VrPos, VrType,
};

use crate::bytecode::MAX_FUNC_ARG;
use crate::error::Result;
use crate::invalid;

/// Handle to an instruction in [`Function::insns`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InsnId(pub u32);

/// Handle to a basic block in [`Function::bbs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BbId(pub u32);

impl InsnId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}
impl BbId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Where to insert a new instruction relative to an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertPos {
    /// Immediately before the anchor (or at the start of a block).
    Front,
    /// Immediately after the anchor (or at the end of a block).
    Back,
    /// At the end of a block but before a trailing jump.
    BackBeforeJmp,
    /// At the start of a block but after any leading phi nodes.
    FrontAfterPhi,
}

/// A basic block: an ordered list of instruction handles plus CFG edges.
#[derive(Debug, Clone, Default)]
pub struct BasicBlock {
    /// Instruction handles in program order.
    pub insns: Vec<InsnId>,
    pub preds: Vec<BbId>,
    pub succs: Vec<BbId>,
    pub flag: u32,
}

impl BasicBlock {
    pub fn first(&self) -> Option<InsnId> {
        self.insns.first().copied()
    }
    pub fn last(&self) -> Option<InsnId> {
        self.insns.last().copied()
    }
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
    pub fn len(&self) -> usize {
        self.insns.len()
    }
}

/// A lifted eBPF function in SSA form.
pub struct Function {
    /// Instruction arena. Dead instructions are tombstoned (`None`), never moved.
    insns: Vec<Option<Insn>>,
    /// Basic-block arena.
    bbs: Vec<BasicBlock>,

    pub entry: BbId,
    /// All blocks, in creation order.
    pub all_bbs: Vec<BbId>,
    /// Blocks reachable from `entry`, in fallthrough-chain layout order.
    pub reachable_bbs: Vec<BbId>,
    /// Blocks with no successors.
    pub end_bbs: Vec<BbId>,

    /// Stack-pointer pseudo-instruction (R10).
    pub sp: InsnId,
    /// Function-argument pseudo-instructions (R1..R5).
    pub args: [InsnId; MAX_FUNC_ARG],
}

impl Function {
    /// Create an empty function with a single entry block and the SP/arg pseudos.
    pub(crate) fn new() -> Self {
        let mut f = Function {
            insns: Vec::new(),
            bbs: Vec::new(),
            entry: BbId(0),
            all_bbs: Vec::new(),
            reachable_bbs: Vec::new(),
            end_bbs: Vec::new(),
            sp: InsnId(0),
            args: [InsnId(0); MAX_FUNC_ARG],
        };
        let entry = f.create_bb();
        f.entry = entry;
        // SP and arg pseudo-instructions are not attached to any block.
        f.sp = f.alloc_detached(InsnKind::Reg {
            reg_id: crate::bytecode::BPF_REG_10,
        });
        for i in 0..MAX_FUNC_ARG {
            f.args[i] = f.alloc_detached(InsnKind::FunctionArg { arg_id: i as u8 });
        }
        f
    }

    // ---- arena access ----

    pub fn insn(&self, id: InsnId) -> &Insn {
        self.insns[id.index()]
            .as_ref()
            .expect("dereferenced a tombstoned instruction")
    }

    pub fn insn_mut(&mut self, id: InsnId) -> &mut Insn {
        self.insns[id.index()]
            .as_mut()
            .expect("dereferenced a tombstoned instruction")
    }

    pub fn try_insn(&self, id: InsnId) -> Option<&Insn> {
        self.insns.get(id.index()).and_then(|x| x.as_ref())
    }

    pub fn is_alive(&self, id: InsnId) -> bool {
        self.insns
            .get(id.index())
            .map(|x| x.is_some())
            .unwrap_or(false)
    }

    pub fn bb(&self, id: BbId) -> &BasicBlock {
        &self.bbs[id.index()]
    }

    pub fn bb_mut(&mut self, id: BbId) -> &mut BasicBlock {
        &mut self.bbs[id.index()]
    }

    pub fn insn_count(&self) -> usize {
        self.insns.iter().filter(|x| x.is_some()).count()
    }

    /// Number of slots in the BB arena (including any unreachable blocks).
    pub fn bb_arena_len(&self) -> usize {
        self.bbs.len()
    }

    // ---- block creation / CFG ----

    fn alloc_detached(&mut self, kind: InsnKind) -> InsnId {
        let id = InsnId(self.insns.len() as u32);
        // Detached pseudo-insns use the entry block as a nominal parent.
        let insn = Insn::new(kind, self.entry);
        self.insns.push(Some(insn));
        id
    }

    pub fn create_bb(&mut self) -> BbId {
        let id = BbId(self.bbs.len() as u32);
        self.bbs.push(BasicBlock::default());
        self.all_bbs.push(id);
        id
    }

    /// Create a detached physical-register pseudo-instruction (used by code-gen).
    pub fn create_reg_pseudo(&mut self, reg_id: u8) -> InsnId {
        self.alloc_detached(InsnKind::Reg { reg_id })
    }

    pub fn connect(&mut self, from: BbId, to: BbId) {
        if !self.bbs[from.index()].succs.contains(&to) {
            self.bbs[from.index()].succs.push(to);
        }
        if !self.bbs[to.index()].preds.contains(&from) {
            self.bbs[to.index()].preds.push(from);
        }
    }

    pub fn disconnect(&mut self, from: BbId, to: BbId) {
        self.bbs[from.index()].succs.retain(|&s| s != to);
        self.bbs[to.index()].preds.retain(|&p| p != from);
    }

    /// The terminator instruction of `bb`, if its last instruction transfers control.
    pub fn terminator(&self, bb: BbId) -> Option<InsnId> {
        self.bb(bb).last().filter(|&id| self.insn(id).is_jmp())
    }

    pub fn is_terminated(&self, bb: BbId) -> bool {
        self.terminator(bb).is_some()
    }

    pub fn successor_targets(&self, bb: BbId) -> Vec<BbId> {
        let Some(term) = self.terminator(bb) else { return Vec::new(); };
        let insn = self.insn(term);
        match insn.kind {
            InsnKind::Ja => insn.bb1.into_iter().collect(),
            InsnKind::CondJmp { .. } => [insn.bb1, insn.bb2].into_iter().flatten().collect(),
            _ => Vec::new(),
        }
    }

    pub fn set_ja_target(&mut self, ja: InsnId, target: BbId) -> Result<()> {
        if !matches!(self.insn(ja).kind, InsnKind::Ja) {
            return Err(invalid!("instruction %{} is not a ja", ja.0));
        }
        let bb = self.insn(ja).parent_bb;
        if let Some(old) = self.insn(ja).bb1 {
            self.disconnect(bb, old);
        }
        self.insn_mut(ja).bb1 = Some(target);
        self.insn_mut(ja).bb2 = None;
        self.connect(bb, target);
        Ok(())
    }

    pub fn set_cond_targets(&mut self, cond: InsnId, fallthrough: BbId, taken: BbId) -> Result<()> {
        if !matches!(self.insn(cond).kind, InsnKind::CondJmp { .. }) {
            return Err(invalid!("instruction %{} is not a conditional jump", cond.0));
        }
        let bb = self.insn(cond).parent_bb;
        for old in [self.insn(cond).bb1, self.insn(cond).bb2].into_iter().flatten() {
            self.disconnect(bb, old);
        }
        {
            let insn = self.insn_mut(cond);
            insn.bb1 = Some(fallthrough);
            insn.bb2 = Some(taken);
        }
        self.connect(bb, fallthrough);
        self.connect(bb, taken);
        Ok(())
    }

    /// Redirect a terminator edge `from -> old_to` to `from -> new_to`.
    ///
    /// This updates the terminator and CFG edge lists. Phi inputs in the old/new
    /// successor are not invented; callers that retarget semantic edges should
    /// update phis as appropriate. Use [`Function::split_edge`] when inserting a
    /// block on an existing edge, as it updates phi predecessor labels safely.
    pub fn replace_successor(&mut self, from: BbId, old_to: BbId, new_to: BbId) -> Result<()> {
        let term = self.terminator(from).ok_or_else(|| invalid!("bb{} has no terminator", from.0))?;
        match self.insn(term).kind {
            InsnKind::Ja => {
                if self.insn(term).bb1 != Some(old_to) {
                    return Err(invalid!("bb{} ja does not target bb{}", from.0, old_to.0));
                }
                self.set_ja_target(term, new_to)?;
            }
            InsnKind::CondJmp { .. } => {
                let mut b1 = self.insn(term).bb1;
                let mut b2 = self.insn(term).bb2;
                let mut found = false;
                if b1 == Some(old_to) { b1 = Some(new_to); found = true; }
                if b2 == Some(old_to) { b2 = Some(new_to); found = true; }
                if !found {
                    return Err(invalid!("bb{} conditional does not target bb{}", from.0, old_to.0));
                }
                self.set_cond_targets(term, b1.unwrap(), b2.unwrap())?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    /// Insert a new block on edge `from -> to`, returning the new block.
    /// Phi inputs in `to` that came from `from` are relabeled to the new block.
    pub fn split_edge(&mut self, from: BbId, to: BbId) -> Result<BbId> {
        if !self.bb(from).succs.contains(&to) {
            return Err(invalid!("edge bb{} -> bb{} does not exist", from.0, to.0));
        }
        let new_bb = self.create_bb();
        let ja = self.create_insn(new_bb, InsnKind::Ja, InsertPos::Back);
        self.insn_mut(ja).bb1 = Some(to);
        self.replace_successor(from, to, new_bb)?;
        self.connect(new_bb, to);

        let phis: Vec<_> = self
            .bb(to)
            .insns
            .iter()
            .copied()
            .take_while(|&id| matches!(self.insn(id).kind, InsnKind::Phi))
            .collect();
        for phi in phis {
            for entry in &mut self.insn_mut(phi).phi {
                if entry.bb == from {
                    entry.bb = new_bb;
                }
            }
        }
        Ok(new_bb)
    }

    /// Split the parent block so that `insn` and following instructions move to a
    /// fresh successor block. Returns the fresh block.
    pub fn split_block_before(&mut self, insn: InsnId) -> Result<BbId> {
        if matches!(self.insn(insn).kind, InsnKind::Phi) {
            return Err(invalid!("cannot split block before phi instruction %{}", insn.0));
        }
        let old_bb = self.insn(insn).parent_bb;
        let pos = self
            .bb(old_bb)
            .insns
            .iter()
            .position(|&id| id == insn)
            .ok_or_else(|| invalid!("instruction %{} is not in its parent block", insn.0))?;

        let new_bb = self.create_bb();
        let moved: Vec<_> = self.bbs[old_bb.index()].insns.split_off(pos);
        for id in &moved {
            self.insn_mut(*id).parent_bb = new_bb;
        }
        self.bbs[new_bb.index()].insns = moved;

        let old_succs = self.bbs[old_bb.index()].succs.clone();
        for succ in old_succs.clone() {
            self.disconnect(old_bb, succ);
            self.connect(new_bb, succ);
            // Edges to old successors now come from the new block; relabel phis.
            let phis: Vec<_> = self
                .bb(succ)
                .insns
                .iter()
                .copied()
                .take_while(|&id| matches!(self.insn(id).kind, InsnKind::Phi))
                .collect();
            for phi in phis {
                for entry in &mut self.insn_mut(phi).phi {
                    if entry.bb == old_bb {
                        entry.bb = new_bb;
                    }
                }
            }
        }

        let ja = self.create_insn(old_bb, InsnKind::Ja, InsertPos::Back);
        self.insn_mut(ja).bb1 = Some(new_bb);
        self.connect(old_bb, new_bb);
        Ok(new_bb)
    }

    /// Split the parent block after `insn`, moving following instructions to a
    /// fresh successor block.
    pub fn split_block_after(&mut self, insn: InsnId) -> Result<BbId> {
        if self.insn(insn).is_jmp() {
            return Err(invalid!("cannot split block after terminator %{}", insn.0));
        }
        let next = self.next_insn(insn).ok_or_else(|| invalid!("instruction %{} has no following instruction to split", insn.0))?;
        self.split_block_before(next)
    }

    pub fn create_ret_block(&mut self, value: Value) -> BbId {
        let bb = self.create_bb();
        let ret = self.create_insn(bb, InsnKind::Ret, InsertPos::Back);
        self.add_value_operand(ret, value);
        bb
    }

    pub fn create_throw_block(&mut self) -> BbId {
        let bb = self.create_bb();
        self.create_insn(bb, InsnKind::Throw, InsertPos::Back);
        bb
    }

    // ---- instruction creation / placement ----

    /// Resolve an insertion position into an index in `bb.insns`.
    fn resolve_index(&self, bb: BbId, anchor: Option<InsnId>, pos: InsertPos) -> usize {
        let block = self.bb(bb);
        match pos {
            InsertPos::Front => match anchor {
                Some(a) => block.insns.iter().position(|&i| i == a).unwrap_or(0),
                None => 0,
            },
            InsertPos::Back => match anchor {
                Some(a) => {
                    block.insns.iter().position(|&i| i == a).map_or(block.insns.len(), |p| p + 1)
                }
                None => block.insns.len(),
            },
            InsertPos::BackBeforeJmp => {
                if let Some(last) = block.last() {
                    if self.insn(last).is_jmp() {
                        return block.insns.len() - 1;
                    }
                }
                block.insns.len()
            }
            InsertPos::FrontAfterPhi => {
                let mut idx = 0;
                for &i in &block.insns {
                    if matches!(self.insn(i).kind, InsnKind::Phi) {
                        idx += 1;
                    } else {
                        break;
                    }
                }
                idx
            }
        }
    }

    /// Create a new instruction and insert it into `bb` at `pos`. Returns its id.
    ///
    /// The caller is responsible for adding operands via [`Function::add_use`]
    /// (the typed `build_*` helpers do this).
    pub fn create_insn(&mut self, bb: BbId, kind: InsnKind, pos: InsertPos) -> InsnId {
        let id = InsnId(self.insns.len() as u32);
        self.insns.push(Some(Insn::new(kind, bb)));
        let idx = self.resolve_index(bb, None, pos);
        self.bbs[bb.index()].insns.insert(idx, id);
        id
    }

    /// Create a new instruction positioned relative to `anchor`.
    pub fn create_insn_at(&mut self, anchor: InsnId, kind: InsnKind, pos: InsertPos) -> InsnId {
        let bb = self.insn(anchor).parent_bb;
        let id = InsnId(self.insns.len() as u32);
        self.insns.push(Some(Insn::new(kind, bb)));
        let idx = self.resolve_index(bb, Some(anchor), pos);
        self.bbs[bb.index()].insns.insert(idx, id);
        id
    }

    // ---- def-use maintenance ----

    /// Record that `user` uses `val` (adds to the def's user list if it's an insn).
    pub fn add_use(&mut self, val: Value, user: InsnId) {
        if let Value::Insn(def) = val {
            let users = &mut self.insn_mut(def).users;
            if !users.contains(&user) {
                users.push(user);
            }
        }
    }

    /// Remove `user` from the user list of `val`'s definition.
    pub fn remove_use(&mut self, val: Value, user: InsnId) {
        if let Value::Insn(def) = val {
            if self.is_alive(def) {
                self.insn_mut(def).users.retain(|&u| u != user);
            }
        }
    }

    /// Replace every use of `old`'s value across the function with `rep`.
    pub fn replace_all_uses(&mut self, old: InsnId, rep: Value) {
        self.replace_all_uses_except(old, rep, None);
    }

    /// Like [`Function::replace_all_uses`] but skips `except`.
    pub fn replace_all_uses_except(&mut self, old: InsnId, rep: Value, except: Option<InsnId>) {
        let users: Vec<InsnId> = self.insn(old).users.clone();
        let old_val = Value::Insn(old);
        for user in users {
            if Some(user) == except || !self.is_alive(user) {
                continue;
            }
            self.replace_value_in(user, old_val, rep);
        }
    }

    /// Replace occurrences of `from` with `to` in a single instruction's operands,
    /// updating def-use bookkeeping.
    pub fn replace_value_in(&mut self, user: InsnId, from: Value, to: Value) {
        let mut changed = false;
        {
            let insn = self.insn_mut(user);
            match &mut insn.kind {
                InsnKind::Phi => {
                    for p in &mut insn.phi {
                        if p.value == from {
                            p.value = to;
                            changed = true;
                        }
                    }
                }
                InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } => {
                    if addr.value == from {
                        addr.value = to;
                        changed = true;
                    }
                    for v in insn.values.iter_mut() {
                        if *v == from {
                            *v = to;
                            changed = true;
                        }
                    }
                }
                _ => {
                    for v in insn.values.iter_mut() {
                        if *v == from {
                            *v = to;
                            changed = true;
                        }
                    }
                }
            }
        }
        if changed {
            self.remove_use(from, user);
            self.add_use(to, user);
        }
    }

    /// Change `*slot_value` of `user` from its current value to `new`, where the
    /// slot is identified by equality with `old`.
    pub fn change_value(&mut self, user: InsnId, old: Value, new: Value) {
        self.replace_value_in(user, old, new);
    }

    /// Add a normal operand value to `user`, updating def-use chains.
    pub fn add_value_operand(&mut self, user: InsnId, value: Value) {
        self.insn_mut(user).values.push(value);
        self.add_use(value, user);
    }

    /// Add a phi operand `(value, predecessor block)`, updating def-use chains.
    pub fn add_phi_operand(&mut self, phi: InsnId, value: Value, bb: BbId) {
        self.insn_mut(phi).phi.push(PhiValue { value, bb });
        self.add_use(value, phi);
    }

    /// Remove all non-phi operand values from `user`, updating def-use chains.
    ///
    /// Phi operands live in [`Insn::phi`] and are intentionally not touched by
    /// this helper.
    pub fn clear_values(&mut self, user: InsnId) {
        let values: Vec<Value> = self.insn(user).values.to_vec();
        for v in values {
            self.remove_use(v, user);
        }
        self.insn_mut(user).values.clear();
    }

    /// Rewrite a conditional terminator into an unconditional jump to `target`.
    pub fn rewrite_cond_to_ja(&mut self, id: InsnId, target: BbId) {
        self.clear_values(id);
        let insn = self.insn_mut(id);
        insn.kind = InsnKind::Ja;
        insn.bb1 = Some(target);
        insn.bb2 = None;
        insn.alu_op = AluOp::Unknown;
    }

    // ---- erasure ----

    /// Tombstone an instruction, detaching it from its block and dropping its
    /// outgoing uses. Panics if it still has live users.
    pub fn erase_insn(&mut self, id: InsnId) {
        let users: Vec<InsnId> = self
            .insn(id)
            .users
            .iter()
            .copied()
            .filter(|&u| u != id)
            .collect();
        assert!(
            users.is_empty(),
            "cannot erase instruction {id:?} that still has users {users:?}"
        );
        // Drop our uses of operands.
        for v in self.insn(id).operand_values() {
            self.remove_use(v, id);
        }
        let bb = self.insn(id).parent_bb;
        self.bbs[bb.index()].insns.retain(|&i| i != id);
        self.insns[id.index()] = None;
    }

    // ---- queries ----

    pub fn prev_insn(&self, id: InsnId) -> Option<InsnId> {
        let bb = self.insn(id).parent_bb;
        let block = self.bb(bb);
        let pos = block.insns.iter().position(|&i| i == id)?;
        if pos == 0 {
            None
        } else {
            Some(block.insns[pos - 1])
        }
    }

    pub fn next_insn(&self, id: InsnId) -> Option<InsnId> {
        let bb = self.insn(id).parent_bb;
        let block = self.bb(bb);
        let pos = block.insns.iter().position(|&i| i == id)?;
        block.insns.get(pos + 1).copied()
    }

    /// Find the IR instruction lifted from a given raw bytecode position.
    pub fn find_by_raw_pos(&self, raw_pos: usize) -> Option<InsnId> {
        for &bb in &self.reachable_bbs {
            for &id in &self.bb(bb).insns {
                let rp = self.insn(id).raw_pos;
                if rp.valid && rp.pos == raw_pos {
                    return Some(id);
                }
            }
        }
        None
    }

    // ---- typed instruction builders (maintain def-use) ----

    /// `%x = alloc <ty>` placed in `bb` at `pos`.
    pub fn build_alloc_bb(&mut self, bb: BbId, ty: VrType, pos: InsertPos) -> InsnId {
        self.create_insn(bb, InsnKind::Alloc { vr_type: ty }, pos)
    }

    /// `%x = assign <val>` placed before/after `anchor`.
    pub fn build_assign_at(&mut self, anchor: InsnId, val: Value, pos: InsertPos) -> InsnId {
        let id = self.create_insn_at(anchor, InsnKind::Assign, pos);
        self.insn_mut(id).values.push(val);
        self.add_use(val, id);
        id
    }

    /// `%x = assign <val>` placed in `bb`.
    pub fn build_assign_bb(&mut self, bb: BbId, val: Value, pos: InsertPos) -> InsnId {
        let id = self.create_insn(bb, InsnKind::Assign, pos);
        self.insn_mut(id).values.push(val);
        self.add_use(val, id);
        id
    }

    /// `store <alloc>, <val>` placed before/after `anchor`.
    pub fn build_store_at(
        &mut self,
        anchor: InsnId,
        alloc: InsnId,
        val: Value,
        pos: InsertPos,
    ) -> InsnId {
        let id = self.create_insn_at(anchor, InsnKind::Store, pos);
        let aval = Value::Insn(alloc);
        self.insn_mut(id).values.push(aval);
        self.insn_mut(id).values.push(val);
        self.add_use(aval, id);
        self.add_use(val, id);
        id
    }

    /// `%x = load <alloc>` placed before/after `anchor`.
    pub fn build_load_at(&mut self, anchor: InsnId, alloc: InsnId, pos: InsertPos) -> InsnId {
        let id = self.create_insn_at(anchor, InsnKind::Load, pos);
        let aval = Value::Insn(alloc);
        self.insn_mut(id).values.push(aval);
        self.add_use(aval, id);
        id
    }

    /// `%x = load <alloc>` placed in `bb`.
    pub fn build_load_bb(&mut self, bb: BbId, alloc: InsnId, pos: InsertPos) -> InsnId {
        let id = self.create_insn(bb, InsnKind::Load, pos);
        let aval = Value::Insn(alloc);
        self.insn_mut(id).values.push(aval);
        self.add_use(aval, id);
        id
    }
}
