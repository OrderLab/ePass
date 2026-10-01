//! Function storage and the editing API that keeps its invariants:
//! intrusive instruction lists, intrusive use lists, and predecessor lists
//! that always match the terminators.

use core::fmt;

use super::{BlockId, FrameSlot, FuncId, InsnId, Op, OpndId, SlotId, Succs, Value};
use crate::error::{Error, Result};
use crate::mem::{Arena, FVec, Heap, Idx, IdxVec};

/// One operand slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operand {
    pub value: Value,
    pub user: InsnId,
    /// Incoming block (phi operands only).
    pub block: Option<BlockId>,
    next_use: Option<OpndId>,
    prev_use: Option<OpndId>,
}

/// One instruction.
#[derive(Clone, Copy, Debug)]
pub struct InsnData {
    pub op: Op,
    /// Source bytecode index, for diagnostics and the offset map.
    pub origin: Option<u32>,
    /// Register the original program kept this value in (an allocation
    /// hint; not part of the IR semantics or formats).
    pub hint: Option<u8>,
    block: BlockId,
    prev: Option<InsnId>,
    next: Option<InsnId>,
    opnd_start: u32,
    opnd_len: u16,
    opnd_cap: u16,
    first_use: Option<OpndId>,
    use_count: u32,
}

impl InsnData {
    pub fn block(&self) -> BlockId {
        self.block
    }
    pub fn operand_count(&self) -> usize {
        self.opnd_len as usize
    }
    pub fn use_count(&self) -> u32 {
        self.use_count
    }
}

/// One basic block.
pub struct BlockData<'h> {
    first: Option<InsnId>,
    last: Option<InsnId>,
    preds: FVec<'h, BlockId>,
    /// Source bytecode index of the block start.
    pub origin: Option<u32>,
}

impl fmt::Debug for BlockData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockData")
            .field("first", &self.first)
            .field("last", &self.last)
            .field("preds", &self.preds)
            .finish()
    }
}

impl BlockData<'_> {
    pub fn preds(&self) -> &[BlockId] {
        self.preds.as_slice()
    }
    pub fn first(&self) -> Option<InsnId> {
        self.first
    }
    pub fn last(&self) -> Option<InsnId> {
        self.last
    }
}

/// Where to insert a new instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// At the end of a block (after its terminator is not allowed: use
    /// `BeforeTerminator` for non-terminators in terminated blocks).
    End(BlockId),
    /// Before the block's terminator, or at the end if it has none.
    BeforeTerminator(BlockId),
    /// After the block's leading phis.
    AfterPhis(BlockId),
    Before(InsnId),
    After(InsnId),
}

/// A function in SSA form.
pub struct Function<'h> {
    heap: &'h Heap<'h>,
    insns: Arena<'h, InsnId, InsnData>,
    opnds: IdxVec<'h, OpndId, Operand>,
    blocks: Arena<'h, BlockId, BlockData<'h>>,
    slots: IdxVec<'h, SlotId, FrameSlot>,
    entry: BlockId,
}

impl fmt::Debug for Function<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Function")
            .field("blocks", &self.blocks.live())
            .field("insns", &self.insns.live())
            .field("entry", &self.entry)
            .finish()
    }
}

const NO_ID: &str = "dead or unknown id";

impl<'h> Function<'h> {
    /// An empty function with one (entry) block.
    pub fn new(heap: &'h Heap<'h>) -> Result<Self> {
        let mut f = Function {
            heap,
            insns: Arena::new(heap),
            opnds: IdxVec::new(heap),
            blocks: Arena::new(heap),
            slots: IdxVec::new(heap),
            entry: BlockId(0),
        };
        f.entry = f.add_block()?;
        Ok(f)
    }

    pub fn heap(&self) -> &'h Heap<'h> {
        self.heap
    }

    pub fn entry(&self) -> BlockId {
        self.entry
    }

    /// Make `b` the entry block. The validator requires it to have no
    /// predecessors.
    pub fn set_entry(&mut self, b: BlockId) -> Result<()> {
        self.block(b)?;
        self.entry = b;
        Ok(())
    }

    // ---------------------------------------------------------------- blocks

    pub fn add_block(&mut self) -> Result<BlockId> {
        self.blocks.alloc(BlockData {
            first: None,
            last: None,
            preds: FVec::new(self.heap),
            origin: None,
        })
    }

    pub fn block(&self, b: BlockId) -> Result<&BlockData<'h>> {
        self.blocks.get(b).ok_or(Error::internal(NO_ID))
    }

    fn block_mut(&mut self, b: BlockId) -> Result<&mut BlockData<'h>> {
        self.blocks.get_mut(b).ok_or(Error::internal(NO_ID))
    }

    pub fn is_block(&self, b: BlockId) -> bool {
        self.blocks.is_live(b)
    }

    /// Live blocks in creation order.
    pub fn blocks(&self) -> impl Iterator<Item = BlockId> + '_ {
        self.blocks.iter().map(|(b, _)| b)
    }

    pub fn block_count(&self) -> usize {
        self.blocks.live()
    }

    /// Upper bound (exclusive) on block id values, for side tables.
    pub fn block_id_bound(&self) -> usize {
        self.blocks.capacity_ids()
    }

    pub fn set_block_origin(&mut self, b: BlockId, origin: Option<u32>) -> Result<()> {
        self.block_mut(b)?.origin = origin;
        Ok(())
    }

    pub fn preds(&self, b: BlockId) -> Result<&[BlockId]> {
        Ok(self.block(b)?.preds.as_slice())
    }

    /// The block's terminator, if its last instruction is one.
    pub fn terminator(&self, b: BlockId) -> Result<Option<InsnId>> {
        let Some(last) = self.block(b)?.last else {
            return Ok(None);
        };
        Ok(if self.insn(last)?.op.is_terminator() {
            Some(last)
        } else {
            None
        })
    }

    pub fn successors(&self, b: BlockId) -> Result<Succs> {
        match self.terminator(b)? {
            Some(t) => Ok(self.insn(t)?.op.successors()),
            None => Ok(Succs::none()),
        }
    }

    /// Remove an empty block (no instructions, no predecessors).
    pub fn remove_block(&mut self, b: BlockId) -> Result<()> {
        let bd = self.block(b)?;
        if bd.first.is_some() || !bd.preds.is_empty() {
            return Err(Error::internal("remove_block: block not empty"));
        }
        if b == self.entry {
            return Err(Error::internal("remove_block: entry block"));
        }
        self.blocks.remove(b);
        Ok(())
    }

    // ----------------------------------------------------------- instructions

    pub fn insn(&self, i: InsnId) -> Result<&InsnData> {
        self.insns.get(i).ok_or(Error::internal(NO_ID))
    }

    fn insn_mut(&mut self, i: InsnId) -> Result<&mut InsnData> {
        self.insns.get_mut(i).ok_or(Error::internal(NO_ID))
    }

    pub fn is_insn(&self, i: InsnId) -> bool {
        self.insns.is_live(i)
    }

    pub fn op(&self, i: InsnId) -> Result<Op> {
        Ok(self.insn(i)?.op)
    }

    pub fn insn_count(&self) -> usize {
        self.insns.live()
    }

    /// Upper bound (exclusive) on instruction id values, for side tables.
    pub fn insn_id_bound(&self) -> usize {
        self.insns.capacity_ids()
    }

    pub fn next(&self, i: InsnId) -> Result<Option<InsnId>> {
        Ok(self.insn(i)?.next)
    }

    pub fn prev(&self, i: InsnId) -> Result<Option<InsnId>> {
        Ok(self.insn(i)?.prev)
    }

    /// Iterate a block's instructions. Do not mutate the block while
    /// iterating; take a snapshot with [`Function::block_insns`] instead.
    pub fn iter_block(&self, b: BlockId) -> BlockIter<'_, 'h> {
        BlockIter {
            f: self,
            cur: self.blocks.get(b).and_then(|bd| bd.first),
        }
    }

    /// Snapshot of a block's instruction ids.
    pub fn block_insns(&self, b: BlockId) -> Result<FVec<'h, InsnId>> {
        let mut v = FVec::new(self.heap);
        for i in self.iter_block(b) {
            v.push(i)?;
        }
        Ok(v)
    }

    /// Change the op of an instruction, keeping its operands. Terminator
    /// edits go through [`Function::set_terminator`].
    pub fn set_op(&mut self, i: InsnId, op: Op) -> Result<()> {
        let old = self.insn(i)?.op;
        if old.is_terminator() || op.is_terminator() {
            return Err(Error::internal("set_op on terminator; use set_terminator"));
        }
        if old.has_result() && !op.has_result() && self.insn(i)?.use_count != 0 {
            return Err(Error::internal("set_op would drop a used result"));
        }
        self.insn_mut(i)?.op = op;
        Ok(())
    }

    pub fn set_hint(&mut self, i: InsnId, hint: Option<u8>) -> Result<()> {
        self.insn_mut(i)?.hint = hint;
        Ok(())
    }

    pub fn set_origin(&mut self, i: InsnId, origin: Option<u32>) -> Result<()> {
        self.insn_mut(i)?.origin = origin;
        Ok(())
    }

    /// Insert a new instruction. Terminators must go at the end of a block
    /// that has none; phis must be inserted with [`Function::insert_phi`].
    pub fn insert(&mut self, at: At, op: Op, operands: &[Value]) -> Result<InsnId> {
        if matches!(op, Op::Phi) {
            return Err(Error::internal("use insert_phi"));
        }
        let (block, after) = self.resolve(at, op.is_terminator())?;
        let n = u16::try_from(operands.len()).map_err(|_| Error::internal("too many operands"))?;
        // Validate operands first so a rejected operand leaves no partial
        // instruction behind.
        for &v in operands {
            self.check_def(v)?;
        }
        for &s in op.successors().as_slice() {
            if !self.is_block(s) {
                return Err(Error::invalid_ir("branch to unknown block"));
            }
        }
        let id = self.insns.alloc(InsnData {
            op,
            origin: None,
            hint: None,
            block,
            prev: None,
            next: None,
            opnd_start: 0,
            opnd_len: 0,
            opnd_cap: 0,
            first_use: None,
            use_count: 0,
        })?;
        let start = self.alloc_opnds(id, n)?;
        {
            let d = self.insn_mut(id)?;
            d.opnd_start = start;
            d.opnd_cap = n;
            d.opnd_len = n;
        }
        for (k, &v) in operands.iter().enumerate() {
            self.set_operand(id, k, v)?;
        }
        self.link_into_block(id, block, after)?;
        if op.is_terminator() {
            self.add_succ_edges(block, op.successors())?;
        }
        Ok(id)
    }

    /// Insert a phi at the head of `block` with the given inputs.
    pub fn insert_phi(&mut self, block: BlockId, inputs: &[(Value, BlockId)]) -> Result<InsnId> {
        let (_, after) = self.resolve(At::AfterPhis(block), false)?;
        let n = u16::try_from(inputs.len()).map_err(|_| Error::internal("too many phi inputs"))?;
        let cap = n.max(2);
        let id = self.insns.alloc(InsnData {
            op: Op::Phi,
            origin: None,
            hint: None,
            block,
            prev: None,
            next: None,
            opnd_start: 0,
            opnd_len: 0,
            opnd_cap: 0,
            first_use: None,
            use_count: 0,
        })?;
        let start = self.alloc_opnds(id, cap)?;
        {
            let d = self.insn_mut(id)?;
            d.opnd_start = start;
            d.opnd_cap = cap;
            d.opnd_len = n;
        }
        for (k, &(v, b)) in inputs.iter().enumerate() {
            self.set_operand(id, k, v)?;
            self.opnd_mut(Self::opnd_id(start, k))?.block = Some(b);
        }
        self.link_into_block(id, block, after)?;
        Ok(id)
    }

    /// Resolve an insertion point to (block, insert-after).
    fn resolve(&self, at: At, is_term: bool) -> Result<(BlockId, Option<InsnId>)> {
        match at {
            At::End(b) => {
                let last = self.block(b)?.last;
                if self.terminator(b)?.is_some() {
                    return Err(Error::internal("insert after terminator"));
                }
                Ok((b, last))
            }
            At::BeforeTerminator(b) => {
                if is_term {
                    return Err(Error::internal("terminator before terminator"));
                }
                match self.terminator(b)? {
                    Some(t) => Ok((b, self.insn(t)?.prev)),
                    None => Ok((b, self.block(b)?.last)),
                }
            }
            At::AfterPhis(b) => {
                let mut after = None;
                for i in self.iter_block(b) {
                    if matches!(self.insn(i)?.op, Op::Phi) {
                        after = Some(i);
                    } else {
                        break;
                    }
                }
                if is_term && self.block(b)?.first.is_some() {
                    return Err(Error::internal("terminator must be last"));
                }
                Ok((b, after))
            }
            At::Before(anchor) => {
                if is_term {
                    return Err(Error::internal("terminator must be last"));
                }
                let d = self.insn(anchor)?;
                Ok((d.block, d.prev))
            }
            At::After(anchor) => {
                let d = self.insn(anchor)?;
                if d.op.is_terminator() {
                    return Err(Error::internal("insert after terminator"));
                }
                if is_term && d.next.is_some() {
                    return Err(Error::internal("terminator must be last"));
                }
                Ok((d.block, Some(anchor)))
            }
        }
    }

    fn link_into_block(&mut self, id: InsnId, block: BlockId, after: Option<InsnId>) -> Result<()> {
        let next = match after {
            Some(a) => self.insn(a)?.next,
            None => self.block(block)?.first,
        };
        {
            let d = self.insn_mut(id)?;
            d.block = block;
            d.prev = after;
            d.next = next;
        }
        match after {
            Some(a) => self.insn_mut(a)?.next = Some(id),
            None => self.block_mut(block)?.first = Some(id),
        }
        match next {
            Some(n) => self.insn_mut(n)?.prev = Some(id),
            None => self.block_mut(block)?.last = Some(id),
        }
        Ok(())
    }

    fn unlink_from_block(&mut self, id: InsnId) -> Result<()> {
        let (block, prev, next) = {
            let d = self.insn(id)?;
            (d.block, d.prev, d.next)
        };
        match prev {
            Some(p) => self.insn_mut(p)?.next = next,
            None => self.block_mut(block)?.first = next,
        }
        match next {
            Some(n) => self.insn_mut(n)?.prev = prev,
            None => self.block_mut(block)?.last = prev,
        }
        let d = self.insn_mut(id)?;
        d.prev = None;
        d.next = None;
        Ok(())
    }

    /// Move an existing non-phi, non-terminator instruction.
    pub fn move_insn(&mut self, id: InsnId, at: At) -> Result<()> {
        let op = self.insn(id)?.op;
        if op.is_terminator() || matches!(op, Op::Phi) {
            return Err(Error::internal("move_insn: terminators and phis stay put"));
        }
        if at == At::Before(id) || at == At::After(id) {
            return Ok(());
        }
        self.unlink_from_block(id)?;
        let (block, after) = self.resolve(at, false)?;
        self.link_into_block(id, block, after)
    }

    /// Remove an instruction whose result is unused.
    pub fn remove(&mut self, id: InsnId) -> Result<()> {
        let d = *self.insn(id)?;
        if d.use_count != 0 {
            return Err(Error::internal("remove: instruction still has uses"));
        }
        if d.op.is_terminator() {
            self.remove_succ_edges(d.block, d.op.successors())?;
        }
        for k in 0..d.opnd_cap as usize {
            let o = Self::opnd_id(d.opnd_start, k);
            self.unlink_use(o)?;
            self.opnd_mut(o)?.value = Value::Undef;
        }
        self.unlink_from_block(id)?;
        self.insns.remove(id);
        Ok(())
    }

    // --------------------------------------------------------------- operands

    fn opnd_id(start: u32, k: usize) -> OpndId {
        OpndId(start.wrapping_add(k as u32))
    }

    fn alloc_opnds(&mut self, user: InsnId, n: u16) -> Result<u32> {
        let start = u32::try_from(self.opnds.len()).map_err(|_| Error::limit("operand space"))?;
        for _ in 0..n {
            self.opnds.push(Operand {
                value: Value::Undef,
                user,
                block: None,
                next_use: None,
                prev_use: None,
            })?;
        }
        Ok(start)
    }

    pub fn opnd(&self, o: OpndId) -> Result<&Operand> {
        self.opnds.at(o)
    }

    fn opnd_mut(&mut self, o: OpndId) -> Result<&mut Operand> {
        self.opnds.at_mut(o)
    }

    /// Operand ids of an instruction, in order.
    pub fn operand_ids(&self, i: InsnId) -> Result<impl Iterator<Item = OpndId>> {
        let d = self.insn(i)?;
        let start = d.opnd_start;
        Ok((0..d.opnd_len as usize).map(move |k| Self::opnd_id(start, k)))
    }

    pub fn operand_count(&self, i: InsnId) -> Result<usize> {
        Ok(self.insn(i)?.opnd_len as usize)
    }

    pub fn operand(&self, i: InsnId, k: usize) -> Result<Value> {
        let d = self.insn(i)?;
        if k >= d.opnd_len as usize {
            return Err(Error::internal("operand index out of range"));
        }
        Ok(self.opnd(Self::opnd_id(d.opnd_start, k))?.value)
    }

    /// Operand values of an instruction, in order.
    pub fn operands(&self, i: InsnId) -> OperandIter<'_, 'h> {
        let (start, len) = match self.insns.get(i) {
            Some(d) => (d.opnd_start, d.opnd_len as usize),
            None => (0, 0),
        };
        OperandIter {
            f: self,
            start,
            k: 0,
            len,
        }
    }

    /// Phi inputs `(value, incoming block)`.
    pub fn phi_inputs(&self, phi: InsnId) -> impl Iterator<Item = (Value, BlockId)> + '_ {
        let (start, len) = match self.insns.get(phi) {
            Some(d) => (d.opnd_start, d.opnd_len as usize),
            None => (0, 0),
        };
        (0..len).filter_map(move |k| {
            let o = self.opnds.get(Self::opnd_id(start, k))?;
            Some((o.value, o.block?))
        })
    }

    /// Set operand `k` of `i`, maintaining use lists.
    pub fn set_operand(&mut self, i: InsnId, k: usize, v: Value) -> Result<()> {
        let d = *self.insn(i)?;
        if k >= d.opnd_cap as usize {
            return Err(Error::internal("operand index out of range"));
        }
        self.check_def(v)?;
        let o = Self::opnd_id(d.opnd_start, k);
        self.unlink_use(o)?;
        self.opnd_mut(o)?.value = v;
        self.link_use(o)
    }

    fn check_def(&self, v: Value) -> Result<()> {
        if let Value::Insn(def) = v {
            let dd = self.insn(def).map_err(|_| Error::invalid_ir("use of dead instruction"))?;
            if !dd.op.has_result() {
                return Err(Error::invalid_ir("use of an instruction without a result"));
            }
        }
        Ok(())
    }

    fn link_use(&mut self, o: OpndId) -> Result<()> {
        let Value::Insn(def) = self.opnd(o)?.value else {
            return Ok(());
        };
        let head = self.insn(def)?.first_use;
        {
            let op = self.opnd_mut(o)?;
            op.prev_use = None;
            op.next_use = head;
        }
        if let Some(h) = head {
            self.opnd_mut(h)?.prev_use = Some(o);
        }
        let dd = self.insn_mut(def)?;
        dd.first_use = Some(o);
        dd.use_count = dd.use_count.saturating_add(1);
        Ok(())
    }

    fn unlink_use(&mut self, o: OpndId) -> Result<()> {
        let op = *self.opnd(o)?;
        let Value::Insn(def) = op.value else {
            return Ok(());
        };
        match op.prev_use {
            Some(p) => self.opnd_mut(p)?.next_use = op.next_use,
            None => {
                if let Some(dd) = self.insns.get_mut(def) {
                    if dd.first_use == Some(o) {
                        dd.first_use = op.next_use;
                    }
                }
            }
        }
        if let Some(n) = op.next_use {
            self.opnd_mut(n)?.prev_use = op.prev_use;
        }
        if let Some(dd) = self.insns.get_mut(def) {
            dd.use_count = dd.use_count.saturating_sub(1);
        }
        let m = self.opnd_mut(o)?;
        m.next_use = None;
        m.prev_use = None;
        Ok(())
    }

    /// Append a phi input, relocating the operand range when full.
    pub fn add_phi_input(&mut self, phi: InsnId, v: Value, block: BlockId) -> Result<()> {
        let d = *self.insn(phi)?;
        if !matches!(d.op, Op::Phi) {
            return Err(Error::internal("add_phi_input on non-phi"));
        }
        if d.opnd_len == d.opnd_cap {
            let new_cap = d.opnd_cap.checked_mul(2).ok_or(Error::limit("phi too large"))?.max(2);
            let new_start = self.alloc_opnds(phi, new_cap)?;
            for k in 0..d.opnd_len as usize {
                let old = Self::opnd_id(d.opnd_start, k);
                let new = Self::opnd_id(new_start, k);
                let (val, blk) = {
                    let o = self.opnd(old)?;
                    (o.value, o.block)
                };
                self.unlink_use(old)?;
                self.opnd_mut(old)?.value = Value::Undef;
                let n = self.opnd_mut(new)?;
                n.value = val;
                n.block = blk;
                self.link_use(new)?;
            }
            let dm = self.insn_mut(phi)?;
            dm.opnd_start = new_start;
            dm.opnd_cap = new_cap;
        }
        let d = *self.insn(phi)?;
        let k = d.opnd_len as usize;
        self.insn_mut(phi)?.opnd_len = d.opnd_len + 1;
        self.set_operand(phi, k, v)?;
        self.opnd_mut(Self::opnd_id(d.opnd_start, k))?.block = Some(block);
        Ok(())
    }

    /// Remove the phi input for `block` (if present).
    pub fn remove_phi_input(&mut self, phi: InsnId, block: BlockId) -> Result<bool> {
        let d = *self.insn(phi)?;
        let len = d.opnd_len as usize;
        let mut found = None;
        for k in 0..len {
            if self.opnd(Self::opnd_id(d.opnd_start, k))?.block == Some(block) {
                found = Some(k);
                break;
            }
        }
        let Some(k) = found else { return Ok(false) };
        let last = len - 1;
        let (lv, lb) = {
            let o = self.opnd(Self::opnd_id(d.opnd_start, last))?;
            (o.value, o.block)
        };
        if k != last {
            self.set_operand(phi, k, lv)?;
            self.opnd_mut(Self::opnd_id(d.opnd_start, k))?.block = lb;
        }
        self.set_operand(phi, last, Value::Undef)?;
        self.opnd_mut(Self::opnd_id(d.opnd_start, last))?.block = None;
        self.insn_mut(phi)?.opnd_len = d.opnd_len - 1;
        Ok(true)
    }

    /// Relabel the incoming block of phi inputs from `old` to `new`.
    pub fn relabel_phi_input(&mut self, phi: InsnId, old: BlockId, new: BlockId) -> Result<()> {
        let ids: FVec<'h, OpndId> = {
            let mut v = FVec::new(self.heap);
            for o in self.operand_ids(phi)? {
                v.push(o)?;
            }
            v
        };
        for &o in ids.iter() {
            let op = self.opnd_mut(o)?;
            if op.block == Some(old) {
                op.block = Some(new);
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------- uses

    /// Iterate the operand slots that use `def`.
    pub fn uses(&self, def: InsnId) -> UseIter<'_, 'h> {
        UseIter {
            f: self,
            cur: self.insns.get(def).and_then(|d| d.first_use),
        }
    }

    pub fn use_count(&self, def: InsnId) -> Result<u32> {
        Ok(self.insn(def)?.use_count)
    }

    /// Replace every use of `def` with `v`.
    pub fn replace_all_uses(&mut self, def: InsnId, v: Value) -> Result<()> {
        if v == Value::Insn(def) {
            return Ok(());
        }
        let mut list: FVec<'h, OpndId> = FVec::new(self.heap);
        for o in self.uses(def) {
            list.push(o)?;
        }
        for &o in list.iter() {
            let (user, k) = self.locate_opnd(o)?;
            self.set_operand(user, k, v)?;
        }
        Ok(())
    }

    /// (user, operand index) of an operand slot.
    pub fn locate_opnd(&self, o: OpndId) -> Result<(InsnId, usize)> {
        let user = self.opnd(o)?.user;
        let start = self.insn(user)?.opnd_start;
        let k = o
            .to_u32()
            .checked_sub(start)
            .ok_or(Error::internal("stale operand"))? as usize;
        Ok((user, k))
    }

    // -------------------------------------------------------------- CFG edits

    fn add_succ_edges(&mut self, from: BlockId, succs: Succs) -> Result<()> {
        for &s in succs.as_slice() {
            self.block_mut(s)
                .map_err(|_| Error::invalid_ir("branch to unknown block"))?
                .preds
                .push_unique(from)?;
        }
        Ok(())
    }

    fn remove_succ_edges(&mut self, from: BlockId, succs: Succs) -> Result<()> {
        for &s in succs.as_slice() {
            if let Some(bd) = self.blocks.get_mut(s) {
                bd.preds.retain(|&p| p != from);
            }
        }
        Ok(())
    }

    /// Replace a block's terminator op (e.g. retarget or fold a branch).
    /// Operands are kept; callers adjust them for a changed operand shape
    /// with [`Function::set_terminator_with`].
    pub fn set_terminator(&mut self, term: InsnId, op: Op) -> Result<()> {
        let d = *self.insn(term)?;
        if !d.op.is_terminator() || !op.is_terminator() {
            return Err(Error::internal("set_terminator on non-terminator"));
        }
        self.remove_succ_edges(d.block, d.op.successors())?;
        self.insn_mut(term)?.op = op;
        self.add_succ_edges(d.block, op.successors())
    }

    /// Replace a terminator with a new op and operand list.
    pub fn set_terminator_with(&mut self, term: InsnId, op: Op, operands: &[Value]) -> Result<InsnId> {
        let block = self.insn(term)?.block;
        let origin = self.insn(term)?.origin;
        self.remove(term)?;
        let id = self.insert(At::End(block), op, operands)?;
        self.set_origin(id, origin)?;
        Ok(id)
    }

    /// Redirect the edge `from -> old` to `from -> new`. Phi inputs are not
    /// changed (see [`Function::split_edge`]).
    pub fn retarget(&mut self, from: BlockId, old: BlockId, new: BlockId) -> Result<()> {
        let term = self
            .terminator(from)?
            .ok_or(Error::internal("retarget: no terminator"))?;
        let op = match self.insn(term)?.op {
            Op::Br { target } if target == old => Op::Br { target: new },
            Op::CondBr { cond, w, t, f } if t == old || f == old => Op::CondBr {
                cond,
                w,
                t: if t == old { new } else { t },
                f: if f == old { new } else { f },
            },
            _ => return Err(Error::internal("retarget: edge not found")),
        };
        self.set_terminator(term, op)
    }

    /// Insert a new block on edge `from -> to`; phi inputs in `to` that came
    /// from `from` now come from the new block.
    pub fn split_edge(&mut self, from: BlockId, to: BlockId) -> Result<BlockId> {
        if !self.successors(from)?.contains(to) {
            return Err(Error::internal("split_edge: no such edge"));
        }
        let mid = self.add_block()?;
        let term_origin = match self.terminator(from)? {
            Some(t) => self.insn(t)?.origin,
            None => None,
        };
        let br = self.insert(At::End(mid), Op::Br { target: to }, &[])?;
        self.set_origin(br, term_origin)?;
        self.retarget(from, to, mid)?;
        for i in self.block_insns(to)?.iter() {
            if !matches!(self.insn(*i)?.op, Op::Phi) {
                break;
            }
            self.relabel_phi_input(*i, from, mid)?;
        }
        Ok(mid)
    }

    // ------------------------------------------------------------------ slots

    pub fn add_slot(&mut self, slot: FrameSlot) -> Result<SlotId> {
        if slot.size == 0 || slot.size > 512 {
            return Err(Error::invalid_ir("bad frame slot size"));
        }
        if slot.may_hold_ptr && (slot.size != 8 || slot.align != 8) {
            return Err(Error::invalid_ir("pointer slots must be 8 bytes, 8-aligned"));
        }
        self.slots.push(slot)
    }

    pub fn slot(&self, s: SlotId) -> Result<FrameSlot> {
        self.slots.at(s).copied()
    }

    pub fn slots(&self) -> impl Iterator<Item = (SlotId, FrameSlot)> + '_ {
        self.slots.iter().map(|(i, s)| (i, *s))
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

/// Iterator over a block's instructions.
pub struct BlockIter<'a, 'h> {
    f: &'a Function<'h>,
    cur: Option<InsnId>,
}

impl fmt::Debug for BlockIter<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockIter").field("cur", &self.cur).finish()
    }
}

impl Iterator for BlockIter<'_, '_> {
    type Item = InsnId;
    fn next(&mut self) -> Option<InsnId> {
        let c = self.cur?;
        self.cur = self.f.insns.get(c).and_then(|d| d.next);
        Some(c)
    }
}

/// Iterator over an instruction's operand values.
pub struct OperandIter<'a, 'h> {
    f: &'a Function<'h>,
    start: u32,
    k: usize,
    len: usize,
}

impl fmt::Debug for OperandIter<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperandIter").field("k", &self.k).finish()
    }
}

impl Iterator for OperandIter<'_, '_> {
    type Item = Value;
    fn next(&mut self) -> Option<Value> {
        if self.k >= self.len {
            return None;
        }
        let o = self.f.opnds.get(Function::opnd_id(self.start, self.k))?;
        self.k += 1;
        Some(o.value)
    }
}

/// Iterator over the uses of a definition.
pub struct UseIter<'a, 'h> {
    f: &'a Function<'h>,
    cur: Option<OpndId>,
}

impl fmt::Debug for UseIter<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UseIter").field("cur", &self.cur).finish()
    }
}

impl Iterator for UseIter<'_, '_> {
    type Item = OpndId;
    fn next(&mut self) -> Option<OpndId> {
        let c = self.cur?;
        self.cur = self.f.opnds.get(c).and_then(|o| o.next_use);
        Some(c)
    }
}

/// A set of functions; v2 compiles exactly one (`main`).
pub struct Module<'h> {
    funcs: IdxVec<'h, FuncId, Function<'h>>,
}

impl fmt::Debug for Module<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module").field("funcs", &self.funcs.len()).finish()
    }
}

impl<'h> Module<'h> {
    pub fn new(heap: &'h Heap<'h>) -> Self {
        Module {
            funcs: IdxVec::new(heap),
        }
    }

    pub fn add(&mut self, f: Function<'h>) -> Result<FuncId> {
        self.funcs.push(f)
    }

    pub fn func(&self, id: FuncId) -> Result<&Function<'h>> {
        self.funcs.at(id)
    }

    pub fn func_mut(&mut self, id: FuncId) -> Result<&mut Function<'h>> {
        self.funcs.at_mut(id)
    }

    pub fn len(&self) -> usize {
        self.funcs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.funcs.is_empty()
    }

    /// The main function (the first one added).
    pub fn main(&self) -> Result<&Function<'h>> {
        self.func(FuncId(0))
    }

    pub fn main_mut(&mut self) -> Result<&mut Function<'h>> {
        self.func_mut(FuncId(0))
    }

    pub fn ids(&self) -> impl Iterator<Item = FuncId> {
        (0..self.funcs.len() as u32).map(FuncId)
    }
}
