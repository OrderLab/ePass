//! Ergonomic IR instruction builder.
//!
//! This mirrors the constructor-style API of the original C core while keeping
//! Rust's arena-based ownership model. Builder methods create an instruction at
//! the configured insertion point, fill opcode-specific fields, and maintain
//! def-use chains for all operands.

use crate::bytecode::MAX_FUNC_ARG;
use crate::error::Result;
use crate::invalid;

use super::insn::{BinOp, Cond, EndKind, InsnKind};
use super::value::{AddrValue, AluOp, LoadImmExtra, PhiValue, RawPos, Value, VrType};
use super::{BbId, Function, InsnId, InsertPos};

/// Where newly-built instructions are inserted.
#[derive(Debug, Clone, Copy)]
pub enum InsertPoint {
    /// Insert in a basic block according to `pos`.
    Bb { bb: BbId, pos: InsertPos },
    /// Insert relative to an existing instruction.
    Insn { anchor: InsnId, pos: InsertPos },
}

/// Builder for constructing IR instructions safely and ergonomically.
pub struct IrBuilder<'f> {
    func: &'f mut Function,
    insert: InsertPoint,
    raw_pos: RawPos,
}

impl<'f> IrBuilder<'f> {
    /// Build at a basic block insertion point.
    pub fn at_bb(func: &'f mut Function, bb: BbId, pos: InsertPos) -> Self {
        Self { func, insert: InsertPoint::Bb { bb, pos }, raw_pos: RawPos::default() }
    }

    /// Build at the end of a block.
    pub fn at_end(func: &'f mut Function, bb: BbId) -> Self {
        Self::at_bb(func, bb, InsertPos::Back)
    }

    /// Build at the start of a block.
    pub fn at_start(func: &'f mut Function, bb: BbId) -> Self {
        Self::at_bb(func, bb, InsertPos::Front)
    }

    /// Build at the end of a block, before an existing terminator if present.
    pub fn before_terminator(func: &'f mut Function, bb: BbId) -> Self {
        Self::at_bb(func, bb, InsertPos::BackBeforeJmp)
    }

    /// Build after any leading phi nodes in a block.
    pub fn after_phi(func: &'f mut Function, bb: BbId) -> Self {
        Self::at_bb(func, bb, InsertPos::FrontAfterPhi)
    }

    /// Build relative to an existing instruction.
    pub fn at_insn(func: &'f mut Function, anchor: InsnId, pos: InsertPos) -> Self {
        Self { func, insert: InsertPoint::Insn { anchor, pos }, raw_pos: RawPos::default() }
    }

    /// Build immediately before an instruction.
    pub fn before(func: &'f mut Function, anchor: InsnId) -> Self {
        Self::at_insn(func, anchor, InsertPos::Front)
    }

    /// Build immediately after an instruction.
    pub fn after(func: &'f mut Function, anchor: InsnId) -> Self {
        Self::at_insn(func, anchor, InsertPos::Back)
    }

    /// Attach source-bytecode provenance to subsequently-created instructions.
    pub fn with_raw_pos(mut self, raw_pos: RawPos) -> Self {
        self.raw_pos = raw_pos;
        self
    }

    /// Change insertion point for this builder.
    pub fn set_insert(&mut self, insert: InsertPoint) {
        self.insert = insert;
    }

    /// Borrow the underlying function.
    pub fn func(&self) -> &Function {
        self.func
    }

    /// Mutably borrow the underlying function.
    pub fn func_mut(&mut self) -> &mut Function {
        self.func
    }

    fn create(&mut self, kind: InsnKind) -> InsnId {
        let id = match self.insert {
            InsertPoint::Bb { bb, pos } => self.func.create_insn(bb, kind, pos),
            InsertPoint::Insn { anchor, pos } => self.func.create_insn_at(anchor, kind, pos),
        };
        self.func.insn_mut(id).raw_pos = self.raw_pos;
        id
    }

    fn push_value(&mut self, id: InsnId, value: Value) {
        self.func.add_value_operand(id, value);
    }

    fn push_values(&mut self, id: InsnId, values: impl IntoIterator<Item = Value>) {
        for v in values {
            self.push_value(id, v);
        }
    }

    /// `%x = alloc <ty>`.
    pub fn alloc(&mut self, ty: VrType) -> InsnId {
        self.create(InsnKind::Alloc { vr_type: ty })
    }

    /// `%x = allocarray <ty> x <num>`.
    pub fn alloc_array(&mut self, ty: VrType, num: u32) -> InsnId {
        self.create(InsnKind::AllocArray { vr_type: ty, num })
    }

    /// `%x = getelemptr <index>, <array>`.
    pub fn get_elem_ptr(&mut self, index: Value, array: Value) -> InsnId {
        let id = self.create(InsnKind::GetElemPtr);
        self.push_value(id, index);
        self.push_value(id, array);
        id
    }

    /// `store <alloc>, <value>`.
    pub fn store(&mut self, alloc: Value, value: Value) -> InsnId {
        let id = self.create(InsnKind::Store);
        self.push_value(id, alloc);
        self.push_value(id, value);
        id
    }

    /// `%x = load <alloc>`.
    pub fn load(&mut self, alloc: Value) -> InsnId {
        let id = self.create(InsnKind::Load);
        self.push_value(id, alloc);
        id
    }

    /// `%x = loadimm.<extra> <imm64>`.
    pub fn load_imm_extra(&mut self, extra: LoadImmExtra, imm64: i64) -> InsnId {
        self.create(InsnKind::LoadImmExtra { extra, imm64 })
    }

    /// `storeraw.<ty> [base+off], value`.
    pub fn store_raw(&mut self, ty: VrType, base: Value, offset: i16, value: Value) -> InsnId {
        self.store_raw_addr(ty, AddrValue::new(base, offset), value)
    }

    /// `storeraw.<ty> addr, value` with a fully-specified address descriptor.
    pub fn store_raw_addr(&mut self, ty: VrType, addr: AddrValue, value: Value) -> InsnId {
        let base = addr.value;
        let id = self.create(InsnKind::StoreRaw { vr_type: ty, addr });
        self.func.add_use(base, id);
        self.push_value(id, value);
        id
    }

    /// `%x = loadraw.<ty> [base+off]`.
    pub fn load_raw(&mut self, ty: VrType, base: Value, offset: i16) -> InsnId {
        self.load_raw_addr(ty, AddrValue::new(base, offset))
    }

    /// `%x = loadraw.<ty> addr` with a fully-specified address descriptor.
    pub fn load_raw_addr(&mut self, ty: VrType, addr: AddrValue) -> InsnId {
        let base = addr.value;
        let id = self.create(InsnKind::LoadRaw { vr_type: ty, addr });
        self.func.add_use(base, id);
        id
    }

    /// `%x = neg<alu> value`.
    pub fn neg(&mut self, alu: AluOp, value: Value) -> InsnId {
        let id = self.create(InsnKind::Neg);
        self.func.insn_mut(id).alu_op = alu;
        self.push_value(id, value);
        id
    }

    /// `%x = end.<kind><width> value`.
    pub fn end(&mut self, kind: EndKind, swap_width: u32, value: Value) -> InsnId {
        let id = self.create(InsnKind::End { kind, swap_width });
        self.func.insn_mut(id).alu_op = AluOp::Alu32;
        self.push_value(id, value);
        id
    }

    /// `%x = <op><alu> lhs, rhs`.
    pub fn bin(&mut self, op: BinOp, alu: AluOp, lhs: Value, rhs: Value) -> InsnId {
        let id = self.create(InsnKind::Bin { op });
        self.func.insn_mut(id).alu_op = alu;
        self.push_value(id, lhs);
        self.push_value(id, rhs);
        id
    }

    pub fn add(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Add, alu, lhs, rhs) }
    pub fn sub(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Sub, alu, lhs, rhs) }
    pub fn mul(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Mul, alu, lhs, rhs) }
    pub fn div(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Div, alu, lhs, rhs) }
    pub fn or(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Or, alu, lhs, rhs) }
    pub fn and(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::And, alu, lhs, rhs) }
    pub fn lsh(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Lsh, alu, lhs, rhs) }
    pub fn arsh(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Arsh, alu, lhs, rhs) }
    pub fn rsh(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Rsh, alu, lhs, rhs) }
    pub fn modulo(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Mod, alu, lhs, rhs) }
    pub fn xor(&mut self, alu: AluOp, lhs: Value, rhs: Value) -> InsnId { self.bin(BinOp::Xor, alu, lhs, rhs) }

    /// `%x = call #fid(args...)`.
    pub fn call(&mut self, fid: i32, args: impl IntoIterator<Item = Value>) -> Result<InsnId> {
        let args: Vec<Value> = args.into_iter().collect();
        if args.len() > MAX_FUNC_ARG {
            return Err(invalid!("call has {} args, max is {}", args.len(), MAX_FUNC_ARG));
        }
        let id = self.create(InsnKind::Call { fid });
        self.push_values(id, args);
        Ok(id)
    }

    /// `%x = ecall(args...)`.
    pub fn ecall(&mut self, args: impl IntoIterator<Item = Value>) -> Result<InsnId> {
        let args: Vec<Value> = args.into_iter().collect();
        if args.len() > MAX_FUNC_ARG {
            return Err(invalid!("ecall has {} args, max is {}", args.len(), MAX_FUNC_ARG));
        }
        let id = self.create(InsnKind::Ecall);
        self.push_values(id, args);
        Ok(id)
    }

    /// `ret value`.
    pub fn ret(&mut self, value: Value) -> InsnId {
        let id = self.create(InsnKind::Ret);
        self.push_value(id, value);
        id
    }

    /// `throw`.
    pub fn throw(&mut self) -> InsnId {
        self.create(InsnKind::Throw)
    }

    /// `ja target`.
    pub fn ja(&mut self, target: BbId) -> InsnId {
        let id = self.create(InsnKind::Ja);
        self.func.insn_mut(id).bb1 = Some(target);
        id
    }

    /// Conditional branch. `fallthrough` is stored in `bb1`; `taken` in `bb2`.
    pub fn cond_jmp(
        &mut self,
        cond: Cond,
        alu: AluOp,
        lhs: Value,
        rhs: Value,
        fallthrough: BbId,
        taken: BbId,
    ) -> InsnId {
        let id = self.create(InsnKind::CondJmp { cond });
        {
            let insn = self.func.insn_mut(id);
            insn.alu_op = alu;
            insn.bb1 = Some(fallthrough);
            insn.bb2 = Some(taken);
        }
        self.push_value(id, lhs);
        self.push_value(id, rhs);
        id
    }

    pub fn jeq(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Eq, alu, lhs, rhs, fallthrough, taken) }
    pub fn jne(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Ne, alu, lhs, rhs, fallthrough, taken) }
    pub fn jgt(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Gt, alu, lhs, rhs, fallthrough, taken) }
    pub fn jge(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Ge, alu, lhs, rhs, fallthrough, taken) }
    pub fn jlt(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Lt, alu, lhs, rhs, fallthrough, taken) }
    pub fn jle(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Le, alu, lhs, rhs, fallthrough, taken) }
    pub fn jsgt(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Sgt, alu, lhs, rhs, fallthrough, taken) }
    pub fn jsge(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Sge, alu, lhs, rhs, fallthrough, taken) }
    pub fn jslt(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Slt, alu, lhs, rhs, fallthrough, taken) }
    pub fn jsle(&mut self, alu: AluOp, lhs: Value, rhs: Value, fallthrough: BbId, taken: BbId) -> InsnId { self.cond_jmp(Cond::Sle, alu, lhs, rhs, fallthrough, taken) }

    /// `%x = phi [value, pred]...`.
    pub fn phi(&mut self, entries: impl IntoIterator<Item = PhiValue>) -> InsnId {
        let id = self.create(InsnKind::Phi);
        for entry in entries {
            self.func.add_phi_operand(id, entry.value, entry.bb);
        }
        id
    }

    /// `%x = phi [value, pred]...` from tuple entries.
    pub fn phi_entries(&mut self, entries: impl IntoIterator<Item = (Value, BbId)>) -> InsnId {
        let id = self.create(InsnKind::Phi);
        for (value, bb) in entries {
            self.func.add_phi_operand(id, value, bb);
        }
        id
    }

    /// `%x = assign value`.
    pub fn assign(&mut self, value: Value) -> InsnId {
        let id = self.create(InsnKind::Assign);
        self.push_value(id, value);
        id
    }

    /// Detached/physical register pseudo. This is usually only for codegen.
    pub fn reg(&mut self, reg_id: u8) -> InsnId {
        self.create(InsnKind::Reg { reg_id })
    }

    /// Function-argument pseudo. Normal functions already provide `func.args`;
    /// this constructor is for specialized transformations/tests only.
    pub fn function_arg(&mut self, arg_id: u8) -> InsnId {
        self.create(InsnKind::FunctionArg { arg_id })
    }
}
