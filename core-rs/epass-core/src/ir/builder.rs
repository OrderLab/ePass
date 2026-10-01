//! A cursor-style builder over [`Function::insert`] for passes and tests.

use super::func::At;
use super::{
    BinOp, BlockId, Callee, Cond, Function, InsnId, Op, Size, SlotId, SwapKind, SymKind, Value,
    Width,
};
use crate::error::Result;

/// Inserts instructions in order at a moving position.
#[derive(Debug)]
pub struct Builder<'f, 'h> {
    pub f: &'f mut Function<'h>,
    at: At,
    origin: Option<u32>,
}

impl<'f, 'h> Builder<'f, 'h> {
    pub fn new(f: &'f mut Function<'h>, at: At) -> Self {
        Builder { f, at, origin: None }
    }

    /// Append to the end of `b` (before its terminator, if any).
    pub fn at_end(f: &'f mut Function<'h>, b: BlockId) -> Self {
        Self::new(f, At::BeforeTerminator(b))
    }

    pub fn set_at(&mut self, at: At) {
        self.at = at;
    }

    /// Source index recorded on subsequently built instructions.
    pub fn set_origin(&mut self, origin: Option<u32>) {
        self.origin = origin;
    }

    pub fn emit(&mut self, op: Op, operands: &[Value]) -> Result<InsnId> {
        let at = match self.at {
            // A terminator closes the block: insert it at the very end.
            At::BeforeTerminator(b) if op.is_terminator() => At::End(b),
            a => a,
        };
        let id = self.f.insert(at, op, operands)?;
        self.f.set_origin(id, self.origin)?;
        // Keep program order for cursors anchored after an instruction.
        if let At::After(_) | At::AfterPhis(_) = self.at {
            self.at = At::After(id);
        }
        Ok(id)
    }

    fn value(&mut self, op: Op, operands: &[Value]) -> Result<Value> {
        self.emit(op, operands).map(Value::Insn)
    }

    pub fn bin(&mut self, op: BinOp, w: Width, a: Value, b: Value) -> Result<Value> {
        self.value(Op::Bin { op, w }, &[a, b])
    }
    pub fn add64(&mut self, a: Value, b: Value) -> Result<Value> {
        self.bin(BinOp::Add, Width::W64, a, b)
    }
    pub fn neg(&mut self, w: Width, a: Value) -> Result<Value> {
        self.value(Op::Neg { w }, &[a])
    }
    pub fn ext(&mut self, from: u8, signed: bool, w: Width, a: Value) -> Result<Value> {
        self.value(Op::Ext { from, signed, w }, &[a])
    }
    /// `w = w` (zero-extend the low 32 bits).
    pub fn zext32(&mut self, a: Value) -> Result<Value> {
        self.ext(32, false, Width::W64, a)
    }
    pub fn bswap(&mut self, bits: u8, kind: SwapKind, a: Value) -> Result<Value> {
        self.value(Op::Bswap { bits, kind }, &[a])
    }
    pub fn load(&mut self, size: Size, signed: bool, base: Value, off: i16) -> Result<Value> {
        self.value(Op::Load { size, signed, off }, &[base])
    }
    pub fn store(&mut self, size: Size, base: Value, off: i16, v: Value) -> Result<InsnId> {
        self.emit(Op::Store { size, off }, &[base, v])
    }
    pub fn ldsym(&mut self, kind: SymKind, imm: u64) -> Result<Value> {
        self.value(Op::LdSym { kind, imm }, &[])
    }
    pub fn slot_addr(&mut self, slot: SlotId, off: i32) -> Result<Value> {
        self.value(Op::SlotAddr { slot, off }, &[])
    }
    pub fn slot_load(&mut self, slot: SlotId) -> Result<Value> {
        self.value(Op::SlotLoad { slot }, &[])
    }
    pub fn slot_store(&mut self, slot: SlotId, v: Value) -> Result<InsnId> {
        self.emit(Op::SlotStore { slot }, &[v])
    }
    pub fn call(&mut self, callee: Callee, args: &[Value]) -> Result<Value> {
        self.value(
            Op::Call {
                callee,
                unknown_arity: false,
            },
            args,
        )
    }
    pub fn br(&mut self, target: BlockId) -> Result<InsnId> {
        self.emit(Op::Br { target }, &[])
    }
    pub fn condbr(
        &mut self,
        cond: Cond,
        w: Width,
        a: Value,
        b: Value,
        t: BlockId,
        f: BlockId,
    ) -> Result<InsnId> {
        self.emit(Op::CondBr { cond, w, t, f }, &[a, b])
    }
    pub fn ret(&mut self, v: Value) -> Result<InsnId> {
        self.emit(Op::Ret, &[v])
    }
    pub fn throw(&mut self) -> Result<InsnId> {
        self.emit(Op::Throw, &[])
    }
}
