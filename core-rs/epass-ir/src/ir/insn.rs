//! IR instructions: the `InsnKind` opcode enum and the `Insn` node stored in
//! the function's instruction arena.

use smallvec::SmallVec;

use super::value::{AddrValue, AluOp, BuiltinConst, LoadImmExtra, PhiValue, RawPos, Value, VrType};
use super::{BbId, InsnId};
use crate::bytecode::MAX_FUNC_ARG;

/// Comparison/condition for conditional jumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Sgt,
    Sge,
    Slt,
    Sle,
}

/// Binary ALU operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Or,
    And,
    Lsh,
    Arsh,
    Rsh,
    Mod,
    Xor,
}

impl BinOp {
    /// Operations whose operands may be swapped without changing the result.
    pub fn is_commutative(self) -> bool {
        matches!(self, BinOp::Add | BinOp::Mul | BinOp::Or | BinOp::And | BinOp::Xor)
    }
}

/// Endianness conversion direction for `BPF_END`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndKind {
    ToLe,
    ToBe,
}

/// The opcode and opcode-specific payload of an IR instruction.
///
/// Operands live separately in [`Insn::values`]; this enum carries the
/// structural / non-value data (jump targets, phi entries, immediates, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnKind {
    /// Allocate a stack/register slot of `vr_type`.
    Alloc { vr_type: VrType },
    /// Allocate a contiguous stack array of `num * sizeof(vr_type)` bytes.
    AllocArray { vr_type: VrType, num: u32 },
    /// Pointer to `values[1][values[0]]` (array element).
    GetElemPtr,
    /// `store values[0], values[1]` (typed; `values[0]` is an `Alloc`).
    Store,
    /// `values[0] = load <alloc>` (typed).
    Load,
    /// Load a 64-bit immediate / map fd / address.
    LoadImmExtra { extra: LoadImmExtra, imm64: i64 },
    /// `storeraw <vr_type> addr, values[0]`.
    StoreRaw { vr_type: VrType, addr: AddrValue },
    /// `loadraw <vr_type> addr`.
    LoadRaw { vr_type: VrType, addr: AddrValue },
    /// `-values[0]`.
    Neg,
    /// Byte-swap of `values[0]` to the given endianness and width.
    End { kind: EndKind, swap_width: u32 },
    /// Binary ALU: `values[0] <op> values[1]`.
    Bin { op: BinOp },
    /// Call helper `fid` with `values[..]` as arguments.
    Call { fid: i32 },
    /// Exit with `values[0]`.
    Ret,
    /// Abort the program (lowered later).
    Throw,
    /// Unconditional jump to `bb1`.
    Ja,
    /// Conditional jump: if `values[0] <cond> values[1]` jump `bb2` else fall to `bb1`.
    CondJmp { cond: Cond },
    /// SSA phi node; entries live in [`Insn::phi`].
    Phi,
    /// Copy `values[0]` into the destination (code-gen only).
    Assign,
    /// A physical register pseudo-instruction (code-gen only).
    Reg { reg_id: u8 },
    /// A function-argument pseudo-instruction (R1..R5).
    FunctionArg { arg_id: u8 },
    /// An ePass extension call.
    Ecall,
}

impl InsnKind {
    /// `true` for control-transfer instructions (jumps, ret, throw).
    pub fn is_jmp(&self) -> bool {
        matches!(
            self,
            InsnKind::Ja | InsnKind::CondJmp { .. } | InsnKind::Ret | InsnKind::Throw
        )
    }

    pub fn is_cond_jmp(&self) -> bool {
        matches!(self, InsnKind::CondJmp { .. })
    }

    pub fn is_bin_alu(&self) -> bool {
        matches!(self, InsnKind::Bin { .. })
    }

    /// `true` if the instruction produces no value (no SSA destination).
    pub fn is_void(&self) -> bool {
        self.is_jmp() || matches!(self, InsnKind::Store | InsnKind::StoreRaw { .. })
    }
}

/// An SSA instruction node.
#[derive(Debug, Clone)]
pub struct Insn {
    pub kind: InsnKind,
    /// Operand values (up to [`MAX_FUNC_ARG`] for calls).
    pub values: SmallVec<[Value; MAX_FUNC_ARG]>,
    /// Result width / ALU class (for ALU / typed memory ops).
    pub alu_op: AluOp,
    /// Phi entries (only for [`InsnKind::Phi`]).
    pub phi: Vec<PhiValue>,
    /// Successor blocks for jump instructions.
    pub bb1: Option<BbId>,
    pub bb2: Option<BbId>,
    /// Instructions that use this value (def-use chain).
    pub users: Vec<InsnId>,
    /// The basic block that owns this instruction.
    pub parent_bb: BbId,
    /// Source-bytecode provenance.
    pub raw_pos: RawPos,
    /// Builtin-constant tag carried on the *instruction* (rarely used directly).
    pub builtin: BuiltinConst,
}

impl Insn {
    pub(crate) fn new(kind: InsnKind, parent_bb: BbId) -> Self {
        Insn {
            kind,
            values: SmallVec::new(),
            alu_op: AluOp::Unknown,
            phi: Vec::new(),
            bb1: None,
            bb2: None,
            users: Vec::new(),
            parent_bb,
            raw_pos: RawPos::default(),
            builtin: BuiltinConst::None,
        }
    }

    pub fn is_jmp(&self) -> bool {
        self.kind.is_jmp()
    }
    pub fn is_cond_jmp(&self) -> bool {
        self.kind.is_cond_jmp()
    }
    pub fn is_bin_alu(&self) -> bool {
        self.kind.is_bin_alu()
    }
    pub fn is_void(&self) -> bool {
        self.kind.is_void()
    }

    pub fn is_commutative_alu(&self) -> bool {
        matches!(&self.kind, InsnKind::Bin { op } if op.is_commutative())
    }

    /// Iterate the operand values that participate in def-use (includes phi).
    pub fn operand_values(&self) -> Vec<Value> {
        if matches!(self.kind, InsnKind::Phi) {
            self.phi.iter().map(|p| p.value).collect()
        } else {
            let mut out: Vec<Value> = self.values.to_vec();
            if let InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } = &self.kind {
                out.push(addr.value);
            }
            out
        }
    }
}
