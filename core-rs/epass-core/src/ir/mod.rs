//! The ePass IR: SSA over 64-bit register values.
//!
//! Type system (see `design.md` §4):
//! - every SSA value is a 64-bit bit pattern; there are no narrower values;
//! - width, signedness, extension and access size live on the operation;
//! - constants are exact 64-bit patterns (`Value::Const(u64)`);
//! - pointer provenance and value class are derived by analyses, never
//!   declared, so untrusted IR cannot claim a type.
//!
//! Storage: instructions, operands and blocks live in arenas indexed by typed
//! ids. A block's instructions form an intrusive doubly linked list; every
//! operand slot is linked into its definition's use list. Successors are
//! derived from the block terminator only; predecessor lists are maintained
//! by the CFG-editing methods of [`Function`].

pub mod builder;
pub mod func;
pub mod verify;

#[cfg(feature = "text")]
pub mod parse;
pub mod print;

pub use builder::Builder;
pub use func::{BlockData, Function, InsnData, Module, Operand};

use crate::define_idx;

define_idx! {
    /// An instruction.
    pub struct InsnId;
}
define_idx! {
    /// A basic block.
    pub struct BlockId;
}
define_idx! {
    /// An operand slot.
    pub struct OpndId;
}
define_idx! {
    /// An ePass-owned frame slot.
    pub struct SlotId;
}
define_idx! {
    /// A function in a module.
    pub struct FuncId;
}

/// Late-bound constants resolved at emission (reserved in v2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BuiltinKind {
    /// Number of emitted instructions in the current block.
    BbInsnCount,
    /// Number of emitted instructions since the nearest critical block.
    BbInsnCriticalCount,
}

/// An SSA value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// The result of an instruction.
    Insn(InsnId),
    /// An exact 64-bit pattern.
    Const(u64),
    /// Function argument register r1..=r5 at entry.
    Param(u8),
    /// The frame pointer r10.
    FramePtr,
    /// Undefined; legal as a phi input or call argument, emits nothing.
    Undef,
    /// Reserved late-bound constant.
    Builtin(BuiltinKind),
}

impl Value {
    pub fn as_insn(self) -> Option<InsnId> {
        match self {
            Value::Insn(i) => Some(i),
            _ => None,
        }
    }
    pub fn as_const(self) -> Option<u64> {
        match self {
            Value::Const(c) => Some(c),
            _ => None,
        }
    }
}

/// Operation width. A 32-bit operation reads the low halves of its operands
/// and zero-extends its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Width {
    W32,
    W64,
}

impl Width {
    pub fn bits(self) -> u32 {
        match self {
            Width::W32 => 32,
            Width::W64 => 64,
        }
    }
}

/// Binary ALU operations (RFC 9669 semantics: shift amounts masked, x/0 = 0,
/// x%0 = x, INT_MIN/-1 = INT_MIN).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    UMod,
    SMod,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
}

impl BinOp {
    pub const ALL: [BinOp; 13] = [
        BinOp::Add,
        BinOp::Sub,
        BinOp::Mul,
        BinOp::UDiv,
        BinOp::SDiv,
        BinOp::UMod,
        BinOp::SMod,
        BinOp::And,
        BinOp::Or,
        BinOp::Xor,
        BinOp::Shl,
        BinOp::LShr,
        BinOp::AShr,
    ];

    pub fn is_commutative(self) -> bool {
        matches!(
            self,
            BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            BinOp::Add => "add",
            BinOp::Sub => "sub",
            BinOp::Mul => "mul",
            BinOp::UDiv => "udiv",
            BinOp::SDiv => "sdiv",
            BinOp::UMod => "umod",
            BinOp::SMod => "smod",
            BinOp::And => "and",
            BinOp::Or => "or",
            BinOp::Xor => "xor",
            BinOp::Shl => "shl",
            BinOp::LShr => "lshr",
            BinOp::AShr => "ashr",
        }
    }
}

/// Branch conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cond {
    Eq,
    Ne,
    Ugt,
    Uge,
    Ult,
    Ule,
    Sgt,
    Sge,
    Slt,
    Sle,
    /// `a & b != 0` (JSET).
    Set,
}

impl Cond {
    pub const ALL: [Cond; 11] = [
        Cond::Eq,
        Cond::Ne,
        Cond::Ugt,
        Cond::Uge,
        Cond::Ult,
        Cond::Ule,
        Cond::Sgt,
        Cond::Sge,
        Cond::Slt,
        Cond::Sle,
        Cond::Set,
    ];

    /// The condition with operands swapped (`a c b` == `b c.swapped() a`).
    pub fn swapped(self) -> Cond {
        match self {
            Cond::Ugt => Cond::Ult,
            Cond::Ult => Cond::Ugt,
            Cond::Uge => Cond::Ule,
            Cond::Ule => Cond::Uge,
            Cond::Sgt => Cond::Slt,
            Cond::Slt => Cond::Sgt,
            Cond::Sge => Cond::Sle,
            Cond::Sle => Cond::Sge,
            c => c,
        }
    }

    /// The negated condition, when one exists in the ISA.
    pub fn negated(self) -> Option<Cond> {
        Some(match self {
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Ugt => Cond::Ule,
            Cond::Ule => Cond::Ugt,
            Cond::Uge => Cond::Ult,
            Cond::Ult => Cond::Uge,
            Cond::Sgt => Cond::Sle,
            Cond::Sle => Cond::Sgt,
            Cond::Sge => Cond::Slt,
            Cond::Slt => Cond::Sge,
            Cond::Set => return None,
        })
    }

    /// Swapping operands is symmetric (no ISA-level change).
    pub fn is_symmetric(self) -> bool {
        matches!(self, Cond::Eq | Cond::Ne | Cond::Set)
    }

    pub fn name(self) -> &'static str {
        match self {
            Cond::Eq => "eq",
            Cond::Ne => "ne",
            Cond::Ugt => "ugt",
            Cond::Uge => "uge",
            Cond::Ult => "ult",
            Cond::Ule => "ule",
            Cond::Sgt => "sgt",
            Cond::Sge => "sge",
            Cond::Slt => "slt",
            Cond::Sle => "sle",
            Cond::Set => "set",
        }
    }
}

/// Memory access size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Size {
    B1,
    B2,
    B4,
    B8,
}

impl Size {
    pub fn bytes(self) -> u32 {
        match self {
            Size::B1 => 1,
            Size::B2 => 2,
            Size::B4 => 4,
            Size::B8 => 8,
        }
    }
    pub fn bits(self) -> u32 {
        self.bytes() * 8
    }
    pub fn from_bytes(n: u32) -> Option<Size> {
        Some(match n {
            1 => Size::B1,
            2 => Size::B2,
            4 => Size::B4,
            8 => Size::B8,
            _ => return None,
        })
    }
}

/// Byte-swap flavor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SwapKind {
    /// Convert to little-endian (ALU-class `END`, TO_LE).
    ToLe,
    /// Convert to big-endian (ALU-class `END`, TO_BE).
    ToBe,
    /// Unconditional swap (ALU64-class `END`, ISA v4).
    Swap,
}

/// Kinds of `ld_imm64` pseudo immediates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymKind {
    MapFd,
    MapValueFd,
    BtfId,
    Func,
    MapIdx,
    MapValueIdx,
}

impl SymKind {
    /// The `src_reg` value of the `ld_imm64` encoding.
    pub fn src_reg(self) -> u8 {
        match self {
            SymKind::MapFd => 1,
            SymKind::MapValueFd => 2,
            SymKind::BtfId => 3,
            SymKind::Func => 4,
            SymKind::MapIdx => 5,
            SymKind::MapValueIdx => 6,
        }
    }
    pub fn from_src_reg(src: u8) -> Option<SymKind> {
        Some(match src {
            1 => SymKind::MapFd,
            2 => SymKind::MapValueFd,
            3 => SymKind::BtfId,
            4 => SymKind::Func,
            5 => SymKind::MapIdx,
            6 => SymKind::MapValueIdx,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            SymKind::MapFd => "map_fd",
            SymKind::MapValueFd => "map_value_fd",
            SymKind::BtfId => "btf_id",
            SymKind::Func => "func",
            SymKind::MapIdx => "map_idx",
            SymKind::MapValueIdx => "map_value_idx",
        }
    }
}

/// Call targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Callee {
    Helper(i32),
    Kfunc { btf_id: i32, fd_idx: i16 },
    Local(FuncId),
}

/// A raw instruction passed through codegen with pinned registers
/// (atomics, LD_ABS/IND).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpaqueInsn {
    /// The encoded instruction slot.
    pub raw: u64,
    /// Register the instruction defines (its SSA result), if any.
    pub def: Option<u8>,
    /// Registers read, in operand order (bit i = register i).
    pub uses: u16,
    /// Registers clobbered besides `def`.
    pub clobbers: u16,
}

/// An ePass frame slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameSlot {
    pub size: u32,
    pub align: u32,
    /// Slots that may hold a pointer must be exactly 8 bytes, 8-aligned, and
    /// written only by full-width stores from a register.
    pub may_hold_ptr: bool,
}

/// Operations. Operands live in the instruction's operand range; the shapes
/// are checked by [`verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    /// `a op b`.
    Bin { op: BinOp, w: Width },
    /// `-a`.
    Neg { w: Width },
    /// Extend the low `from` bits of `a` (zero or sign), truncate to `w`, then
    /// zero-extend to 64. `w1 = w2` is `Ext{from: 32, signed: false}`.
    Ext { from: u8, signed: bool, w: Width },
    /// Byte swap of the low `bits` bits; the result is zero-extended.
    Bswap { bits: u8, kind: SwapKind },
    /// `[base + off]` of `size` bytes, zero- or sign-extended.
    Load { size: Size, signed: bool, off: i16 },
    /// `[base + off] = value` (operands: base, value).
    Store { size: Size, off: i16 },
    /// `ld_imm64` with a pseudo source. `imm` is the 64-bit immediate as
    /// encoded (for map values: fd/idx in the low half, offset in the high).
    LdSym { kind: SymKind, imm: u64 },
    /// Address of an ePass frame slot plus a byte offset.
    SlotAddr { slot: SlotId, off: i32 },
    /// Load a whole 8-byte slot.
    SlotLoad { slot: SlotId },
    /// Store a value into a whole 8-byte slot (operand: value).
    SlotStore { slot: SlotId },
    /// Call with 0..=5 argument operands. `unknown_arity` calls pass all
    /// five registers (undefined ones as `undef`).
    Call { callee: Callee, unknown_arity: bool },
    /// Reserved ePass extension call.
    Ecall { id: i32 },
    /// Raw instruction with pinned registers.
    Opaque(OpaqueInsn),
    /// SSA phi; each operand carries its incoming block.
    Phi,
    // ---- terminators ----
    Br { target: BlockId },
    /// `if a cond b goto t else f` (operands: a, b).
    CondBr { cond: Cond, w: Width, t: BlockId, f: BlockId },
    /// Return operand 0 in r0.
    Ret,
    /// Abort; lowered by `lower_throw`.
    Throw,
    /// A libbpf-poisoned call: emitted verbatim, never returns.
    Poison { imm: i32 },
}

impl Op {
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Op::Br { .. } | Op::CondBr { .. } | Op::Ret | Op::Throw | Op::Poison { .. }
        )
    }

    /// Whether the instruction produces an SSA value.
    pub fn has_result(&self) -> bool {
        match self {
            Op::Store { .. } | Op::SlotStore { .. } => false,
            Op::Opaque(o) => o.def.is_some(),
            op => !op.is_terminator(),
        }
    }

    /// Whether removing the instruction (when unused) is safe.
    pub fn is_pure(&self) -> bool {
        matches!(
            self,
            Op::Bin { .. }
                | Op::Neg { .. }
                | Op::Ext { .. }
                | Op::Bswap { .. }
                | Op::LdSym { .. }
                | Op::SlotAddr { .. }
                | Op::Phi
        )
    }

    /// Successor blocks (terminators only).
    pub fn successors(&self) -> Succs {
        match *self {
            Op::Br { target } => Succs::one(target),
            Op::CondBr { t, f, .. } => Succs::two(t, f),
            _ => Succs::none(),
        }
    }
}

/// Up to two successors, without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Succs {
    blocks: [BlockId; 2],
    len: u8,
}

impl Succs {
    pub fn none() -> Self {
        Succs {
            blocks: [BlockId(0); 2],
            len: 0,
        }
    }
    pub fn one(a: BlockId) -> Self {
        Succs {
            blocks: [a, BlockId(0)],
            len: 1,
        }
    }
    /// Two successors; a branch with both targets equal has one successor.
    pub fn two(a: BlockId, b: BlockId) -> Self {
        if a == b {
            Self::one(a)
        } else {
            Succs {
                blocks: [a, b],
                len: 2,
            }
        }
    }
    pub fn len(&self) -> usize {
        self.len as usize
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_slice(&self) -> &[BlockId] {
        self.blocks.get(..self.len as usize).unwrap_or(&[])
    }
    pub fn contains(&self, b: BlockId) -> bool {
        self.as_slice().contains(&b)
    }
}
