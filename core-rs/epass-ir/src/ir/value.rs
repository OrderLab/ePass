//! IR values: a value is either a constant, a reference to a defining
//! instruction (SSA), a physical-register position (after RA), or undefined.

use crate::bytecode::BpfInsn;

use super::InsnId;

/// Operand width / signedness class for ALU and constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AluOp {
    /// Unset — guards against forgetting to specify a width (matches C `IR_ALU_UNKNOWN`).
    #[default]
    Unknown,
    /// 32-bit operation.
    Alu32,
    /// 64-bit operation.
    Alu64,
}

/// Virtual-register width for typed memory operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VrType {
    #[default]
    Unknown,
    B8,
    B16,
    B32,
    B64,
}

impl VrType {
    /// Size in bytes.
    pub fn size(self) -> u32 {
        match self {
            VrType::B8 => 1,
            VrType::B16 => 2,
            VrType::B32 => 4,
            VrType::B64 => 8,
            VrType::Unknown => 0,
        }
    }

    /// Map a BPF load/store size field to a [`VrType`].
    pub fn from_bpf_size(size: u8) -> Option<VrType> {
        use crate::bytecode::size;
        Some(match size {
            size::B => VrType::B8,
            size::H => VrType::B16,
            size::W => VrType::B32,
            size::DW => VrType::B64,
            _ => return None,
        })
    }
}

/// Late-bound builtin constants, resolved during code generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuiltinConst {
    #[default]
    None,
    /// Number of instructions in the current basic block.
    BbInsnCnt,
    /// Number of instructions since the nearest critical block.
    BbInsnCriticalCnt,
}

/// How a constant operand relates to the stack pointer.
///
/// `RawOff`/`RawOffRev` values get the final stack offset folded in late
/// (see the `add_stack_offset` CG step), so they must be kept distinct from
/// plain constants to avoid double-patching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConstKind {
    #[default]
    Plain,
    /// `value + stack_offset` after CG.
    RawOff,
    /// `value - stack_offset` after CG.
    RawOffRev,
}

/// The position of a virtual register after register allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VrPos {
    /// Whether this value occupies a concrete location (regs/stack) yet.
    pub allocated: bool,
    /// If spilled, the size in bytes occupied on the stack.
    pub spilled_size: u32,
    /// Allocated physical register (valid when `spilled == 0`).
    pub alloc_reg: u8,
    /// Stack offset if spilled; `0` means "in a register".
    pub spilled: i32,
}

impl VrPos {
    /// The fixed position of the stack pointer (R10).
    pub fn stack_ptr() -> Self {
        VrPos {
            allocated: true,
            spilled_size: 0,
            alloc_reg: crate::bytecode::BPF_REG_10,
            spilled: 0,
        }
    }
}

/// An SSA value: an operand of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// A literal constant.
    Const {
        v: i64,
        ty: AluOp,
        kind: ConstKind,
        builtin: BuiltinConst,
    },
    /// A reference to a defining instruction (the SSA def).
    Insn(InsnId),
    /// A finalized register/stack position (only used during/after RA).
    VrPos(VrPos),
    /// A flattened destination position (code-gen only).
    FlattenDst(VrPos),
    /// Undefined.
    Undef,
}

impl Value {
    pub fn const32(v: i32) -> Value {
        Value::Const {
            v: v as i64,
            ty: AluOp::Alu32,
            kind: ConstKind::Plain,
            builtin: BuiltinConst::None,
        }
    }

    pub fn const64(v: i64) -> Value {
        Value::Const {
            v,
            ty: AluOp::Alu64,
            kind: ConstKind::Plain,
            builtin: BuiltinConst::None,
        }
    }

    pub fn const32_rawoff(v: i32) -> Value {
        Value::Const {
            v: v as i64,
            ty: AluOp::Alu32,
            kind: ConstKind::RawOff,
            builtin: BuiltinConst::None,
        }
    }

    pub fn insn(id: InsnId) -> Value {
        Value::Insn(id)
    }

    pub fn vrpos(pos: VrPos) -> Value {
        Value::VrPos(pos)
    }

    pub fn undef() -> Value {
        Value::Undef
    }

    /// If this value references a defining instruction, return its id.
    pub fn as_insn(self) -> Option<InsnId> {
        match self {
            Value::Insn(id) => Some(id),
            _ => None,
        }
    }

    pub fn is_const(self) -> bool {
        matches!(self, Value::Const { .. })
    }
}

/// A base value plus a signed byte offset (used by raw load/store).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrValue {
    pub value: Value,
    pub offset: i16,
    /// The kind of the offset constant (plain vs. stack-relative).
    pub offset_kind: ConstKind,
}

impl AddrValue {
    pub fn new(value: Value, offset: i16) -> Self {
        AddrValue {
            value,
            offset,
            offset_kind: ConstKind::Plain,
        }
    }
}

/// A single `(value, predecessor block)` entry of a phi node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhiValue {
    pub value: Value,
    pub bb: super::BbId,
}

/// Extra immediate-load kinds for 64-bit immediates (map fds, addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadImmExtra {
    Imm64,
    MapByFd,
    MapValFd,
    VarAddr,
    CodeAddr,
    MapByIdx,
    MapValIdx,
}

impl LoadImmExtra {
    /// Map the `src_reg` of a `BPF_LD_IMM64` to its extra-load kind.
    pub fn from_src_reg(src: u8) -> Option<LoadImmExtra> {
        Some(match src {
            0 => LoadImmExtra::Imm64,
            1 => LoadImmExtra::MapByFd,
            2 => LoadImmExtra::MapValFd,
            3 => LoadImmExtra::VarAddr,
            4 => LoadImmExtra::CodeAddr,
            5 => LoadImmExtra::MapByIdx,
            6 => LoadImmExtra::MapValIdx,
            _ => return None,
        })
    }

    pub fn to_src_reg(self) -> u8 {
        match self {
            LoadImmExtra::Imm64 => 0,
            LoadImmExtra::MapByFd => 1,
            LoadImmExtra::MapValFd => 2,
            LoadImmExtra::VarAddr => 3,
            LoadImmExtra::CodeAddr => 4,
            LoadImmExtra::MapByIdx => 5,
            LoadImmExtra::MapValIdx => 6,
        }
    }
}

/// Original position of an instruction/value in the source bytecode, used to
/// correlate IR back to verifier diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawPos {
    pub valid: bool,
    pub pos: usize,
    pub kind: RawPosKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RawPosKind {
    #[default]
    Insn,
    Imm,
    Dst,
    Src,
}

impl RawPos {
    pub fn at(pos: usize, kind: RawPosKind) -> Self {
        RawPos {
            valid: true,
            pos,
            kind,
        }
    }
}

/// Helper to build the second slot of a 64-bit immediate load instruction.
#[allow(dead_code)]
pub(crate) fn imm64_low_high(imm64: i64) -> (BpfInsn, BpfInsn) {
    let low = (imm64 & 0xffff_ffff) as i32;
    let high = (imm64 >> 32) as i32;
    (
        BpfInsn {
            imm: low,
            ..Default::default()
        },
        BpfInsn {
            imm: high,
            ..Default::default()
        },
    )
}
