//! Normalization and bytecode emission.
//!
//! After register allocation, each value has a concrete location (register,
//! stack slot, or constant). This stage rewrites IR instructions into a
//! two-address, machine-encodable form, resolves builtin constants and jump
//! targets, and finally synthesizes `bpf_insn`s into `env.insns`.

use std::collections::HashMap;

use crate::bytecode::{self as bc, BpfInsn, BPF_REG_0, BPF_REG_10};
use crate::env::Env;
use crate::error::Result;
use crate::ir::insn::{BinOp, Cond, EndKind, InsnKind};
use crate::ir::value::{AluOp, VrPos, VrType};
use crate::ir::{BbId, Function, InsnId, Value};
use crate::{internal, invalid};

use super::CgState;

/// A concrete operand location after RA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Loc {
    Reg(u8),
    Stack(i32),
    Const { v: i64, alu: AluOp },
    Undef,
}

/// Resolve a value to its concrete location.
fn loc_of(v: Value) -> Loc {
    match v {
        Value::Const { v, ty, .. } => Loc::Const { v, alu: ty },
        Value::VrPos(p) | Value::FlattenDst(p) => loc_of_pos(p),
        Value::Undef => Loc::Undef,
        Value::Insn(_) => Loc::Undef, // must have been flattened already
    }
}

fn loc_of_pos(p: VrPos) -> Loc {
    if !p.allocated {
        Loc::Undef
    } else if p.spilled != 0 {
        Loc::Stack(p.spilled)
    } else {
        Loc::Reg(p.alloc_reg)
    }
}

/// The destination position finalized for an instruction.
fn dst_pos(cg: &CgState, func: &Function, id: InsnId) -> VrPos {
    let _ = func;
    match cg.extra.get(&id).and_then(|e| e.dst) {
        Some(d) => cg.extra(d).vr_pos,
        None => VrPos::default(),
    }
}

/// Flatten all instruction-valued operands to their finalized positions.
fn flatten(func: &mut Function, cg: &CgState) {
    let bbs = func.reachable_bbs.clone();
    for bb in bbs {
        let insns = func.bb(bb).insns.clone();
        for id in insns {
            // Propagate alloc widths to load/store.
            // (Typed load/store carry their alloc's width; raw ones already do.)
            let n = func.insn(id).values.len();
            for i in 0..n {
                if let Value::Insn(def) = func.insn(id).values[i] {
                    let pos = cg.extra(def).vr_pos;
                    func.insn_mut(id).values[i] = Value::FlattenDst(pos);
                }
            }
            // Raw address bases.
            match &mut func.insn_mut(id).kind {
                InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } => {
                    if let Value::Insn(_) = addr.value {
                        // resolved below using a fresh borrow
                    }
                }
                _ => {}
            }
            if let InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } =
                func.insn(id).kind.clone()
            {
                if let Value::Insn(def) = addr.value {
                    let pos = cg.extra(def).vr_pos;
                    if let InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } =
                        &mut func.insn_mut(id).kind
                    {
                        addr.value = Value::FlattenDst(pos);
                    }
                }
            }
        }
    }
}

/// Replace builtin constants with their computed values.
fn replace_builtin_consts(func: &mut Function) {
    let bbs = func.reachable_bbs.clone();
    for bb in bbs {
        let cnt = bb_insn_cnt(func, bb);
        let insns = func.bb(bb).insns.clone();
        for id in insns {
            let n = func.insn(id).values.len();
            for i in 0..n {
                if let Value::Const { v, builtin, .. } = &mut func.insn_mut(id).values[i] {
                    use crate::ir::value::BuiltinConst::*;
                    match *builtin {
                        BbInsnCnt => {
                            *v = cnt as i64;
                            *builtin = None;
                        }
                        BbInsnCriticalCnt => {
                            *v = cnt as i64;
                            *builtin = None;
                        }
                        None => {}
                    }
                }
            }
        }
    }
}

fn bb_insn_cnt(func: &Function, bb: BbId) -> u32 {
    func.bb(bb)
        .insns
        .iter()
        .filter(|&&id| {
            !matches!(
                func.insn(id).kind,
                InsnKind::Alloc { .. } | InsnKind::AllocArray { .. }
            )
        })
        .count() as u32
}

// ---- emission ----

/// One emitted machine instruction (possibly wide).
#[derive(Debug, Clone, Copy)]
struct Emitted {
    insn: BpfInsn,
    wide: bool,
    imm64: i64,
    /// Filled during relocation for jumps.
    is_ja: bool,
    is_cond: bool,
    target1: Option<BbId>, // ja target / cond fallthrough is implicit
    target2: Option<BbId>, // cond taken target
}

impl Emitted {
    fn simple(insn: BpfInsn) -> Self {
        Emitted {
            insn,
            wide: false,
            imm64: 0,
            is_ja: false,
            is_cond: false,
            target1: None,
            target2: None,
        }
    }
    fn wide(dst: u8, src: u8, imm64: i64, code: u8) -> Self {
        Emitted {
            insn: BpfInsn::new(code, dst, src, 0, (imm64 & 0xffff_ffff) as i32),
            wide: true,
            imm64,
            is_ja: false,
            is_cond: false,
            target1: None,
            target2: None,
        }
    }
}

fn alu_class(alu: AluOp) -> u8 {
    if alu == AluOp::Alu64 {
        bc::class::ALU64
    } else {
        bc::class::ALU
    }
}

fn binop_code(op: BinOp) -> u8 {
    match op {
        BinOp::Add => bc::op::ADD,
        BinOp::Sub => bc::op::SUB,
        BinOp::Mul => bc::op::MUL,
        BinOp::Div => bc::op::DIV,
        BinOp::Or => bc::op::OR,
        BinOp::And => bc::op::AND,
        BinOp::Lsh => bc::op::LSH,
        BinOp::Arsh => bc::op::ARSH,
        BinOp::Rsh => bc::op::RSH,
        BinOp::Mod => bc::op::MOD,
        BinOp::Xor => bc::op::XOR,
    }
}

fn cond_code(c: Cond) -> u8 {
    match c {
        Cond::Eq => bc::op::JEQ,
        Cond::Ne => bc::op::JNE,
        Cond::Gt => bc::op::JGT,
        Cond::Ge => bc::op::JGE,
        Cond::Lt => bc::op::JLT,
        Cond::Le => bc::op::JLE,
        Cond::Sgt => bc::op::JSGT,
        Cond::Sge => bc::op::JSGE,
        Cond::Slt => bc::op::JSLT,
        Cond::Sle => bc::op::JSLE,
    }
}

/// Swap a condition when operands are reversed (for `const <cond> reg`).
fn swap_cond(c: Cond) -> Cond {
    match c {
        Cond::Gt => Cond::Lt,
        Cond::Lt => Cond::Gt,
        Cond::Ge => Cond::Le,
        Cond::Le => Cond::Ge,
        Cond::Sgt => Cond::Slt,
        Cond::Slt => Cond::Sgt,
        Cond::Sge => Cond::Sle,
        Cond::Sle => Cond::Sge,
        Cond::Eq => Cond::Eq,
        Cond::Ne => Cond::Ne,
    }
}

fn vr_size(t: VrType) -> u8 {
    match t {
        VrType::B8 => bc::size::B,
        VrType::B16 => bc::size::H,
        VrType::B32 => bc::size::W,
        VrType::B64 => bc::size::DW,
        VrType::Unknown => bc::size::DW,
    }
}

/// Emit a `dst = imm` move (32- or 64-bit).
fn emit_load_const(out: &mut Vec<Emitted>, dst: u8, v: i64, alu: AluOp) {
    if alu == AluOp::Alu64 {
        // 64-bit immediate -> wide load.
        out.push(Emitted::wide(dst, 0, v, bc::class::LD | bc::mode::IMM | bc::size::DW));
    } else {
        out.push(Emitted::simple(BpfInsn::new(
            bc::class::ALU64 | bc::op::MOV | bc::src::K,
            dst,
            0,
            0,
            v as i32,
        )));
    }
}

/// Emit `dst = src` register move.
fn emit_reg_move(out: &mut Vec<Emitted>, dst: u8, src: u8) {
    if dst == src {
        return;
    }
    out.push(Emitted::simple(BpfInsn::new(
        bc::class::ALU64 | bc::op::MOV | bc::src::X,
        dst,
        src,
        0,
        0,
    )));
}

/// Load a value into `dst` register, materializing const/stack as needed.
fn emit_into_reg(out: &mut Vec<Emitted>, dst: u8, loc: Loc) -> Result<()> {
    match loc {
        Loc::Reg(r) => emit_reg_move(out, dst, r),
        Loc::Const { v, alu } => emit_load_const(out, dst, v, alu),
        Loc::Stack(off) => {
            // dst = *(u64 *)(r10 + off)
            out.push(Emitted::simple(BpfInsn::new(
                bc::class::LDX | bc::mode::MEM | bc::size::DW,
                dst,
                BPF_REG_10,
                off as i16,
                0,
            )));
        }
        Loc::Undef => return Err(internal!("undefined operand in emission")),
    }
    Ok(())
}

/// Emit all machine instructions for one IR instruction.
fn emit_insn(
    func: &Function,
    cg: &CgState,
    id: InsnId,
    out: &mut Vec<Emitted>,
) -> Result<()> {
    let insn = func.insn(id);
    let dpos = dst_pos(cg, func, id);
    let dreg = dpos.alloc_reg;
    let dst_stack = dpos.allocated && dpos.spilled != 0;

    match &insn.kind {
        InsnKind::Alloc { .. } | InsnKind::AllocArray { .. } => {} // no code
        InsnKind::Assign => {
            let v0 = loc_of(insn.values[0]);
            emit_assign(out, dpos, v0)?;
        }
        InsnKind::Bin { op } => {
            if dst_stack {
                return Err(internal!("ALU destination spilled (unsupported)"));
            }
            emit_bin(out, dreg, *op, insn.alu_op, loc_of(insn.values[0]), loc_of(insn.values[1]))?;
        }
        InsnKind::Neg => {
            emit_into_reg_if_needed(out, dreg, loc_of(insn.values[0]))?;
            out.push(Emitted::simple(BpfInsn::new(
                alu_class(insn.alu_op) | bc::op::NEG | bc::src::K,
                dreg,
                0,
                0,
                0,
            )));
        }
        InsnKind::End { kind, swap_width } => {
            emit_into_reg_if_needed(out, dreg, loc_of(insn.values[0]))?;
            let sub = match kind {
                EndKind::ToBe => bc::end::TO_BE,
                EndKind::ToLe => bc::end::TO_LE,
            };
            out.push(Emitted::simple(BpfInsn::new(
                bc::class::ALU | bc::op::END | sub,
                dreg,
                0,
                0,
                *swap_width as i32,
            )));
        }
        InsnKind::LoadRaw { vr_type, addr } => {
            if dst_stack {
                return Err(internal!("loadraw destination spilled (unsupported)"));
            }
            emit_load_raw(out, dreg, *vr_type, addr)?;
        }
        InsnKind::StoreRaw { vr_type, addr } => {
            emit_store_raw(out, *vr_type, addr, loc_of(insn.values[0]))?;
        }
        InsnKind::LoadImmExtra { extra, imm64 } => {
            let code = bc::class::LD | bc::mode::IMM | bc::size::DW;
            let mut e = Emitted::wide(dreg, extra.to_src_reg(), *imm64, code);
            e.insn.src_reg = extra.to_src_reg();
            out.push(e);
        }
        InsnKind::Ret => {
            if !insn.values.is_empty() {
                emit_into_reg(out, BPF_REG_0, loc_of(insn.values[0]))?;
            }
            out.push(Emitted::simple(BpfInsn::new(bc::class::JMP | bc::op::EXIT, 0, 0, 0, 0)));
        }
        InsnKind::Call { fid } => {
            out.push(Emitted::simple(BpfInsn::new(
                bc::class::JMP | bc::op::CALL,
                0,
                0,
                0,
                *fid,
            )));
        }
        InsnKind::Ja => {
            let mut e = Emitted::simple(BpfInsn::new(bc::class::JMP | bc::op::JA, 0, 0, 0, 0));
            e.is_ja = true;
            e.target1 = insn.bb1;
            out.push(e);
        }
        InsnKind::CondJmp { cond } => {
            emit_cond_jmp(out, *cond, insn.alu_op, loc_of(insn.values[0]), loc_of(insn.values[1]), insn.bb2)?;
        }
        InsnKind::Throw => {
            // Lowered earlier in a full pipeline; emit exit as a safe fallback.
            out.push(Emitted::simple(BpfInsn::new(bc::class::JMP | bc::op::EXIT, 0, 0, 0, 0)));
        }
        InsnKind::Store => {
            // store <alloc>, <val>  ==>  assign val into the alloc's position.
            let alloc_pos = match insn.values[0] {
                Value::FlattenDst(p) | Value::VrPos(p) => p,
                _ => return Err(internal!("store target is not an allocated slot")),
            };
            let src = loc_of(insn.values[1]);
            emit_assign(out, alloc_pos, src)?;
        }
        InsnKind::Load => {
            // %x = load <alloc>  ==>  assign the alloc's position into %x.
            let src = loc_of(insn.values[0]);
            emit_assign(out, dpos, src)?;
        }
        InsnKind::GetElemPtr => {
            return Err(internal!("getelemptr survived to emission (unsupported)"));
        }
        InsnKind::Phi => return Err(internal!("phi survived to emission")),
        InsnKind::Reg { .. } | InsnKind::FunctionArg { .. } => {}
        InsnKind::Ecall => return Err(internal!("ecall survived to emission")),
    }
    Ok(())
}

fn emit_assign(out: &mut Vec<Emitted>, dpos: VrPos, src: Loc) -> Result<()> {
    let dst_stack = dpos.allocated && dpos.spilled != 0;
    if dst_stack {
        // store src on stack at dpos.spilled
        match src {
            Loc::Reg(r) => out.push(Emitted::simple(BpfInsn::new(
                bc::class::STX | bc::mode::MEM | bc::size::DW,
                BPF_REG_10,
                r,
                dpos.spilled as i16,
                0,
            ))),
            Loc::Const { v, .. } => out.push(Emitted::simple(BpfInsn::new(
                bc::class::ST | bc::mode::MEM | bc::size::DW,
                BPF_REG_10,
                0,
                dpos.spilled as i16,
                v as i32,
            ))),
            Loc::Stack(_) => return Err(internal!("stack-to-stack assign (unsupported)")),
            Loc::Undef => return Err(internal!("undef assign source")),
        }
    } else {
        emit_into_reg(out, dpos.alloc_reg, src)?;
    }
    Ok(())
}

fn emit_into_reg_if_needed(out: &mut Vec<Emitted>, dreg: u8, src: Loc) -> Result<()> {
    match src {
        Loc::Reg(r) if r == dreg => Ok(()),
        _ => emit_into_reg(out, dreg, src),
    }
}

fn emit_bin(
    out: &mut Vec<Emitted>,
    dreg: u8,
    op: BinOp,
    alu: AluOp,
    v0: Loc,
    v1: Loc,
) -> Result<()> {
    // Normalize so v0 lands in dreg, then apply op with v1.
    // Commutative: if v1 is in dreg, swap.
    let (v0, v1) = if op.is_commutative() {
        if let Loc::Reg(r) = v1 {
            if r == dreg {
                (v1, v0)
            } else {
                (v0, v1)
            }
        } else {
            (v0, v1)
        }
    } else {
        (v0, v1)
    };

    emit_into_reg_if_needed(out, dreg, v0)?;
    let code = binop_code(op);
    match v1 {
        Loc::Reg(r) => out.push(Emitted::simple(BpfInsn::new(
            alu_class(alu) | code | bc::src::X,
            dreg,
            r,
            0,
            0,
        ))),
        Loc::Const { v, .. } => {
            if op == BinOp::Add && v == 0 {
                return Ok(()); // no-op
            }
            out.push(Emitted::simple(BpfInsn::new(
                alu_class(alu) | code | bc::src::K,
                dreg,
                0,
                0,
                v as i32,
            )))
        }
        Loc::Stack(off) => {
            // Reload into a scratch is unsupported here; spill prep should
            // prevent stack operands for ALU. Treat as error.
            let _ = off;
            return Err(internal!("ALU operand on stack (unsupported)"));
        }
        Loc::Undef => return Err(internal!("undef ALU operand")),
    }
    Ok(())
}

fn emit_load_raw(
    out: &mut Vec<Emitted>,
    dreg: u8,
    vr_type: VrType,
    addr: &crate::ir::value::AddrValue,
) -> Result<()> {
    let size = vr_size(vr_type);
    match loc_of(addr.value) {
        Loc::Reg(base) => out.push(Emitted::simple(BpfInsn::new(
            bc::class::LDX | size | bc::mode::MEM,
            dreg,
            base,
            addr.offset,
            0,
        ))),
        other => return Err(internal!("loadraw base not a register: {other:?}")),
    }
    Ok(())
}

fn emit_store_raw(
    out: &mut Vec<Emitted>,
    vr_type: VrType,
    addr: &crate::ir::value::AddrValue,
    val: Loc,
) -> Result<()> {
    let size = vr_size(vr_type);
    let base = match loc_of(addr.value) {
        Loc::Reg(b) => b,
        other => return Err(internal!("storeraw base not a register: {other:?}")),
    };
    match val {
        Loc::Reg(r) => out.push(Emitted::simple(BpfInsn::new(
            bc::class::STX | size | bc::mode::MEM,
            base,
            r,
            addr.offset,
            0,
        ))),
        Loc::Const { v, .. } => out.push(Emitted::simple(BpfInsn::new(
            bc::class::ST | size | bc::mode::MEM,
            base,
            0,
            addr.offset,
            v as i32,
        ))),
        other => return Err(internal!("storeraw value unsupported: {other:?}")),
    }
    Ok(())
}

fn emit_cond_jmp(
    out: &mut Vec<Emitted>,
    cond: Cond,
    alu: AluOp,
    v0: Loc,
    v1: Loc,
    target: Option<BbId>,
) -> Result<()> {
    let jmp_class = if alu == AluOp::Alu64 {
        bc::class::JMP
    } else {
        bc::class::JMP32
    };
    // Ensure v0 is a register; if v0 is const and v1 is reg, swap+invert.
    let (cond, v0, v1) = match (v0, v1) {
        (Loc::Reg(_), _) => (cond, v0, v1),
        (Loc::Const { .. }, Loc::Reg(_)) => (swap_cond(cond), v1, v0),
        _ => return Err(internal!("conditional jump needs at least one register operand")),
    };
    let dst = match v0 {
        Loc::Reg(r) => r,
        _ => return Err(internal!("cond jmp dst not a register")),
    };
    let mut e = match v1 {
        Loc::Reg(r) => Emitted::simple(BpfInsn::new(
            jmp_class | cond_code(cond) | bc::src::X,
            dst,
            r,
            0,
            0,
        )),
        Loc::Const { v, .. } => Emitted::simple(BpfInsn::new(
            jmp_class | cond_code(cond) | bc::src::K,
            dst,
            0,
            0,
            v as i32,
        )),
        _ => return Err(internal!("cond jmp src unsupported")),
    };
    e.is_cond = true;
    e.target2 = target;
    out.push(e);
    Ok(())
}

/// Full normalization + emission driver.
pub fn normalize_and_emit(env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    flatten(func, cg);
    replace_builtin_consts(func);

    // Emit per block, recording each block's starting machine position.
    let mut block_emits: Vec<(BbId, Vec<(InsnId, Vec<Emitted>)>)> = Vec::new();
    let bbs = func.reachable_bbs.clone();
    for bb in bbs {
        let mut insn_emits = Vec::new();
        let insns = func.bb(bb).insns.clone();
        for id in insns {
            let mut out = Vec::new();
            emit_insn(func, cg, id, &mut out)?;
            insn_emits.push((id, out));
        }
        block_emits.push((bb, insn_emits));
    }

    // Compute machine positions for each block and instruction.
    let mut block_pos: HashMap<BbId, usize> = HashMap::new();
    let mut pos = 0usize;
    for (bb, insn_emits) in &block_emits {
        block_pos.insert(*bb, pos);
        for (_, emits) in insn_emits {
            for e in emits {
                pos += if e.wide { 2 } else { 1 };
            }
        }
    }
    let total = pos;
    if total >= 1_000_000 {
        return Err(invalid!("program too large after code generation"));
    }

    // Relocate jumps and synthesize.
    let mut insns = vec![BpfInsn::default(); total];
    let mut cur = 0usize;
    for (_bb, insn_emits) in &block_emits {
        for (_, emits) in insn_emits {
            for e in emits {
                let mut machine = e.insn;
                if e.is_ja {
                    let target = e.target1.ok_or_else(|| internal!("ja without target"))?;
                    let tpos = *block_pos.get(&target).unwrap();
                    machine.off = (tpos as i64 - cur as i64 - 1) as i16;
                }
                if e.is_cond {
                    let target = e.target2.ok_or_else(|| internal!("cond jmp without target"))?;
                    let tpos = *block_pos.get(&target).unwrap();
                    machine.off = (tpos as i64 - cur as i64 - 1) as i16;
                }
                insns[cur] = machine;
                if e.wide {
                    insns[cur + 1] = BpfInsn {
                        imm: (e.imm64 >> 32) as i32,
                        ..Default::default()
                    };
                    cur += 2;
                } else {
                    cur += 1;
                }
            }
        }
    }

    env.insns = insns;
    let _ = (cg, func);
    Ok(())
}
