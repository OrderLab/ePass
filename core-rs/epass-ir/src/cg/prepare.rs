//! Code-generation preparation: initialize RA metadata, lower calls and
//! function arguments to pre-colored copies, pre-spill arrays and
//! non-encodable constants, and fold the final stack offset into raw offsets.

use std::collections::HashMap;

use crate::bytecode::{BPF_REG_0, MAX_FUNC_ARG};
use crate::env::Env;
use crate::error::Result;
use crate::ir::insn::InsnKind;
use crate::ir::value::{ConstKind, VrPos, VrType};
use crate::ir::{Function, InsertPos, Value};

use super::{CgExtra, CgState, RA_COLORS};

/// Initialize per-instruction CG metadata and the physical-register pseudos.
pub fn init_cg(_env: &mut Env, func: &mut Function) -> Result<CgState> {
    // Create R0..R9 pseudo-instructions (pre-colored, non-virtual).
    let mut regs = [crate::ir::InsnId(0); RA_COLORS];
    for (i, slot) in regs.iter_mut().enumerate() {
        *slot = func.create_reg_pseudo(i as u8);
    }

    let mut extra: HashMap<crate::ir::InsnId, CgExtra> = HashMap::new();

    // Every real instruction gets a CgExtra; its `dst` is itself unless void.
    for &bb in &func.reachable_bbs {
        for &id in &func.bb(bb).insns {
            let dst = if func.insn(id).is_void() { None } else { Some(id) };
            extra.insert(id, CgExtra::new(dst));
        }
    }

    // Physical registers: pre-colored, finalized, non-virtual.
    for (i, &reg) in regs.iter().enumerate() {
        let mut e = CgExtra::new(Some(reg));
        e.vr_pos = VrPos {
            allocated: true,
            alloc_reg: i as u8,
            spilled: 0,
            spilled_size: 0,
        };
        e.nonvr = true;
        e.finalized = true;
        extra.insert(reg, e);
    }

    // Stack pointer pseudo.
    {
        let mut e = CgExtra::new(Some(func.sp));
        e.vr_pos = VrPos::stack_ptr();
        e.nonvr = true;
        e.finalized = true;
        extra.insert(func.sp, e);
    }

    Ok(CgState {
        extra,
        regs,
        seo: Vec::new(),
        all_var: Vec::new(),
        stack_offset: 0,
    })
}

/// Lower each `call`: move arguments into pre-colored R1..R5, and the result
/// out of R0.
pub fn change_call(_env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let calls: Vec<_> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .filter(|&id| matches!(func.insn(id).kind, InsnKind::Call { .. } | InsnKind::Ecall))
        .collect();

    for call in calls {
        // Arguments -> assign into R1..R5 (pre-colored), inserted before the call.
        let args: Vec<Value> = func.insn(call).values.to_vec();
        for (i, arg) in args.iter().enumerate() {
            func.remove_use(*arg, call);
            let assign = func.build_assign_at(call, *arg, InsertPos::Front);
            pre_color(cg, func, assign, (i + 1) as u8);
        }
        func.insn_mut(call).values.clear();

        // Result: if used, copy R0 into a fresh assign and rewrite users.
        let has_users = !func.insn(call).users.is_empty();
        cg.extra_mut(call).dst = None;
        if has_users {
            let r0 = cg.regs[BPF_REG_0 as usize];
            let assign = func.build_assign_at(call, Value::Insn(r0), InsertPos::Back);
            ensure_extra(cg, func, assign);
            func.replace_all_uses(call, Value::Insn(assign));
        }
    }
    Ok(())
}

/// Replace uses of function-argument pseudos with copies from R1..R5.
pub fn change_fun_arg(_env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    for i in 0..MAX_FUNC_ARG {
        let arg = func.args[i];
        if func.insn(arg).users.is_empty() {
            continue;
        }
        let reg = cg.regs[i + 1];
        let entry = func.entry;
        let assign = func.build_assign_bb(entry, Value::Insn(reg), InsertPos::FrontAfterPhi);
        ensure_extra(cg, func, assign);
        func.replace_all_uses(arg, Value::Insn(assign));
    }
    Ok(())
}

/// Assign fixed stack slots to `allocarray` instructions.
pub fn spill_array(_env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let arrays: Vec<_> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .filter(|&id| matches!(func.insn(id).kind, InsnKind::AllocArray { .. }))
        .collect();
    for id in arrays {
        let (vr_type, num) = match func.insn(id).kind {
            InsnKind::AllocArray { vr_type, num } => (vr_type, num),
            _ => unreachable!(),
        };
        let size = num * vr_type.size();
        if size == 0 {
            return Err(crate::invalid!("allocarray with size 0"));
        }
        let roundup = (size + 7) & !7;
        let off = cg.new_spill(roundup);
        let e = cg.extra_mut(id);
        e.vr_pos.allocated = true;
        e.vr_pos.spilled = off;
        e.vr_pos.spilled_size = size;
        e.finalized = true;
    }
    Ok(())
}

/// Materialize constants that the BPF ISA cannot encode directly.
pub fn spill_const(_env: &mut Env, func: &mut Function, cg: &mut CgState) -> Result<()> {
    let insns: Vec<_> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .collect();

    for id in insns {
        // Non-commutative binary ALU: first operand cannot be a constant.
        if func.insn(id).is_bin_alu() && !func.insn(id).is_commutative_alu() {
            let v0 = func.insn(id).values[0];
            if v0.is_const() {
                let assign = func.build_assign_at(id, v0, InsertPos::Front);
                ensure_extra(cg, func, assign);
                func.change_value(id, v0, Value::Insn(assign));
            }
        }
        // Conditional jump: both operands cannot be constants.
        if func.insn(id).is_cond_jmp() && func.insn(id).values.len() == 2 {
            let v0 = func.insn(id).values[0];
            let v1 = func.insn(id).values[1];
            if v0.is_const() && v1.is_const() {
                // Promote values[1] into a register.
                let assign = func.build_assign_at(id, v1, InsertPos::Front);
                ensure_extra(cg, func, assign);
                func.change_value(id, v1, Value::Insn(assign));
            }
        }
    }
    Ok(())
}

/// Fold the final stack offset into stack-relative raw constants.
pub fn add_stack_offset(func: &mut Function, offset: i32) {
    let insns: Vec<_> = func
        .reachable_bbs
        .iter()
        .flat_map(|&bb| func.bb(bb).insns.clone())
        .collect();
    for id in insns {
        // Raw load/store address offsets.
        match &mut func.insn_mut(id).kind {
            InsnKind::LoadRaw { addr, .. } | InsnKind::StoreRaw { addr, .. } => match addr.offset_kind
            {
                ConstKind::RawOff => {
                    addr.offset += offset as i16;
                    addr.offset_kind = ConstKind::Plain;
                }
                ConstKind::RawOffRev => {
                    addr.offset -= offset as i16;
                    addr.offset_kind = ConstKind::Plain;
                }
                ConstKind::Plain => {}
            },
            _ => {}
        }
        // Operand constants that are stack-relative.
        let n = func.insn(id).values.len();
        for i in 0..n {
            if let Value::Const { v, kind, .. } = &mut func.insn_mut(id).values[i] {
                match *kind {
                    ConstKind::RawOff => {
                        *v += offset as i64;
                        *kind = ConstKind::Plain;
                    }
                    ConstKind::RawOffRev => {
                        *v -= offset as i64;
                        *kind = ConstKind::Plain;
                    }
                    ConstKind::Plain => {}
                }
            }
        }
    }
}

// ---- helpers ----

fn pre_color(cg: &mut CgState, func: &Function, insn: crate::ir::InsnId, reg: u8) {
    ensure_extra(cg, func, insn);
    let e = cg.extra_mut(insn);
    e.finalized = true;
    e.vr_pos.allocated = true;
    e.vr_pos.alloc_reg = reg;
    e.vr_pos.spilled = 0;
}

/// Make sure a freshly-created instruction has a CgExtra entry.
pub(super) fn ensure_extra(cg: &mut CgState, func: &Function, insn: crate::ir::InsnId) {
    cg.extra.entry(insn).or_insert_with(|| {
        let dst = if func.insn(insn).is_void() {
            None
        } else {
            Some(insn)
        };
        CgExtra::new(dst)
    });
}

/// Add a fresh alloc instruction (used by the spiller) with CG metadata.
pub(super) fn create_alloc(
    cg: &mut CgState,
    func: &mut Function,
    bb: crate::ir::BbId,
    ty: VrType,
    pos: InsertPos,
) -> crate::ir::InsnId {
    let id = func.build_alloc_bb(bb, ty, pos);
    ensure_extra(cg, func, id);
    id
}
