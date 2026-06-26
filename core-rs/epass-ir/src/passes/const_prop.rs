//! Conservative constant propagation and folding.
//!
//! This pass only folds pure SSA values with plain constants. It deliberately
//! avoids memory, calls, map/value immediates, stack-relative constants, and
//! builtin constants. The main CFG transform is folding conditional branches
//! whose operands are both known constants.

use crate::env::Env;
use crate::error::Result;
use crate::ir::insn::{BinOp, Cond, InsnKind};
use crate::ir::value::{AluOp, BuiltinConst, ConstKind, Value};
use crate::ir::{Function, InsnId};
use crate::pass::{FnPass, Pass};

fn plain_const(v: Value) -> Option<(i64, AluOp)> {
    match v {
        Value::Const {
            v,
            ty,
            kind: ConstKind::Plain,
            builtin: BuiltinConst::None,
        } => Some((v, ty)),
        _ => None,
    }
}

fn const_value(v: i64, ty: AluOp) -> Value {
    Value::Const {
        v: match ty {
            AluOp::Alu32 => (v as u32 as i32) as i64,
            AluOp::Alu64 | AluOp::Unknown => v,
        },
        ty,
        kind: ConstKind::Plain,
        builtin: BuiltinConst::None,
    }
}

fn fold_bin(op: BinOp, alu: AluOp, lhs: i64, rhs: i64) -> Option<Value> {
    let width = if alu == AluOp::Alu32 { 32 } else { 64 };
    let sh = rhs as u64;
    if matches!(op, BinOp::Lsh | BinOp::Rsh | BinOp::Arsh) && sh >= width {
        return None;
    }

    let out = match alu {
        AluOp::Alu32 => {
            let a = lhs as u32;
            let b = rhs as u32;
            let r = match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::Div => {
                    if b == 0 { return None; }
                    a.wrapping_div(b)
                }
                BinOp::Mod => {
                    if b == 0 { return None; }
                    a.wrapping_rem(b)
                }
                BinOp::Or => a | b,
                BinOp::And => a & b,
                BinOp::Xor => a ^ b,
                BinOp::Lsh => a.wrapping_shl(sh as u32),
                BinOp::Rsh => a.wrapping_shr(sh as u32),
                BinOp::Arsh => ((a as i32) >> (sh as u32)) as u32,
            };
            (r as i32) as i64
        }
        AluOp::Alu64 | AluOp::Unknown => {
            let a = lhs as u64;
            let b = rhs as u64;
            let r = match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::Div => {
                    if b == 0 { return None; }
                    a.wrapping_div(b)
                }
                BinOp::Mod => {
                    if b == 0 { return None; }
                    a.wrapping_rem(b)
                }
                BinOp::Or => a | b,
                BinOp::And => a & b,
                BinOp::Xor => a ^ b,
                BinOp::Lsh => a.wrapping_shl(sh as u32),
                BinOp::Rsh => a.wrapping_shr(sh as u32),
                BinOp::Arsh => ((a as i64) >> (sh as u32)) as u64,
            };
            r as i64
        }
    };
    Some(const_value(out, alu))
}

fn fold_neg(alu: AluOp, v: i64) -> Value {
    match alu {
        AluOp::Alu32 => const_value((v as u32).wrapping_neg() as i32 as i64, AluOp::Alu32),
        AluOp::Alu64 | AluOp::Unknown => const_value((v as u64).wrapping_neg() as i64, alu),
    }
}

fn eval_cond(cond: Cond, alu: AluOp, lhs: i64, rhs: i64) -> bool {
    match cond {
        Cond::Eq => lhs == rhs,
        Cond::Ne => lhs != rhs,
        Cond::Gt => {
            if alu == AluOp::Alu32 { (lhs as u32) > (rhs as u32) } else { (lhs as u64) > (rhs as u64) }
        }
        Cond::Ge => {
            if alu == AluOp::Alu32 { (lhs as u32) >= (rhs as u32) } else { (lhs as u64) >= (rhs as u64) }
        }
        Cond::Lt => {
            if alu == AluOp::Alu32 { (lhs as u32) < (rhs as u32) } else { (lhs as u64) < (rhs as u64) }
        }
        Cond::Le => {
            if alu == AluOp::Alu32 { (lhs as u32) <= (rhs as u32) } else { (lhs as u64) <= (rhs as u64) }
        }
        Cond::Sgt => {
            if alu == AluOp::Alu32 { (lhs as i32) > (rhs as i32) } else { lhs > rhs }
        }
        Cond::Sge => {
            if alu == AluOp::Alu32 { (lhs as i32) >= (rhs as i32) } else { lhs >= rhs }
        }
        Cond::Slt => {
            if alu == AluOp::Alu32 { (lhs as i32) < (rhs as i32) } else { lhs < rhs }
        }
        Cond::Sle => {
            if alu == AluOp::Alu32 { (lhs as i32) <= (rhs as i32) } else { lhs <= rhs }
        }
    }
}

fn replace_with_const(func: &mut Function, id: InsnId, c: Value) {
    func.replace_all_uses(id, c);
    if func.is_alive(id) && func.insn(id).users.iter().all(|&u| u == id) {
        // Drop any self-use first (possible for degenerate phis).
        if matches!(func.insn(id).kind, InsnKind::Phi) {
            let entries = func.insn(id).phi.clone();
            for entry in entries {
                func.remove_use(entry.value, id);
            }
            func.insn_mut(id).phi.clear();
        }
        func.erase_insn(id);
    }
}

pub fn const_prop(_env: &mut Env, func: &mut Function) -> Result<()> {
    let mut changed = true;
    while changed {
        changed = false;
        let insns: Vec<InsnId> = func
            .reachable_bbs
            .iter()
            .flat_map(|&bb| func.bb(bb).insns.clone())
            .collect();

        for id in insns {
            if !func.is_alive(id) {
                continue;
            }
            let kind = func.insn(id).kind.clone();
            match kind {
                InsnKind::Assign => {
                    if let Some((v, ty)) = plain_const(func.insn(id).values[0]) {
                        replace_with_const(func, id, const_value(v, ty));
                        changed = true;
                    }
                }
                InsnKind::Bin { op } => {
                    let vals = func.insn(id).values.clone();
                    if vals.len() == 2 {
                        if let (Some((l, _)), Some((r, _))) = (plain_const(vals[0]), plain_const(vals[1])) {
                            if let Some(c) = fold_bin(op, func.insn(id).alu_op, l, r) {
                                replace_with_const(func, id, c);
                                changed = true;
                            }
                        }
                    }
                }
                InsnKind::Neg => {
                    if let Some((v, _)) = plain_const(func.insn(id).values[0]) {
                        let c = fold_neg(func.insn(id).alu_op, v);
                        replace_with_const(func, id, c);
                        changed = true;
                    }
                }
                InsnKind::Phi => {
                    let mut same: Option<Value> = None;
                    let mut foldable = true;
                    for entry in func.insn(id).phi.clone() {
                        let Some((v, ty)) = plain_const(entry.value) else {
                            foldable = false;
                            break;
                        };
                        let c = const_value(v, ty);
                        if let Some(prev) = same {
                            if prev != c {
                                foldable = false;
                                break;
                            }
                        } else {
                            same = Some(c);
                        }
                    }
                    if foldable {
                        if let Some(c) = same {
                            replace_with_const(func, id, c);
                            changed = true;
                        }
                    }
                }
                InsnKind::CondJmp { cond } => {
                    let vals = func.insn(id).values.clone();
                    if vals.len() == 2 {
                        if let (Some((l, _)), Some((r, _))) = (plain_const(vals[0]), plain_const(vals[1])) {
                            let taken = eval_cond(cond, func.insn(id).alu_op, l, r);
                            let target = if taken { func.insn(id).bb2 } else { func.insn(id).bb1 };
                            if let Some(target) = target {
                                func.rewrite_cond_to_ja(id, target);
                                changed = true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn pass() -> impl Pass {
    FnPass::new("const_prop", const_prop)
}
