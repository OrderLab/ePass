//! `const_prop`: fold operations on constants (exact RFC 9669 semantics),
//! fold branches on constants, apply exact 64-bit identities, and delete
//! blocks that become unreachable.

use crate::analysis::Cfg;
use crate::error::Result;
use crate::ir::cleanup::remove_unreachable;
use crate::ir::{eval, BinOp, Function, InsnId, Op, Value, Width};
use crate::mem::FVec;
use crate::pm::{no_args, PassCx, PassInfo, Phase};

pub const INFO: PassInfo = PassInfo {
    name: "const_prop",
    phase: Phase::Optimize,
    after: &[],
    before: &[],
    default_on: true,
    user_controllable: true,
    mandatory: false,
    check_args: no_args,
    run,
};

/// The value an instruction simplifies to, if any.
fn simplify(f: &Function<'_>, i: InsnId, big_endian: bool) -> Result<Option<Value>> {
    let c = |k: usize| f.operand(i, k).map(Value::as_const);
    Ok(match f.op(i)? {
        Op::Bin { op, w } => {
            let (a, b) = (f.operand(i, 0)?, f.operand(i, 1)?);
            match (a.as_const(), b.as_const()) {
                (Some(x), Some(y)) => Some(Value::Const(eval::bin(op, w, x, y))),
                // Exact identities; 32-bit forms would need a zext.
                (None, Some(y)) if w == Width::W64 => match (op, y) {
                    (BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor, 0) => Some(a),
                    (BinOp::Shl | BinOp::LShr | BinOp::AShr, 0) => Some(a),
                    (BinOp::Mul | BinOp::UDiv | BinOp::SDiv, 1) => Some(a),
                    (BinOp::And, u64::MAX) => Some(a),
                    _ => None,
                },
                (Some(x), None) if w == Width::W64 => match (op, x) {
                    (BinOp::Add | BinOp::Or | BinOp::Xor, 0) => Some(b),
                    (BinOp::Mul, 1) => Some(b),
                    (BinOp::And, u64::MAX) => Some(b),
                    _ => None,
                },
                _ => None,
            }
        }
        Op::Neg { w } => c(0)?.map(|x| Value::Const(eval::neg(w, x))),
        Op::Ext { from, signed, w } => c(0)?.map(|x| Value::Const(eval::ext(from, signed, w, x))),
        Op::Bswap { bits, kind } => c(0)?.map(|x| Value::Const(eval::bswap(bits, kind, big_endian, x))),
        Op::Phi => {
            let mut same: Option<u64> = None;
            let mut ok = true;
            for (v, _) in f.phi_inputs(i) {
                match v {
                    Value::Undef => {}
                    Value::Insn(d) if d == i => {}
                    Value::Const(x) => match same {
                        None => same = Some(x),
                        Some(s) if s == x => {}
                        Some(_) => ok = false,
                    },
                    _ => ok = false,
                }
            }
            if ok {
                same.map(Value::Const)
            } else {
                None
            }
        }
        _ => None,
    })
}

fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    run_on(f, cx).map(|_| ())
}

pub fn run_on<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>) -> Result<bool> {
    let mut any = false;
    loop {
        let mut changed = false;
        let cfg = Cfg::compute(f, cx.ctx)?;
        let mut order: FVec<'h, InsnId> = FVec::new(f.heap());
        for &b in cfg.rpo() {
            for i in f.iter_block(b) {
                order.push(i)?;
            }
        }
        for &i in order.iter() {
            cx.ctx.tick()?;
            if !f.is_insn(i) {
                continue;
            }
            if let Op::CondBr { cond, w, t, f: fb } = f.op(i)? {
                let (a, b) = (f.operand(i, 0)?, f.operand(i, 1)?);
                if let (Some(x), Some(y)) = (a.as_const(), b.as_const()) {
                    let taken = eval::cond(cond, w, x, y);
                    let (target, other) = if taken { (t, fb) } else { (fb, t) };
                    let here = f.insn(i)?.block();
                    if other != target {
                        for p in f.block_insns(other)?.iter() {
                            if !matches!(f.op(*p)?, Op::Phi) {
                                break;
                            }
                            f.remove_phi_input(*p, here)?;
                        }
                    }
                    f.set_terminator_with(i, Op::Br { target }, &[])?;
                    changed = true;
                }
                continue;
            }
            if let Some(v) = simplify(f, i, cx.opts.big_endian)? {
                if v != Value::Insn(i) && f.use_count(i)? > 0 {
                    f.replace_all_uses(i, v)?;
                    changed = true;
                }
            }
        }
        if remove_unreachable(f, cx.ctx)? {
            changed = true;
        }
        if !changed {
            return Ok(any);
        }
        any = true;
    }
}
