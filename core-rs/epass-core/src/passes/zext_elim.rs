//! `zext_elim`: drop `zext.32` of values whose upper 32 bits are known zero:
//! zero-extending loads of at most 4 bytes, 32-bit ALU results, other
//! `zext.32`s, constants below 2^32, and phis whose inputs all qualify.
//! Never after a sign extension, a sign-extending load, or a pointer.

use crate::analysis::{Cfg, UpperZero};
use crate::error::Result;
use crate::ir::{Function, InsnId, Op, Value};
use crate::mem::FVec;
use crate::pm::{no_args, PassCx, PassInfo, Phase};

pub const INFO: PassInfo = PassInfo {
    name: "zext_elim",
    phase: Phase::Optimize,
    after: &["const_prop", "phi"],
    before: &[],
    default_on: true,
    user_controllable: true,
    mandatory: false,
    check_args: no_args,
    run,
};

fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    let cfg = Cfg::compute(f, cx.ctx)?;
    let uz = UpperZero::compute(f, &cfg, cx.ctx)?;
    let mut todo: FVec<'h, (InsnId, Value)> = FVec::new(f.heap());
    for &b in cfg.rpo() {
        for i in f.iter_block(b) {
            cx.ctx.tick()?;
            if let Op::Ext { from: 32, signed: false, .. } = f.op(i)? {
                let src = f.operand(i, 0)?;
                if uz.of(src) {
                    todo.push((i, src))?;
                }
            }
        }
    }
    for &(i, src) in todo.iter() {
        f.replace_all_uses(i, src)?;
        f.set_operand(i, 0, Value::Undef)?;
        f.remove(i)?;
    }
    Ok(())
}
