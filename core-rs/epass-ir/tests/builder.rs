use epass_ir::bytecode::{class, op, src, BpfInsn};
use epass_ir::ir::{AluOp, BinOp, InsertPos, IrBuilder, Value};
use epass_ir::{check, lift, Env, Opts};

fn env_minimal() -> Env {
    Env::new(
        Opts::default(),
        vec![
            BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 0),
            BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
        ],
    )
}

#[test]
fn builder_bin_updates_def_use() {
    let mut env = env_minimal();
    let mut func = lift(&mut env).expect("lift");
    let bb = func.entry;
    let ret = func.bb(bb).last().unwrap();
    let x = {
        let mut b = IrBuilder::at_insn(&mut func, ret, InsertPos::Front);
        b.bin(BinOp::Add, AluOp::Alu64, Value::const64(1), Value::const64(2))
    };
    assert!(func.insn(x).users.is_empty());
    check::prog_check(&env, &func).expect("check");
}

#[test]
fn builder_call_checks_arg_limit() {
    let mut env = env_minimal();
    let mut func = lift(&mut env).expect("lift");
    let bb = func.entry;
    let ret = func.bb(bb).last().unwrap();
    let mut b = IrBuilder::at_insn(&mut func, ret, InsertPos::Front);
    let args = vec![Value::const64(0); 6];
    assert!(b.call(1, args).is_err());
}
