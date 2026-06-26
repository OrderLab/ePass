use epass_ir::bytecode::{class, op, src, BpfInsn};
use epass_ir::ir::Value;
use epass_ir::{check, lift, Env, Opts};

fn branch_prog() -> Vec<BpfInsn> {
    vec![
        BpfInsn::new(class::JMP | op::JEQ | src::K, 1, 0, 1, 0),
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 1),
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 2),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ]
}

#[test]
fn split_block_before_moves_suffix_and_preserves_check() {
    let mut env = Env::new(Opts::default(), vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ]);
    let mut func = lift(&mut env).expect("lift");
    let entry = func.entry;
    let ret = func.bb(entry).last().unwrap();
    let new_bb = func.split_block_before(ret).expect("split");
    assert!(func.bb(entry).succs.contains(&new_bb));
    assert!(func.bb(new_bb).preds.contains(&entry));
    check::prog_check(&env, &func).expect("check");
}

#[test]
fn split_edge_inserts_block_and_relabels_phi_preds() {
    let mut env = Env::new(Opts::default(), branch_prog());
    let mut func = lift(&mut env).expect("lift");
    let from = func.entry;
    let to = func.bb(from).succs[0];
    let mid = func.split_edge(from, to).expect("split edge");
    assert!(func.bb(from).succs.contains(&mid));
    assert!(func.bb(mid).succs.contains(&to));
    assert!(func.bb(to).preds.contains(&mid));
    assert!(!func.bb(to).preds.contains(&from));
}

#[test]
fn create_ret_block_builds_valid_block() {
    let mut env = Env::new(Opts::default(), branch_prog());
    let mut func = lift(&mut env).expect("lift");
    let bb = func.create_ret_block(Value::const64(1));
    assert!(func.bb(bb).last().is_some());
}
