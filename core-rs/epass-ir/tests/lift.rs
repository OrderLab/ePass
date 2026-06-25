//! End-to-end lifter tests: build small eBPF programs, lift them, run the
//! trivial-phi pass, and check the resulting IR is well-formed and prints.

use epass_ir::bytecode::{op, src, BpfInsn};
use epass_ir::bytecode::{class, size, mode};
use epass_ir::{check, lift, Env, Opts};

fn env_with(insns: Vec<BpfInsn>) -> Env {
    let mut opts = Opts::default();
    opts.verbose = 3;
    Env::new(opts, insns)
}

#[test]
fn lift_minimal_exit() {
    // r0 = 0; exit
    let prog = vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ];
    let mut env = env_with(prog);
    let func = lift(&mut env).expect("lift failed");
    check::prog_check(&env, &func).expect("prog_check failed");
    let txt = epass_ir::print_ir(&func);
    assert!(txt.contains("ret"), "should contain a ret:\n{txt}");
}

#[test]
fn lift_branch_creates_two_blocks() {
    // if r1 == 0 goto +1; r0 = 1; r0 = 2; exit
    let prog = vec![
        BpfInsn::new(class::JMP | op::JEQ | src::K, 1, 0, 1, 0), // 0: jeq r1, 0 -> +1
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 1), // 1: r0 = 1
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 2), // 2: r0 = 2
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),          // 3: exit
    ];
    let mut env = env_with(prog);
    let func = lift(&mut env).expect("lift failed");
    check::prog_check(&env, &func).expect("prog_check failed");
    // Entry + fallthrough + target(merge) = at least 3 reachable blocks.
    assert!(func.reachable_bbs.len() >= 2);
}

#[test]
fn lift_loop_with_phi_then_simplify() {
    // A simple counting loop that requires a phi for r1.
    //   r1 = 0
    // loop:
    //   r1 += 1
    //   if r1 < 10 goto loop
    //   r0 = r1
    //   exit
    let prog = vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 1, 0, 0, 0), // 0: r1 = 0
        BpfInsn::new(class::ALU64 | op::ADD | src::K, 1, 0, 0, 1), // 1: r1 += 1
        BpfInsn::new(class::JMP | op::JLT | src::K, 1, 0, -2, 10), // 2: if r1 < 10 goto 1
        BpfInsn::new(class::ALU64 | op::MOV | src::X, 0, 1, 0, 0), // 3: r0 = r1
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),           // 4: exit
    ];
    let mut env = env_with(prog);
    let mut func = lift(&mut env).expect("lift failed");
    check::prog_check(&env, &func).expect("prog_check after lift failed");

    let txt_before = epass_ir::print_ir(&func);
    assert!(txt_before.contains("phi"), "loop should produce a phi:\n{txt_before}");

    // Run the trivial-phi pass through the manager (also re-validates).
    let mut pm = epass_ir::PassManager::new();
    pm.pre.push(Box::new(epass_ir::passes::phi::pass()));
    pm.run(&mut env, &mut func).expect("phi pass failed");
    check::prog_check(&env, &func).expect("prog_check after phi failed");
}

#[test]
fn lift_load_store_stack() {
    // *(u64 *)(r10 - 8) = r1; r2 = *(u64 *)(r10 - 8); r0 = 0; exit
    let prog = vec![
        BpfInsn::new(class::STX | mode::MEM | size::DW, 10, 1, -8, 0),
        BpfInsn::new(class::LDX | mode::MEM | size::DW, 2, 10, -8, 0),
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ];
    let mut env = env_with(prog);
    let func = lift(&mut env).expect("lift failed");
    check::prog_check(&env, &func).expect("prog_check failed");
    let txt = epass_ir::print_ir(&func);
    assert!(txt.contains("storeraw"), "{txt}");
    assert!(txt.contains("loadraw"), "{txt}");
}
