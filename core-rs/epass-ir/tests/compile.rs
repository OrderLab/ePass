//! End-to-end compile tests: lift -> passes -> codegen, then sanity-check the
//! emitted bytecode (and that it round-trips through the dump format).

use epass_ir::bytecode::{class, mode, op, size, src, BpfInsn};
use epass_ir::{autorun, default_passes, logfmt, Env, Opts};

fn compile(prog: Vec<BpfInsn>) -> (Env, Vec<BpfInsn>) {
    let mut opts = Opts::default();
    opts.verbose = 3;
    let mut env = Env::new(opts, prog);
    let passes = default_passes();
    autorun(&mut env, &passes).expect("autorun failed");
    let out = env.insns.clone();
    (env, out)
}

#[test]
fn compile_minimal_exit() {
    let prog = vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ];
    let (_env, out) = compile(prog);
    assert!(!out.is_empty());
    // Must end with EXIT.
    let last = *out.last().unwrap();
    assert_eq!(last.code, class::JMP | op::EXIT, "last insn should be exit");
}

#[test]
fn compile_add_and_return() {
    // r1 = 5; r2 = 7; r1 += r2; r0 = r1; exit
    let prog = vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 1, 0, 0, 5),
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 2, 0, 0, 7),
        BpfInsn::new(class::ALU64 | op::ADD | src::X, 1, 2, 0, 0),
        BpfInsn::new(class::ALU64 | op::MOV | src::X, 0, 1, 0, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ];
    let (_env, out) = compile(prog);
    assert_eq!(out.last().unwrap().code, class::JMP | op::EXIT);
    // Dump round-trips.
    let dumped = logfmt::to_dump(&out);
    assert_eq!(logfmt::parse_dump(&dumped), out);
}

#[test]
fn compile_loop() {
    // counting loop
    let prog = vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 1, 0, 0, 0), // r1 = 0
        BpfInsn::new(class::ALU64 | op::ADD | src::K, 1, 0, 0, 1), // r1 += 1
        BpfInsn::new(class::JMP | op::JLT | src::K, 1, 0, -2, 10), // if r1<10 goto -2
        BpfInsn::new(class::ALU64 | op::MOV | src::X, 0, 1, 0, 0), // r0 = r1
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ];
    let (_env, out) = compile(prog);
    assert!(out.iter().any(|i| class::JMP == (i.code & 0x07) && (i.code & 0xf0) == op::JLT
        || (i.code & 0x07) == class::JMP32 && (i.code & 0xf0) == op::JLT
        || (i.code & 0xf0) == op::JGT));
    assert_eq!(out.last().unwrap().code, class::JMP | op::EXIT);
}

#[test]
fn compile_stack_load_store() {
    let prog = vec![
        BpfInsn::new(class::STX | mode::MEM | size::DW, 10, 1, -8, 0),
        BpfInsn::new(class::LDX | mode::MEM | size::DW, 0, 10, -8, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ];
    let (_env, out) = compile(prog);
    assert_eq!(out.last().unwrap().code, class::JMP | op::EXIT);
}
