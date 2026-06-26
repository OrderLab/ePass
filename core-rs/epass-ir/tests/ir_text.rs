use epass_ir::bytecode::{class, op, src, BpfInsn};
use epass_ir::{autorun, default_passes, dump_ir, lift, load_ir_str, Env, Opts};

fn minimal_prog() -> Vec<BpfInsn> {
    vec![
        BpfInsn::new(class::ALU64 | op::MOV | src::K, 0, 0, 0, 0),
        BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0),
    ]
}

#[test]
fn dump_load_roundtrip_compiles() {
    let mut env = Env::new(Opts::default(), minimal_prog());
    let func = lift(&mut env).expect("lift");
    let text = dump_ir(&func);
    let func2 = load_ir_str(&text).expect("load ir");
    let text2 = dump_ir(&func2);
    assert!(text2.contains("ret"), "{text2}");
}

#[test]
fn load_ir_gopt_bypasses_lift_and_compiles() {
    let mut env = Env::new(Opts::default(), minimal_prog());
    let func = lift(&mut env).expect("lift");
    let text = dump_ir(&func);
    let path = std::env::temp_dir().join("epass_ir_text_test.epir");
    std::fs::write(&path, text).unwrap();

    let mut opts = Opts::default();
    opts.apply_gopt(&format!("load_ir={}", path.display())).unwrap();
    let mut env2 = Env::new(opts, vec![BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0)]);
    autorun(&mut env2, &default_passes()).expect("autorun load_ir");
    assert_eq!(env2.insns.last().unwrap().code, class::JMP | op::EXIT);
}
