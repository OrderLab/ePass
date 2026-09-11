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
    opts.apply_gopt(&format!("load_ir={}", path.display()))
        .unwrap();
    let mut env2 = Env::new(opts, vec![BpfInsn::new(class::JMP | op::EXIT, 0, 0, 0, 0)]);
    autorun(&mut env2, &default_passes()).expect("autorun load_ir");
    assert_eq!(env2.insns.last().unwrap().code, class::JMP | op::EXIT);
}

fn run_loaded_ir(path: &str, popt: &str) -> Env {
    let mut opts = Opts::default();
    opts.verbose = 3;
    opts.apply_gopt(&format!("load_ir={}", path)).unwrap();
    let mut env = Env::new(opts, vec![]);
    let passes = epass_ir::passes_from_popt(popt).unwrap();
    autorun(&mut env, &passes).expect("RA should converge");
    eprintln!("produced {} instructions", env.insns.len());
    assert!(!env.insns.is_empty(), "should produce output instructions");
    let last = env.insns.last().unwrap();
    eprintln!("last insn: code={:#04x}", last.code);
    env
}

#[test]
fn ra_pressure_reload_spill_converges() {
    // Load the EPIR test case that creates high register pressure at a use
    // point.  Before the fix (reload temps not marked spilled_once), the RA
    // allocator could recursively spill reload temps and fail to converge.
    // We disable const_prop and optimize_ir so that loadimm values are not
    // constant-folded away, preserving the high register pressure.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/epir/ra_pressure_reload_spill.epir"
    );
    run_loaded_ir(path, "!const_prop,!optimize_ir");
}

#[test]
fn ra_min_phi_6_converges() {
    // This small loop used to fail in pre-spilling: the MCS earlier-neighbor set
    // is larger than RA_COLORS but is not a real clique because the interference
    // graph is non-chordal.  Treating it as a clique caused repeated false spills
    // until only protected reload/phi fragments remained.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/epir/min_phi_6.epir");
    run_loaded_ir(path, "");
}
