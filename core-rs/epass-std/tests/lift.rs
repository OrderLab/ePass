//! M3 tests: the lifter (per opcode family, error cases, the Falco corpus,
//! deep CFGs on a 16 KB stack) and the value-fact analyses.

use epass_core::analysis::{frame_extent, Cfg, Class, Classes, Provenance, UpperZero};
use epass_core::bpf::BpfInsn;
use epass_core::facts::{default_helper, DefaultFacts, Facts, RetClass};
use epass_core::ir::print::print;
use epass_core::ir::{Callee, Function, Op, Value};
use epass_core::lift::lift;
use epass_core::{Ctx, ErrorKind, Heap, Level, Limits};
use epass_interp::asm::*;
use epass_interp::prog;
use epass_std::StdHost;

fn insns(p: &[u64]) -> Vec<BpfInsn> {
    p.iter().map(|&r| BpfInsn::from_u64(r)).collect()
}

fn text_of(f: &Function<'_>) -> String {
    let mut s = String::new();
    print(&mut s as &mut dyn std::fmt::Write, f).unwrap();
    s
}

fn small_limits() -> Limits {
    Limits {
        log_bytes: 4096,
        ..Limits::USERSPACE
    }
}

/// Lift and return the printed IR (panics with the error otherwise).
fn lift_text(p: &[u64]) -> String {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 30);
    let ctx = Ctx::new(&heap, small_limits(), Level::Debug).unwrap();
    let f = lift(&insns(p), &DefaultFacts::default(), &ctx).unwrap_or_else(|e| panic!("lift failed: {e}"));
    text_of(&f)
}

fn lift_err(p: &[u64], facts: &dyn Facts) -> epass_core::Error {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 30);
    let ctx = Ctx::new(&heap, small_limits(), Level::Debug).unwrap();
    lift(&insns(p), facts, &ctx).expect_err("lift should fail")
}

fn has(text: &str, needle: &str) -> bool {
    text.lines().any(|l| l.contains(needle))
}

#[test]
fn canonical_constants_and_extensions() {
    // w2 = -1 is 0xffffffff; r3 = -1 is all ones; w0 = w1 is a zext.
    let t = lift_text(&prog![
        mov32_imm(R2, -1),
        mov64_imm(R3, -1),
        ldx(Size::DW, R1, R1, 0),
        mov32_reg(R0, R1),
        alu64_reg(Alu::Add, R0, R2),
        alu64_reg(Alu::Add, R0, R3),
        exit()
    ]);
    assert!(has(&t, "zext.32.64"), "{t}");
    assert!(has(&t, "add.64 %1, 0xffffffff"), "{t}");
    assert!(has(&t, "add.64 %2, -1"), "{t}");
    // Constant folding of mov32 X on a constant source.
    let t = lift_text(&prog![mov64_imm(R1, -1), mov32_reg(R0, R1), exit()]);
    assert!(has(&t, "ret 0xffffffff"), "{t}");
}

#[test]
fn v4_and_signed_operations() {
    let t = lift_text(&prog![
        ldxs(Size::B, R2, R1, 0),
        movsx64(R3, R2, 16),
        movsx32(R4, R2, 8),
        sdiv64_reg(R3, R2),
        smod64_reg(R3, R4),
        bswap(R3, 64),
        be(R3, 16),
        le(R3, 32),
        mov64_reg(R0, R3),
        gotol(0),
        exit()
    ]);
    for needle in [
        "load.s8 [%arg1+0]",
        "sext.16.64",
        "sext.8.32",
        "sdiv.64",
        "smod.64",
        "bswap.swap.64",
        "bswap.be.16",
        "bswap.le.32",
    ] {
        assert!(has(&t, needle), "missing {needle}:\n{t}");
    }
}

#[test]
fn jset_and_jmp32() {
    let t = lift_text(&prog![
        ldx(Size::DW, R2, R1, 0),
        mov64_imm(R0, 0),
        jmp_imm(Jmp::Jset, R2, 1, 1),
        jmp32_imm(Jmp::Jslt, R2, -1, 1),
        mov64_imm(R0, 1),
        exit()
    ]);
    assert!(has(&t, "condbr.64.set %0, 1"), "{t}");
    assert!(has(&t, "condbr.32.slt %0, 0xffffffff"), "{t}");
}

#[test]
fn entry_loop_header_gets_phis() {
    // pc 0 is a loop header: r1 += 1; if r1 < 5 goto pc 0
    let t = lift_text(&prog![
        alu64_imm(Alu::Add, R1, 1),
        jmp_imm(Jmp::Jlt, R1, 5, -2),
        mov64_reg(R0, R1),
        exit()
    ]);
    assert!(has(&t, "phi [%arg1, bb0]"), "{t}");
    assert!(t.lines().next().is_some());
}

#[test]
fn calls_atomics_packet_loads_and_poison() {
    let t = lift_text(&prog![
        mov64_reg(R6, R1),
        st(Size::W, R10, -4, 0),
        ld_map_fd(R1, 7),
        mov64_reg(R2, R10),
        alu64_imm(Alu::Add, R2, -4),
        call(1),
        mov64_imm(R2, 1),
        atomic(Size::DW, R10, R2, -8, 0x01),
        ld_abs(Size::B, 12),
        mov64_reg(R7, R0),
        mov64_reg(R1, R6),
        raw_kfunc(1234, 0),
        jmp_imm(Jmp::Jeq, R7, 0, 2),
        mov64_reg(R0, R7),
        exit(),
        call(0xbad2310)
    ]);
    assert!(has(&t, "ldsym.map_fd 7"), "{t}");
    assert!(has(&t, "call helper#1("), "{t}");
    assert!(has(&t, "opaque 0x00000001fff82adb(1, %fp)"), "{t}");
    assert!(has(&t, "opaque 0x0000000c00000030(%arg1)"), "{t}");
    assert!(has(&t, "call.unknown kfunc#1234:0("), "{t}");
    assert!(has(&t, "poison 195896080"), "{t}");
}

/// `call` with src = 2 (kfunc), imm = btf id, off = fd index.
fn raw_kfunc(btf_id: i32, fd_idx: i16) -> u64 {
    BpfInsn::new(0x85, 0, 2, fd_idx, btf_id).to_u64()
}

#[test]
fn unsupported_and_invalid_inputs_are_errors() {
    let user = DefaultFacts::default();
    let kernel = DefaultFacts {
        allow_unknown_calls: false,
        ..DefaultFacts::default()
    };
    let cases: Vec<(&str, Vec<u64>, &dyn Facts, ErrorKind)> = vec![
        ("bpf2bpf", prog![call_local(1), exit(), mov64_imm(R0, 0), exit()], &user, ErrorKind::Unsupported),
        ("may_goto", prog![BpfInsn::new(0xe5, 0, 0, 0, 0).to_u64(), mov64_imm(R0, 0), exit()], &user, ErrorKind::Unsupported),
        ("uninitialized", prog![mov64_reg(R0, R6), exit()], &user, ErrorKind::InvalidInput),
        ("jump out of range", prog![ja(5), exit()], &user, ErrorKind::InvalidInput),
        ("falls off the end", prog![mov64_imm(R0, 0)], &user, ErrorKind::InvalidInput),
        ("truncated ld_imm64", prog![ld_imm64(R0, 1)[0]], &user, ErrorKind::InvalidInput),
        ("jump into ld_imm64", prog![ja(1), ld_imm64(R0, 1), exit()], &user, ErrorKind::InvalidInput),
        ("unknown helper in kernel mode", prog![call(250), exit()], &kernel, ErrorKind::Unsupported),
        ("kfunc without facts in kernel mode", prog![raw_kfunc(1, 0), exit()], &kernel, ErrorKind::Unsupported),
        ("write to r10", prog![mov64_imm(R10, 0), mov64_imm(R0, 0), exit()], &user, ErrorKind::InvalidInput),
        ("reserved ALU off", prog![BpfInsn::new(0x07, 0, 0, 3, 1).to_u64(), exit()], &user, ErrorKind::InvalidInput),
        ("ld_imm64 func", prog![ld_imm64_src(R1, 4, 2), mov64_imm(R0, 0), exit()], &user, ErrorKind::Unsupported),
        ("helper arg uninitialized", prog![call(5), call(1), exit()], &user, ErrorKind::InvalidInput),
    ];
    for (name, p, facts, kind) in cases {
        let e = lift_err(&p, facts);
        assert_eq!(e.kind, kind, "{name}: {e}");
    }
}

#[test]
fn unknown_helper_in_userspace_passes_all_registers() {
    let t = lift_text(&prog![mov64_imm(R1, 7), call(250), exit()]);
    assert!(has(&t, "call.unknown helper#250(7, %arg2, %arg3, %arg4, %arg5)"), "{t}");
    // trace_printk: optional arguments become undef.
    let t = lift_text(&prog![
        st(Size::DW, R10, -8, 0),
        mov64_reg(R1, R10),
        alu64_imm(Alu::Add, R1, -8),
        mov64_imm(R2, 8),
        call(6),
        exit()
    ]);
    assert!(has(&t, "call helper#6(%0, 8, %arg3, %arg4, %arg5)"), "{t}");
    let t = lift_text(&prog![
        st(Size::DW, R10, -8, 0),
        mov64_reg(R1, R10),
        alu64_imm(Alu::Add, R1, -8),
        mov64_imm(R2, 8),
        call(5),
        mov64_reg(R1, R10),
        alu64_imm(Alu::Add, R1, -8),
        mov64_imm(R2, 8),
        call(6),
        exit()
    ]);
    assert!(has(&t, "call helper#6(%2, 8, undef, undef, undef)"), "{t}");
}

#[test]
fn value_facts() {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 30);
    let ctx = Ctx::new(&heap, small_limits(), Level::Debug).unwrap();
    let p = prog![
        st(Size::W, R10, -20, 0),
        ld_map_fd(R1, 1),
        mov64_reg(R2, R10),
        alu64_imm(Alu::Add, R2, -20),
        call(1),
        jmp_imm(Jmp::Jeq, R0, 0, 3),
        ldx(Size::W, R3, R0, 0),
        alu32_imm(Alu::Add, R3, 1),
        stx(Size::W, R0, R3, 0),
        mov64_imm(R0, 0),
        exit()
    ];
    let f = lift(&insns(&p), &DefaultFacts::default(), &ctx).unwrap();
    let cfg = Cfg::compute(&f, &ctx).unwrap();
    let prov = Provenance::compute(&f, &cfg, &UpperZero::compute(&f, &cfg, &ctx).unwrap(), &ctx).unwrap();
    let ext = frame_extent(&f, &prov, &cfg, &ctx).unwrap();
    assert_eq!(ext.lowest, -20);
    assert!(!ext.unknown);
    let ret = |op: &Op| match op {
        Op::Call {
            callee: Callee::Helper(id),
            ..
        } => default_helper(*id).map_or(RetClass::Scalar, |s| s.ret),
        _ => RetClass::Scalar,
    };
    let classes = Classes::compute(&f, &cfg, &ctx, &ret).unwrap();
    let uz = UpperZero::compute(&f, &cfg, &ctx).unwrap();
    let mut saw_lookup = false;
    let mut saw_add32 = false;
    for b in f.blocks() {
        for i in f.iter_block(b) {
            match f.op(i).unwrap() {
                Op::Call { .. } => {
                    let c = classes.of(Value::Insn(i));
                    assert_eq!(c.class, Class::MapValue);
                    assert!(c.nullable);
                    saw_lookup = true;
                }
                Op::Bin { w: epass_core::ir::Width::W32, .. } => {
                    assert!(uz.of(Value::Insn(i)));
                    saw_add32 = true;
                }
                Op::Bin { .. } => assert!(!uz.of(Value::Insn(i))),
                Op::Load { .. } => assert!(uz.of(Value::Insn(i))),
                _ => {}
            }
        }
    }
    assert!(saw_lookup && saw_add32);
    // A frame pointer stored to memory makes the extent unknown.
    let esc = prog![stx(Size::DW, R10, R10, -8), mov64_imm(R0, 0), exit()];
    let f = lift(&insns(&esc), &DefaultFacts::default(), &ctx).unwrap();
    let cfg = Cfg::compute(&f, &ctx).unwrap();
    let prov = Provenance::compute(&f, &cfg, &UpperZero::compute(&f, &cfg, &ctx).unwrap(), &ctx).unwrap();
    assert!(frame_extent(&f, &prov, &cfg, &ctx).unwrap().unknown);
}

fn falco_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bpftests/falco")
}

fn read_dump(path: &std::path::Path) -> Vec<BpfInsn> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .map(BpfInsn::from_u64)
        .collect()
}

#[test]
fn falco_corpus_lifts_and_validates() {
    let dir = falco_dir();
    if !dir.exists() {
        eprintln!("skipping: no falco corpus");
        return;
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("prog") && n != "progs.txt" && n.ends_with(".txt"))
        })
        .collect();
    files.sort();
    assert_eq!(files.len(), 339);
    let mut failures = Vec::new();
    let mut unknown_extent = 0;
    for p in &files {
        let host = StdHost::new();
        let heap = Heap::new(&host, 1 << 31);
        let ctx = Ctx::new(&heap, small_limits(), Level::Error).unwrap();
        let prog = read_dump(p);
        match lift(&prog, &DefaultFacts::default(), &ctx) {
            Ok(f) => {
                let cfg = Cfg::compute(&f, &ctx).unwrap();
                let prov = Provenance::compute(&f, &cfg, &UpperZero::compute(&f, &cfg, &ctx).unwrap(), &ctx).unwrap();
                let ext = frame_extent(&f, &prov, &cfg, &ctx).unwrap();
                if ext.unknown {
                    unknown_extent += 1;
                }
            }
            Err(e) => failures.push(format!("{}: {e}", p.display())),
        };
    }
    eprintln!("falco: {} lifted, {} with unknown frame extent", files.len() - failures.len(), unknown_extent);
    // prog285 and prog298 reference callbacks (ld_imm64 of a function),
    // which v2 rejects instead of silently dropping the callback bodies.
    let expected = ["prog285.txt", "prog298.txt"];
    assert_eq!(failures.len(), expected.len(), "lift failures:\n{}", failures.join("\n"));
    for (f, name) in failures.iter().zip(expected) {
        assert!(f.contains(name) && f.contains("callbacks"), "{f}");
    }
}

#[test]
fn deep_cfg_lifts_on_a_16k_stack() {
    // 120,000 blocks of `ja +0`, then a return.
    let mut p: Vec<u64> = vec![ja(0); 120_000];
    p.push(mov64_imm(R0, 0));
    p.push(exit());
    let prog = insns(&p);
    // The kernel builds optimized code: the gate is a 16 KB stack in release
    // builds. Unoptimized debug frames need more, but a constant amount
    // (the same 64 KB covers a 10-block and a 120,000-block program).
    let kb = if cfg!(debug_assertions) { 64 } else { 16 };
    let t = std::thread::Builder::new()
        .stack_size(kb * 1024)
        .spawn(move || {
            let host = StdHost::new();
            let heap = Heap::new(&host, 1 << 31);
            let ctx = Ctx::new(&heap, small_limits(), Level::Error).unwrap();
            let f = lift(&prog, &DefaultFacts::default(), &ctx).map_err(|e| e.to_string())?;
            Ok::<usize, String>(f.block_count())
        })
        .unwrap();
    let blocks = t.join().expect("lift overflowed a 16 KB stack").unwrap();
    assert!(blocks > 120_000);
}

