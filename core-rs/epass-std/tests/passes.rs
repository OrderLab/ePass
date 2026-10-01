//! M4 tests: pass registry ordering, the policy/popt precedence table,
//! failure dispositions, each builtin pass, and the default pipeline on the
//! Falco corpus.

use epass_core::bpf::BpfInsn;
use epass_core::facts::DefaultFacts;
use epass_core::ir::parse::parse;
use epass_core::ir::print::print;
use epass_core::ir::verify::verify;
use epass_core::ir::Function;
use epass_core::lift::lift;
use epass_core::pm::{registry_order, Disposition, Mode, Options, PassCx, Pipeline, Policy, REGISTRY};
use epass_core::{Ctx, ErrorKind, Heap, Level, Limits};
use epass_std::StdHost;

fn limits() -> Limits {
    Limits {
        log_bytes: 1 << 16,
        ..Limits::USERSPACE
    }
}

fn text_of(f: &Function<'_>) -> String {
    let mut s = String::new();
    print(&mut s as &mut dyn std::fmt::Write, f).unwrap();
    s
}

fn names(p: &Pipeline<'_>) -> Vec<&'static str> {
    p.names().collect()
}

#[test]
fn registry_order_is_valid_and_deterministic() {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 20);
    let order = registry_order(&heap).unwrap();
    let got: Vec<_> = order.iter().map(|&i| REGISTRY[i].name).collect();
    assert_eq!(got, ["dump_ir", "const_prop", "phi", "zext_elim", "dce", "lower_throw"]);
}

#[test]
fn policy_precedence_table() {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 20);
    let build = |policy: &str, popt: &'static str| {
        let policy: &'static str = Box::leak(policy.to_string().into_boxed_str());
        let p = Policy::parse(policy, &heap).unwrap();
        Pipeline::build(&p, popt, &heap).map(|pl| (names(&pl), pl.enforced))
    };
    // allowed (default): loader silent -> defaults; enable -> on; disable -> off
    let (n, enf) = build("", "").unwrap();
    assert_eq!(n, ["const_prop", "phi", "zext_elim", "dce", "lower_throw"]);
    assert!(!enf);
    assert!(build("", "dump_ir").unwrap().0.contains(&"dump_ir"));
    assert!(!build("", "!const_prop").unwrap().0.contains(&"const_prop"));
    // forced: silent -> on (enforced); touching it -> Denied
    let (n, enf) = build("+dump_ir", "").unwrap();
    assert!(n.contains(&"dump_ir") && enf);
    assert_eq!(build("+dump_ir", "dump_ir").unwrap_err().kind, ErrorKind::Denied);
    assert_eq!(build("+dump_ir", "!dump_ir").unwrap_err().kind, ErrorKind::Denied);
    // denied: silent -> off; enable -> Denied; disable -> off
    assert!(!build("-const_prop", "").unwrap().0.contains(&"const_prop"));
    assert_eq!(build("-const_prop", "const_prop").unwrap_err().kind, ErrorKind::Denied);
    assert!(!build("-const_prop", "!const_prop").unwrap().0.contains(&"const_prop"));
    // allowed with admin default args, loader args override (no-arg passes reject args)
    assert_eq!(build("", "dump_ir(x)").unwrap_err().kind, ErrorKind::InvalidInput);
    // loader popt forbidden by policy
    assert_eq!(build("user_popt=0", "!dce").unwrap_err().kind, ErrorKind::Denied);
    assert!(build("user_popt=0", "").is_ok());
    // mandatory passes are not loader-controllable and cannot be denied
    assert_eq!(build("", "!lower_throw").unwrap_err().kind, ErrorKind::Denied);
    assert!(Policy::parse("-lower_throw", &heap).is_err());
    // unknown names and malformed strings
    assert_eq!(build("", "frobnicate").unwrap_err().kind, ErrorKind::InvalidInput);
    assert!(Policy::parse("+frobnicate", &heap).is_err());
    assert!(Policy::parse("mode=sometimes", &heap).is_err());
    assert_eq!(build("", "dump_ir(").unwrap_err().kind, ErrorKind::InvalidInput);
    assert_eq!(build("", "dce,dce").unwrap_err().kind, ErrorKind::InvalidInput);
}

#[test]
fn modes_and_failure_dispositions() {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 20);
    let off = Policy::parse("mode=off,+dump_ir", &heap).unwrap();
    assert_eq!(off.mode, Mode::Off);
    assert!(!off.should_run(true));
    let optin = Policy::parse("mode=optin", &heap).unwrap();
    assert!(optin.should_run(true) && !optin.should_run(false));
    let forced = Policy::parse("+dump_ir", &heap).unwrap();
    assert!(forced.should_run(false), "a forced pass makes ePass run");
    let always = Policy::parse("mode=always", &heap).unwrap();
    assert!(always.should_run(false));

    let plain = Pipeline::build(&optin, "", &heap).unwrap();
    assert_eq!(plain.on_failure(false), Disposition::LoadOriginal);
    assert_eq!(plain.on_failure(true), Disposition::Reject);
    let enf = Pipeline::build(&forced, "", &heap).unwrap();
    assert_eq!(enf.on_failure(false), Disposition::Reject);
}

/// Parse, run one pass by name (plus validation), print.
fn run_pass(src: &str, pass: &str, opts: Options) -> String {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 28);
    let ctx = Ctx::new(&heap, limits(), Level::Debug).unwrap();
    let mut f = parse(src, &heap, &ctx).unwrap();
    verify(&f, &ctx, false).unwrap();
    let info = epass_core::pm::find(pass).unwrap();
    let facts = DefaultFacts::default();
    let cx = PassCx {
        ctx: &ctx,
        facts: &facts,
        opts: &opts,
    };
    (info.run)(&mut f, &cx, None).unwrap();
    verify(&f, &ctx, false).unwrap_or_else(|e| panic!("{pass} produced invalid IR: {e}\n{}", text_of(&f)));
    text_of(&f)
}

fn opts() -> Options {
    Options::default()
}

#[test]
fn const_prop_folds_exactly_and_folds_branches() {
    let t = run_pass(
        "func main {\nbb0:\n  %0 = add.32 0x7fffffff, 0x7fffffff\n  %1 = add.64 0x7fffffff, 0x7fffffff\n  %2 = shl.64 1, 40\n  %3 = load.u64 [%arg1+0]\n  %4 = add.64 %3, %2\n  %5 = add.64 %4, %0\n  %6 = add.64 %5, %1\n  ret %6\n}",
        "const_prop",
        opts(),
    );
    assert!(t.contains("add.64 %3, 0x10000000000"), "{t}");
    // 0x7fffffff + 0x7fffffff is 0xfffffffe at both widths.
    assert_eq!(t.matches(", 0xfffffffe").count(), 2, "{t}");
    // branch folding removes the dead edge and its phi input
    let t = run_pass(
        "func main {\nbb0:\n  condbr.64.sgt 1, 0xffffffffffffffff, bb1, bb2\nbb1:\n  br bb3\nbb2:\n  br bb3\nbb3:\n  %0 = phi [10, bb1], [20, bb2]\n  ret %0\n}",
        "const_prop",
        opts(),
    );
    assert!(t.contains("ret 10"), "{t}");
    assert!(!t.contains("condbr"), "{t}");
    // 32-bit compare uses the low halves
    let t = run_pass(
        "func main {\nbb0:\n  condbr.32.eq 0x500000001, 1, bb1, bb2\nbb1:\n  ret 1\nbb2:\n  ret 2\n}",
        "const_prop",
        opts(),
    );
    assert!(t.contains("ret 1") && !t.contains("ret 2"), "{t}");
}

#[test]
fn phi_removal_respects_dominance() {
    // [v, undef] where v dominates the phi block: replaced.
    let t = run_pass(
        "func main {\nbb0:\n  %0 = load.u64 [%arg1+0]\n  condbr.64.eq %0, 0, bb1, bb2\nbb1:\n  br bb2\nbb2:\n  %1 = phi [%0, bb0], [undef, bb1]\n  ret %1\n}",
        "phi",
        opts(),
    );
    assert!(t.contains("ret %0") && !t.contains("phi"), "{t}");
    // [v, undef] where v does not dominate: kept.
    let t = run_pass(
        "func main {\nbb0:\n  condbr.64.eq %arg1, 0, bb1, bb2\nbb1:\n  %0 = load.u64 [%arg1+0]\n  br bb3\nbb2:\n  br bb3\nbb3:\n  %1 = phi [%0, bb1], [undef, bb2]\n  ret %1\n}",
        "phi",
        opts(),
    );
    assert!(t.contains("phi"), "{t}");
    // loop phi that only refers to itself and one value
    let t = run_pass(
        "func main {\nbb0:\n  %0 = load.u64 [%arg1+0]\n  br bb1\nbb1:\n  %1 = phi [%0, bb0], [%1, bb1]\n  condbr.64.eq %1, 0, bb1, bb2\nbb2:\n  ret %1\n}",
        "phi",
        opts(),
    );
    assert!(!t.contains("phi") && t.contains("ret %0"), "{t}");
}

#[test]
fn zext_elim_keeps_needed_extensions() {
    let t = run_pass(
        "func main {\nbb0:\n  %0 = load.u64 [%arg1+0]\n  %1 = add.32 %0, 1\n  %2 = zext.32.64 %1\n  %3 = load.s32 [%arg1+8]\n  %4 = zext.32.64 %3\n  %5 = add.64 %0, 1\n  %6 = zext.32.64 %5\n  %7 = add.64 %2, %4\n  %8 = add.64 %7, %6\n  ret %8\n}",
        "zext_elim",
        opts(),
    );
    assert_eq!(t.matches("zext.32.64").count(), 2, "{t}");
    assert!(t.contains("%3 = zext.32.64 %2"), "{t}");
    assert!(t.contains("%5 = zext.32.64 %4"), "{t}");
}

#[test]
fn dce_removes_dead_cycles_but_keeps_effects() {
    let t = run_pass(
        "func main {\nbb0:\n  %0 = add.64 %arg1, 1\n  store.u64 [%fp-8], 1\n  %1 = call helper#5()\n  br bb1\nbb1:\n  %2 = phi [0, bb0], [%3, bb1]\n  %3 = add.64 %2, 1\n  condbr.64.eq %arg2, 0, bb1, bb2\nbb2:\n  ret 0\n}",
        "dce",
        opts(),
    );
    assert!(!t.contains("phi") && !t.contains("add.64"), "{t}");
    assert!(t.contains("store.u64") && t.contains("call helper#5"), "{t}");
}

#[test]
fn lower_throw_releases_outstanding_reservations() {
    let src = "func main {\nbb0:\n  %0 = ldsym.map_fd 3\n  %1 = call helper#131(%0, 16, 0)\n  condbr.64.eq %1, 0, bb1, bb2\nbb1:\n  ret 0\nbb2:\n  condbr.64.eq %arg2, 0, bb3, bb4\nbb3:\n  throw\nbb4:\n  %2 = call helper#132(%1, 0)\n  ret 0\n}";
    let t = run_pass(src, "lower_throw", opts());
    assert!(t.contains("call helper#133(%1, 0)"), "{t}");
    assert!(!t.contains("throw"), "{t}");
    let o = Options {
        throw_ret: 1,
        ..opts()
    };
    let t = run_pass("func main {\nbb0:\n  throw\n}", "lower_throw", o);
    assert!(t.contains("ret 1"), "{t}");
}

#[test]
fn default_pipeline_on_falco() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bpftests/falco");
    if !dir.exists() {
        return;
    }
    let mut ok = 0;
    let mut before = 0usize;
    let mut after = 0usize;
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if !name.starts_with("prog") || name == "progs.txt" {
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap();
        let prog: Vec<BpfInsn> = text
            .lines()
            .take_while(|l| !l.trim().is_empty())
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .map(BpfInsn::from_u64)
            .collect();
        let host = StdHost::new();
        let heap = Heap::new(&host, 1 << 31);
        let ctx = Ctx::new(&heap, limits(), Level::Error).unwrap();
        let facts = DefaultFacts::default();
        let Ok(mut f) = lift(&prog, &facts, &ctx) else { continue };
        before += f.insn_count();
        let policy = Policy::permissive(&heap);
        let pl = Pipeline::build(&policy, "", &heap).unwrap();
        let o = Options::default();
        let cx = PassCx {
            ctx: &ctx,
            facts: &facts,
            opts: &o,
        };
        pl.run(&mut f, &cx).unwrap_or_else(|e| panic!("{name}: {e}"));
        after += f.insn_count();
        ok += 1;
    }
    eprintln!("falco pipeline: {ok} programs, IR insns {before} -> {after}");
    assert_eq!(ok, 337);
    assert!(after <= before);
}
