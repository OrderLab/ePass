//! M6 structural gates on the whole pipeline (`driver::run`: lift, passes,
//! codegen): small stacks, allocation failure at every point, interruption
//! at every yield, heap and time limits, compile time and memory.

use epass_core::bpf::BpfInsn;
use epass_core::driver::{self, Gopt, Input, Outcome, Request};
use epass_core::facts::DefaultFacts;
use epass_core::pm::Policy;
use epass_core::{Ctx, ErrorKind, Heap, Level, Limits};
use epass_interp::asm::*;
use epass_std::StdHost;

/// Deterministic LCG.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// `n` straight-line instructions over every register, the stack and the
/// context, with all ten registers live throughout.
fn straight(n: usize) -> Vec<u64> {
    let mut r = Rng(42);
    let mut p = vec![mov64_reg(R6, R1)];
    for reg in [0u8, 1, 2, 3, 4, 5, 7, 8, 9] {
        p.push(mov64_imm(reg, reg as i32 + 1));
    }
    let regs = [0u8, 1, 2, 3, 4, 5, 7, 8, 9];
    let ops = [Alu::Add, Alu::Sub, Alu::Mul, Alu::Or, Alu::And, Alu::Xor, Alu::Lsh, Alu::Rsh];
    while p.len() < n - 1 {
        let d = regs[r.below(9) as usize];
        let s = regs[r.below(9) as usize];
        let off = -8 * (1 + r.below(32) as i16);
        p.push(match r.below(8) {
            0 => stx(Size::DW, R10, s, off),
            1 => ldx(Size::DW, d, R10, off),
            2 => ldx(Size::W, d, R6, 4 * r.below(16) as i16),
            3 => alu32_reg(ops[r.below(6) as usize], d, s),
            4 => alu64_imm(ops[r.below(8) as usize], d, r.below(31) as i32),
            _ => alu64_reg(ops[r.below(6) as usize], d, s),
        });
    }
    // Initialize every slot first so loads never read uninitialized stack.
    let mut init: Vec<u64> = (1..=32).map(|k| st(Size::DW, R10, -8 * k, 0)).collect();
    init.extend(p);
    init.push(exit());
    init
}

/// 120,000 empty blocks.
fn ja_chain(n: usize) -> Vec<u64> {
    let mut p = vec![ja(0); n];
    p.push(mov64_imm(R0, 0));
    p.push(exit());
    p
}

/// `n` diamonds in sequence, each merging two values (one phi each).
fn diamonds(n: usize) -> Vec<u64> {
    let mut p = vec![ldx(Size::DW, R6, R1, 0), mov64_imm(R0, 0)];
    for k in 0..n {
        p.extend([
            jmp_imm(Jmp::Jgt, R6, k as i32, 2),
            alu64_imm(Alu::Add, R0, 1),
            ja(1),
            alu64_imm(Alu::Xor, R0, 3),
        ]);
    }
    p.push(exit());
    p
}

fn insns(p: &[u64]) -> Vec<BpfInsn> {
    p.iter().map(|&r| BpfInsn::from_u64(r)).collect()
}

fn limits() -> Limits {
    Limits {
        log_bytes: 1 << 12,
        ..Limits::USERSPACE
    }
}

/// Run the driver; `Ok(len)` when compiled, else the error kind.
fn compile(host: &StdHost, prog: &[BpfInsn], limits: Limits) -> (Result<usize, ErrorKind>, usize) {
    let heap = Heap::new(host, limits.max_bytes);
    let ctx = match Ctx::new(&heap, limits, Level::Error) {
        Ok(c) => c,
        Err(e) => return (Err(e.kind), heap.peak()),
    };
    let policy = Policy::permissive(&heap);
    let req = Request {
        input: Input::Bytecode(prog),
        gopt: Gopt::default(),
        popt: "",
        requested: true,
    };
    let r = match driver::run(&ctx, &DefaultFacts::default(), &policy, &req) {
        Ok(Outcome::Compiled(o)) => Ok(o.insns.len()),
        Ok(Outcome::LoadOriginal(Some(e))) | Err(e) => Err(e.kind),
        Ok(Outcome::LoadOriginal(None)) => Err(ErrorKind::Internal),
    };
    (r, heap.peak())
}

#[test]
fn pipeline_runs_on_a_16k_stack() {
    // The kernel builds optimized code: 16 KB is the release gate. Debug
    // frames are larger but constant (64 KB covers every size).
    let kb = if cfg!(debug_assertions) { 64 } else { 16 };
    let scale = if cfg!(debug_assertions) { 10 } else { 1 };
    let cases = [
        ("straight 200k", straight(200_000 / scale)),
        ("ja chain 120k", ja_chain(120_000 / scale)),
        ("diamonds 30k", diamonds(30_000 / scale)),
    ];
    for (name, p) in cases {
        let prog = insns(&p);
        let t = std::thread::Builder::new()
            .stack_size(kb * 1024)
            .spawn(move || {
                let host = StdHost::new();
                compile(&host, &prog, limits()).0
            })
            .unwrap();
        let r = t.join().unwrap_or_else(|_| panic!("{name}: overflowed a {kb} KB stack"));
        assert!(r.is_ok(), "{name}: {r:?}");
    }
}

#[test]
fn compile_time_and_memory() {
    let n = if cfg!(debug_assertions) { 20_000 } else { 200_000 };
    let prog = insns(&straight(n));
    let host = StdHost::new();
    let t0 = std::time::Instant::now();
    let (r, peak) = compile(&host, &prog, limits());
    let dt = t0.elapsed();
    let out = r.unwrap();
    eprintln!("straight {n}: {n} -> {out} instructions in {dt:.2?}, peak heap {} KB ({} B/insn)", peak / 1024, peak / n);
    if !cfg!(debug_assertions) {
        assert!(dt.as_secs_f64() < 5.0, "200k instructions took {dt:?}");
    }
    // Memory is linear in the input: a generous per-instruction bound.
    assert!(peak / n < 4096, "{} bytes per instruction", peak / n);
    assert_eq!(host.live_allocations(), 0);

    // Real programs fit the kernel's default heap limit with room to spare.
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bpftests/falco");
    let Ok(rd) = std::fs::read_dir(&dir) else { return };
    let (mut max_peak, mut max_name, mut max_len) = (0usize, String::new(), 0usize);
    for e in rd {
        let path = e.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("prog") || name == "progs.txt" {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let p: Vec<BpfInsn> = text
            .lines()
            .take_while(|l| !l.trim().is_empty())
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .map(BpfInsn::from_u64)
            .collect();
        let host = StdHost::new();
        let (_, peak) = compile(&host, &p, Limits { max_bytes: Limits::KERNEL.max_bytes, ..limits() });
        if peak > max_peak {
            (max_peak, max_name, max_len) = (peak, name, p.len());
        }
    }
    eprintln!("falco: max peak heap {} KB ({max_name}, {max_len} instructions)", max_peak / 1024);
    assert!(max_peak < Limits::KERNEL.max_bytes / 4);
}

/// A program with loops, calls, stack traffic and spills.
fn mixed() -> Vec<u64> {
    let mut p = vec![ldx(Size::DW, R6, R1, 0), ldx(Size::DW, R7, R1, 8), mov64_imm(R8, 0), mov64_imm(R9, 5)];
    p.extend([
        st(Size::DW, R10, -8, 1),
        // loop: r8 += r6 * r9; call helper 5 (ktime); r9 -= 1
        mov64_reg(R2, R6),
        alu64_reg(Alu::Mul, R2, R9),
        alu64_reg(Alu::Add, R8, R2),
        call(5),
        alu64_reg(Alu::Xor, R8, R0),
        mov32_reg(R3, R8),
        mov32_reg(R3, R3),
        stx(Size::DW, R10, R3, -16),
        alu64_imm(Alu::Sub, R9, 1),
        jmp_imm(Jmp::Jne, R9, 0, -10),
        ldx(Size::DW, R0, R10, -16),
        alu64_reg(Alu::Add, R0, R7),
        jmp_imm(Jmp::Jsgt, R0, 100, 1),
        alu64_imm(Alu::Mul, R0, 3),
        exit(),
    ]);
    p
}

#[test]
fn every_allocation_failure_is_clean() {
    let prog = insns(&mixed());
    let host = StdHost::new();
    assert!(compile(&host, &prog, limits()).0.is_ok());
    let total = host.allocations();
    assert!(total > 20, "{total} allocations");
    for k in 1..=total {
        let host = StdHost::new();
        host.fail_allocation_at(k);
        let (r, _) = compile(&host, &prog, limits());
        assert_eq!(r, Err(ErrorKind::OutOfMemory), "allocation {k} of {total}");
        assert_eq!(host.live_allocations(), 0, "leak after failing allocation {k}");
    }
}

#[test]
fn every_interrupt_is_clean() {
    let prog = insns(&mixed());
    let lim = Limits { yield_every: 4, ..limits() };
    let host = StdHost::new();
    assert!(compile(&host, &prog, lim).0.is_ok());
    // Count yields by interrupting far away.
    let probe = StdHost::new();
    probe.interrupt_at_yield(u64::MAX / 2);
    let _ = compile(&probe, &prog, lim);
    let mut k = 1;
    loop {
        let host = StdHost::new();
        host.interrupt_at_yield(k);
        let (r, _) = compile(&host, &prog, lim);
        assert_eq!(host.live_allocations(), 0, "leak after interrupt {k}");
        if r.is_ok() {
            break;
        }
        assert_eq!(r, Err(ErrorKind::Interrupted), "interrupt {k}");
        k += 1;
    }
    assert!(k > 10, "only {k} yield points");
}

#[test]
fn heap_and_time_limits() {
    let prog = insns(&straight(20_000));
    let host = StdHost::new();
    // The heap's byte cap is a configured limit (E2BIG), not host OOM.
    let (r, peak) = compile(&host, &prog, Limits { max_bytes: 256 << 10, ..limits() });
    assert_eq!(r, Err(ErrorKind::Limit));
    assert!(peak <= 256 << 10);
    assert_eq!(host.live_allocations(), 0);
    let host = StdHost::new();
    let (r, _) = compile(&host, &prog, Limits { time_ns: 1, yield_every: 1, ..limits() });
    assert_eq!(r, Err(ErrorKind::Limit));
    // The input instruction limit.
    let (r, _) = compile(&host, &prog, Limits { max_insns: 1000, ..limits() });
    assert_eq!(r, Err(ErrorKind::Limit));
}

/// The large generated programs also keep their meaning (interpreter
/// oracle), including under register pressure.
#[test]
fn large_programs_keep_semantics() {
    use epass_interp::{compare, run};
    let n = if cfg!(debug_assertions) { 3_000 } else { 30_000 };
    for (name, p) in [("straight", straight(n)), ("diamonds", diamonds(n / 4))] {
        for colors in [10u8, 5] {
            let host = StdHost::new();
            let heap = Heap::new(&host, limits().max_bytes);
            let ctx = Ctx::new(&heap, limits(), Level::Error).unwrap();
            let policy = Policy::permissive(&heap);
            let prog = insns(&p);
            let req = Request {
                input: Input::Bytecode(&prog),
                gopt: Gopt { ra_colors: colors, ..Gopt::default() },
                popt: "",
                requested: true,
            };
            let out = match driver::run(&ctx, &DefaultFacts::default(), &policy, &req).unwrap() {
                Outcome::Compiled(o) => o.insns.iter().map(|i| i.to_u64()).collect::<Vec<u64>>(),
                o => panic!("{name}: {o:?}"),
            };
            for seed in [1u64, 7, 1 << 40] {
                let ctx_bytes: Vec<u8> = (0..64).map(|k| (seed.wrapping_mul(k + 3) >> 3) as u8).collect();
                let input = epass_interp::Input { ctx: ctx_bytes, ..Default::default() };
                compare(&run(&p, &input), &run(&out, &input))
                    .unwrap_or_else(|m| panic!("{name} colors={colors} seed={seed}: {m:?}"));
            }
        }
    }
}
