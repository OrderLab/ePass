//! M5 semantic gate: every program is compiled by ePass and run on the
//! reference interpreter before and after; r0, ctx bytes, helper events and
//! every stack byte the original wrote must agree.
//!
//! 1. the regression set: one program per confirmed v1 defect;
//! 2. a differential generator: random structured programs (diamonds,
//!    bounded loops, stack traffic through r10 and derived pointers,
//!    helper calls that clobber r1-r5, atomics, ISA v4 forms), compiled with
//!    10, 6 and 4 allocatable registers to force spilling.

use epass_core::bpf::BpfInsn;
use epass_core::cg::{self, CgOptions};
use epass_core::facts::DefaultFacts;
use epass_core::ir::parse::parse;
use epass_core::lift::lift;
use epass_core::pm::{Options, PassCx, Pipeline, Policy};
use epass_core::{Ctx, Heap, Level, Limits};
use epass_interp::asm::*;
use epass_interp::{compare, prog, run, Input};
use epass_std::StdHost;

fn limits() -> Limits {
    Limits {
        log_bytes: 1 << 12,
        ..Limits::USERSPACE
    }
}

/// Lift, run the default pipeline, compile.
fn compile_with(p: &[u64], colors: u8) -> Result<Vec<u64>, String> {
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 30);
    let ctx = Ctx::new(&heap, limits(), Level::Error).unwrap();
    let insns: Vec<BpfInsn> = p.iter().map(|&r| BpfInsn::from_u64(r)).collect();
    let facts = DefaultFacts::default();
    let mut f = lift(&insns, &facts, &ctx).map_err(|e| format!("lift: {e}"))?;
    let policy = Policy::permissive(&heap);
    let pl = Pipeline::build(&policy, "", &heap).map_err(|e| e.to_string())?;
    let o = Options::default();
    pl.run(
        &mut f,
        &PassCx {
            ctx: &ctx,
            facts: &facts,
            opts: &o,
        },
    )
    .map_err(|e| format!("passes: {e}"))?;
    let co = CgOptions {
        ra_colors: colors,
        check: true,
        ..CgOptions::default()
    };
    let out = cg::compile(&mut f, &ctx, &co).map_err(|e| format!("codegen: {e}"))?;
    Ok(out.insns.iter().map(|i| i.to_u64()).collect())
}

fn ctx_bytes(words: &[u64]) -> Vec<u8> {
    let mut v: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    v.resize(256, 0);
    v
}

fn disasm(p: &[u64]) -> String {
    let mut s = String::new();
    for (i, &r) in p.iter().enumerate() {
        let x = BpfInsn::from_u64(r);
        s.push_str(&format!(
            "  {i:4}: code={:#04x} dst=r{} src=r{} off={} imm={}\n",
            x.code, x.dst, x.src, x.off, x.imm
        ));
    }
    s
}

/// Compile `p` with each color budget and compare on each input.
fn check_equiv(name: &str, p: &[u64], inputs: &[Input], colors: &[u8]) -> Result<(), String> {
    for &c in colors {
        let out = compile_with(p, c).map_err(|e| format!("{name} (colors={c}): {e}"))?;
        for input in inputs {
            let a = run(p, input);
            let b = run(&out, input);
            if let Err(m) = compare(&a, &b) {
                return Err(format!(
                    "{name} (colors={c}): {m}\noriginal:\n{}rewritten:\n{}",
                    disasm(p),
                    disasm(&out)
                ));
            }
        }
    }
    Ok(())
}

fn input(words: &[u64]) -> Input {
    Input {
        ctx: ctx_bytes(words),
        ..Input::default()
    }
}

// ------------------------------------------------------------ regressions

#[test]
fn regression_set() {
    let i2 = |a: u64, b: u64| input(&[a, b]);
    let all = [10u8, 6, 4];
    let cases: Vec<(&str, Vec<u64>, Vec<Input>)> = vec![
        ("D1 mov32 reg truncates", prog![ldx(Size::DW, R2, R1, 0), mov32_reg(R0, R2), exit()], vec![i2(0x1_0000_0005, 0), i2(7, 0)]),
        ("D2 mov32 negative imm", prog![ldx(Size::DW, R0, R1, 0), mov32_imm(R2, -1), alu64_reg(Alu::Add, R0, R2), exit()], vec![i2(1, 0), i2(0, 0)]),
        ("D3 jset", prog![ldx(Size::DW, R2, R1, 0), jmp_imm(Jmp::Jset, R2, 1, 2), mov64_imm(R0, 0), exit(), mov64_imm(R0, 1), exit()], vec![i2(1, 0), i2(2, 0)]),
        ("D4 memsx", prog![ldxs(Size::B, R0, R1, 0), exit()], vec![i2(0xff, 0), i2(0x7f, 0)]),
        ("D5 movsx", prog![ldx(Size::DW, R2, R1, 0), movsx64(R0, R2, 8), exit()], vec![i2(0xff, 0), i2(0x7f, 0)]),
        ("D6a wide constant", prog![ldx(Size::DW, R0, R1, 0), mov64_imm(R2, 1), alu64_imm(Alu::Lsh, R2, 40), alu64_reg(Alu::Add, R0, R2), exit()], vec![i2(5, 0)]),
        ("D6b 0x7fffffff*2 at 64 bits", prog![ldx(Size::DW, R2, R1, 0), mov64_imm(R1, 0x7fff_ffff), alu64_imm(Alu::Add, R1, 0x7fff_ffff), alu64_reg(Alu::Add, R2, R1), mov64_reg(R0, R2), exit()], vec![i2(0, 0)]),
        ("D7 phi swap", prog![
            mov64_imm(R1, 1), mov64_imm(R2, 2), mov64_imm(R4, 0),
            mov64_reg(R3, R1), mov64_reg(R1, R2), mov64_reg(R2, R3), alu64_imm(Alu::Add, R4, 1),
            jmp_imm(Jmp::Jlt, R4, 3, -5),
            mov64_reg(R0, R1), alu64_imm(Alu::Lsh, R0, 4), alu64_reg(Alu::Add, R0, R2), exit()
        ], vec![i2(0, 0)]),
        ("D8 lost copy", prog![
            ldx(Size::DW, R6, R1, 0), ldx(Size::DW, R7, R1, 8),
            jmp_imm(Jmp::Jne, R7, 0, 4),
            mov64_imm(R0, 10), mov64_imm(R2, 20), jmp_imm(Jmp::Jne, R6, 0, 6), ja(3),
            mov64_imm(R0, 30), mov64_imm(R2, 40), jmp_imm(Jmp::Jne, R6, 0, 2),
            alu64_imm(Alu::Add, R0, 1000), exit(),
            mov64_reg(R0, R2), exit()
        ], vec![i2(0, 0), i2(1, 0), i2(0, 1), i2(1, 1)]),
        ("D9 derived stack pointer under spills", prog![
            ldx(Size::DW, R6, R1, 0), ldx(Size::DW, R7, R1, 8), ldx(Size::DW, R8, R1, 16), ldx(Size::DW, R9, R1, 24),
            st(Size::DW, R10, -16, 42),
            call(7), stx(Size::DW, R10, R0, -24), call(5), mov64_reg(R3, R0),
            ldx(Size::DW, R2, R10, -24),
            mov64_reg(R4, R10), alu64_imm(Alu::Add, R4, -16),
            ldx(Size::DW, R5, R4, 0),
            alu64_reg(Alu::Add, R5, R6), alu64_reg(Alu::Add, R5, R7), alu64_reg(Alu::Add, R5, R8), alu64_reg(Alu::Add, R5, R9),
            alu64_reg(Alu::Xor, R5, R2), alu64_reg(Alu::Xor, R5, R3),
            stx(Size::DW, R4, R5, 0),
            ldx(Size::DW, R0, R10, -16), exit()
        ], vec![i2(1, 2), i2(3, 4)]),
        ("D10 entry block loop header", prog![alu64_imm(Alu::Add, R1, 1), jmp_imm(Jmp::Jlt, R1, 0x1000_0005, -2), mov64_reg(R0, R1), exit()], vec![i2(0, 0)]),
        ("D12a sdiv/smod", prog![ldx(Size::DW, R2, R1, 0), ldx(Size::DW, R3, R1, 8), mov64_reg(R0, R2), sdiv64_reg(R0, R3), smod64_reg(R2, R3), alu64_reg(Alu::Xor, R0, R2), exit()], vec![i2((-7i64) as u64, 2), i2(1 << 63, u64::MAX), i2(9, 0)]),
        ("D12b atomic fetch-add", prog![ldx(Size::DW, R2, R1, 0), st(Size::DW, R10, -8, 10), atomic(Size::DW, R10, R2, -8, 0x01), ldx(Size::DW, R0, R10, -8), alu64_reg(Alu::Mul, R0, R2), exit()], vec![i2(5, 0), i2(7, 0)]),
        // The frame pointer is offset by a loop counter: spill slots must
        // go below the lowest address the counted loop can reach.
        ("counted loop indexes the frame under spills", prog![
            ldx(Size::DW, R6, R1, 0), ldx(Size::DW, R7, R1, 8), ldx(Size::DW, R8, R1, 16),
            st(Size::DW, R10, -48, 1), st(Size::DW, R10, -40, 2), st(Size::DW, R10, -32, 3),
            st(Size::DW, R10, -24, 4), st(Size::DW, R10, -16, 5), st(Size::DW, R10, -8, 6),
            mov64_imm(R0, 0), mov64_imm(R9, 40),
            mov64_reg(R1, R10), alu64_imm(Alu::Add, R1, -48), alu64_reg(Alu::Add, R1, R9),
            ldx(Size::DW, R2, R1, 0),
            alu64_reg(Alu::Add, R0, R2), alu64_reg(Alu::Xor, R0, R6), alu64_reg(Alu::Add, R0, R7), alu64_reg(Alu::Add, R0, R8),
            stx(Size::DW, R1, R0, 0),
            alu64_imm(Alu::Add, R9, -8),
            jmp_imm(Jmp::Jeq, R9, -8, 1), ja(-12),
            ldx(Size::DW, R3, R10, -48), alu64_reg(Alu::Add, R0, R3),
            ldx(Size::DW, R3, R10, -8), alu64_reg(Alu::Add, R0, R3), exit()
        ], vec![input(&[1, 2, 3]), input(&[0xdead_beef, 1 << 40, 7])]),
        ("D13 unknown helper keeps its arguments", prog![mov64_imm(R1, 7), mov64_imm(R2, 9), call(250), exit()], vec![i2(0, 0)]),
    ];
    let mut failures = Vec::new();
    for (name, p, inputs) in &cases {
        if let Err(e) = check_equiv(name, p, inputs, &all) {
            failures.push(e);
        }
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n\n"));
}

#[test]
fn regression_throw_lowers_to_ret() {
    // D14: `throw` from IR becomes `ret throw_ret` (default 0).
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 28);
    let ctx = Ctx::new(&heap, limits(), Level::Error).unwrap();
    let mut f = parse(
        "func main {\nbb0:\n  %0 = load.u64 [%arg1+0]\n  condbr.64.eq %0, 0, bb1, bb2\nbb1:\n  throw\nbb2:\n  ret 5\n}",
        &heap,
        &ctx,
    )
    .unwrap();
    let facts = DefaultFacts::default();
    let policy = Policy::permissive(&heap);
    let pl = Pipeline::build(&policy, "", &heap).unwrap();
    pl.run(&mut f, &PassCx { ctx: &ctx, facts: &facts, opts: &Options::default() }).unwrap();
    let out = cg::compile(&mut f, &ctx, &CgOptions::default()).unwrap();
    let p: Vec<u64> = out.insns.iter().map(|i| i.to_u64()).collect();
    assert_eq!(run(&p, &input(&[0])).r0(), Some(0));
    assert_eq!(run(&p, &input(&[1])).r0(), Some(5));
}

// ------------------------------------------------------- differential fuzz

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
    fn imm(&mut self) -> i32 {
        match self.below(6) {
            0 => self.pick(&[0, 1, -1, 2, 31, 32, 63]),
            1 => self.pick(&[i32::MIN, i32::MAX, 0x7fff_ffff, -0x8000_0000, 0xffff]),
            _ => (self.next() as i32) >> self.below(30),
        }
    }
}

const POOL: [u8; 8] = [0, 2, 3, 4, 5, 7, 8, 9];

struct Gen {
    rng: Rng,
    in_loop: bool,
    /// Stack slots (r10 - 8k, k = 1..=8) fully written so far.
    written: u16,
}

impl Gen {
    fn defined_regs(defined: u16) -> Vec<u8> {
        POOL.iter().copied().filter(|&r| defined & (1 << r) != 0).collect()
    }

    fn body(&mut self, out: &mut Vec<u64>, defined: &mut u16, depth: u32, reserved: u16) {
        let n = 2 + self.rng.below(6);
        for _ in 0..n {
            let regs = Self::defined_regs(*defined);
            let dsts: Vec<u8> = POOL.iter().copied().filter(|&r| reserved & (1 << r) == 0).collect();
            let dst = self.rng.pick(&dsts);
            let src = self.rng.pick(&regs);
            let a = self.rng.pick(&regs);
            let choice = self.rng.below(22);
            match choice {
                0..=5 => {
                    let ops = [Alu::Add, Alu::Sub, Alu::Mul, Alu::Div, Alu::Or, Alu::And, Alu::Lsh, Alu::Rsh, Alu::Mod, Alu::Xor, Alu::Arsh];
                    let op = self.rng.pick(&ops);
                    if *defined & (1 << dst) == 0 {
                        out.push(mov64_reg(dst, a));
                        *defined |= 1 << dst;
                    }
                    let use_imm = self.rng.below(2) == 0;
                    let wide = self.rng.below(2) == 0;
                    out.push(match (wide, use_imm) {
                        (true, true) => alu64_imm(op, dst, self.rng.imm()),
                        (true, false) => alu64_reg(op, dst, src),
                        (false, true) => alu32_imm(op, dst, self.rng.imm()),
                        (false, false) => alu32_reg(op, dst, src),
                    });
                }
                6 => {
                    out.push(match self.rng.below(5) {
                        0 => mov32_reg(dst, src),
                        1 => mov32_imm(dst, self.rng.imm()),
                        2 => movsx64(dst, src, self.rng.pick(&[8, 16, 32])),
                        3 => movsx32(dst, src, self.rng.pick(&[8, 16])),
                        _ => mov64_imm(dst, self.rng.imm()),
                    });
                    *defined |= 1 << dst;
                }
                7 => {
                    let v = self.rng.next();
                    out.extend(ld_imm64(dst, v));
                    *defined |= 1 << dst;
                }
                8 => {
                    let sz = self.rng.pick(&[Size::B, Size::H, Size::W, Size::DW]);
                    let off = (self.rng.below(31) * 8) as i16;
                    if self.rng.below(2) == 0 && sz != Size::DW {
                        out.push(ldxs(sz, dst, R6, off));
                    } else {
                        out.push(ldx(sz, dst, R6, off));
                    }
                    *defined |= 1 << dst;
                }
                9 | 10 => {
                    let k = 1 + self.rng.below(8) as i16;
                    out.push(stx(Size::DW, R10, src, -8 * k));
                    self.written |= 1 << k;
                }
                11 => {
                    let ks: Vec<i16> = (1..=8).filter(|&k| self.written & (1 << k) != 0).collect();
                    if let Some(&k) = ks.first() {
                        let k = ks[self.rng.below(ks.len() as u64) as usize].max(k);
                        let sz = self.rng.pick(&[Size::B, Size::H, Size::W, Size::DW]);
                        out.push(ldx(sz, dst, R10, -8 * k));
                        *defined |= 1 << dst;
                    }
                }
                12 => {
                    // Access through a derived frame pointer.
                    let ks: Vec<i16> = (1..=8).filter(|&k| self.written & (1 << k) != 0).collect();
                    if !ks.is_empty() && dst != src {
                        let k = ks[self.rng.below(ks.len() as u64) as usize];
                        out.push(mov64_reg(dst, R10));
                        out.push(alu64_imm(Alu::Add, dst, -8 * k as i32));
                        if self.rng.below(2) == 0 {
                            out.push(stx(Size::DW, dst, src, 0));
                            // Do not let the frame pointer escape.
                            out.push(mov64_imm(dst, self.rng.imm()));
                        } else {
                            out.push(ldx(Size::W, dst, dst, 4));
                        }
                        *defined |= 1 << dst;
                    }
                }
                13 => {
                    // Atomic add on a written slot.
                    let ks: Vec<i16> = (1..=8).filter(|&k| self.written & (1 << k) != 0).collect();
                    if !ks.is_empty() && reserved & (1 << src) == 0 {
                        let k = ks[self.rng.below(ks.len() as u64) as usize];
                        let op = self.rng.pick(&[0x00, 0x01, 0x40, 0xa1, 0xe1]);
                        out.push(atomic(Size::DW, R10, src, -8 * k, op));
                    }
                }
                14 => {
                    out.push(match self.rng.below(4) {
                        0 => bswap(dst, self.rng.pick(&[16, 32, 64])),
                        1 => be(dst, self.rng.pick(&[16, 32, 64])),
                        2 => le(dst, self.rng.pick(&[16, 32, 64])),
                        _ => neg64(dst),
                    });
                    if *defined & (1 << dst) == 0 {
                        // Make sure the operand was defined.
                        out.pop();
                        out.push(mov64_reg(dst, a));
                    }
                    *defined |= 1 << dst;
                }
                15 => {
                    if *defined & (1 << dst) == 0 {
                        out.push(mov64_reg(dst, a));
                        *defined |= 1 << dst;
                    }
                    out.push(if self.rng.below(2) == 0 { sdiv64_reg(dst, src) } else { smod64_reg(dst, src) });
                }
                16 | 17 if depth < 3 => self.diamond(out, defined, depth, reserved),
                18 if depth < 2 => self.lp(out, defined, depth, reserved),
                19 => {
                    // A helper call: r0 = result, r1-r5 clobbered. Not inside
                    // loops: the next iteration would read clobbered values.
                    if reserved & 0b11_1111 == 0 && !self.in_loop {
                        out.push(call(self.rng.pick(&[5, 7, 8, 14])));
                        *defined |= 1;
                        *defined &= !0b11_1110;
                    }
                }
                _ => {
                    out.push(mov64_reg(dst, a));
                    *defined |= 1 << dst;
                }
            }
        }
    }

    fn cond_jump(&mut self, defined: u16, off: i16) -> u64 {
        let regs = Self::defined_regs(defined);
        let a = self.rng.pick(&regs);
        let b = self.rng.pick(&regs);
        let conds = [Jmp::Jeq, Jmp::Jne, Jmp::Jgt, Jmp::Jge, Jmp::Jlt, Jmp::Jle, Jmp::Jsgt, Jmp::Jsge, Jmp::Jslt, Jmp::Jsle, Jmp::Jset];
        let c = self.rng.pick(&conds);
        match self.rng.below(4) {
            0 => jmp_imm(c, a, self.rng.imm(), off),
            1 => jmp_reg(c, a, b, off),
            2 => jmp32_imm(c, a, self.rng.imm(), off),
            _ => jmp32_reg(c, a, b, off),
        }
    }

    fn diamond(&mut self, out: &mut Vec<u64>, defined: &mut u16, depth: u32, reserved: u16) {
        let saved = self.written;
        let mut d_then = *defined;
        let mut then_b = Vec::new();
        self.body(&mut then_b, &mut d_then, depth + 1, reserved);
        let w_then = self.written;
        self.written = saved;
        let mut d_else = *defined;
        let mut else_b = Vec::new();
        self.body(&mut else_b, &mut d_else, depth + 1, reserved);
        let w_else = self.written;
        // if cond goto else; then; ja end; else: ...
        out.push(self.cond_jump(*defined, (then_b.len() + 1) as i16));
        out.extend(then_b);
        out.push(ja(else_b.len() as i16));
        out.extend(else_b);
        *defined = d_then & d_else;
        self.written = w_then & w_else;
    }

    fn lp(&mut self, out: &mut Vec<u64>, defined: &mut u16, depth: u32, reserved: u16) {
        let free: Vec<u8> = [7u8, 8, 9].iter().copied().filter(|&r| reserved & (1 << r) == 0).collect();
        if free.is_empty() {
            return;
        }
        let c = self.rng.pick(&free);
        out.push(mov64_imm(c, 1 + self.rng.below(3) as i32));
        *defined |= 1 << c;
        let saved_w = self.written;
        let mut d = *defined;
        let mut b = Vec::new();
        let was = self.in_loop;
        self.in_loop = true;
        self.body(&mut b, &mut d, depth + 1, reserved | (1 << c));
        self.in_loop = was;
        // Registers first defined inside the loop are not defined on entry.
        let entry_defined = *defined;
        let body_len = b.len();
        out.extend(b);
        out.push(alu64_imm(Alu::Sub, c, 1));
        out.push(jmp_imm(Jmp::Jne, c, 0, -(body_len as i16) - 2));
        // After the loop, only registers defined on every iteration path
        // from entry are safe; be conservative.
        *defined = entry_defined | (d & entry_defined);
        self.written = saved_w & self.written;
    }

    fn program(&mut self) -> Vec<u64> {
        let mut out = vec![mov64_reg(R6, R1)];
        let mut defined: u16 = 1 << 6 | 1 << 1;
        for &r in &POOL {
            if self.rng.below(3) == 0 {
                out.push(mov64_imm(r, self.rng.imm()));
            } else {
                out.push(ldx(Size::DW, r, R6, (self.rng.below(31) * 8) as i16));
            }
            defined |= 1 << r;
        }
        self.body(&mut out, &mut defined, 0, 1 << 6);
        let regs = Self::defined_regs(defined);
        if defined & 1 == 0 {
            out.push(mov64_imm(R0, 0));
        }
        for &r in &regs {
            if r != 0 {
                out.push(alu64_reg(Alu::Xor, R0, r));
            }
        }
        out.push(exit());
        out
    }
}

fn random_input(rng: &mut Rng) -> Input {
    let mut ctx = vec![0u8; 256];
    for b in ctx.iter_mut() {
        *b = (rng.next() >> 11) as u8;
    }
    Input {
        ctx,
        max_steps: 200_000,
        ..Input::default()
    }
}

#[test]
fn differential_generator() {
    let seeds: u64 = if cfg!(debug_assertions) { 1_000 } else { 10_000 };
    let mut failures = Vec::new();
    let mut compiled = 0u64;
    for seed in 1..=seeds {
        let mut g = Gen {
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            in_loop: false,
            written: 0,
        };
        let p = g.program();
        let mut irng = Rng(seed ^ 0xdead_beef);
        let inputs = [random_input(&mut irng), random_input(&mut irng)];
        match check_equiv(&format!("seed {seed}"), &p, &inputs, &[10, 6, 4]) {
            Ok(()) => compiled += 1,
            Err(e) => {
                failures.push(e);
                if failures.len() >= 3 {
                    break;
                }
            }
        }
    }
    assert!(failures.is_empty(), "{} mismatches (first shown):\n{}", failures.len(), failures.join("\n\n"));
    eprintln!("differential: {compiled} programs x 3 register budgets, 0 mismatches");
}

/// Reproduce one generator case with the codegen log:
/// `SEED=n COLORS=c cargo test --release --test semantic debug_seed -- --ignored --nocapture`.
#[test]
#[ignore]
fn debug_seed() {
    let seed: u64 = std::env::var("SEED").unwrap().parse().unwrap();
    let colors: u8 = std::env::var("COLORS").map(|c| c.parse().unwrap()).unwrap_or(4);
    let mut g = Gen { rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1), in_loop: false, written: 0 };
    let p = g.program();
    eprintln!("{}", disasm(&p));
    let host = StdHost::new();
    let heap = Heap::new(&host, 1 << 30);
    let ctx = Ctx::new(&heap, Limits { log_bytes: 1 << 20, ..Limits::USERSPACE }, Level::Debug).unwrap();
    let insns: Vec<BpfInsn> = p.iter().map(|&r| BpfInsn::from_u64(r)).collect();
    let facts = DefaultFacts::default();
    let mut f = lift(&insns, &facts, &ctx).unwrap();
    let policy = Policy::permissive(&heap);
    let pl = Pipeline::build(&policy, "", &heap).unwrap();
    pl.run(&mut f, &PassCx { ctx: &ctx, facts: &facts, opts: &Options::default() }).unwrap();
    let mut s = String::new();
    epass_core::ir::print::print(&mut s as &mut dyn std::fmt::Write, &f).unwrap();
    eprintln!("{s}");
    let r = cg::compile(&mut f, &ctx, &CgOptions { ra_colors: colors, check: true, ..CgOptions::default() });
    let log = ctx.log.borrow();
    let (a, b) = log.parts();
    eprintln!("{}{}", String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    eprintln!("{:?}", r.map(|_| ()));
}

/// Falco corpus: every liftable program compiles, and the program's own
/// frame is untouched: every r10-relative offset the output uses inside the
/// original frame region was used by the original, and everything else lies
/// in ePass's region below it.
#[test]
fn falco_compiles_and_keeps_the_frame() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bpftests/falco");
    if !dir.exists() {
        return;
    }
    fn frame_offsets(p: &[u64]) -> (std::collections::BTreeSet<i64>, i64) {
        let mut set = std::collections::BTreeSet::new();
        let mut lowest = 0i64;
        let mut k = 0;
        while k < p.len() {
            let i = BpfInsn::from_u64(p[k]);
            let class = i.code & 7;
            if (class == 1 && i.src == 10) || ((class == 2 || class == 3) && i.dst == 10) {
                set.insert(i.off as i64);
                lowest = lowest.min(i.off as i64);
            }
            // rX = r10; rX += c
            if i.code == 0xbf && i.src == 10 {
                if let Some(n) = p.get(k + 1).map(|&r| BpfInsn::from_u64(r)) {
                    if n.code == 0x07 && n.dst == i.dst {
                        set.insert(n.imm as i64);
                        lowest = lowest.min(n.imm as i64);
                    }
                }
            }
            k += if i.code == 0x18 { 2 } else { 1 };
        }
        (set, lowest)
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let n = p.file_name().unwrap().to_str().unwrap();
            n.starts_with("prog") && n != "progs.txt"
        })
        .collect();
    files.sort();
    let (mut ok, mut rejected, mut before, mut after) = (0, Vec::new(), 0usize, 0usize);
    let t0 = std::time::Instant::now();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        let p: Vec<u64> = text
            .lines()
            .take_while(|l| !l.trim().is_empty())
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        match compile_with(&p, 10) {
            Ok(out) => {
                ok += 1;
                before += p.len();
                after += out.len();
                let (orig, orig_low) = frame_offsets(&p);
                let (new, _) = frame_offsets(&out);
                let d = orig_low.div_euclid(8) * 8;
                for off in new {
                    if off >= d {
                        assert!(orig.contains(&off), "{}: offset {off} inside the program frame was not in the original", path.display());
                    } else {
                        assert!(off >= -512, "{}: offset {off} beyond the 512-byte frame", path.display());
                    }
                }
            }
            Err(e) => rejected.push(format!("{}: {e}", path.file_name().unwrap().to_str().unwrap())),
        }
    }
    eprintln!(
        "falco codegen: {ok}/{} compiled in {:.2?}, {before} -> {after} instructions; rejected: {rejected:?}",
        files.len(),
        t0.elapsed()
    );
    assert!(ok >= 337, "only {ok} programs compiled: {rejected:?}");
    for r in &rejected {
        assert!(r.contains("callbacks"), "unexpected rejection: {r}");
    }
}
