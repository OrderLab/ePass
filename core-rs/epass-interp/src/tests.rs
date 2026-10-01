//! Semantics tests for the reference interpreter. Expected values are worked
//! out by hand from RFC 9669, independently of any ePass code.

use super::asm::*;
use super::*;
use crate::prog;

fn r0(p: &[u64]) -> u64 {
    let r = run(p, &Input::default());
    match r.outcome {
        Outcome::Exit(v) => v,
        Outcome::Fault(f) => panic!("fault: {f:?}"),
    }
}

fn r0_ctx(p: &[u64], ctx: &[u8]) -> u64 {
    let input = Input {
        ctx: ctx.to_vec(),
        ..Input::default()
    };
    run(p, &input).r0().expect("exit")
}

#[test]
fn mov_immediates_extend_by_class() {
    assert_eq!(r0(&prog![mov32_imm(R0, -1), exit()]), 0xffff_ffff);
    assert_eq!(r0(&prog![mov64_imm(R0, -1), exit()]), u64::MAX);
    assert_eq!(r0(&prog![ld_imm64(R0, 0x1_0000_0005), mov32_reg(R0, R0), exit()]), 5);
}

#[test]
fn alu32_wraps_and_zero_extends() {
    let p = prog![
        ld_imm64(R0, 0xffff_ffff_ffff_fff0),
        alu32_imm(Alu::Add, R0, 0x20),
        exit()
    ];
    assert_eq!(r0(&p), 0x10);
    // 64-bit add of a sign-extended immediate.
    assert_eq!(r0(&prog![mov64_imm(R0, 1), alu64_imm(Alu::Add, R0, -2), exit()]), u64::MAX);
}

#[test]
fn division_and_modulo_edge_cases() {
    // x / 0 = 0, x % 0 = x (ALU32: zero-extended low half).
    assert_eq!(r0(&prog![mov64_imm(R0, 7), mov64_imm(R1, 0), alu64_reg(Alu::Div, R0, R1), exit()]), 0);
    assert_eq!(r0(&prog![mov64_imm(R0, 7), mov64_imm(R1, 0), alu64_reg(Alu::Mod, R0, R1), exit()]), 7);
    assert_eq!(
        r0(&prog![ld_imm64(R0, 0x1_0000_0007), mov64_imm(R1, 0), alu32_reg(Alu::Mod, R0, R1), exit()]),
        7
    );
    // Unsigned vs signed.
    assert_eq!(r0(&prog![mov64_imm(R0, -7), mov64_imm(R1, 2), sdiv64_reg(R0, R1), exit()]), (-3i64) as u64);
    assert_eq!(r0(&prog![mov64_imm(R0, -7), mov64_imm(R1, 2), smod64_reg(R0, R1), exit()]), (-1i64) as u64);
    assert_eq!(
        r0(&prog![mov64_imm(R0, -7), mov64_imm(R1, 2), alu64_reg(Alu::Div, R0, R1), exit()]),
        ((-7i64) as u64) / 2
    );
    // INT_MIN / -1 = INT_MIN.
    assert_eq!(
        r0(&prog![ld_imm64(R0, 1 << 63), mov64_imm(R1, -1), sdiv64_reg(R0, R1), exit()]),
        1 << 63
    );
    assert_eq!(r0(&prog![mov32_imm(R0, i32::MIN), sdiv32_imm(R0, -1), exit()]), 0x8000_0000);
    // Signed modulo by -1 is 0.
    assert_eq!(
        r0(&prog![ld_imm64(R0, 1 << 63), mov64_imm(R1, -1), smod64_reg(R0, R1), exit()]),
        0
    );
}

#[test]
fn shifts_mask_the_amount() {
    assert_eq!(r0(&prog![mov64_imm(R0, 1), mov64_imm(R1, 65), alu64_reg(Alu::Lsh, R0, R1), exit()]), 2);
    assert_eq!(r0(&prog![mov64_imm(R0, 1), mov64_imm(R1, 33), alu32_reg(Alu::Lsh, R0, R1), exit()]), 2);
    assert_eq!(r0(&prog![mov32_imm(R0, -8), alu32_imm(Alu::Arsh, R0, 1), exit()]), 0xffff_fffc);
    assert_eq!(r0(&prog![mov64_imm(R0, -8), alu64_imm(Alu::Arsh, R0, 1), exit()]), (-4i64) as u64);
    assert_eq!(r0(&prog![mov64_imm(R0, -8), alu64_imm(Alu::Rsh, R0, 60), exit()]), 0xf);
}

#[test]
fn neg_and_sign_extension_moves() {
    assert_eq!(r0(&prog![mov64_imm(R0, 5), neg64(R0), exit()]), (-5i64) as u64);
    assert_eq!(r0(&prog![mov64_imm(R1, 0xff), movsx64(R0, R1, 8), exit()]), u64::MAX);
    assert_eq!(r0(&prog![mov64_imm(R1, 0x7f), movsx64(R0, R1, 8), exit()]), 0x7f);
    assert_eq!(r0(&prog![mov64_imm(R1, 0x8000), movsx64(R0, R1, 16), exit()]), 0xffff_ffff_ffff_8000);
    assert_eq!(r0(&prog![mov32_imm(R1, -2), movsx64(R0, R1, 32), exit()]), (-2i64) as u64);
    // 32-bit movsx: sign-extend to 32 bits, then zero-extend.
    assert_eq!(r0(&prog![mov64_imm(R1, 0xff), movsx32(R0, R1, 8), exit()]), 0xffff_ffff);
}

#[test]
fn byte_swaps() {
    assert_eq!(r0(&prog![mov64_imm(R0, 0x1234), be(R0, 16), exit()]), 0x3412);
    assert_eq!(r0(&prog![ld_imm64(R0, 0x1_0000_1234), le(R0, 16), exit()]), 0x1234);
    assert_eq!(
        r0(&prog![ld_imm64(R0, 0x0102_0304_0506_0708), bswap(R0, 64), exit()]),
        0x0807_0605_0403_0201
    );
    assert_eq!(r0(&prog![ld_imm64(R0, 0x1_1122_3344), be(R0, 32), exit()]), 0x4433_2211);
}

#[test]
fn conditional_jumps() {
    // JSET.
    let p = |v: i32| prog![mov64_imm(R1, v), mov64_imm(R0, 0), jmp_imm(Jmp::Jset, R1, 4, 1), exit(), mov64_imm(R0, 1), exit()];
    assert_eq!(r0(&p(6)), 1);
    assert_eq!(r0(&p(3)), 0);
    // JMP32 compares only the low halves.
    let q = prog![
        ld_imm64(R1, 0x5_0000_0001),
        mov64_imm(R0, 0),
        jmp32_imm(Jmp::Jeq, R1, 1, 1),
        exit(),
        mov64_imm(R0, 1),
        exit()
    ];
    assert_eq!(r0(&q), 1);
    // Signed vs unsigned.
    let s = prog![
        mov64_imm(R1, -1),
        mov64_imm(R0, 0),
        jmp_imm(Jmp::Jsgt, R1, 0, 2),
        jmp_imm(Jmp::Jgt, R1, 0, 2),
        exit(),
        exit(),
        mov64_imm(R0, 2),
        exit()
    ];
    assert_eq!(r0(&s), 2);
    // gotol.
    assert_eq!(r0(&prog![mov64_imm(R0, 1), gotol(1), mov64_imm(R0, 2), exit()]), 1);
}

#[test]
fn loads_stores_and_sign_extending_loads() {
    let mut ctx = vec![0u8; 64];
    ctx[0] = 0xff;
    ctx[8..16].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(r0_ctx(&prog![ldxs(Size::B, R0, R1, 0), exit()], &ctx), u64::MAX);
    assert_eq!(r0_ctx(&prog![ldx(Size::B, R0, R1, 0), exit()], &ctx), 0xff);
    assert_eq!(r0_ctx(&prog![ldx(Size::W, R0, R1, 8), exit()], &ctx), 0x5566_7788);
    let p = prog![
        st(Size::DW, R10, -8, -1),
        stx(Size::W, R10, R1, -16),
        ldx(Size::DW, R0, R10, -8),
        exit()
    ];
    let r = run(&p, &Input::default());
    assert_eq!(r.r0(), Some(u64::MAX));
    assert!(r.stack_written[504..512].iter().all(|&w| w));
    assert!(r.stack_written[496..500].iter().all(|&w| w));
    assert!(!r.stack_written[500]);
}

#[test]
fn atomics() {
    let base = prog![st(Size::DW, R10, -8, 10), mov64_imm(R2, 5)];
    let fetch_add = prog![base.clone(), atomic(Size::DW, R10, R2, -8, 0x01), ldx(Size::DW, R0, R10, -8), alu64_reg(Alu::Mul, R0, R2), exit()];
    assert_eq!(r0(&fetch_add), 15 * 10);
    let xchg = prog![base.clone(), atomic(Size::DW, R10, R2, -8, 0xe1), mov64_reg(R0, R2), exit()];
    assert_eq!(r0(&xchg), 10);
    let cas_ok = prog![base.clone(), mov64_imm(R0, 10), atomic(Size::DW, R10, R2, -8, 0xf1), ldx(Size::DW, R0, R10, -8), exit()];
    assert_eq!(r0(&cas_ok), 5);
    let cas_fail = prog![base, mov64_imm(R0, 3), atomic(Size::DW, R10, R2, -8, 0xf1), exit()];
    assert_eq!(r0(&cas_fail), 10);
}

#[test]
fn helpers_clobber_and_record() {
    let p = prog![
        mov64_imm(R6, 7),
        st(Size::W, R10, -4, 42),
        ld_map_fd(R1, 3),
        mov64_reg(R2, R10),
        alu64_imm(Alu::Add, R2, -4),
        call(1),
        mov64_reg(R7, R0),
        mov64_reg(R0, R1),
        exit()
    ];
    let r = run(&p, &Input::default());
    let v = r.r0().unwrap();
    assert_eq!(v & 0xffff_0000_0000_0000, CLOBBER_BASE);
    assert!(matches!(&r.events[0], Event::Call { id: 1, args } if args.len() == 2));
}

#[test]
fn local_calls_preserve_callee_saved() {
    let p = prog![
        mov64_imm(R6, 11),
        call_local(2),
        alu64_reg(Alu::Add, R0, R6),
        exit(),
        // callee
        mov64_imm(R6, 100),
        st(Size::DW, R10, -8, 5),
        ldx(Size::DW, R0, R10, -8),
        exit()
    ];
    let r = run(&p, &Input::default());
    assert_eq!(r.r0(), Some(16));
    // The callee's frame is not the main frame.
    assert!(!r.stack_written[504]);
}

#[test]
fn packet_loads() {
    let input = Input {
        packet: vec![0x12, 0x34, 0x56, 0x78],
        ..Input::default()
    };
    let p = prog![mov64_imm(R6, 0), ld_abs(Size::H, 1), exit()];
    assert_eq!(run(&p, &input).r0(), Some(0x3456));
    let oob = prog![mov64_imm(R0, 9), ld_abs(Size::W, 2), exit()];
    assert_eq!(run(&oob, &input).r0(), Some(0));
}

#[test]
fn faults() {
    let r = run(&prog![ldx(Size::DW, R0, R10, 0), exit()], &Input::default());
    assert!(matches!(r.outcome, Outcome::Fault(Fault::OutOfBounds { .. })));
    let r = run(&prog![mov64_imm(R0, 0)], &Input::default());
    assert!(matches!(r.outcome, Outcome::Fault(Fault::PcOutOfRange { .. })));
    let r = run(&prog![ja(-1)], &Input { max_steps: 100, ..Input::default() });
    assert_eq!(r.outcome, Outcome::Fault(Fault::StepLimit));
}

#[test]
fn compare_detects_differences() {
    let a = run(&prog![mov64_imm(R0, 1), exit()], &Input::default());
    let b = run(&prog![mov64_imm(R0, 2), exit()], &Input::default());
    assert!(compare(&a, &b).is_err());
    // Writes only the rewritten program made (spill slots) are ignored.
    let orig = run(&prog![st(Size::DW, R10, -8, 1), mov64_imm(R0, 0), exit()], &Input::default());
    let new = run(
        &prog![st(Size::DW, R10, -8, 1), st(Size::DW, R10, -16, 9), mov64_imm(R0, 0), exit()],
        &Input::default(),
    );
    assert!(compare(&orig, &new).is_ok());
    let bad = run(&prog![st(Size::DW, R10, -8, 2), mov64_imm(R0, 0), exit()], &Input::default());
    assert!(compare(&orig, &bad).is_err());
}
