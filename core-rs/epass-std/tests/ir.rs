//! M2 tests: IR construction and editing, the validator, the `.epir` text
//! round trip, the binary blob round trip, blob mutation robustness, and
//! allocation-failure robustness.

use std::fmt::Write as _;

use epass_core::analysis::{Cfg, DomTree};
use epass_core::bin;
use epass_core::ir::func::At;
use epass_core::ir::{parse::parse, print::print, verify::verify};
use epass_core::ir::{
    BinOp, Builder, Callee, Cond, FrameSlot, Function, Op, Size, SwapKind, SymKind, Value, Width,
};
use epass_core::mem::FVec;
use epass_core::{Ctx, ErrorKind, Heap, Level, Limits};
use epass_std::StdHost;

fn text_of(f: &Function<'_>) -> String {
    let mut s = String::new();
    print(&mut s as &mut dyn std::fmt::Write, f).unwrap();
    s
}

struct Env {
    host: StdHost,
}

impl Env {
    fn new() -> Self {
        Env {
            host: StdHost::new(),
        }
    }
}

macro_rules! with_ctx {
    ($env:expr, |$heap:ident, $ctx:ident| $body:block) => {{
        let $heap = Heap::new(&$env.host, 1 << 30);
        let $ctx = Ctx::new(&$heap, Limits::USERSPACE, Level::Debug).unwrap();
        $body
    }};
}

/// A function exercising every op kind.
fn build_all_ops<'h>(heap: &'h Heap<'h>) -> Function<'h> {
    let mut f = Function::new(heap).unwrap();
    let e = f.entry();
    let b1 = f.add_block().unwrap();
    let b2 = f.add_block().unwrap();
    let b3 = f.add_block().unwrap();
    let s0 = f
        .add_slot(FrameSlot {
            size: 8,
            align: 8,
            may_hold_ptr: true,
        })
        .unwrap();
    let s1 = f
        .add_slot(FrameSlot {
            size: 16,
            align: 8,
            may_hold_ptr: false,
        })
        .unwrap();
    let mut b = Builder::at_end(&mut f, e);
    let x = b.load(Size::B4, true, Value::Param(1), -2).unwrap();
    let y = b.bin(BinOp::SDiv, Width::W32, x, Value::Const(7)).unwrap();
    let z = b.zext32(y).unwrap();
    let s = b.ext(8, true, Width::W64, z).unwrap();
    let n = b.neg(Width::W64, s).unwrap();
    let sw = b.bswap(16, SwapKind::ToBe, n).unwrap();
    b.store(Size::B8, Value::FramePtr, -8, sw).unwrap();
    b.store(Size::B2, Value::FramePtr, -10, Value::Const(u64::MAX)).unwrap();
    let m = b.ldsym(SymKind::MapFd, 3).unwrap();
    let mv = b.ldsym(SymKind::MapValueFd, (8u64 << 32) | 4).unwrap();
    let sa = b.slot_addr(s1, 8).unwrap();
    b.slot_store(s0, mv).unwrap();
    let sl = b.slot_load(s0).unwrap();
    let c = b.call(Callee::Helper(1), &[m, sa]).unwrap();
    let k = b
        .call(
            Callee::Kfunc {
                btf_id: 1234,
                fd_idx: 0,
            },
            &[c, sl],
        )
        .unwrap();
    let op = epass_core::ir::verify::opaque_signature(
        // lock *(u64 *)(r1 + 0) += r2, with fetch: r2 = old
        0xdb | (1 << 8) | (2 << 12) | (0x01u64 << 32),
    )
    .unwrap();
    let a = b.emit(Op::Opaque(op), &[k, Value::Const(5)]).unwrap();
    b.condbr(Cond::Set, Width::W32, Value::Insn(a), Value::Const(1), b1, b2).unwrap();
    let mut b = Builder::at_end(&mut f, b1);
    let u = b.bin(BinOp::AShr, Width::W64, x, Value::Const(3)).unwrap();
    b.br(b3).unwrap();
    let mut b = Builder::at_end(&mut f, b2);
    b.br(b3).unwrap();
    let phi = f.insert_phi(b3, &[(u, b1), (Value::Const(0x1_0000_0000), b2)]).unwrap();
    let mut b = Builder::at_end(&mut f, b3);
    let r = b
        .call(
            Callee::Helper(6),
            &[Value::Insn(phi), Value::Undef],
        )
        .unwrap();
    b.ret(r).unwrap();
    f
}

#[test]
fn all_ops_validate_and_round_trip_through_text_and_blob() {
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        let f = build_all_ops(&heap);
        verify(&f, &ctx, false).unwrap();
        let t1 = text_of(&f);
        // text round trip
        let g = parse(&t1, &heap, &ctx).unwrap();
        verify(&g, &ctx, false).unwrap();
        assert_eq!(text_of(&g), t1);
        // blob round trip
        let mut blob: FVec<u8> = FVec::new(&heap);
        bin::encode(&f, &mut blob).unwrap();
        let h = bin::decode(blob.as_slice(), &heap, &ctx).unwrap();
        verify(&h, &ctx, false).unwrap();
        assert_eq!(text_of(&h), t1);
        // and once more through the blob of the parsed copy
        let mut blob2: FVec<u8> = FVec::new(&heap);
        bin::encode(&g, &mut blob2).unwrap();
        assert_eq!(blob.as_slice(), blob2.as_slice());
    })
}

const LOOP_SWAP: &str = r#"
; two phis that swap each iteration (forward references)
func main {
bb0:
  br bb1
bb1:
  %0 = phi [1, bb0], [%1, bb1]
  %1 = phi [2, bb0], [%0, bb1]
  %2 = phi [0, bb0], [%3, bb1]
  %3 = add.64 %2, 1
  condbr.64.ult %3, 3, bb1, bb2
bb2:
  %4 = shl.64 %0, 4
  %5 = add.64 %4, %1
  ret %5
}
"#;

const DIAMOND: &str = r#"
func main {
bb0:
  %0 = load.u64 [%arg1+0]
  condbr.64.eq %0, 0, bb1, bb2
bb1:
  %1 = add.64 %0, 10
  br bb3
bb2:
  %2 = sub.32 %0, 1
  br bb3
bb3:
  %3 = phi [%1, bb1], [%2, bb2]
  ret %3
}
"#;

#[test]
fn hand_written_text_parses_and_validates() {
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        for src in [LOOP_SWAP, DIAMOND] {
            let f = parse(src, &heap, &ctx).unwrap();
            verify(&f, &ctx, false).unwrap();
            let t = text_of(&f);
            let g = parse(&t, &heap, &ctx).unwrap();
            assert_eq!(text_of(&g), t);
        }
    })
}

#[test]
fn dominators_on_a_diamond_and_a_loop() {
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        let f = parse(DIAMOND, &heap, &ctx).unwrap();
        let cfg = Cfg::compute(&f, &ctx).unwrap();
        let dom = DomTree::compute(&f, &cfg, &ctx).unwrap();
        let blocks: Vec<_> = f.blocks().collect();
        let (b0, b1, b2, b3) = (blocks[0], blocks[1], blocks[2], blocks[3]);
        assert!(dom.dominates(b0, b3));
        assert!(!dom.dominates(b1, b3));
        assert!(!dom.dominates(b2, b3));
        assert_eq!(dom.idom(b3), Some(b0));
        assert_eq!(cfg.rpo()[0], b0);
        let l = parse(LOOP_SWAP, &heap, &ctx).unwrap();
        let cfg = Cfg::compute(&l, &ctx).unwrap();
        let dom = DomTree::compute(&l, &cfg, &ctx).unwrap();
        let lb: Vec<_> = l.blocks().collect();
        assert!(dom.dominates(lb[1], lb[2]));
        assert!(dom.dominates(lb[1], lb[1]));
        assert!(!dom.dominates(lb[2], lb[1]));
    })
}

/// Each case must fail to parse or fail validation with the given kind.
#[test]
fn invalid_functions_are_rejected() {
    let cases: &[(&str, &str)] = &[
        ("use before def", "func main {\nbb0:\n  %0 = add.64 %1, 1\n  %1 = add.64 1, 1\n  ret %0\n}"),
        ("missing terminator", "func main {\nbb0:\n  %0 = add.64 1, 1\n}"),
        ("phi input from non-pred", "func main {\nbb0:\n  br bb1\nbb1:\n  %0 = phi [1, bb0], [2, bb1]\n  ret %0\n}"),
        ("phi missing a pred", "func main {\nbb0:\n  condbr.64.eq %arg1, 0, bb1, bb2\nbb1:\n  br bb2\nbb2:\n  %0 = phi [1, bb0]\n  ret %0\n}"),
        ("not dominated", "func main {\nbb0:\n  condbr.64.eq %arg1, 0, bb1, bb2\nbb1:\n  %0 = add.64 1, 2\n  br bb2\nbb2:\n  ret %0\n}"),
        ("undef in ALU", "func main {\nbb0:\n  %0 = add.64 undef, 1\n  ret %0\n}"),
        ("bad param", "func main {\nbb0:\n  ret %arg6\n}"),
        ("branch to entry", "func main {\nbb0:\n  %0 = add.64 1, 1\n  condbr.64.eq %0, 0, bb0, bb1\nbb1:\n  ret 0\n}"),
        ("bad extension", "func main {\nbb0:\n  %0 = zext.7.64 %arg1\n  ret %0\n}"),
        ("too many slot bytes", "func main {\n  slot $0 size=512 align=8\n  slot $1 size=8 align=8\nbb0:\n  ret 0\n}"),
        ("unknown opcode", "func main {\nbb0:\n  frob %arg1\n}"),
        ("store with result", "func main {\nbb0:\n  %0 = store.u64 [%fp-8], 1\n  ret 0\n}"),
        ("local calls", "func main {\nbb0:\n  %0 = call local#1()\n  ret %0\n}"),
        ("opaque mismatch", "func main {\nbb0:\n  %0 = opaque 0x00000001000021db(%arg1)\n  ret %0\n}"),
    ];
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        for (name, src) in cases {
            let res = parse(src, &heap, &ctx).and_then(|f| verify(&f, &ctx, false));
            let e = res.expect_err(name);
            assert!(
                matches!(
                    e.kind,
                    ErrorKind::InvalidIr | ErrorKind::InvalidInput | ErrorKind::Unsupported
                ),
                "{name}: unexpected error {e}"
            );
        }
    })
}

#[test]
fn editing_keeps_invariants() {
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        let mut f = parse(DIAMOND, &heap, &ctx).unwrap();
        let blocks: Vec<_> = f.blocks().collect();
        let (b0, b1, b3) = (blocks[0], blocks[1], blocks[3]);
        // Split an edge into a phi block: the phi input is relabeled.
        let mid = f.split_edge(b1, b3).unwrap();
        verify(&f, &ctx, false).unwrap();
        let phi = f.iter_block(b3).next().unwrap();
        assert!(f.phi_inputs(phi).any(|(_, b)| b == mid));
        // Replace all uses of the load with a constant and remove it.
        let load = f.iter_block(b0).next().unwrap();
        assert_eq!(f.use_count(load).unwrap(), 3);
        f.replace_all_uses(load, Value::Const(5)).unwrap();
        assert_eq!(f.use_count(load).unwrap(), 0);
        f.remove(load).unwrap();
        verify(&f, &ctx, false).unwrap();
        // Grow a phi past its capacity several times; uses follow.
        let extra: Vec<_> = (0..40).map(|_| f.add_block().unwrap()).collect();
        let def = f
            .insert(At::BeforeTerminator(b0), Op::Bin { op: BinOp::Add, w: Width::W64 }, &[Value::Param(1), Value::Const(1)])
            .unwrap();
        let ph = f.insert_phi(b3, &[]).unwrap();
        for &eb in &extra {
            f.add_phi_input(ph, Value::Insn(def), eb).unwrap();
        }
        assert_eq!(f.use_count(def).unwrap(), 40);
        assert_eq!(f.uses(def).count(), 40);
        for &eb in &extra[..10] {
            assert!(f.remove_phi_input(ph, eb).unwrap());
        }
        assert_eq!(f.use_count(def).unwrap(), 30);
        assert_eq!(f.phi_inputs(ph).count(), 30);
    })
}

/// Deterministic generator for the mutation test.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

#[test]
fn mutated_blobs_never_panic() {
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        let mut corpus: Vec<Vec<u8>> = Vec::new();
        for f in [
            build_all_ops(&heap),
            parse(LOOP_SWAP, &heap, &ctx).unwrap(),
            parse(DIAMOND, &heap, &ctx).unwrap(),
        ] {
            let mut blob: FVec<u8> = FVec::new(&heap);
            bin::encode(&f, &mut blob).unwrap();
            corpus.push(blob.as_slice().to_vec());
        }
        let mut rng = Lcg(42);
        let iters = if cfg!(debug_assertions) { 20_000 } else { 200_000 };
        let (mut accepted, mut rejected) = (0u32, 0u32);
        for it in 0..iters {
            let mut b = corpus[it % corpus.len()].clone();
            match rng.next() % 4 {
                0 => {
                    let n = 1 + rng.next() as usize % 4;
                    for _ in 0..n {
                        let i = rng.next() as usize % b.len();
                        b[i] ^= 1 << (rng.next() % 8);
                    }
                }
                1 => {
                    let i = rng.next() as usize % b.len();
                    b[i] = rng.next() as u8;
                }
                2 => {
                    let n = rng.next() as usize % b.len();
                    b.truncate(n);
                }
                _ => {
                    // Overwrite a random u32 with a random small or huge value.
                    let i = (rng.next() as usize % b.len()) & !3;
                    let v: u32 = if rng.next().is_multiple_of(2) { (rng.next() % 64) as u32 } else { u32::MAX - (rng.next() % 4) as u32 };
                    if i + 4 <= b.len() {
                        b[i..i + 4].copy_from_slice(&v.to_le_bytes());
                    }
                }
            }
            let mheap = Heap::new(&env.host, 1 << 26);
            let small = Limits { log_bytes: 256, ..Limits::USERSPACE };
            let mctx = Ctx::new(&mheap, small, Level::Error).unwrap();
            match bin::decode(&b, &mheap, &mctx).and_then(|f| verify(&f, &mctx, false)) {
                Ok(()) => accepted += 1,
                Err(_) => rejected += 1,
            }
        }
        assert!(rejected > 0 && accepted > 0, "accepted={accepted} rejected={rejected}");
    })
}

#[test]
fn allocation_failure_at_every_point_is_clean() {
    // Count allocations of a full parse/verify/encode/decode cycle, then
    // fail each one in turn.
    let run = |host: &StdHost| -> Result<(), epass_core::Error> {
        let heap = Heap::new(host, 1 << 26);
        let ctx = Ctx::new(&heap, Limits { log_bytes: 256, ..Limits::USERSPACE }, Level::Error)?;
        let f = parse(DIAMOND, &heap, &ctx)?;
        verify(&f, &ctx, false)?;
        let mut blob: FVec<u8> = FVec::new(&heap);
        bin::encode(&f, &mut blob)?;
        let g = bin::decode(blob.as_slice(), &heap, &ctx)?;
        verify(&g, &ctx, false)
    };
    let probe = StdHost::new();
    run(&probe).unwrap();
    let total = probe.allocations();
    assert!(total > 20, "suspiciously few allocations: {total}");
    for k in 1..=total {
        let host = StdHost::new();
        host.fail_allocation_at(k);
        let e = run(&host).expect_err("injected failure must surface");
        assert_eq!(e.kind, ErrorKind::OutOfMemory, "allocation {k}: {e}");
        assert_eq!(host.live_allocations(), 0, "leak after failing allocation {k}");
    }
}

#[test]
fn text_reports_line_numbers() {
    let env = Env::new();
    with_ctx!(env, |heap, ctx| {
        let e = parse("func main {\nbb0:\n  ret %7\n}", &heap, &ctx).unwrap_err();
        assert_eq!(e.pos, Some(3));
        let mut s = String::new();
        write!(s, "{e}").unwrap();
        assert!(s.contains("undefined"));
    })
}
