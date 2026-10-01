//! The C ABI end to end, through the exported `extern "C"` functions with
//! C-style hosts: return codes and dispositions, logs, offsets, IR input,
//! interruption, allocation failure and leak freedom.

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};

use epass::*;
use epass_core::bpf::BpfInsn;
use epass_core::facts::DefaultFacts;
use epass_core::mem::FVec;
use epass_core::{Ctx, Heap, Level, Limits};
use epass_interp::asm::*;
use epass_interp::{compare, prog, run, Input};
use epass_std::StdHost;

/// A malloc host that counts, can fail the n-th allocation, and can ask
/// for interruption.
#[derive(Default)]
struct Counting {
    allocs: Cell<usize>,
    live: Cell<isize>,
    fail_at: Cell<Option<usize>>,
    interrupt: Cell<bool>,
    lines: std::cell::RefCell<Vec<String>>,
}

unsafe extern "C" fn c_alloc(ctx: *mut c_void, size: usize, align: usize) -> *mut c_void {
    let h = unsafe { &*(ctx as *const Counting) };
    let n = h.allocs.get();
    h.allocs.set(n + 1);
    if h.fail_at.get() == Some(n) {
        return std::ptr::null_mut();
    }
    h.live.set(h.live.get() + 1);
    unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(size, align).unwrap()).cast() }
}

unsafe extern "C" fn c_free(ctx: *mut c_void, p: *mut c_void, size: usize, align: usize) {
    let h = unsafe { &*(ctx as *const Counting) };
    h.live.set(h.live.get() - 1);
    unsafe { std::alloc::dealloc(p.cast(), std::alloc::Layout::from_size_align(size, align).unwrap()) };
}

unsafe extern "C" fn c_log(ctx: *mut c_void, _level: c_int, msg: *const c_char, len: usize) {
    let h = unsafe { &*(ctx as *const Counting) };
    let s = unsafe { std::slice::from_raw_parts(msg.cast::<u8>(), len) };
    h.lines.borrow_mut().push(String::from_utf8_lossy(s).into_owned());
}

unsafe extern "C" fn c_yield(ctx: *mut c_void) -> c_int {
    let h = unsafe { &*(ctx as *const Counting) };
    h.interrupt.get() as c_int
}

fn host_of(c: &Counting) -> epass_host {
    epass_host {
        ctx: c as *const Counting as *mut c_void,
        alloc: Some(c_alloc),
        free: Some(c_free),
        log: Some(c_log),
        now_ns: None,
        should_yield: Some(c_yield),
    }
}

fn insns_of(p: &[u64]) -> Vec<epass_insn> {
    p.iter().map(|&r| epass_insn::from(BpfInsn::from_u64(r))).collect()
}

fn to_u64(p: &[epass_insn]) -> Vec<u64> {
    p.iter().map(|&i| BpfInsn::from(i).to_u64()).collect()
}

struct Call<'a> {
    prog: &'a [u64],
    ir: &'a [u8],
    gopt: &'a str,
    popt: &'a str,
    policy: Option<&'a str>,
    facts: Option<&'a epass_facts>,
    requested: bool,
}

impl Default for Call<'_> {
    fn default() -> Self {
        Call { prog: &[], ir: &[], gopt: "", popt: "", policy: None, facts: None, requested: true }
    }
}

struct Res {
    rc: c_int,
    error: c_int,
    insns: Vec<u64>,
    offsets: Option<Vec<u32>>,
    log: String,
}

fn compile(c: &Counting, call: &Call<'_>) -> Res {
    let host = host_of(c);
    let insns = insns_of(call.prog);
    let input = epass_input {
        insns: if insns.is_empty() { std::ptr::null() } else { insns.as_ptr() },
        insn_cnt: insns.len() as u32,
        ir_len: call.ir.len() as u32,
        ir: call.ir.as_ptr().cast(),
        gopt: call.gopt.as_ptr().cast(),
        popt: call.popt.as_ptr().cast(),
        gopt_len: call.gopt.len() as u32,
        popt_len: call.popt.len() as u32,
        flags: if call.requested { EPASS_IN_REQUESTED } else { 0 },
        reserved: 0,
    };
    let pol = call.policy.map(|s| epass_policy {
        str: s.as_ptr().cast(),
        len: s.len() as u32,
        preset: EPASS_PRESET_USER,
        max_insns: 0,
        log_bytes: 0,
        max_bytes: 0,
        time_ns: 0,
    });
    let mut out = std::mem::MaybeUninit::<epass_output>::uninit();
    let rc = unsafe {
        epass_compile(
            &host,
            call.facts.map_or(std::ptr::null(), |f| f as *const _),
            pol.as_ref().map_or(std::ptr::null(), |p| p as *const _),
            &input,
            out.as_mut_ptr(),
        )
    };
    let mut out = unsafe { out.assume_init() };
    let slice = |p: *const epass_insn, n: u32| if p.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(p, n as usize) } };
    let res = Res {
        rc,
        error: out.error,
        insns: to_u64(slice(out.insns, out.insn_cnt)),
        offsets: (!out.offsets.is_null()).then(|| unsafe { std::slice::from_raw_parts(out.offsets, out.offsets_cnt as usize) }.to_vec()),
        log: if out.log.is_null() {
            String::new()
        } else {
            let b = unsafe { std::slice::from_raw_parts(out.log.cast::<u8>(), out.log_len as usize + 1) };
            assert_eq!(b.last(), Some(&0), "log must be NUL-terminated");
            String::from_utf8_lossy(&b[..b.len() - 1]).into_owned()
        },
    };
    unsafe { epass_output_free(&mut out) };
    // Freeing twice is harmless.
    unsafe { epass_output_free(&mut out) };
    assert_eq!(c.live.get(), 0, "leaked host allocations");
    res
}

fn sample() -> Vec<u64> {
    prog![
        ldx(Size::DW, R2, R1, 0),
        mov64_imm(R3, 5),
        alu64_imm(Alu::Mul, R3, 3),
        alu64_reg(Alu::Add, R2, R3),
        jmp_imm(Jmp::Jgt, R2, 100, 2),
        mov64_reg(R0, R2),
        exit(),
        mov64_imm(R0, 1),
        exit()
    ]
}

fn ctx_input(v: u64) -> Input {
    Input { ctx: v.to_le_bytes().to_vec(), ..Input::default() }
}

#[test]
fn compiles_and_matches_the_interpreter() {
    let c = Counting::default();
    let p = sample();
    let r = compile(&c, &Call { prog: &p, gopt: "verbose=2", ..Call::default() });
    assert_eq!(r.rc, 0, "log: {}", r.log);
    assert!(r.log.contains("instructions"), "log: {}", r.log);
    for v in [0u64, 7, 99, 1000] {
        compare(&run(&p, &ctx_input(v)), &run(&r.insns, &ctx_input(v))).unwrap();
    }
    let offs = r.offsets.unwrap();
    assert_eq!(offs.len(), p.len() + 1);
    assert_eq!(offs[0], 0);
    assert_eq!(*offs.last().unwrap() as usize, r.insns.len());
    assert!(offs.iter().all(|&o| o as usize <= r.insns.len()));
    // const_prop folded r3 = 15: fewer instructions.
    assert!(r.insns.len() < p.len());
}

#[test]
fn policy_dispositions() {
    let c = Counting::default();
    let p = sample();
    // ePass off: load the original, no error.
    let r = compile(&c, &Call { prog: &p, policy: Some("mode=off"), ..Call::default() });
    assert_eq!((r.rc, r.error), (1, 0));
    assert!(r.insns.is_empty());
    // opt-in without a request: skipped.
    let r = compile(&c, &Call { prog: &p, policy: Some("mode=optin"), requested: false, ..Call::default() });
    assert_eq!((r.rc, r.error), (1, 0));
    // always: runs without a request.
    let r = compile(&c, &Call { prog: &p, policy: Some("mode=always"), requested: false, ..Call::default() });
    assert_eq!(r.rc, 0);
    // A loader asking for a denied pass, or touching a forced one: EPERM.
    let r = compile(&c, &Call { prog: &p, policy: Some("-const_prop"), popt: "const_prop", ..Call::default() });
    assert_eq!(r.rc, -1, "log: {}", r.log);
    let r = compile(&c, &Call { prog: &p, policy: Some("+dump_ir"), popt: "!dump_ir", ..Call::default() });
    assert_eq!(r.rc, -1);
    // Loader popt forbidden.
    let r = compile(&c, &Call { prog: &p, policy: Some("user_popt=0"), popt: "dump_ir", ..Call::default() });
    assert_eq!(r.rc, -1);
    // Malformed policy or options: EINVAL, explained in the log.
    let r = compile(&c, &Call { prog: &p, policy: Some("mode=sometimes"), ..Call::default() });
    assert_eq!(r.rc, -22);
    let r = compile(&c, &Call { prog: &p, gopt: "frobnicate", ..Call::default() });
    assert_eq!(r.rc, -22);
    assert!(r.log.contains("gopt"), "log: {}", r.log);
    let r = compile(&c, &Call { prog: &p, popt: "nosuchpass", ..Call::default() });
    assert_eq!(r.rc, -22);
}

#[test]
fn failures_open_or_closed() {
    let c = Counting::default();
    // bpf-to-bpf calls are unsupported: optional passes fail open.
    let p = prog![call_local(1), exit(), mov64_imm(R0, 0), exit()];
    let r = compile(&c, &Call { prog: &p, ..Call::default() });
    assert_eq!((r.rc, r.error), (1, -95), "log: {}", r.log);
    assert!(r.log.contains("unsupported"), "log: {}", r.log);
    // A forced pass fails closed.
    let r = compile(&c, &Call { prog: &p, policy: Some("+dump_ir"), ..Call::default() });
    assert_eq!(r.rc, -95);
    // Without unknown-call permission, an unknown helper is unsupported.
    let facts = epass_facts { ctx: std::ptr::null_mut(), prog_type: 0, isa: 4, flags: 0, helper: None, kfunc: None };
    let p = prog![mov64_imm(R1, 1), call(250), exit()];
    let r = compile(&c, &Call { prog: &p, facts: Some(&facts), ..Call::default() });
    assert_eq!((r.rc, r.error), (1, -95));
    let r = compile(&c, &Call { prog: &p, ..Call::default() });
    assert_eq!(r.rc, 0, "NULL facts accept unknown calls: {}", r.log);
}

unsafe extern "C" fn only_lookup(_ctx: *mut c_void, id: i32, sig: *mut epass_sig) -> c_int {
    if id != 1 {
        return -1;
    }
    unsafe { *sig = epass_sig { nargs: 2, optional_from: 2, ret: 1, reserved: 0 } };
    0
}

#[test]
fn helper_facts_come_from_the_host() {
    let c = Counting::default();
    let facts = epass_facts { ctx: std::ptr::null_mut(), prog_type: 0, isa: 4, flags: 0, helper: Some(only_lookup), kfunc: None };
    let ok = prog![ld_map_fd(R1, 1), mov64_reg(R2, R10), alu64_imm(Alu::Add, R2, -8), st(Size::DW, R10, -8, 0), call(1), mov64_imm(R0, 0), exit()];
    let r = compile(&c, &Call { prog: &ok, facts: Some(&facts), ..Call::default() });
    assert_eq!(r.rc, 0, "log: {}", r.log);
    // Helper 2 is in the built-in table, but this host does not know it.
    let bad = prog![mov64_imm(R1, 0), mov64_imm(R2, 0), call(2), exit()];
    let r = compile(&c, &Call { prog: &bad, facts: Some(&facts), ..Call::default() });
    assert_eq!((r.rc, r.error), (1, -95));
}

#[test]
fn ir_blob_input() {
    let c = Counting::default();
    let p = sample();
    let blob = {
        let host = StdHost::new();
        let heap = Heap::new(&host, 1 << 26);
        let ctx = Ctx::new(&heap, Limits::USERSPACE, Level::Warn).unwrap();
        let insns: Vec<BpfInsn> = p.iter().map(|&r| BpfInsn::from_u64(r)).collect();
        let f = epass_core::lift::lift(&insns, &DefaultFacts::default(), &ctx).unwrap();
        let mut out = FVec::new(&heap);
        epass_core::bin::encode(&f, &mut out).unwrap();
        out.as_slice().to_vec()
    };
    let r = compile(&c, &Call { ir: &blob, ..Call::default() });
    assert_eq!(r.rc, 0, "log: {}", r.log);
    assert!(r.offsets.is_none());
    for v in [0u64, 99, 1000] {
        compare(&run(&p, &ctx_input(v)), &run(&r.insns, &ctx_input(v))).unwrap();
    }
    // Policy forbids IR, or ePass is off: IR cannot fall back.
    assert_eq!(compile(&c, &Call { ir: &blob, policy: Some("ir=0"), ..Call::default() }).rc, -1);
    assert_eq!(compile(&c, &Call { ir: &blob, policy: Some("mode=off"), ..Call::default() }).rc, -1);
    // Corrupt IR fails closed.
    let mut bad = blob.clone();
    bad[40] ^= 0xff;
    let r = compile(&c, &Call { ir: &bad, ..Call::default() });
    assert!(r.rc < 0, "corrupt IR must be rejected, got {}", r.rc);
    // Both inputs at once.
    assert_eq!(compile(&c, &Call { prog: &p, ir: &blob, ..Call::default() }).rc, -22);
}

#[test]
fn interrupt_rejects() {
    let c = Counting::default();
    c.interrupt.set(true);
    // Long enough to reach a yield point.
    let mut p = Vec::new();
    for k in 0..3000 {
        p.extend(prog![alu64_imm(Alu::Add, R0, k)]);
    }
    p.extend(prog![exit()]);
    p.insert(0, prog![mov64_imm(R0, 0)][0]);
    let r = compile(&c, &Call { prog: &p, ..Call::default() });
    assert_eq!(r.rc, -4, "log: {}", r.log);
}

#[test]
fn every_allocation_failure_is_clean() {
    let p = sample();
    let total = {
        let c = Counting::default();
        assert_eq!(compile(&c, &Call { prog: &p, gopt: "verbose=3", ..Call::default() }).rc, 0);
        c.allocs.get()
    };
    assert!(total > 10);
    let mut tally = [0usize; 3];
    for k in 0..total {
        let c = Counting::default();
        c.fail_at.set(Some(k));
        let r = compile(&c, &Call { prog: &p, gopt: "verbose=3", ..Call::default() });
        // Fails cleanly (ENOMEM, or open with ENOMEM), or succeeded because
        // the failed allocation was only the log copy.
        assert!(r.rc == -12 || (r.rc == 1 && r.error == -12) || r.rc == 0, "alloc {k}: rc {} error {}", r.rc, r.error);
        tally[match r.rc { -12 => 0, 1 => 1, _ => 2 }] += 1;
        if r.rc == 0 {
            // Only the final log copy may fail without affecting the result.
            assert_eq!(k, total - 1, "alloc {k} failed but compilation succeeded");
            assert!(r.log.is_empty());
        }
    }
    // Early failures reject (heap/log setup), later ones fail open.
    assert!(tally[0] >= 1 && tally[1] > total / 2, "tally {tally:?} of {total}");
}

#[test]
fn null_arguments() {
    let c = Counting::default();
    let host = host_of(&c);
    let mut out = std::mem::MaybeUninit::<epass_output>::uninit();
    assert_eq!(unsafe { epass_compile(&host, std::ptr::null(), std::ptr::null(), std::ptr::null(), out.as_mut_ptr()) }, -22);
    unsafe { epass_output_free(out.as_mut_ptr()) };
    assert_eq!(unsafe { epass_compile(std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null_mut()) }, -22);
    unsafe { epass_output_free(std::ptr::null_mut()) };
    // An empty program.
    assert_eq!(compile(&c, &Call::default()).rc, -22);
}

#[test]
fn default_host_works() {
    let p = sample();
    let insns = insns_of(&p);
    let input = epass_input {
        insns: insns.as_ptr(),
        insn_cnt: insns.len() as u32,
        ir_len: 0,
        ir: std::ptr::null(),
        gopt: std::ptr::null(),
        popt: std::ptr::null(),
        gopt_len: 0,
        popt_len: 0,
        flags: EPASS_IN_REQUESTED,
        reserved: 0,
    };
    let mut out = std::mem::MaybeUninit::<epass_output>::uninit();
    let rc = unsafe { epass_compile(epass_default_host(), std::ptr::null(), std::ptr::null(), &input, out.as_mut_ptr()) };
    assert_eq!(rc, 0);
    unsafe { epass_output_free(out.as_mut_ptr()) };
}
