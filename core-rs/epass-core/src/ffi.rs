//! C ABI (`include/epass.h`), shared by the kernel glue and libepass.a.
//!
//! Besides `mem`, this is the only module with `unsafe`: it turns C
//! pointers into slices, calls the host's callbacks, and allocates the
//! output buffers through the host. Every pointer is checked for NULL and
//! every length for overflow before use; nothing here panics.
#![allow(unsafe_code)]
#![allow(non_camel_case_types)]

use core::alloc::Layout;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{self, NonNull};

use crate::bpf::BpfInsn;
use crate::ctx::{Ctx, Limits};
use crate::driver::{self, Gopt, Input, Outcome, Request};
use crate::error::{Error, Result};
use crate::facts::{default_helper, Facts, Isa, RetClass, Sig};
use crate::log::Level;
use crate::mem::{FVec, Heap, Host, Interrupted};
use crate::pm::Policy;

const EINVAL: c_int = -22;

/// `struct epass_insn`: bit-compatible with `struct bpf_insn`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct epass_insn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl From<epass_insn> for BpfInsn {
    fn from(c: epass_insn) -> Self {
        // The register bitfields are allocated from the low bit on
        // little-endian targets and from the high bit on big-endian ones.
        let (dst, src) = if cfg!(target_endian = "big") {
            (c.regs >> 4, c.regs & 0xf)
        } else {
            (c.regs & 0xf, c.regs >> 4)
        };
        BpfInsn::new(c.code, dst, src, c.off, c.imm)
    }
}

impl From<BpfInsn> for epass_insn {
    fn from(b: BpfInsn) -> Self {
        let regs = if cfg!(target_endian = "big") {
            ((b.dst & 0xf) << 4) | (b.src & 0xf)
        } else {
            (b.dst & 0xf) | ((b.src & 0xf) << 4)
        };
        epass_insn {
            code: b.code,
            regs,
            off: b.off,
            imm: b.imm,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct epass_host {
    pub ctx: *mut c_void,
    pub alloc: Option<unsafe extern "C" fn(*mut c_void, usize, usize) -> *mut c_void>,
    pub free: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize)>,
    pub log: Option<unsafe extern "C" fn(*mut c_void, c_int, *const c_char, usize)>,
    pub now_ns: Option<unsafe extern "C" fn(*mut c_void) -> u64>,
    pub should_yield: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct epass_sig {
    pub nargs: u8,
    pub optional_from: u8,
    pub ret: u8,
    pub reserved: u8,
}

pub const EPASS_FACTS_UNKNOWN_CALLS: u32 = 1;

#[repr(C)]
#[derive(Debug)]
pub struct epass_facts {
    pub ctx: *mut c_void,
    pub prog_type: u32,
    pub isa: u32,
    pub flags: u32,
    pub helper: Option<unsafe extern "C" fn(*mut c_void, i32, *mut epass_sig) -> c_int>,
    pub kfunc: Option<unsafe extern "C" fn(*mut c_void, i32, i16, *mut epass_sig) -> c_int>,
}

pub const EPASS_PRESET_USER: u32 = 0;
pub const EPASS_PRESET_KERNEL: u32 = 1;

#[repr(C)]
#[derive(Debug)]
pub struct epass_policy {
    pub str: *const c_char,
    pub len: u32,
    pub preset: u32,
    pub max_insns: u32,
    pub log_bytes: u32,
    pub max_bytes: u64,
    pub time_ns: u64,
}

pub const EPASS_IN_REQUESTED: u32 = 1;

#[repr(C)]
#[derive(Debug)]
pub struct epass_input {
    pub insns: *const epass_insn,
    pub insn_cnt: u32,
    pub ir_len: u32,
    pub ir: *const c_void,
    pub gopt: *const c_char,
    pub popt: *const c_char,
    pub gopt_len: u32,
    pub popt_len: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct epass_output {
    pub insns: *mut epass_insn,
    pub insn_cnt: u32,
    pub offsets_cnt: u32,
    pub offsets: *mut u32,
    pub log: *mut c_char,
    pub log_len: u32,
    pub error: c_int,
    pub host: *const epass_host,
}

impl epass_output {
    const EMPTY: epass_output = epass_output {
        insns: ptr::null_mut(),
        insn_cnt: 0,
        offsets_cnt: 0,
        offsets: ptr::null_mut(),
        log: ptr::null_mut(),
        log_len: 0,
        error: 0,
        host: ptr::null(),
    };
}

/// [`Host`] over a C vtable.
struct CHost<'a> {
    h: &'a epass_host,
}

impl Host for CHost<'_> {
    fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
        let f = self.h.alloc?;
        // SAFETY: the callback contract in epass.h.
        NonNull::new(unsafe { f(self.h.ctx, layout.size(), layout.align()) }.cast::<u8>())
    }

    unsafe fn free(&self, ptr: NonNull<u8>, layout: Layout) {
        if let Some(f) = self.h.free {
            // SAFETY: `ptr` came from `alloc` with this layout.
            unsafe { f(self.h.ctx, ptr.as_ptr().cast(), layout.size(), layout.align()) };
        }
    }

    fn log(&self, level: Level, msg: &str) {
        if let Some(f) = self.h.log {
            // SAFETY: `msg` is valid for `len` bytes during the call.
            unsafe { f(self.h.ctx, level as c_int, msg.as_ptr().cast(), msg.len()) };
        }
    }

    fn now_ns(&self) -> u64 {
        match self.h.now_ns {
            // SAFETY: the callback contract in epass.h.
            Some(f) => unsafe { f(self.h.ctx) },
            None => 0,
        }
    }

    fn should_yield(&self) -> core::result::Result<(), Interrupted> {
        match self.h.should_yield {
            // SAFETY: the callback contract in epass.h.
            Some(f) if unsafe { f(self.h.ctx) } != 0 => Err(Interrupted),
            _ => Ok(()),
        }
    }
}

/// [`Facts`] over a C vtable (or the userspace defaults when NULL).
struct CFacts<'a> {
    f: Option<&'a epass_facts>,
}

fn sig_of(s: epass_sig) -> Option<Sig> {
    let ret = match s.ret {
        0 => RetClass::Scalar,
        1 => RetClass::MapValueOrNull,
        2 => RetClass::MemOrNull,
        3 => RetClass::Ptr,
        _ => return None,
    };
    if s.nargs > 5 || s.optional_from > s.nargs {
        return None;
    }
    Some(Sig {
        nargs: s.nargs,
        optional_from: s.optional_from,
        ret,
    })
}

impl Facts for CFacts<'_> {
    fn helper(&self, id: i32) -> Option<Sig> {
        let Some(f) = self.f else { return default_helper(id) };
        let Some(cb) = f.helper else { return default_helper(id) };
        let mut s = epass_sig::default();
        // SAFETY: the callback contract in epass.h; `s` outlives the call.
        if unsafe { cb(f.ctx, id, &mut s) } != 0 {
            return None;
        }
        sig_of(s)
    }

    fn kfunc(&self, btf_id: i32, fd_idx: i16) -> Option<Sig> {
        let f = self.f?;
        let cb = f.kfunc?;
        let mut s = epass_sig::default();
        // SAFETY: as above.
        if unsafe { cb(f.ctx, btf_id, fd_idx, &mut s) } != 0 {
            return None;
        }
        sig_of(s)
    }

    fn allow_unknown_calls(&self) -> bool {
        self.f.is_none_or(|f| f.flags & EPASS_FACTS_UNKNOWN_CALLS != 0)
    }

    fn isa(&self) -> Isa {
        match self.f.map_or(0, |f| f.isa) {
            1 => Isa::V1,
            2 => Isa::V2,
            3 => Isa::V3,
            _ => Isa::V4,
        }
    }
}

fn limits_of(p: Option<&epass_policy>) -> Limits {
    let Some(p) = p else { return Limits::USERSPACE };
    let base = if p.preset == EPASS_PRESET_KERNEL {
        Limits::KERNEL
    } else {
        Limits::USERSPACE
    };
    let pick = |v: u64, d: u64| if v == 0 { d } else { v };
    Limits {
        max_insns: pick(p.max_insns as u64, base.max_insns as u64) as u32,
        log_bytes: pick(p.log_bytes as u64, base.log_bytes as u64) as usize,
        max_bytes: usize::try_from(pick(p.max_bytes, base.max_bytes as u64)).unwrap_or(usize::MAX),
        time_ns: pick(p.time_ns, base.time_ns),
        yield_every: base.yield_every,
    }
}

/// # Safety
/// `p` is NULL with `len == 0`, or valid for `len` bytes for `'a`.
unsafe fn bytes<'a>(p: *const u8, len: u32) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { core::slice::from_raw_parts(p, len as usize) })
}

/// # Safety
/// As [`bytes`].
unsafe fn text<'a>(p: *const c_char, len: u32) -> Result<&'a str> {
    // SAFETY: the caller's contract.
    let b = unsafe { bytes(p.cast(), len) }.ok_or(Error::invalid_input("NULL option string"))?;
    core::str::from_utf8(b).map_err(|_| Error::invalid_input("option string is not UTF-8"))
}

/// Allocate `n` elements of `T` through the host (NULL when `n == 0`).
fn alloc_array<T>(h: &epass_host, n: usize) -> Result<*mut T> {
    if n == 0 {
        return Ok(ptr::null_mut());
    }
    let layout = Layout::array::<T>(n).map_err(|_| Error::limit("output too large"))?;
    let f = h.alloc.ok_or(Error::invalid_input("host has no allocator"))?;
    // SAFETY: the callback contract in epass.h.
    let p = unsafe { f(h.ctx, layout.size(), layout.align()) }.cast::<T>();
    if p.is_null() {
        return Err(Error::oom());
    }
    Ok(p)
}

/// Compile one program; see `include/epass.h`.
///
/// # Safety
/// Every non-NULL pointer must be valid as documented in `epass.h`; `host`
/// must stay valid until `epass_output_free(out)`.
#[no_mangle]
pub unsafe extern "C" fn epass_compile(
    host: *const epass_host,
    facts: *const epass_facts,
    policy: *const epass_policy,
    input: *const epass_input,
    out: *mut epass_output,
) -> c_int {
    if out.is_null() {
        return EINVAL;
    }
    // SAFETY: `out` is valid for writes (contract).
    unsafe { out.write(epass_output::EMPTY) };
    // SAFETY: NULL or valid (contract).
    let (Some(h), Some(inp)) = (unsafe { host.as_ref() }, unsafe { input.as_ref() }) else {
        return EINVAL;
    };
    if h.alloc.is_none() || h.free.is_none() {
        return EINVAL;
    }
    // SAFETY: NULL or valid (contract).
    let (pol, fa) = unsafe { (policy.as_ref(), facts.as_ref()) };
    // SAFETY: `out` is valid (contract); written only through this reference.
    let o = unsafe { &mut *out };
    o.host = host;
    let ch = CHost { h };
    let limits = limits_of(pol);
    let heap = Heap::new(&ch, limits.max_bytes);
    // SAFETY: the input's strings are valid for their lengths (contract).
    let gopt = unsafe { text(inp.gopt, inp.gopt_len) }.and_then(Gopt::parse);
    let level = gopt.as_ref().map_or(Level::Error, |g| g.level);
    let ctx = match Ctx::new(&heap, limits, level) {
        Ok(c) => c,
        Err(e) => return e.errno(),
    };
    let rc = match gopt {
        // SAFETY: forwarded contract.
        Ok(g) => unsafe { compile_in(&ctx, &CFacts { f: fa }, pol, inp, g, h, o) },
        Err(e) => {
            crate::ctx_log!(&ctx, Level::Error, "epass: gopt: {}\n", e);
            e.errno()
        }
    };
    if let Err(e) = copy_log(&ctx, h, o) {
        // The log is best effort; a failure here never changes the outcome.
        let _ = e;
    }
    rc
}

/// # Safety
/// As [`epass_compile`].
unsafe fn compile_in<'h>(
    ctx: &Ctx<'h>,
    facts: &CFacts<'_>,
    pol: Option<&epass_policy>,
    inp: &epass_input,
    gopt: Gopt,
    h: &epass_host,
    o: &mut epass_output,
) -> c_int {
    let heap = ctx.heap;
    let res = (|| -> Result<Outcome<'h>> {
        let policy = match pol {
            // SAFETY: the policy string is valid for its length (contract).
            Some(p) if p.len > 0 => Policy::parse(unsafe { text(p.str, p.len) }?, heap)?,
            _ => Policy::permissive(heap),
        };
        // SAFETY: as above.
        let popt: &str = unsafe { text(inp.popt, inp.popt_len) }?;
        let mut prog: FVec<'h, BpfInsn> = FVec::new(heap);
        let input = match (inp.insn_cnt, inp.ir_len) {
            (0, 0) => return Err(Error::invalid_input("no program")),
            (n, 0) => {
                if n > ctx.limits.max_insns {
                    return Err(Error::limit("too many instructions"));
                }
                if inp.insns.is_null() {
                    return Err(Error::invalid_input("NULL instructions"));
                }
                prog.reserve_exact(n as usize)?;
                for k in 0..n as usize {
                    // SAFETY: `insns` holds `insn_cnt` elements (contract);
                    // `bpf_insn` is only 4-byte aligned, so read unaligned.
                    let c = unsafe { inp.insns.add(k).read_unaligned() };
                    prog.push(BpfInsn::from(c))?;
                }
                Input::Bytecode(prog.as_slice())
            }
            (0, n) => {
                // SAFETY: `ir` holds `ir_len` bytes (contract).
                let blob = unsafe { bytes(inp.ir.cast(), n) }.ok_or(Error::invalid_input("NULL IR"))?;
                Input::Ir(blob)
            }
            _ => return Err(Error::invalid_input("both bytecode and IR given")),
        };
        let req = Request {
            input,
            gopt,
            popt,
            requested: inp.flags & EPASS_IN_REQUESTED != 0,
        };
        driver::run(ctx, facts, &policy, &req)
    })();
    match res {
        Ok(Outcome::Compiled(out)) => match publish(h, &out, o) {
            Ok(()) => 0,
            Err(e) => {
                crate::ctx_log!(ctx, Level::Error, "epass: {}\n", e);
                o.error = e.errno();
                1
            }
        },
        Ok(Outcome::LoadOriginal(e)) => {
            o.error = e.map_or(0, |e| e.errno());
            1
        }
        Err(e) => e.errno(),
    }
}

/// Copy the compiled program into host-allocated output buffers.
fn publish(h: &epass_host, out: &driver::Output<'_>, o: &mut epass_output) -> Result<()> {
    let n = out.insns.len();
    let insns = alloc_array::<epass_insn>(h, n)?;
    for (k, &i) in out.insns.iter().enumerate() {
        // SAFETY: `insns` has room for `n` elements.
        unsafe { insns.add(k).write(epass_insn::from(i)) };
    }
    o.insns = insns;
    o.insn_cnt = u32::try_from(n).map_err(|_| Error::limit("output too long"))?;
    let m = out.offsets.len();
    let offs = alloc_array::<u32>(h, m)?;
    for (k, &v) in out.offsets.iter().enumerate() {
        // SAFETY: `offs` has room for `m` elements.
        unsafe { offs.add(k).write(v) };
    }
    o.offsets = offs;
    o.offsets_cnt = u32::try_from(m).map_err(|_| Error::limit("output too long"))?;
    Ok(())
}

/// Copy the compilation log out, NUL-terminated.
fn copy_log(ctx: &Ctx<'_>, h: &epass_host, o: &mut epass_output) -> Result<()> {
    let log = ctx.log.try_borrow().map_err(|_| Error::internal("log busy"))?;
    let (a, b) = log.parts();
    let n = a.len() + b.len();
    if n == 0 {
        return Ok(());
    }
    let len = u32::try_from(n).map_err(|_| Error::limit("log too long"))?;
    let p = alloc_array::<u8>(h, n + 1)?;
    for (k, &byte) in a.iter().chain(b.iter()).enumerate() {
        // SAFETY: `p` has room for `n + 1` bytes.
        unsafe { p.add(k).write(byte) };
    }
    // SAFETY: as above.
    unsafe { p.add(n).write(0) };
    o.log = p.cast();
    o.log_len = len;
    Ok(())
}

/// Release an output's buffers.
///
/// # Safety
/// `out` is NULL or an output filled by [`epass_compile`] (or zeroed).
#[no_mangle]
pub unsafe extern "C" fn epass_output_free(out: *mut epass_output) {
    // SAFETY: NULL or valid (contract).
    let Some(o) = (unsafe { out.as_mut() }) else { return };
    // SAFETY: `host` was valid at compile time and must still be (contract).
    if let Some(h) = unsafe { o.host.as_ref() } {
        if let Some(free) = h.free {
            let release = |p: *mut c_void, layout: core::result::Result<Layout, core::alloc::LayoutError>| {
                if let (false, Ok(l)) = (p.is_null(), layout) {
                    // SAFETY: allocated by `alloc_array` with this layout.
                    unsafe { free(h.ctx, p, l.size(), l.align()) };
                }
            };
            release(o.insns.cast(), Layout::array::<epass_insn>(o.insn_cnt as usize));
            release(o.offsets.cast(), Layout::array::<u32>(o.offsets_cnt as usize));
            release(o.log.cast(), Layout::array::<u8>(o.log_len as usize + 1));
        }
    }
    *o = epass_output::EMPTY;
}

// Layouts must match epass.h on every target.
const _: () = {
    assert!(core::mem::size_of::<epass_insn>() == 8);
    assert!(core::mem::align_of::<epass_insn>() == 4);
    assert!(core::mem::size_of::<epass_sig>() == 4);
};
