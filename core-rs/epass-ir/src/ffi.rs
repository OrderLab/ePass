//! C ABI for embedding ePass into C projects (notably the patched libbpf).
//!
//! The Rust API uses non-FFI-safe types (`Vec`, enums, `Result`), so this
//! module provides a small, stable C surface. A run takes a `bpf_insn` array
//! plus an option string, produces an opaque result holding the rewritten
//! program and a log, and exposes accessors plus a free function.
//!
//! ```c
//! struct bpf_insn;                       // the standard kernel/libbpf type
//! typedef struct epass_result epass_result;
//!
//! epass_result *epass_run(const struct bpf_insn *insns, size_t insn_cnt,
//!                         const char *gopt, int *out_err);
//! const struct bpf_insn *epass_result_insns(const epass_result *r);
//! size_t epass_result_insn_cnt(const epass_result *r);
//! const char *epass_result_log(const epass_result *r);   // NUL-terminated
//! void epass_result_free(epass_result *r);
//! ```
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, CStr, CString};

use crate::bytecode::BpfInsn;
use crate::{autorun, default_passes, Env, Opts};

/// C-ABI mirror of the kernel/libbpf `struct bpf_insn` (8 bytes, packed bitfields
/// for the registers). Field order/sizes match exactly so the two are
/// bit-compatible.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct epass_insn {
    pub code: u8,
    /// `dst_reg:4 | src_reg:4` packed (low nibble = dst).
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl From<epass_insn> for BpfInsn {
    fn from(c: epass_insn) -> Self {
        BpfInsn {
            code: c.code,
            dst_reg: c.regs & 0x0f,
            src_reg: (c.regs >> 4) & 0x0f,
            off: c.off,
            imm: c.imm,
        }
    }
}

impl From<BpfInsn> for epass_insn {
    fn from(b: BpfInsn) -> Self {
        epass_insn {
            code: b.code,
            regs: (b.dst_reg & 0x0f) | ((b.src_reg & 0x0f) << 4),
            off: b.off,
            imm: b.imm,
        }
    }
}

/// Opaque result handle returned to C.
pub struct epass_result {
    insns: Vec<epass_insn>,
    log: CString,
}

/// Run the full ePass pipeline on a program.
///
/// # Safety
/// `insns` must point to `insn_cnt` valid `epass_insn` values. `gopt` may be
/// NULL or a NUL-terminated UTF-8 string. On success returns a non-null handle
/// and writes `0` to `out_err` (if non-null); on failure returns NULL and
/// writes a negative errno-style code.
#[no_mangle]
pub unsafe extern "C" fn epass_run(
    insns: *const epass_insn,
    insn_cnt: usize,
    gopt: *const c_char,
    out_err: *mut c_int,
) -> *mut epass_result {
    let set_err = |v: c_int| {
        if !out_err.is_null() {
            unsafe { *out_err = v };
        }
    };

    if insns.is_null() && insn_cnt != 0 {
        set_err(-22); // -EINVAL
        return std::ptr::null_mut();
    }

    // Decode the input program.
    let input: Vec<BpfInsn> = (0..insn_cnt)
        .map(|i| unsafe { *insns.add(i) }.into())
        .collect();

    // Parse options.
    let mut opts = Opts::default();
    if !gopt.is_null() {
        if let Ok(s) = unsafe { CStr::from_ptr(gopt) }.to_str() {
            if let Err(_e) = opts.apply_gopt(s) {
                set_err(-22);
                return std::ptr::null_mut();
            }
        }
    }

    let mut env = Env::new(opts, input);
    let passes = default_passes();
    match autorun(&mut env, &passes) {
        Ok(()) => {
            let insns: Vec<epass_insn> = env.insns.iter().map(|&b| b.into()).collect();
            let log = CString::new(env.take_log()).unwrap_or_default();
            set_err(0);
            Box::into_raw(Box::new(epass_result { insns, log }))
        }
        Err(e) => {
            set_err(e.errno() as c_int);
            std::ptr::null_mut()
        }
    }
}

/// Pointer to the rewritten instruction array (valid until `epass_result_free`).
///
/// # Safety
/// `r` must be a handle returned by [`epass_run`].
#[no_mangle]
pub unsafe extern "C" fn epass_result_insns(r: *const epass_result) -> *const epass_insn {
    if r.is_null() {
        return std::ptr::null();
    }
    unsafe { (*r).insns.as_ptr() }
}

/// Number of rewritten instructions.
///
/// # Safety
/// `r` must be a handle returned by [`epass_run`].
#[no_mangle]
pub unsafe extern "C" fn epass_result_insn_cnt(r: *const epass_result) -> usize {
    if r.is_null() {
        return 0;
    }
    unsafe { (*r).insns.len() }
}

/// NUL-terminated log text accumulated during the run.
///
/// # Safety
/// `r` must be a handle returned by [`epass_run`].
#[no_mangle]
pub unsafe extern "C" fn epass_result_log(r: *const epass_result) -> *const c_char {
    if r.is_null() {
        return std::ptr::null();
    }
    unsafe { (*r).log.as_ptr() }
}

/// Free a result handle.
///
/// # Safety
/// `r` must be a handle returned by [`epass_run`] (or NULL), and must not be
/// used afterwards.
#[no_mangle]
pub unsafe extern "C" fn epass_result_free(r: *mut epass_result) {
    if !r.is_null() {
        drop(unsafe { Box::from_raw(r) });
    }
}
