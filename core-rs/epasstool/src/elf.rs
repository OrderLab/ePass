//! ELF object input/output via libbpf (raw FFI through `libbpf-sys`).
//!
//! We read each program's instruction stream, run it through ePass, and
//! (optionally) write the rewritten instructions back into the object.

use std::ffi::{CStr, CString};

use epass_ir::BpfInsn;
use libbpf_sys as bpf;

use crate::cli::{Mode, UserOpts};
use crate::run;

type Error = Box<dyn std::error::Error>;

/// Convert a libbpf `bpf_insn` to our representation via its packed bits.
fn from_lib(insn: &bpf::bpf_insn) -> BpfInsn {
    // Reconstruct the packed u64 from the C bitfields.
    // libbpf-sys exposes dst_reg/src_reg as a single byte via bitfields; we
    // read the raw bytes to be layout-independent.
    let raw: u64 = unsafe { std::mem::transmute_copy(insn) };
    BpfInsn::from_u64(raw)
}

fn to_lib(insn: &BpfInsn) -> bpf::bpf_insn {
    let raw = insn.to_u64();
    unsafe { std::mem::transmute_copy(&raw) }
}

pub fn run_elf(uo: &UserOpts) -> Result<(), Error> {
    let path = CString::new(uo.prog.as_str())?;
    let obj = unsafe { bpf::bpf_object__open(path.as_ptr()) };
    if obj.is_null() {
        return Err(format!("failed to open ELF object '{}'", uo.prog).into());
    }
    let result = process_object(uo, obj);
    unsafe { bpf::bpf_object__close(obj) };
    result
}

fn process_object(uo: &UserOpts, obj: *mut bpf::bpf_object) -> Result<(), Error> {
    let want_section = uo.section.clone();
    let mut prog = unsafe { bpf::bpf_object__next_program(obj, std::ptr::null_mut()) };
    let mut processed_any = false;
    let mut total = 0usize;

    while !prog.is_null() {
        let name = unsafe {
            let n = bpf::bpf_program__name(prog);
            if n.is_null() {
                String::new()
            } else {
                CStr::from_ptr(n).to_string_lossy().into_owned()
            }
        };

        // If a specific section was requested, skip non-matching programs.
        let selected = match &want_section {
            Some(s) => &name == s,
            None => true,
        };

        if selected {
            let cnt = unsafe { bpf::bpf_program__insn_cnt(prog) } as usize;
            let insns_ptr = unsafe { bpf::bpf_program__insns(prog) };
            let mut prog_insns = Vec::with_capacity(cnt);
            for i in 0..cnt {
                let insn = unsafe { &*insns_ptr.add(i) };
                prog_insns.push(from_lib(insn));
            }
            total += cnt;
            processed_any = true;

            let out = run::process(uo, prog_insns)?;

            // Write back into the program (read mode only, when modified).
            if uo.mode == Mode::Read {
                let lib_insns: Vec<bpf::bpf_insn> = out.iter().map(to_lib).collect();
                let rc = unsafe {
                    bpf::bpf_program__set_insns(
                        prog,
                        lib_insns.as_ptr() as *mut bpf::bpf_insn,
                        lib_insns.len() as bpf::size_t,
                    )
                };
                if rc != 0 {
                    return Err(format!("bpf_program__set_insns failed ({rc})").into());
                }
            }

            // Write the output file if requested (last selected program wins,
            // matching the per-program behavior of the C tool).
            if let Some(path) = &uo.prog_out {
                run::write_output(uo, path, &out)?;
            }
        }

        prog = unsafe { bpf::bpf_object__next_program(obj, prog) };
        // If a section was explicitly requested, stop after the first program
        // when not iterating all.
        if want_section.is_some() && selected {
            break;
        }
    }

    if !processed_any {
        return Err("no matching program found in object".into());
    }
    eprintln!("processed {total} instructions");
    Ok(())
}
