//! ELF object input via libbpf (`libbpf-sys`).

use std::ffi::{CStr, CString};

use epass_core::bpf::BpfInsn;
use libbpf_sys as bpf;

/// Every program in the object (or the one named `section`), as
/// `(name, instructions)`.
pub fn programs(path: &str, section: Option<&str>) -> Result<Vec<(String, Vec<BpfInsn>)>, String> {
    let c = CString::new(path).map_err(|e| e.to_string())?;
    // SAFETY: `c` is a valid C string; the object is closed below.
    let obj = unsafe { bpf::bpf_object__open(c.as_ptr()) };
    if obj.is_null() {
        return Err(format!("libbpf cannot open '{path}'"));
    }
    let mut out = Vec::new();
    // SAFETY: `obj` is a live object; the iteration and accessors follow
    // libbpf's API, and instruction pointers are read within insn_cnt.
    unsafe {
        let mut prog = bpf::bpf_object__next_program(obj, std::ptr::null_mut());
        while !prog.is_null() {
            let n = bpf::bpf_program__name(prog);
            let name = if n.is_null() { String::new() } else { CStr::from_ptr(n).to_string_lossy().into_owned() };
            if section.is_none_or(|s| s == name) {
                let cnt = bpf::bpf_program__insn_cnt(prog) as usize;
                let p = bpf::bpf_program__insns(prog).cast::<u64>();
                let insns = (0..cnt).map(|k| BpfInsn::from_u64(p.add(k).read_unaligned())).collect();
                out.push((name, insns));
            }
            prog = bpf::bpf_object__next_program(obj, prog);
        }
        bpf::bpf_object__close(obj);
    }
    if out.is_empty() {
        return Err(match section {
            Some(s) => format!("no program named '{s}' in '{path}'"),
            None => format!("no programs in '{path}'"),
        });
    }
    Ok(out)
}
