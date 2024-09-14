use libbpf_rs::{libbpf_sys::bpf_insn, ObjectBuilder};
use std::ffi::{c_char, c_int, c_ulong};

#[repr(C)]
pub struct BpfIrEnv {
    err: c_int,
    insn_cnt: c_ulong,
    log: *mut c_char,
    insns: *mut bpf_insn,
    log_pos: c_ulong,
}

extern "C" {
    pub fn bpf_ir_print_log_dbg(env: *mut BpfIrEnv);
    pub fn bpf_ir_init_env() -> *mut BpfIrEnv;
    pub fn bpf_ir_free_env(env: *mut BpfIrEnv);
    pub fn bpf_ir_run(env: *mut BpfIrEnv, insns: *const bpf_insn, insn_cnt: c_ulong);
}

fn main() {
    let mut builder = ObjectBuilder::default();
    let obj = builder
        .open_file("../IR/tests/loop1.o")
        .expect("Failed to open object file");
    let prog = obj
        .progs()
        .find(|map| map.name() == "prog")
        .expect("Failed to find program");
    unsafe {
        let env = bpf_ir_init_env();
        bpf_ir_run(env, prog.insns().as_ptr(), prog.insns().len() as c_ulong);
        bpf_ir_print_log_dbg(env);
        bpf_ir_free_env(env);
    }
}
