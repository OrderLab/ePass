const SRC_FILES: &[&str] = &[
    "bpf_ir.c",
    "array.c",
    "ir_helper.c",
    "ir_value.c",
    "ir_bb.c",
    "ir_insn.c",
    "passes/phi_pass.c",
    "passes/add_counter_pass.c",
    "passes/add_constraint_pass.c",
    "passes/cut_bb_pass.c",
    "aux/prog_check.c",
    "aux/disasm.c",
    "ir_code_gen.c",
    "lii.c",
];

const SRC_DIR: &str = "../IR/";

const SRC_INCLUDE: &str = "../IR/include/";

fn main() {
    // println!("cargo:rustc-link-search=../IR/build/");
    for src_file in SRC_FILES {
        println!("cargo:rerun-if-changed={}", format!("{}{}", SRC_DIR, src_file));
    }
    println!("cargo:rerun-if-changed={}", format!("{}{}", SRC_INCLUDE, "linux/bpf_ir.h"));

    let mut builder = cc::Build::new();
    builder.include(SRC_INCLUDE);
    for src_file in SRC_FILES {
        builder.file(format!("{}{}", SRC_DIR, src_file));
    }
    builder.compile("hello");
}
