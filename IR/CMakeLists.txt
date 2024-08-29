cmake_minimum_required(VERSION 3.20)
project(bpf_ir)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wstrict-prototypes -O3")

add_executable(
    read
    read.c
    bpf_ir.c
    array.c
    ir_helper.c
    ir_value.c
    ir_bb.c
    ir_insn.c
    passes/phi_pass.c
    passes/reachable_bb.c
    passes/add_counter_pass.c
    passes/add_constraint_pass.c
    passes/cut_bb_pass.c
    passes/end_bb.c
    aux/prog_check.c
    aux/fix_bb_succ.c
    ir_code_gen.c
)

add_executable(probe probe.c read.c array.c)

include_directories(include)
