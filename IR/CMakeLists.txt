cmake_minimum_required(VERSION 3.20)
project(bpf_ir)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3")

add_executable(
    read
    read.c
    bpf_ir.c
    array.c
    ir_helper.c
    ir_bb.c
    ir_insn.c
    passes/phi_pass.c
    passes/reachable_bb.c
    passes/add_counter_pass.c
    passes/add_constraint_pass.c
    passes/cut_bb_pass.c
    passes/end_bb.c
    aux/add_stack_offset.c
    aux/live_variable.c
    aux/prog_check.c
    aux/eliminate_ssa.c
    aux/conflict_analysis.c
    aux/graph_coloring.c
    aux/explicit_reg.c
    aux/coaleasing.c
    aux/spill.c
    aux/translate.c
    ir_code_gen.c
)

add_executable(probe probe.c read.c array.c)

include_directories(include)
