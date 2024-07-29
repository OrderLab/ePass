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
    phi_pass.c
    reachable_bb.c
    add_counter_pass.c
    add_stack_offset.c
    add_constraint_pass.c
    live_variable.c
    cut_bb_pass.c
)

add_executable(probe probe.c read.c array.c)

include_directories(include)
