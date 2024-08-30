cmake_minimum_required(VERSION 3.20)
project(bpf_ir)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wstrict-prototypes -O3")

add_library(bpf_ir STATIC 
    bpf_ir.c
    array.c
    ir_helper.c
    ir_value.c
    ir_bb.c
    ir_insn.c
    passes/phi_pass.c
    passes/add_counter_pass.c
    passes/add_constraint_pass.c
    passes/cut_bb_pass.c
    aux/prog_check.c
    ir_code_gen.c
    lii.c
)

add_executable(read read.c)

add_executable(readlog readlog.c)

target_link_libraries(read bpf_ir)

target_link_libraries(readlog bpf_ir)

add_executable(probe probe.c read.c array.c lii.c)

include_directories(include)
