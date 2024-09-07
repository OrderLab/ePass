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

add_executable(read userspace/read.c)
add_executable(readlog userspace/readlog.c)
add_executable(print userspace/print.c)
add_executable(printlog userspace/printlog.c)

target_link_libraries(read bpf bpf_ir)
target_link_libraries(readlog bpf_ir)
target_link_libraries(print bpf)

include_directories(include)
