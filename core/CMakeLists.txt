cmake_minimum_required(VERSION 3.20)
project(epass)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wstrict-prototypes -Wenum-compare -Wunused-variable -Wunused-but-set-variable -Wsign-compare -O3")

add_library(epass STATIC
    bpf_ir.c
    array.c
    ir_helper.c
    ir_value.c
    ir_bb.c
    ir_insn.c
    passes/phi_pass.c
    passes/add_counter_pass.c
    passes/translate_throw.c
    passes/optimization.c
    passes/cg_prepare.c
    aux/prog_check.c
    aux/disasm.c
    aux/kern_utils.c
    ir_code_gen.c
    lii.c
)

add_executable(readload userspace/readload.c)
add_executable(read userspace/read.c userspace/test_pass1.c)
add_executable(readlog userspace/readlog.c)
add_executable(print userspace/print.c)
add_executable(printlog userspace/printlog.c)
add_executable(epasstool userspace/epasstool.c)

target_link_libraries(read bpf epass)
target_link_libraries(readload bpf epass)
target_link_libraries(readlog epass)
target_link_libraries(print bpf epass)
target_link_libraries(printlog epass)
target_link_libraries(epasstool bpf epass)

include_directories(include)

INSTALL(TARGETS epass
        LIBRARY DESTINATION usr/local/lib
)
