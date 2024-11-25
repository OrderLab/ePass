cmake_minimum_required(VERSION 3.20)
project(epass C)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wstrict-prototypes -Wenum-compare -Wunused-variable -Wunused-but-set-variable -Wsign-compare -O3")
OPTION(EPASS_LIBBPF "Compile with ePass libbpf" OFF)
IF(EPASS_LIBBPF)
    ADD_DEFINITIONS(-DEPASS_LIBBPF)
ENDIF(EPASS_LIBBPF)
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
    passes/msan.c
    passes/div_by_zero.c
    passes/jmp_complexity.c
    aux/prog_check.c
    aux/disasm.c
    aux/kern_utils.c
    ir_code_gen.c
    lii.c
)

include_directories(include)

set_target_properties(epass PROPERTIES PUBLIC_HEADER "include/linux/bpf_ir.h")

add_subdirectory(epasstool)

INSTALL(TARGETS epass)
