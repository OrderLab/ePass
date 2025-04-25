cmake_minimum_required(VERSION 3.20)
project(epass VERSION 0.2.0 LANGUAGES C)
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Werror -Wunused-function -Wstrict-prototypes -Wenum-compare -Wunused-variable -Wunused-but-set-variable -Wsign-compare -O3"
)

add_library(
  epass STATIC
  bpf_ir.c
  array.c
  ptrset.c
  ir_helper.c
  ir_value.c
  ir_bb.c
  ir_insn.c
  passes/phi_pass.c
  passes/insn_counter_pass.c
  passes/translate_throw.c
  passes/optimization.c
  passes/cg_prepare.c
  passes/code_compaction.c
  passes/msan.c
  passes/div_by_zero.c
  passes/jmp_complexity.c
  aux/prog_check.c
  aux/disasm.c
  aux/kern_utils.c
  aux/cg_prog_check.c
  ir_cg_v2.c
  ir_cg_norm_v2.c
  lli.c
  include/linux/bpf_ir.h)

add_executable(test_list tests/test_list.c)
add_executable(test_ptrset tests/test_ptrset.c)

target_link_libraries(test_ptrset epass)

include_directories(include)

set_target_properties(epass PROPERTIES PUBLIC_HEADER "include/linux/bpf_ir.h")

add_subdirectory(epasstool)

install(TARGETS epass)
