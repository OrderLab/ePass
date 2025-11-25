cmake_minimum_required(VERSION 3.20)
project(epass VERSION 0.2.0 LANGUAGES C)
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Werror -Wunused-function -Wstrict-prototypes -Wenum-compare -Wunused-variable -Wunused-but-set-variable -Wsign-compare -O2 -fstack-protector-strong -fno-omit-frame-pointer -fno-strict-aliasing -std=gnu11"
)

find_path(LIBBPF_INCLUDE_DIR bpf/libbpf.h)
find_library(LIBBPF_LIBRARY bpf)

if(NOT LIBBPF_INCLUDE_DIR OR NOT LIBBPF_LIBRARY)
    message(FATAL_ERROR "libbpf not found. Please install it.")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
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
  passes/constraint.c
  aux/prog_check.c
  aux/disasm.c
  aux/kern_utils.c
  aux/cg_prog_check.c
  ir_cg.c
  ir_cg_norm.c
  lli.c
  include/linux/bpf_ir.h)

add_executable(test_list tests/test_list.c)
add_executable(test_ptrset tests/test_ptrset.c)

target_link_libraries(test_ptrset epass)

include_directories(include)

set_target_properties(epass PROPERTIES PUBLIC_HEADER "include/linux/bpf_ir.h")

add_subdirectory(epasstool)

install(TARGETS epass)
