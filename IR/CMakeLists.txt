cmake_minimum_required(VERSION 3.20)
project(bpf_ir)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3")

add_executable(read read.c bpf_ir.c array.c ir_helper.c)
add_executable(probe probe.c read.c array.c)
