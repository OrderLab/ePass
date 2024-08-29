#!/bin/bash

# Generating kernel source files

KERNEL_PATH=/home/linsy/Projects/ebpf/eBPF-kernel

rm -rf build/kernel

mkdir -p build/kernel

files=$(find . -iname '*.c' -not -path "./build/*" -not -path "./tests/*")

for file in $files; do
    cp $file build/kernel
done


cd build/kernel

rm read.c probe.c

cfiles=$(ls *.c)

filelist=""

for file in $cfiles; do
    filelist="${filelist} ${file::-1}o"
done

echo $filelist

makefile_content="""
obj-y :=$filelist
"""

echo $makefile_content > Makefile
# Remove redundant files

rm -rf ${KERNEL_PATH}/kernel/bpf/ir/
mkdir ${KERNEL_PATH}/kernel/bpf/ir/
cp * ${KERNEL_PATH}/kernel/bpf/ir/

cd ../../

rm ${KERNEL_PATH}/include/linux/bpf_ir.h

cp include/linux/bpf_ir.h ${KERNEL_PATH}/include/linux/
