#!/bin/bash

# Generating kernel source files

rm -rf build/kernel

mkdir -p build/kernel

files=$(find . -iname '*.c' -not -path "./build/*" -not -path "./tests/*")

for file in $files; do
    cp $file build/kernel
done

cp include/bpf_ir.h build/kernel

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

rm -rf /home/linsy/Projects/ebpf/eBPF-kernel/kernel/bpf/ir/
mkdir /home/linsy/Projects/ebpf/eBPF-kernel/kernel/bpf/ir/
cp * /home/linsy/Projects/ebpf/eBPF-kernel/kernel/bpf/ir/
