#!/bin/bash

# Generating kernel source files

rm -rf build/kernel

mkdir -p build/kernel

files=$(find . -iname '*.h' -o -iname '*.c' -not -path "./build/*")

for file in $files; do
    cp $file build/kernel
done

cd build/kernel

rm read.c read.h probe.c

cfiles=$(find . -iname '*.c' -not -path "./build/*")

filelist=""

for file in $cfiles; do
    filelist="${filelist} ${file:2:-1}o"
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