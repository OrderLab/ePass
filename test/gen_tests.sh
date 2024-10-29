#!/bin/bash

bpftool btf dump file /sys/kernel/btf/vmlinux format c > progs/vmlinux.h

mkdir -p output

files=$(find . -iname '*.c')

for file in $files; do
    base_name=$(basename $file)
    clang -O2 -I/usr/include/$(uname -m)-linux-gnu -target bpf -g -c $file -o output/$base_name.o
    clang -O0 -I/usr/include/$(uname -m)-linux-gnu -target bpf -g -c $file -o output/$base_name.nop.o
done

