#!/bin/bash

# bpftool btf dump file /sys/kernel/btf/vmlinux format c > progs/vmlinux.h

mkdir -p output

files=$(find . \( -path ./env -o -path ./pass \) -prune -o -name '*.c' -print)

rm Makefile
all_objs=""

for file in $files; do
    base_name=$(echo $file | sed -r 's/\.c//g' | sed -r 's/\.\///g' | tr '/' '_')
    printf "output/$base_name.o: $file\n\tclang -O2 -I./progs -I/usr/include/$(uname -m)-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -c \$< -o \$@\n" >> Makefile
    printf "output/$base_name.ll: $file\n\tclang -O2 -I./progs -I/usr/include/$(uname -m)-linux-gnu -D__TARGET_ARCH_x86 -target bpf -g -emit-llvm -S -c \$< -o \$@\n" >> Makefile
    all_objs="output/$base_name.o output/$base_name.ll "$all_objs
done

echo "all:$all_objs" >> Makefile
