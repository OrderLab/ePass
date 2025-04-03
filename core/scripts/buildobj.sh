#!/bin/bash

mkdir -p build

files=$(find . -iname '*.c' -not -path "./build/*" -not -path "./tests/*" -not -path "./bpftests/*" -not -path "./epasstool/*")

for file in $files; do
  name=$(basename $file)
  echo "  CC       $name.o"
  gcc -O2 -Iinclude -c $file -o build/$name.o
done
