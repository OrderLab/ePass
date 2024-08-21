#!/bin/bash

files=$(find . -iname '*.h' -o -iname '*.c' -not -path "./build/*")

for file in $files; do
    echo "Formatting $file"
    clang-format -i $file &
done

for job in `jobs -p`; do
    wait $job
done
