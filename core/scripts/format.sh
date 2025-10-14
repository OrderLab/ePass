#!/bin/bash

files=$(find . -iname '*.h' -o -iname '*.c' -not -path "./build/*")


clang_path=$(command -v clang-format 2>/dev/null)

if [ -z "$clang_path" ]; then
    for ver in {18..14}; do  # check clang-20 down to clang-10
        if command -v clang-format-$ver &>/dev/null; then
            clang_path=$(command -v clang-format-$ver)
            break
        fi
    done
fi

if [ -z "$clang_path" ]; then
    echo "Clang-format not found"
    exit 1
fi

for file in $files; do
    # echo "Formatting $file"
    $clang_path -i $file
done

for job in `jobs -p`; do
    wait $job
done

echo "Formatting done"
