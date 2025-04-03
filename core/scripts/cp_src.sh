#!/bin/bash
if [ ! -d $1 ]; then
  echo "Directory does not exists"
  exit 1
fi

files=$(find . -iname '*.c' -not -path "./build/*" -not -path "./tests/*" -not -path "./bpftests/*" -not -path "./epasstool/*")

for file in $files; do
    cp $file $1/
done
