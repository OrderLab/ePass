#!/bin/bash

files=$(find output -iname '*.o')

for file in $files; do
    epasstool -m read -p $file -s "prog"
    retVal=$?
    if [ $retVal -ne 0 ]; then
        echo "Found error with $file"
    fi
done
