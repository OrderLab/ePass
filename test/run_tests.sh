#!/bin/bash

# files=$(find output -iname '*.o')

# for file in $files; do
#     printf "Testing $file ..."
#     epasstool -m read -p $file -s "prog"
#     retVal=$?
#     if [ $retVal -ne 0 ]; then
#         echo "FAILED"
#         continue
#     fi
#     echo "PASSED"
# done

# Test logs, may not pass (in most cases)
# files=$(find progs/txt/fail -iname '*.txt')
# for file in $files; do
#     printf "Testing $file ..."
#     epasstool -m readlog -p $file > /dev/null
#     echo "PASSED"
# done

files=$(find progs/txt/pass -iname '*.txt')

for file in $files; do
    printf "Testing $file ..."
    epasstool -m readlog -p $file -s "prog"
    retVal=$?
    if [ $retVal -ne 0 ]; then
        echo "FAILED"
        continue
    fi
    echo "PASSED"
done
