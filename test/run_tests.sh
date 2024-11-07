#!/bin/bash

success=0
tot=0

start=$(date +%s.%N)

files=$(find output -iname '*.o')

for file in $files; do
    tot=$((tot+1))
    printf "Testing $file ..."
    epass -m read -p $file -s "prog"
    retVal=$?
    if [ $retVal -ne 0 ]; then
        echo "FAILED"
        continue
    fi
    success=$((success+1))
    echo "PASSED"
done

# Test logs, may not pass (in most cases)

files=$(find progs/txt -iname '*.txt')

for file in $files; do
    tot=$((tot+1))
    printf "Testing $file ..."
    epass -m readlog -p $file -s "prog"
    retVal=$?
    if [ $retVal -ne 0 ]; then
        echo "FAILED"
        continue
    fi
    success=$((success+1))
    echo "PASSED"
done

end=$(date +%s.%N)
runtime=$( echo "$end - $start" | bc -l )

echo "Finished testing $tot tests in $runtime seconds"
echo "Success: $success/$tot"
