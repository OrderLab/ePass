import re
import glob
import os

o_files = glob.glob(os.path.join("output", "*.s"))
nums = []
for f in o_files:
    with open(f, "r") as file:
        content = file.read()
    count = re.findall(r" ([0-9]*?):", content)
    maxn = 0
    for c in count:
        if c != "" and int(c) > maxn:
            maxn = int(c)
    nums.append(maxn+1)

print(nums)

o_files = glob.glob(os.path.join("progs/txt", "*.txt"))
nums = []
for f in o_files:
    with open(f, "r") as file:
        content = file.read()
    count = re.findall(r"insn\[([0-9]*?)\]", content)
    maxn = 0
    for c in count:
        if c != "" and int(c) > maxn:
            maxn = int(c)
    nums.append(maxn+1)

print(max(nums), min(nums), sum(nums)/len(nums))
