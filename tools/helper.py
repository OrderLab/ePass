#!/usr/bin/env python3
import subprocess
import re

with open("helper.h", "r") as f:
    content = f.read()

res = re.compile(r"FN\((.*?), (.*?),").findall(content)

kernel_path = "/home/linsy/Projects/ebpf/ePass-kernel"

mapping = {}

for name, i in res:
    # print(name, int(i))

    process = subprocess.Popen(['/usr/bin/rg', '-rn', kernel_path, '-e', f"BPF_CALL_.\\(bpf_{name}", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    # print(err)
    # print(out)
    num = re.compile(r"BPF_CALL_(.*?)\(bpf_" + name + r"(,|\))").findall(out.decode())
    # print(len(num))
    ctnum = -1
    err = 0
    for it, _ in num:
        if ctnum == -1:
            ctnum = int(it)
        if ctnum != int(it):
            err = 1
            break
    if err == 1 or ctnum == -1:
        print("Error", name, i)
        continue
    mapping[int(i)] = (ctnum, name)

header = ""
body = ""

for k, (vn, name) in mapping.items():
    header += f"{k},"
    body += f"[{k}] = {vn}, // {name}\n"

with open("helper.c", "w") as f:
    f.write(f"{header}\n\n{body}\n")
