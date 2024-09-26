#!/usr/bin/env python3

import regex as re

gid = 0
gmap = dict()


def fun(match):
    global gid, gmap
    old = match.group()
    newitem = f"verbose_err({gid}, "
    gmap[gid] = match.group(1)
    gid += 1
    return old.replace("verbose(", newitem)


content = ""
with open("verifier.c", "r") as f:
    content = f.read()

rec = r'verbose\(env[^"]*?"([^"]*?)"[^;]*?;[\s\n]*return'
rec = re.compile(rec)

nc = re.sub(rec, fun, content)

with open("verifier_modified.c", "w") as f:
    f.write(nc)

data = ""
for i in gmap:
    comment = gmap[i]
    if comment[-2:] == "\\n":
        comment = comment[:-2]
    data += f"BPF_VERIFIER_ERR_{i} = {i}, // {comment} \n"

header = f"""
enum bpf_verifier_error{{
    {data}
}};
"""

with open("error.h", "w") as f:
    f.write(header)
