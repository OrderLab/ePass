#!/usr/bin/env python3

import regex as re

gid = 0

def fun(match):
    global gid
    old = match.group()
    newitem = f"verbose_err({gid}, "
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
