#!/usr/bin/env python3

# This script generates the constructor for the instruction class from base constructor

import regex as re


def handle_ir(matches, header, src):
    # print(matches)
    for insn, args in matches:
        print(insn)
        args = args.split(",")
        args = [arg.strip() for arg in args]
        if len(args) == 0:
            print("Error: zero arguments")
            continue
        if args[0] != "struct bpf_ir_env *env":
            print("Error: First argument is not struct bpf_ir_env *env")
            continue
        print(args)


def handle_cg(matches, header, src):
    # print(matches)
    for insn, args in matches:
        print(insn)


def main():
    header = []
    src = []
    proto = ""
    with open("ir_insn.c") as f:
        proto = f.read()
    regc = r"static struct ir_insn \*create_(.*?)_insn_base\(([\s\S]*?)\)"
    regc = re.compile(regc)
    all_matches = regc.findall(proto)
    handle_ir(all_matches, header, src)
    regc = r"static struct ir_insn \*create_(.*?)_insn_base_cg\(([\s\S]*?)\)"
    regc = re.compile(regc)
    all_matches = regc.findall(proto)
    handle_cg(all_matches, header, src)


main()
