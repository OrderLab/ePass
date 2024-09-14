#!/usr/bin/env python3

# This script generates the constructor for the instruction class from base constructor

import regex as re


def handle_ir(matches, header, src):
    # print(matches)
    for insn,extra, args in matches:
        args = args.split(",")
        args = [arg.strip() for arg in args]
        if len(args) < 2:
            print("Error: wrong arguments")
            continue
        if args[0] != "struct bpf_ir_env *env":
            print("Error: First argument is not struct bpf_ir_env *env")
            continue
        if args[1] != "struct ir_basic_block *bb":
            print("Error: Second argument is not struct ir_basic_block *bb")
            continue
        del args[0]
        del args[0]
        # print(args)
        cargs = []
        rec = r".*[ \*](.*)$"
        rec = re.compile(rec)
        for arg in args:
            res = rec.findall(arg)
            cargs.append(res[0])

        pargs = ", ".join(args)
        cargs = ", ".join(cargs)
        if len(pargs) > 0:
            pargs = pargs + ","
        if len(cargs) > 0:
            cargs = "," +cargs 
        ir_fun = f"""
struct ir_insn *{insn}{extra}(struct bpf_ir_env *env, struct ir_insn *pos_insn, {pargs} enum insert_position pos)
{{
	struct ir_insn *new_insn =
		{insn}_base{extra}(pos_insn->parent_bb {cargs});
	insert_at(new_insn, pos_insn, pos);
	return new_insn;
}}

struct ir_insn *{insn}_bb{extra}(struct bpf_ir_env *env, struct ir_basic_block *pos_bb, {pargs} enum insert_position pos)
{{
	struct ir_insn *new_insn =
		{insn}_base{extra}(pos_bb {cargs});
	insert_at_bb(new_insn, pos_bb, pos);
	return new_insn;
}}
"""
        src.append(ir_fun)

        ir_fun_h = f"""
struct ir_insn *{insn}{extra}(struct bpf_ir_env *env, struct ir_insn *pos_insn, {pargs} enum insert_position pos);

struct ir_insn *{insn}_bb{extra}(struct bpf_ir_env *env, struct ir_basic_block *pos_bb, {pargs} enum insert_position pos);
"""
        header.append(ir_fun_h)

def insert(header, src):
    srcfile = ""
    with open("ir_insn.c") as f:
        srcfile = f.read().split("/* Generated Constructors End */")
    print(srcfile)
    with open("ir_insn.c", "w") as f:
        f.write(srcfile[0])
        f.write("/* Generated Constructors Start */")
        # f.write(header)
        # f.write(src)
        f.write("/* Generated Constructors End */")

def main():
    header = []
    src = []
    proto = ""
    with open("ir_insn.c") as f:
        proto = f.read()
    regc = r"static struct ir_insn \*(create_.*?_insn)_base(.*?)\(([\s\S]*?)\)"
    regc = re.compile(regc)
    all_matches = regc.findall(proto)
    handle_ir(all_matches, header, src)
    header = "".join(header)
    src = "".join(src)
    # print(src)
    insert(header, src)


main()
