read: read.c bpf_ir.c array.c
	gcc -O2 -o read read.c bpf_ir.c array.c

probe_insn: read.c probe.c
	gcc -O2 -o probe_insn read.c probe.c
