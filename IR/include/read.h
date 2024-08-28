#ifndef __READ_H__
#define __READ_H__
#include <linux/bpf.h>
#include <stdio.h>

int run(struct bpf_insn *, size_t);

#endif
