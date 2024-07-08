#ifndef __READ_H__
#define __READ_H__
#include <linux/bpf.h>
#include <stdio.h>

void run(struct bpf_insn *, size_t);

#endif
