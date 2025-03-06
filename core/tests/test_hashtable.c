// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

struct h_node {
	int data;
	char name[32];
};

static u32 hash(const char *s)
{
	u32 key = 0;
	char c;

	while ((c = *s++))
		key += c;

	return key;
}

int main(void)
{
	return 0;
}
