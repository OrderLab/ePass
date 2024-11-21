// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

// Kernel-side Low-level Interface Implementation

#ifdef __KERNEL__

void *malloc_proto(size_t size)
{
	return kvzalloc(size, GFP_KERNEL);
}

void free_proto(void *ptr)
{
	kvfree(ptr);
}

int parse_int(const char *str, int *val)
{
	return kstrtoint(str, 10, val);
}

u64 get_cur_time_ns(void)
{
	return ktime_get_ns();
}

#else

void *malloc_proto(size_t size)
{
	void *data = malloc(size);
	if (data) {
		memset(data, 0, size);
	}
	return data;
}

void free_proto(void *ptr)
{
	free(ptr);
}

int parse_int(const char *str, int *val)
{
	char *end;
	*val = strtol(str, &end, 10);
	if (*end != '\0') {
		return -EINVAL;
	}
	return 0;
}

u64 get_cur_time_ns(void)
{
	struct timespec t = { 0, 0 };
	clock_gettime(CLOCK_MONOTONIC, &t);
	return 1e9 * t.tv_sec + t.tv_nsec;
}

#endif
