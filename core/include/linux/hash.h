/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_HASHTABLE_H
#define _LINUX_HASHTABLE_H

#include <linux/types.h>

#define GOLDEN_RATIO_32 0x61C88647

static inline __u32 __hash_32(__u32 val)
{
	return val * GOLDEN_RATIO_32;
}

#endif
