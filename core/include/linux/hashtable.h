/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Statically sized hash table implementation
 * (C) 2012  Sasha Levin <levinsasha928@gmail.com>
 */

#ifndef _LINUX_HASHTABLE_H
#define _LINUX_HASHTABLE_H

#include "linux/list.h"
#include <linux/types.h>

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

#define hash_long(val, bits) hash_64(val, bits)

static __always_inline int fls(__u32 n)
{
	if (n == 0)
		return 0;
	return 32 - __builtin_clz(n);
}

static __always_inline int fls64(__u64 n)
{
	if (n == 0)
		return 0;
	return 64 - __builtin_clzll(n);
}

static __always_inline __attribute__((const)) int __ilog2_u32(__u32 n)
{
	return fls(n) - 1;
}

static __always_inline int __ilog2_u64(__u64 n)
{
	return fls64(n) - 1;
}
/**
 * ilog2 - log base 2 of 32-bit or a 64-bit unsigned value
 * @n: parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 * the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
#define ilog2(n)                                                             \
	(__builtin_constant_p(n) ? ((n) < 2 ? 0 : 63 - __builtin_clzll(n)) : \
	 (sizeof(n) <= 4)	 ? __ilog2_u32(n) :                          \
				   __ilog2_u64(n))

static inline __u32 __hash_32(__u32 val)
{
	return val * GOLDEN_RATIO_32;
}

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static inline __u32 hash_32(__u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32(val) >> (32 - bits);
}

static __always_inline __u32 hash_64(__u64 val, unsigned int bits)
{
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
}

#define DEFINE_HASHTABLE(name, bits)                                         \
	struct hlist_head name[1 << (bits)] = { [0 ...((1 << (bits)) - 1)] = \
							HLIST_HEAD_INIT }

#define DEFINE_READ_MOSTLY_HASHTABLE(name, bits)              \
	struct hlist_head name[1 << (bits)] __read_mostly = { \
		[0 ...((1 << (bits)) - 1)] = HLIST_HEAD_INIT  \
	}

#define DECLARE_HASHTABLE(name, bits) struct hlist_head name[1 << (bits)]

#define HASH_SIZE(name) (ARRAY_SIZE(name))
#define HASH_BITS(name) ilog2(HASH_SIZE(name))

/* Use hash_32 when possible to allow for fast 32bit hashing in 64bit kernels. */
#define hash_min(val, bits) \
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))

static inline void __hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

/**
  * hash_init - initialize a hash table
  * @hashtable: hashtable to be initialized
  *
  * Calculates the size of the hashtable from the given parameter, otherwise
  * same as hash_init_size.
  *
  * This has to be a macro since HASH_BITS() will not work on pointers since
  * it calculates the size during preprocessing.
  */
#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))

/**
  * hash_add - add an object to a hashtable
  * @hashtable: hashtable to add to
  * @node: the &struct hlist_node of the object to be added
  * @key: the key of the object to be added
  */
#define hash_add(hashtable, node, key) \
	hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])

/**
  * hash_hashed - check whether an object is in any hashtable
  * @node: the &struct hlist_node of the object to be checked
  */
static inline bool hash_hashed(struct hlist_node *node)
{
	return !hlist_unhashed(node);
}

static inline bool __hash_empty(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		if (!hlist_empty(&ht[i]))
			return false;

	return true;
}

/**
  * hash_empty - check whether a hashtable is empty
  * @hashtable: hashtable to check
  *
  * This has to be a macro since HASH_BITS() will not work on pointers since
  * it calculates the size during preprocessing.
  */
#define hash_empty(hashtable) __hash_empty(hashtable, HASH_SIZE(hashtable))

/**
  * hash_del - remove an object from a hashtable
  * @node: &struct hlist_node of the object to remove
  */
static inline void hash_del(struct hlist_node *node)
{
	hlist_del_init(node);
}

/**
  * hash_for_each - iterate over a hashtable
  * @name: hashtable to iterate
  * @bkt: integer to use as bucket loop cursor
  * @obj: the type * to use as a loop cursor for each entry
  * @member: the name of the hlist_node within the struct
  */
#define hash_for_each(name, bkt, obj, member)                               \
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name); \
	     (bkt)++)                                                       \
		hlist_for_each_entry(obj, &name[bkt], member)

/**
  * hash_for_each_safe - iterate over a hashtable safe against removal of
  * hash entry
  * @name: hashtable to iterate
  * @bkt: integer to use as bucket loop cursor
  * @tmp: a &struct hlist_node used for temporary storage
  * @obj: the type * to use as a loop cursor for each entry
  * @member: the name of the hlist_node within the struct
  */
#define hash_for_each_safe(name, bkt, tmp, obj, member)                     \
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name); \
	     (bkt)++)                                                       \
		hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)

/**
  * hash_for_each_possible - iterate over all possible objects hashing to the
  * same bucket
  * @name: hashtable to iterate
  * @obj: the type * to use as a loop cursor for each entry
  * @member: the name of the hlist_node within the struct
  * @key: the key of the objects to iterate over
  */
#define hash_for_each_possible(name, obj, member, key) \
	hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)

/**
  * hash_for_each_possible_safe - iterate over all possible objects hashing to the
  * same bucket safe against removals
  * @name: hashtable to iterate
  * @obj: the type * to use as a loop cursor for each entry
  * @tmp: a &struct hlist_node used for temporary storage
  * @member: the name of the hlist_node within the struct
  * @key: the key of the objects to iterate over
  */
#define hash_for_each_possible_safe(name, obj, tmp, member, key) \
	hlist_for_each_entry_safe(                               \
		obj, tmp, &name[hash_min(key, HASH_BITS(name))], member)

#endif
