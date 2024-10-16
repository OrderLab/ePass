static __always_inline void *							\
ctx_ ## FIELD(const struct xdp_md *ctx)						\
{										\
	void *ptr;								\
										\
	/* LLVM may generate u32 assignments of ctx->{data,data_end,data_meta}.	\
	 * With this inline asm, LLVM loses track of the fact this field is on	\
	 * 32 bits.								\
	 */									\
	asm volatile("%0 = *(u32 *)(%1 + %2)"					\
		     : "=r"(ptr)						\
		     : "r"(ctx), "i"(offsetof(struct xdp_md, FIELD)));		\
	return ptr;								\
}

#ifndef barrier
# define barrier()		asm volatile("": : :"memory")
#endif

#ifndef barrier_data
# define barrier_data(ptr)	asm volatile("": :"r"(ptr) :"memory")
#endif

static __always_inline void bpf_barrier(void)
{
	/* Workaround to avoid verifier complaint:
	 * "dereference of modified ctx ptr R5 off=48+0, ctx+const is allowed,
	 *        ctx+const+const is not"
	 */
	barrier();
}

static __always_inline __maybe_unused __u32
map_array_get_32(const __u32 *array, __u32 index, const __u32 limit)
{
	__u32 datum = 0;

	if (__builtin_constant_p(index) ||
	    !__builtin_constant_p(limit))
		__throw_build_bug();

	/* LLVM tends to optimize code away that is needed for the verifier to
	 * understand dynamic map access. Input constraint is that index < limit
	 * for this util function, so we never fail here, and returned datum is
	 * always valid.
	 */
	asm volatile("%[index] <<= 2\n\t"
		     "if %[index] > %[limit] goto +1\n\t"
		     "%[array] += %[index]\n\t"
		     "%[datum] = *(u32 *)(%[array] + 0)\n\t"
		     : [datum]"=r"(datum)
		     : [limit]"i"(limit), [array]"r"(array), [index]"r"(index)
		     : /* no clobbers */ );

	return datum;
}


/* Don't gamble, but _guarantee_ that LLVM won't optimize setting
 * r2 and r3 from different paths ending up at the same call insn as
 * otherwise we won't be able to use the jmpq/nopl retpoline-free
 * patching by the x86-64 JIT in the kernel.
 *
 * Note on clobber list: we need to stay in-line with BPF calling
 * convention, so even if we don't end up using r0, r4, r5, we need
 * to mark them as clobber so that LLVM doesn't end up using them
 * before / after the call.
 *
 * WARNING: The loader relies on the exact instruction sequence
 * emitted by this macro. Consult with the loader team before
 * changing this macro.
 */
#define tail_call_static(ctx_ptr, map, slot)				\
{								\
	if (!__builtin_constant_p(slot))			\
		__throw_build_bug();				\
								\
	asm volatile("r1 = %[ctx]\n\t"				\
		"r2 = " __stringify(map) " ll\n\t"		\
		"r3 = %[slot_idx]\n\t"				\
		"call 12\n\t"					\
		:: [ctx]"r"(ctx_ptr), [slot_idx]"i"(slot)	\
		: "r0", "r1", "r2", "r3", "r4", "r5");		\
}


