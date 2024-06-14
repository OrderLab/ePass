/**
    Cilium defines a bpf_barrier function to pass some verifier complaint about dereferencing.
 */

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


// ./cilium/bpf_overlay.c:289
// ./cilium/bpf_overlay.c:59

	/* verifier workaround (dereference of modified ctx ptr) */
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;