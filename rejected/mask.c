/**
    People use mask to enforce that the number is in a range.

    However, doing this every time could have some overhead?

    `BPF_FORBIDS_ZERO_ACCESS` is defined before kernel 4.14

    ./falco/bpf/filler_helpers.h:414
	./cilium/lib/drop.h:55
 */

static __always_inline int bpf_addr_to_kernel(void *uaddr, int ulen,
					      struct sockaddr *kaddr)
{
	int len = ulen & 0xfff;	/* required by BPF verifier */  // <---------------

	if (len < 0 || len > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (len == 0)
		return 0;

#ifdef BPF_FORBIDS_ZERO_ACCESS
	if (bpf_probe_read_user(kaddr, ((len - 1) & 0xff) + 1, uaddr))  // <---------------
#else
	if (bpf_probe_read_user(kaddr, len & 0xff, uaddr))
#endif
		return -EFAULT;

	return 0;
}

static __always_inline int bpf_push_empty_param(struct filler_data *data)
{
	/* We push 0 in the length array */
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, 0);
	data->curarg_already_on_frame = false;

	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);  // <---------------
	return PPM_SUCCESS;
}

// 8 similar code using SAFE_ARG_NUMBER