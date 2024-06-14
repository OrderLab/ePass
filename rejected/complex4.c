/**
    Exceeds maximum complexity.

    ./falco/bpf/fillers.h:3564
 */
	long retval = bpf_syscall_get_retval(data->ctx);
	struct file *f = bpf_fget(retval);
	if(f == NULL)
	{
		/* In theory here we should send an empty param but we are experimenting some issues
		 * with the verifier on debian10 (4.19.0-25-amd64). Sending an empty param exceeds
		 * the complexity limit of the verifier for this reason we simply return an error code.
		 * Returning an error code means that we drop the entire event, but please note that this should
		 * never happen since we previosuly check `retval > 0`. The kernel should always have an entry for
		 * this fd in the fd table.
		 */
		return PPM_FAILURE_BUG;
	}