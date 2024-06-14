/**
    Not sure why this is needed to pass verifier, but they copy all the data structure to the stack.

    ./falco/bpf/probe.c:136
 */


#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	call_filler(ctx, ctx, evt_type, drop_flags, socketcall_syscall_id);
#else
	/* Duplicated here to avoid verifier madness */
	struct sys_enter_args stack_ctx;

	memcpy(stack_ctx.args, ctx->args, sizeof(ctx->args));
	if (stash_args(stack_ctx.args))
		return 0;

	call_filler(ctx, &stack_ctx, evt_type, drop_flags, socketcall_syscall_id);
#endif
