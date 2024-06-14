/**
    Must split due to limit of one program.

    ./falco/modern_bpf/programs/attached/events/sched_process_fork.bpf.c:214

	Other same problems:

	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/fork.bpf.c:163:         * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/fork.bpf.c:213:         * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/execveat.bpf.c:179:     * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/vfork.bpf.c:161:        * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/vfork.bpf.c:211:        * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/clone3.bpf.c:161:       * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/clone3.bpf.c:218:       * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/execve.bpf.c:165:       * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/clone.bpf.c:161:        * for the verifier (limit 1000000 instructions).
	./falco/modern_bpf/programs/tail_called/events/syscall_dispatched_events/clone.bpf.c:221:        * for the verifier (limit 1000000 instructions).
 */

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* We have to split here the bpf program, otherwise, it is too large
	 * for the verifier (limit 1000000 instructions).
	 */
	bpf_tail_call(ctx, &extra_event_prog_tail_table, T2_SCHED_PROC_FORK);
	return 0;
}