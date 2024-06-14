/**
    Ringbuff not recognized as a real pointer.

    ./falco/modern_bpf/programs/attached/events/sched_process_exit.bpf.c:156
 */


/* From linux tree: /include/trace/events/sched.h
 * TP_PROTO(struct task_struct *p)
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_proc_exit, struct task_struct *task)
{
	/* NOTE: this is a fixed-size event and so we should use the `ringbuf-approach`.
	 * Unfortunately we are hitting a sort of complexity limit in some kernel versions (<5.10)
	 * It seems like the verifier is not able to recognize the `ringbuf` pointer as a real pointer
	 * after a certain number of instructions but it considers it as an `invariant` causing a verifier error like:
	 * R1 invalid mem access 'inv'
	 * 
	 * Right now we solved it using the `auxmap-approach` but in the next future maybe we could
	 * switch again to the `ringbuf-approach`.
	 */