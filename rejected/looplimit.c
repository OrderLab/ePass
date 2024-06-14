/**
    There is a strict limit of how many instructions one program may excute.

    If some loops are nested, it is very likely the maximum possible iteration exceeds the limit.

    However, it may not be common for them to exceed during runtime.

    We may need to have a policy for users to state how to deal with programs that have runtime exceptions.

    ./falco/bpf/fillers.h:5272
 */



/* In this kernel version the instruction limit was bumped to 1000000.
 * We use these 2 values because they are the minimum required to run our eBPF probe
 * on some GKE environments. See https://github.com/falcosecurity/libs/issues/1639
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
#define MAX_THREADS_GROUPS 25
#define MAX_HIERARCHY_TRAVERSE 35
#else
/* We need to find the right calibration here. On kernel 4.14 the limit
 * seems to be MAX_THREADS_GROUPS*MAX_HIERARCHY_TRAVERSE <= 100
 */
#define MAX_THREADS_GROUPS 10
#define MAX_HIERARCHY_TRAVERSE 10
#endif


#pragma unroll MAX_THREADS_GROUPS
	for(struct task_struct *t = container_of(next_thread, typeof(struct task_struct), thread_node);
	    next_thread != (head) && cnt < MAX_THREADS_GROUPS;
	    t = container_of(next_thread, typeof(struct task_struct), thread_node))
	{
		cnt++;
		bpf_probe_read_kernel(&flags, sizeof(flags), &t->flags);
		if(!(flags & PF_EXITING))
		{
			/* Found it */
			return _READ(t->pid);
		}
		next_thread = (struct list_head *)_READ(t->thread_node.next);
	}

	/* If we cannot loop over all threads, we cannot know the right reaper */
	if(cnt == MAX_THREADS_GROUPS) // <--- HERE
	{
		return -1;
	}

	/* We didn't find it */
	return 0;
}