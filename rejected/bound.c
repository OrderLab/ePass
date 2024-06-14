/**
    Problem with certain version of verifiers.

	Cannot directly copy char, but need to use `bpf_probe_read_kernel` for certain verifier version.

    ./falco/bpf/filler_helpers.h:210
 */
		/* This check shouldn't be necessary, right now we
		 * keep it just to be extra safe. Unfortunately, it causes
		 * verifier issues on s390x (5.15.0-75-generic Ubuntu s390x)
		 */
#ifndef CONFIG_S390
		if(effective_name_len <= 1)
		{
			/* If effective_name_len is 0 or 1 we have an error
			 * (path can't be null nor an empty string)
			 */
			break;
		}
#endif
		/* 1. `max_buf_len -= 1` point to the `\0` of the just written name.
		 * 2. We replace it with a `/`. Note that we have to use `bpf_probe_read_kernel`
		 *    to please some old verifiers like (Oracle Linux 4.14).
		 * 3. Then we set `max_buf_len` to the last written char.
		 */
		max_buf_len -= 1;
		bpf_probe_read_kernel(&(data->tmp_scratch[SAFE_TMP_SCRATCH_ACCESS(max_buf_len)]), 1, &slash);
		max_buf_len -= (effective_name_len - 1);