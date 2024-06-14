/**
    Need to unroll to pass the verifier

    ./falco/modern_bpf/helpers/store/auxmap_store_params.h:1721
 */


/* We need the unroll here otherwise the verifier complains about back-edges */
#pragma unroll
	for(int i = 0; i < MAX_NUM_COMPONENTS; i++)
	{
		BPF_CORE_READ_INTO(&d_parent, dentry, d_parent);
		if(dentry == mnt_root_p || dentry == d_parent)
		{
			if(dentry != mnt_root_p)
			{
				/* We reached the root (dentry == d_parent)
				 * but not the mount root...there is something weird, stop here.
				 */
				break;
			}

			if(mnt_p != mnt_parent_p)
			{
				/* We reached root, but not global root - continue with mount point path */
				BPF_CORE_READ_INTO(&dentry, mnt_p, mnt_mountpoint);
				BPF_CORE_READ_INTO(&mnt_p, mnt_p, mnt_parent);
				BPF_CORE_READ_INTO(&mnt_parent_p, mnt_p, mnt_parent);
				vfsmnt = &mnt_p->mnt;
				BPF_CORE_READ_INTO(&mnt_root_p, vfsmnt, mnt_root);
				continue;
			}

			/* We have the full path, stop here */
			break;
		}

		/* Get the dentry name */
		bpf_core_read(&d_name, sizeof(struct qstr), &(dentry->d_name));

		/* +1 for the terminator that is not considered in d_name.len.
		 * Reserve space for the name trusting the len
		 * written in `qstr` struct
		 */
		current_off = max_buf_len - (d_name.len + 1);

		effective_name_len = bpf_probe_read_kernel_str(&(auxmap->data[SAFE_TMP_SCRATCH_ACCESS(current_off)]),
							       MAX_COMPONENT_LEN, (void *)d_name.name);

		if(effective_name_len <= 1)
		{
			/* If effective_name_len is 0 or 1 we have an error
			 * (path can't be null nor an empty string)
			 */
			break;
		}

		/* 1. `max_buf_len -= 1` point to the `\0` of the just written name.
		 * 2. We replace it with a `/`.
		 * 3. Then we set `max_buf_len` to the last written char.
		 */
		max_buf_len -= 1;
		auxmap->data[SAFE_TMP_SCRATCH_ACCESS(max_buf_len)] = '/';
		max_buf_len -= (effective_name_len - 1);

		dentry = d_parent;
	}