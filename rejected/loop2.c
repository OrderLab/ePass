/**
    Cannot directly break.

    ./falco/modern_bpf/helpers/store/auxmap_store_params.h:1030
 */

for(int j = 0; j < MAX_IOVCNT; j++)
	{
		if(total_size_to_read > len_to_read)
		{
			/* If we break here it could be that `payload_pos` overcame the max `len_to_read` for this reason
			 * we have an enforcement after the for loop.
			 */
			total_size_to_read = len_to_read;
			break;
		}

		if(j == iov_cnt)
		{
			break;
		}

		uint16_t bytes_read = push__bytebuf(auxmap->data, &auxmap->payload_pos, (unsigned long)iovec[j].iov_base, iovec[j].iov_len, USER);
		if(!bytes_read)
		{
			push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_read);
			return;
		}
		total_size_to_read += bytes_read;
	}