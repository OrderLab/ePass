// https://stackoverflow.com/questions/77762365/ebpf-value-is-outside-of-the-allowed-memory-range-when-reading-data-into-arra

struct ReadArgs{
    int fd;
    uintptr_t buf;  // https://github.com/cilium/ebpf/discussions/1066 work around for pointer in struct
};

struct ReadEvent{
    int eventType;
    int fd;
    int len;
    u8 content[MAX_READ_CONTENT_LENGTH];
};

static __always_inline int readData(struct ReadArgs* args, struct ReadEvent* event, int read){
    if((void *) args->buf == NULL){
        return -1;
    }
    event->fd = args->fd;
    if(event->len > MAX_READ_CONTENT_LENGTH){
        return -1;
    } else {
        event->len &= (MAX_READ_CONTENT_LENGTH-1);
    }
    if(read > MAX_READ_CONTENT_LENGTH){
        read = MAX_READ_CONTENT_LENGTH - 1;
    }else{
        read &= (MAX_READ_CONTENT_LENGTH-1);
    }
    if(event->len + read < MAX_READ_CONTENT_LENGTH) {
        long res = bpf_probe_read_user(&event->content[event->len], read, (const void *) args->buf);    // failed at here
        if (res < 0) {
            DEBUG("readData: bpf_probe_read_user return %d", res);
            return -1;
        }
        event->len += read;
    }
    return 0;
}
