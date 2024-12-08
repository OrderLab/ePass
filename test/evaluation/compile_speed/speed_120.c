#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct server_name {
    char  server_name[256];
    __u16 length;
};

SEC("xdp")
int prog(struct xdp_md *ctx) {
    __u64 t = bpf_ktime_get_ns();
    char xx[] = "asfdsf";
    for (__u64 i = 0; i < t; ++i) {
        bpf_trace_printk(xx, i);
    }
    t = bpf_ktime_get_ns();
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk(xx, x);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk(xx, x);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk(xx, x);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk(xx, x);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    for (__u64 i = 0; i < t; ++i) {
        int x = bpf_ktime_get_ns();
        bpf_trace_printk("vdnvd", x);
        bpf_trace_printk("fasas", 2, x + i);
    }
    char *data_end          = (char *)(long)ctx->data_end;
    char *data              = (char *)(long)ctx->data;
    int   host_header_found = 0;

    for (__u16 i = 0; i <= 512; i++) {
        host_header_found = 0;

        if (data_end < data + 6) {
            return 0;
        }

        // Elf loader does not allow NULL terminated strings, so have to check each char manually
        if (data[0] == 'H' && data[1] == 'o' && data[2] == 's' && data[3] == 't' &&
            data[4] == ':' && data[5] == ' ') {
            host_header_found = 1;
            data += 3;
            break;
        }

        data++;
    }

    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < 11; j++) {
            if (data_end < data + 1) {
                return 0;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
