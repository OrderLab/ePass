/**
    A complex eBPF program that the verifier cannot verify.

    https://stackoverflow.com/questions/70841631/bpf-verifier-says-program-exceeds-1m-instruction

 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct server_name {
    char  server_name[256];
    __u16 length;
};

#define MAX_SERVER_NAME_LENGTH 253
#define HEADER_LEN             6

SEC("xdp")
int collect_ips_prog(struct xdp_md *ctx) {
    char *data_end          = (char *)(long)ctx->data_end;
    char *data              = (char *)(long)ctx->data;
    int   host_header_found = 0;

    for (__u16 i = 0; i <= 512 - HEADER_LEN; i++) {
        host_header_found = 0;

        if (data_end < data + HEADER_LEN) {
            goto end;
        }

        // Elf loader does not allow NULL terminated strings, so have to check each char manually
        if (data[0] == 'H' && data[1] == 'o' && data[2] == 's' && data[3] == 't' &&
            data[4] == ':' && data[5] == ' ') {
            host_header_found = 1;
            data += HEADER_LEN;
            break;
        }

        data++;
    }

    if (host_header_found) {
        struct server_name sn = {"a", 0};

        for (__u16 j = 0; j < MAX_SERVER_NAME_LENGTH; j++) {
            if (data_end < data + 1) {
                goto end;
            }

            if (*data == '\r') {
                break;
            }

            sn.server_name[j] = *data++;
            sn.length++;
        }
    }

end:
    return XDP_PASS;
}
