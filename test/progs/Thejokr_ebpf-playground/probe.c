#include <stdint.h>
#include <assert.h>
#include <linux/types.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "regs.h"
#include "go.h"

// To read data from memory (via bpf_probe_read_user), our eBPF program must be GPL licensed.
const char LICENSE[] SEC("license") = "Dual MIT/GPL";
const uint32_t KVER SEC("version") = KERNEL_VERSION(5, 8, 0);

// eBPF programs exchange data with their host application using maps. The map's type
// defines its interface and capabilities. We use a ringbuf map, which implements a
// unidirectional FIFO queue with dynamic entries (available since Linux 5.8, Aug 2020).
// Map definitions use special libbpf macros for encoding into the eBPF binary,
// see https://docs.kernel.org/bpf/btf.html#bpf-map-create.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);  // must be multiple of PAGE_SIZE
} traces SEC(".maps");

// Global variables are also converted into maps by the eBPF loader. Constants can conveniently
// be rewritten before loading the eBPF program into the kernel (as seen in the Go code).
// These two constants are necessary to retrieve the namespaced PID of the instrumented program.
volatile const __u64 pidns_dev;
volatile const __u64 pidns_ino;


#define HTTP_TRACE_SIZE (512 - 8)
#define HTTP_TRACE_BUF (HTTP_TRACE_SIZE - sizeof(struct http_trace_head))

struct http_trace_head {
    bool partial;  // if true, reading some net/http struct failed
    uint8_t protocol;

    // past-the-end indices for strings in http_trace::buf
    uint8_t method_end;  // buf[0:method_end] = method
    uint16_t url_end; // buf[method_end:url_end] = url

    uint16_t status_code;
    uint32_t content_length;
    uint32_t pid;
};
struct http_trace {
    struct http_trace_head head;
    // shared buffer for dynamically-sized strings
    uint8_t buf[HTTP_TRACE_BUF];
};

// Force LLVM to emit type information for struct http_trace
const struct http_trace *t_unused __attribute__((unused));

// Helper functions to define the semantics of struct http_trace_head's fields
static __always_inline uint8_t http_protocol(uint64_t major, uint64_t minor) {
    return ((major & 0x0f) << 4) | (minor & 0x0f);
}

static __always_inline uint32_t http_content_length(int64_t content_length) {
    if (content_length < 0)
        return UINT32_MAX;  // marker for "negative content_length"
    if (content_length >= UINT32_MAX)
        return UINT32_MAX - 1;  // marker for "exceeds field capacity"
    return content_length;
}

static __always_inline int write_method(struct http_trace *, const string *);
static __always_inline int write_url(struct http_trace *, const struct net_url *);


// This is the probe's "main" function, which will be executed by the kernel whenever
// the probe point we set up is hit. The setup is done in the host Go application.
SEC("uretprobe/http_transport_roundtrip")
// func (t *Transport) RoundTrip(*Request) (*Response, error)
int http_transport_roundtrip_ret(const struct pt_regs *ctx) {
    // A uretprobe triggers on return from the instrumented function.
    // Since this function is implemented in Go, it follows Go's
    // (nonstandard, unstable) ABIInternal: https://go.dev/s/regabi
    // TL;DR: the return values are stored unpacked in registers.

    // R0 = *Response
    // (R1, R2) = error (struct ifacehdr)
    const uintptr_t resp_ptr = GOABI_R0(ctx), err_data = GOABI_R2(ctx);

    // Skip trace if error is set in return
    if (err_data || !resp_ptr)
        return 0;

    // Allocate a fresh trace event in the ringbuf
    struct http_trace *const t = bpf_ringbuf_reserve(&traces, sizeof(*t), 0);
    if (!t)
        return 0;  // ringbuf is full and not being drained fast enough

    union {
        struct net_http_response resp;
        struct net_http_request req;
        struct net_url url;
    } r;  // shared stack space for reads from process memory
    void *next = (void*)resp_ptr;

    // eBPF helper for: r.resp = *next (except its fallible)
    if (bpf_probe_read_user(&r.resp, sizeof(r.resp), next) != 0) {
        bpf_ringbuf_discard(t, BPF_RB_NO_WAKEUP);
        return 1;  // failed to copy struct from process memory
    }

    // Retrieve namespaced PID. If that fails, fall back to the PID from the root ns.
    // The user-facing PID is called tgid in the kernel.
    struct bpf_pidns_info pid = {0};
    if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &pid, sizeof(pid)) != 0) {
        pid.tgid = bpf_get_current_pid_tgid() >> 32;
    }

    // At this point, we have enough data to fill most of our trace header.
    // We set partial = true in case a later operation fails, but from here
    // on, we will always submit the trace.
    t->head = (struct http_trace_head){
        .partial = true,
        .protocol = http_protocol(r.resp.proto_major, r.resp.proto_minor),
        .status_code = r.resp.status_code,
        .content_length = http_content_length(r.resp.content_length),
        .pid = pid.tgid,
    };

    next = r.resp.request;
    if (bpf_probe_read_user(&r.req, sizeof(r.req), next) != 0)
        goto out_submit;
    if (write_method(t, &r.req.method) != 0)
        goto out_submit;

    next = r.req.url;
    if (bpf_probe_read_user(&r.url, sizeof(r.url), next) != 0)
        goto out_submit;
    if (write_url(t, &r.url) != 0)
        goto out_submit;

    t->head.partial = false;

out_submit:
    bpf_ringbuf_submit(t, 0);
    return 0;
}


static ssize_t append_string(struct http_trace *t, size_t buf_used, const string *s) {
    if (s->len <= 0 || buf_used >= sizeof(t->buf))
        return 0;

    // Read as many bytes as the buffer can still hold,
    // but not more than the string's length itself.
    size_t read_len = sizeof(t->buf) - buf_used;
    if (read_len > (size_t)s->len)
        read_len = s->len;

    // eBPF workaround: the verifier can't prove that buf_used + read_len <= sizeof(t->buf),
    // since it can't tie two variables together. Instead, we copy fixed-size chunks from s.
    // A simple and relatively efficient way to do so is by decomposing read_len into its
    // binary representation, i.e., using power-of-two chunks.
    static_assert(sizeof(t->buf) < (0x100 * 2), "t->buf exceeds preset copy capacity");
    uint8_t *src = s->ptr;
    for (size_t cpy = 0x100; cpy != 0; cpy >>= 1) {
        if (!(read_len & cpy))
            continue;
        if (buf_used > sizeof(t->buf) - cpy)
            return -2;  // assertion for eBPF verifier, this can never happen

        if (bpf_probe_read_user(&t->buf[buf_used], cpy, src) != 0)
            return -1;
        src += cpy;
        buf_used += cpy;
    }

    return read_len;
}

static __always_inline int write_method(struct http_trace *t, const string *method) {
    ssize_t len = append_string(t, 0, method);
    if (len < 0)
        return 1;

    t->head.method_end = len;
    return 0;
}

static __always_inline int write_url(struct http_trace *t, const struct net_url *url) {
    size_t buf_used = t->head.method_end;
    int ret = 1;

    // scheme
    ssize_t len = append_string(t, buf_used, &url->scheme);
    if (len < 0)
        goto out_set_len;
    buf_used += (size_t)len;

    // scheme separator
    if (buf_used <= sizeof(t->buf) - 3) {
        t->buf[buf_used++] = ':';
        t->buf[buf_used++] = '/';
        t->buf[buf_used++] = '/';
    }

    // host
    len = append_string(t, buf_used, &url->host);
    if (len < 0)
        goto out_set_len;
    buf_used += (size_t)len;

    // path
    len = append_string(t, buf_used, &url->path);
    if (len < 0)
        goto out_set_len;
    buf_used += (size_t)len;

    // query
    if (url->force_query || url->raw_query.len > 0) {
        if (buf_used < sizeof(t->buf))
            t->buf[buf_used++] = '?';

        len = append_string(t, buf_used, &url->raw_query);
        if (len < 0)
            goto out_set_len;
        buf_used += (size_t)len;
    }

    ret = 0;

out_set_len:
    t->head.url_end = buf_used;
    return ret;
}