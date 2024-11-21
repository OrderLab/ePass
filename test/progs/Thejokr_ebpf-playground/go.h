#pragma once
#ifndef OBSERVER_BPF_GO_H
#define OBSERVER_BPF_GO_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/*
 * Go's struct layout is (currently) compatible to clang's layout for C structs.
 * Base types map directly to their C equivalents. However, we use void* for all
 * pointers since eBPF must read memory via helper functions.
 *
 * See https://go.dev/s/regabi for details on Go's layout rules.
 */

// interface{...} underlying value (runtime.eface, runtime.iface)
typedef struct ifacehdr {
    void *typ;  // *_type (interface{}) or *itab (other)
    void *data;  // *T
} iface;

// []T underlying value (runtime.slice)
typedef struct slicehdr {
    void *ptr;  // *T
    ssize_t len, cap;
} slice;

// string underlying value (reflect.StringHeader)
typedef struct stringhdr {
    void *ptr;  // *byte
    ssize_t len;
} string;

// net/url
struct net_url {
    string scheme, opaque;
    void *userinfo;  // *Userinfo
    string host, path, raw_path;
    bool omit_host, force_query;
    string raw_query, fragment, raw_fragment;
};

// net/http
struct net_http_request {
    string method;
    void *url;  // *url.URL
    string proto;
    ssize_t proto_major, proto_minor;
    void *header;  // map[string][]string
    // +other fields we don't care about
};

struct net_http_response {
    string status;
    ssize_t status_code;
    string proto;
    ssize_t proto_major, proto_minor;
    void *header;  // map[string][]string
    iface body;
    int64_t content_length;
    slice transfer_encoding;  // []string
    bool close, uncompressed;
    void *trailer;  // map[string][]string
    void *request;  // *Request
    // +other fields we don't care about
};

#endif  // OBSERVER_BPF_GO_H