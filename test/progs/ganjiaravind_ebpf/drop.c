#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf_elf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "common.h"

typedef unsigned long long uint64_t;
typedef unsigned int    uint32_t;

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

__section("RX")
int ingress_drop(struct __sk_buff *skb)
{
	char fmt[] = "ingress drop from daddr4:%x: saddr %x\n";
	void *data_end = (void *)(uint64_t)skb->data_end;
	void *data = (void *)(uint64_t)skb->data;
	struct ethhdr *eth = (struct ethhdr *)data;
	struct iphdr *ip;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	ip = (struct iphdr *)(data + sizeof(*eth));

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;

	if (bpf_htonl(ip->daddr) == 0xa0a0a78) {
		bpf_trace_printk(fmt, sizeof(fmt), bpf_htonl(ip->daddr), bpf_htonl(ip->saddr));
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
