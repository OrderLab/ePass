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

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif


typedef unsigned long long uint64_t;
typedef	unsigned int	uint32_t;

struct pair {
	uint32_t	local_ip;
	uint32_t	remote_ip;
};

struct stats {
	uint64_t	tx_cnt;
	uint64_t	tx_bytes;
};

struct bpf_elf_map __section("maps") track = {
	.type		=	BPF_MAP_TYPE_HASH,
	.size_key	=	sizeof(struct pair),
	.size_value	=	sizeof(struct stats),
	.max_elem	=	2048,
	.pinning	=	PIN_GLOBAL_NS,
};


static bool parse_ipv4(void *data, void *data_end, struct pair *tx)
{

	struct ethhdr *eth = (struct ethhdr *)data;
	struct iphdr *ip;
	char fmt[] = "egress forward to daddr4:%x: saddr %x\n";

	if ((void *)(eth + 1) > data_end)
		return false;

/*	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return false;*/

	ip = (struct iphdr *)(data + sizeof(*eth));
	if ((void *)(ip + 1) > data_end)
		return false;

/*	if (ip->protocol != IPPROTO_TCP)
		return false;*/

	tx->local_ip = ip->saddr;
	tx->remote_ip = ip->daddr;

	bpf_trace_printk(fmt, sizeof(fmt), bpf_htonl(ip->daddr), bpf_htonl(ip->saddr));
	return true;
}

static void update_tx_stats(struct pair *tx_pair, uint64_t bytes)
{
	struct stats *tx_stats, newstats = {0, 0};

	tx_stats = bpf_map_lookup_elem(&track, tx_pair);
	if (tx_stats) {
		tx_stats->tx_cnt++;
		tx_stats->tx_bytes += bytes;
	} else {
		newstats.tx_cnt = 1;
		newstats.tx_bytes = bytes;
		bpf_map_update_elem(&track, tx_pair, &newstats, BPF_NOEXIST);
	}
}


__section("TX") 
int egress_tc_prog(struct __sk_buff *skb)
{
	struct pair tx_pair;
	void *data_end = (void *)(uint64_t)skb->data_end;
	void *data = (void *)(uint64_t)skb->data;

	if (!parse_ipv4(data, data_end, &tx_pair))
		return TC_ACT_SHOT;

	update_tx_stats(&tx_pair, data_end - data);
	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
