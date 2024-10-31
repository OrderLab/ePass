#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf_elf.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

#define MAX_TRAFFIC_CLASS	16
#define DEFAULT_QUEUE		0

typedef unsigned long long uint64_t;
typedef	unsigned int	uint32_t;

struct bpf_elf_map SEC("maps") skb_queue_start_num = {
	.type		=	BPF_MAP_TYPE_ARRAY,
	.size_key	=	sizeof(uint32_t),
	.size_value	=	sizeof(uint32_t),
	.pinning	=	PIN_GLOBAL_NS,
	.max_elem	=	16,
};

struct bpf_elf_map SEC("maps") class_range_queues_num = {
	.type		=	BPF_MAP_TYPE_ARRAY,
	.size_key	=	sizeof(uint32_t),
	.size_value	=	sizeof(uint32_t),
	.pinning	=	PIN_GLOBAL_NS,
	.max_elem	=	16,
};

struct bpf_elf_map SEC("maps") l4_port_start_num = {
	.type		=	BPF_MAP_TYPE_ARRAY,
	.size_key	=	sizeof(uint32_t),
	.size_value	=	sizeof(uint32_t),
	.pinning	=	PIN_GLOBAL_NS,
	.max_elem	=	16,
};

__section("TX")
int tc_mqprio_skb_prio_queue_map(struct __sk_buff *skb)
{
	void *data_end = (void *)(uint64_t)skb->data_end;
	void *data = (void *)(uint64_t)skb->data;
	struct ethhdr *eth = (struct ethhdr *)data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	/*map variables*/
	__u32 key, *Qstart, *Crange, *L4Port;
	__u32 Queue;
	__u16 sk_port;
	__u8 prio;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_SHOT;

	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;

	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return TC_ACT_UNSPEC;

	switch(ip->protocol) {
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)(ip + 1);

			if ((void *)(tcp + 1) > data_end)
				return TC_ACT_SHOT;

			sk_port = bpf_ntohs(tcp->dest);
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr *)(ip + 1);

			if ((void *)(udp + 1) > data_end)
				return TC_ACT_SHOT;

			sk_port = bpf_ntohs(udp->dest);
			break;
	}

	key = 0;
	Queue = DEFAULT_QUEUE;
	for (prio = 0; prio < MAX_TRAFFIC_CLASS; prio++) {

		L4Port = bpf_map_lookup_elem(&l4_port_start_num, &key);
		if (!L4Port)
			return TC_ACT_RECLASSIFY;
		Crange = bpf_map_lookup_elem(&class_range_queues_num, &key);
		if (!Crange)
			return TC_ACT_RECLASSIFY;
		if (sk_port < (*L4Port + *Crange)) {
			Qstart = bpf_map_lookup_elem(&skb_queue_start_num, &key);
			if (!Qstart)
				return TC_ACT_RECLASSIFY;
/*			Crange = bpf_map_lookup_elem(&class_range_queues_num, &key);
			if (!Crange)
				return TC_ACT_RECLASSIFY;*/

			Queue = *Qstart + ((sk_port - *L4Port) % (*Crange));
			goto out;
		}

		key++;
	}
out:
	if (Queue != DEFAULT_QUEUE) {
		skb->priority = prio;
		skb->queue_mapping = Queue + 1; /*extra 1 is for stack queue logic in skb_tx_hash*/
	}

	return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
