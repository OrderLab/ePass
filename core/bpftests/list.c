#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct list_node {
	int data;
	struct list_node *next;
};

SEC("xdp")
int prog(void *ctx)
{
	struct list_node *elem = (struct list_node *)
		bpf_ktime_get_ns(); // Some dummy function here
	elem->data = 43;
	elem->next = NULL;
	struct list_node *head = (struct list_node *)bpf_ktime_get_ns();
	head->data = 42;
	head->next = elem;
	return 0;
}

char _license[] SEC("license") = "GPL";
