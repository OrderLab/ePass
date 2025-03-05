// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf_ir.h>

struct h_node {
	int data;
	char name[32];
	struct hlist_node node;
};

static u32 hash(const char *s)
{
	u32 key = 0;
	char c;

	while ((c = *s++))
		key += c;

	return key;
}

void static_test(void)
{
	printf("Test: static list\n");
	DEFINE_HASHTABLE(tbl, 9);
	struct h_node a, b, *cur;
	u32 key_a, key_b;
	unsigned bkt;

	a.data = 3;
	strcpy(a.name, "foo");

	b.data = 7;
	strcpy(b.name, "oof");

	key_a = hash(a.name);
	key_b = hash(b.name);

	printf("myhashtable: key_a = %u, key_b = %u\n", key_a, key_b);

	hash_add(tbl, &a.node, key_a);
	hash_add(tbl, &b.node, key_b);

	hash_for_each(tbl, bkt, cur, node) {
		printf("myhashtable: element: data = %d, name = %s\n",
		       cur->data, cur->name);
	}

	hash_for_each_possible(tbl, cur, node, key_a) {
		printf("myhashtable: match for key %u: data = %d, name = %s\n",
		       key_a, cur->data, cur->name);

		if (!strcmp(cur->name, "foo")) {
			printf("myhashtable: element named \"foo\" found!\n");
			break;
		}
	}

	hash_del(&a.node);
	hash_del(&b.node);
}

void dyn_test(void)
{
	printf("Test: dynamic list\n");

	// Initialize head element
	struct hlist_node *p = NULL;
	struct h_node *cur;

	// Dynamic version

	struct hlist_head *dlist_head = malloc(sizeof(struct hlist_head));
	INIT_HLIST_HEAD(dlist_head);
	for (int i = 0; i < 10; ++i) {
		struct h_node *new_node = malloc(sizeof(struct h_node));
		new_node->data = i;
		// Number to string

		sprintf(new_node->name, "data-%d", i);
		hlist_add_head(&new_node->node, dlist_head);
	}
	hlist_for_each(p, dlist_head) {
		struct h_node *entry = hlist_entry(p, struct h_node, node);
		printf("List element: %d: %s\n", entry->data, entry->name);
	}
	unsigned bkt = 0;
	hash_for_each(dlist_head, bkt, cur, node) {
		printf("myhashtable: element: data = %d, name = %s\n",
		       cur->data, cur->name);
	}
	// Free
	struct hlist_node *tmp = NULL;
	hlist_for_each_safe(p, tmp, dlist_head) {
		struct h_node *entry = hlist_entry(p, struct h_node, node);
		printf("Removing element: %d: %s\n", entry->data, entry->name);
		hlist_del(p);
		free(entry);
	}
	free(dlist_head);
	// Result: 9 8 7 6 5 4 3 2 1 0
}

int main(void)
{
	static_test();
	dyn_test();
	return 0;
}
