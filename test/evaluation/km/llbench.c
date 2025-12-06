#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/ktime.h>

#define LIST_SIZE  (1024)

struct ll_node {
    u32 key;
    // u32 value;
    struct ll_node *next;
};

static struct ll_node *head;

/* -------------------- Linked list ops -------------------- */

/* O(1) insert / update: always insert or replace at head */
static void ll_insert_or_update(u32 key)
{
    struct ll_node *n = kmalloc(sizeof(*n), GFP_KERNEL);
    n->key = key;
    // n->value = value;
    n->next = head;
    head = n;
}

/* O(N) lookup */
static struct ll_node *ll_lookup(u32 key)
{
    struct ll_node *cur = head;
    while (cur) {
        if (cur->key == key)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

/* O(N) delete */
static bool ll_delete(u32 key)
{
    struct ll_node *cur = head;
    struct ll_node *prev = NULL;

    while (cur) {
        if (cur->key == key) {
            if (prev)
                prev->next = cur->next;
            else
                head = cur->next;
            kfree(cur);
            return true;
        }
        prev = cur;
        cur = cur->next;
    }
    return false;
}

/* -------------------- Timing helpers -------------------- */

static u64 now_ns(void)
{
    return ktime_get_ns();
}

/* safe integer division for throughput */
static u64 div64_safe(u64 a, u64 b)
{
    return b ? div64_u64(a, b) : 0;
}

/* -------------------- Benchmark -------------------- */

static void benchmark(void)
{
    u32 i;
    u64 t_start, t_end, latency, throughput;
    // u32 key;

    pr_info("llbench: building list with %u elements\n", LIST_SIZE);

    /* build linked list: O(1) inserts */
    t_start = now_ns();
    for (i = 0; i < LIST_SIZE; i++) {
        ll_insert_or_update(i);
    }
    t_end = now_ns();
    latency = div64_safe(t_end - t_start, LIST_SIZE);
    throughput = div64_safe((u64)LIST_SIZE * 1000000000ULL, (t_end - t_start));

    pr_info("llbench: insert/update: avg = %llu ns, throughput = %llu ops/s\n",
            latency, throughput);

    /* lookup test: 64K random accesses */
    t_start = now_ns();
    for (i = 0; i < LIST_SIZE; i++) {
        // get_random_bytes(&key, sizeof(key));
        // key %= LIST_SIZE;
        ll_lookup(11111);
    }
    t_end = now_ns();
    latency = div64_safe(t_end - t_start, LIST_SIZE);
    throughput = div64_safe((u64)LIST_SIZE * 1000000000ULL, (t_end - t_start));

    pr_info("llbench: lookup: avg = %llu ns, throughput = %llu ops/s\n",
            latency, throughput);

    /* delete test: delete sequentially; delete is O(N) */
    t_start = now_ns();
    for (i = 0; i < LIST_SIZE; i++) {
        ll_delete(LIST_SIZE - i - 1);
    }
    t_end = now_ns();
    latency = div64_safe(t_end - t_start, LIST_SIZE);
    throughput = div64_safe((u64)LIST_SIZE * 1000000000ULL, (t_end - t_start));

    pr_info("llbench: delete: avg = %llu ns, throughput = %llu ops/s\n",
            latency, throughput);
}

/* -------------------- Module init/exit -------------------- */

static int __init llbench_init(void)
{
    pr_info("llbench: start\n");
    benchmark();
    return 0;
}

static void __exit llbench_exit(void)
{
    struct ll_node *cur = head, *next;
    while (cur) {
        next = cur->next;
        kfree(cur);
        cur = next;
    }
    pr_info("llbench: exit\n");
}

module_init(llbench_init);
module_exit(llbench_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatGPT");
MODULE_DESCRIPTION("Linked list latency/throughput benchmark");
