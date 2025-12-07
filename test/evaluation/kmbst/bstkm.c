#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/ktime.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BST benchmark in kernel module");

// ---------------- BST Node ----------------
struct bst_node {
    int key;
    struct bst_node *left, *right;
};

// BST Insert
struct bst_node* bst_insert(struct bst_node* root, int key) {
    if (!root) {
        struct bst_node* n = kmalloc(sizeof(*n), GFP_KERNEL);
        n->key = key;
        n->left = n->right = NULL;
        return n;
    }
    if (key < root->key)
        root->left = bst_insert(root->left, key);
    else if (key > root->key)
        root->right = bst_insert(root->right, key);
    return root; // ignore duplicates
}

// BST Lookup
struct bst_node* bst_lookup(struct bst_node* root, int key) {
    while (root) {
        if (key < root->key)
            root = root->left;
        else if (key > root->key)
            root = root->right;
        else
            return root;
    }
    return NULL;
}

// BST Delete
struct bst_node* bst_delete(struct bst_node* root, int key) {
    if (!root) return NULL;

    if (key < root->key)
        root->left = bst_delete(root->left, key);
    else if (key > root->key)
        root->right = bst_delete(root->right, key);
    else {
        if (!root->left) {
            struct bst_node* tmp = root->right;
            kfree(root);
            return tmp;
        } else if (!root->right) {
            struct bst_node* tmp = root->left;
            kfree(root);
            return tmp;
        } else {
            // find min in right subtree
            struct bst_node* tmp = root->right;
            while (tmp->left) tmp = tmp->left;
            root->key = tmp->key;
            root->right = bst_delete(root->right, tmp->key);
        }
    }
    return root;
}

// Free BST
void bst_free(struct bst_node* root) {
    if (!root) return;
    bst_free(root->left);
    bst_free(root->right);
    kfree(root);
}

// ---------------- LCG PRNG ----------------
static inline unsigned int lcg_next(unsigned int *state) {
    *state = (*state * 1664525 + 1013904223);
    return *state;
}

static inline unsigned int rand_range(unsigned int *state, unsigned int max) {
    return lcg_next(state) % max;
}

// Fisher-Yates shuffle
void shuffle(int *arr, int n, unsigned int seed) {
    unsigned int state = seed;
    int i;
    for (i = n - 1; i > 0; i--) {
        int j = rand_range(&state, i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

// ---------------- Benchmark ----------------
#define N (64 * 1024)

static int __init bst_benchmark_init(void)
{
    int i;
    unsigned long long start, end, total;
    struct bst_node* root = NULL;

    int *data = kmalloc_array(N, sizeof(int), GFP_KERNEL);
    for (i = 0; i < N; i++) data[i] = i + 1;
    shuffle(data, N, 114514); // fixed seed

    pr_info("bst Benchmark: N=%d\n", N);

    // ----- Insert -----
    total = 0;
    for (i = 0; i < N; i++) {
        start = ktime_get_ns();
        root = bst_insert(root, data[i]);
        end = ktime_get_ns();
        total += (end - start);
    }
    pr_info("bst Insert avg latency: %llu ns\n", total / N);

    // ----- Lookup -----
    total = 0;
    for (i = 0; i < N; i++) {
        start = ktime_get_ns();
        if (!bst_lookup(root, data[i])) pr_info("Lookup error!\n");
        end = ktime_get_ns();
        total += (end - start);
    }
    pr_info("bst Lookup avg latency: %llu ns\n", total / N);

    // ----- Delete -----
    total = 0;
    for (i = 0; i < N; i++) {
        start = ktime_get_ns();
        root = bst_delete(root, data[i]);
        end = ktime_get_ns();
        total += (end - start);
    }
    pr_info("bst Delete avg latency: %llu ns\n", total / N);

    bst_free(root);
    return 0;
}

static void __exit bst_benchmark_exit(void)
{
    pr_info("BST benchmark module exit\n");
}

module_init(bst_benchmark_init);
module_exit(bst_benchmark_exit);
