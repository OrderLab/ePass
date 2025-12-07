#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define META_SIZE 65000
#define META_BLOCK_SIZE 32
#define HEAP_SIZE ((META_SIZE + 1) * META_BLOCK_SIZE)

struct perf_data {
  __u64 root;
  __u64 lat;
  __u64 times;
  __u64 se_lat;
  __u64 se_times;
  __u64 del_lat;
  __u64 del_times;
  __u64 __gar;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct perf_data);
} perf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, META_SIZE + 1);
  __type(key, __u32);
  __type(value, __u32);
} meta SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, char[HEAP_SIZE]);
} data SEC(".maps");

static __always_inline char *init_heap(long size) {
  int i = 0;
  char *head = bpf_map_lookup_elem(&data, &i);
  return head;
}

static __noinline __u64 malloc(__u32 size) {
  __u32 i = 0;
  // long rv = 0;
  __u32 *head = bpf_map_lookup_elem(&meta, &i);
  if (head == 0) {
    return 0;
  }
  if (size >= HEAP_SIZE || size <= 1) {
    return 0;
  }
  __u32 rid = *head + 1;

  __u32 blocks = 1 + (size - 1) / META_BLOCK_SIZE;

  if (*head + blocks >= META_SIZE) {
    *head = 0;
    // TODO find free space
    return 0;
  }
  (*head) += blocks;
  // Directly use head->pos
  // int newpos = head->pos+1;
  // We got a free space at idx head->pos and data pos head->size

  __u32 *init_pos = bpf_map_lookup_elem(&meta, &rid);
  if (init_pos == 0) {
    return 0;
  }
  *init_pos = blocks;

  for (int i = 1; i < META_SIZE; i++) {
    if (i >= blocks) {
      break;
    }
    __u32 check_idx = rid + i;
    if (check_idx >= META_SIZE) {
      // Out of space
      return 0;
    }
    __u32 *check_pos = bpf_map_lookup_elem(&meta, &check_idx);
    if (check_pos == 0) {
      return 0;
    }
    *check_pos = 1;
  }

  return (rid - 1) * META_BLOCK_SIZE;
}

static __noinline void free(__u32 idx) {
  __u32 block_idx = idx / META_BLOCK_SIZE + 1;
  __u32 *meta_pos = bpf_map_lookup_elem(&meta, &block_idx);
  if (meta_pos == 0) {
    return;
  }
  __u32 blocks = *meta_pos;
  if (blocks >= 1) {
    __u32 *cur_pos = bpf_map_lookup_elem(&meta, &block_idx);
    if (cur_pos == 0) {
      return;
    }
    *cur_pos = 0;
  }
  return;
}

struct bstnode {
  __u64 key;
  __u64 left, right;
};

inline __u64 new_node(char *data_ptr, __u64 key) {
  __u64 n = malloc(sizeof(struct bstnode));
  if (n > HEAP_SIZE - 100) {
    return 0;
  }
  struct bstnode *ts = (struct bstnode *)(data_ptr + n);
  ts->key = key;
  ts->left = ts->right = 0;
  return n;
}

inline __u64 insert(char *data_ptr, __u64 root, __u64 key) {
  __u64 parent = 0, cur = root;

  // Search for insertion point
  for (int i = 0; i < 1000; ++i) {
    if (cur == 0)
      break;
    if (cur > HEAP_SIZE - 100) {
      return 0;
    }
    struct bstnode *curt = (struct bstnode *)(data_ptr + cur);
    parent = cur;
    if (key < curt->key)
      cur = curt->left;
    else if (key > curt->key)
      cur = curt->right;
    else
      return root; // duplicate, ignore
  }

  __u64 n = new_node(data_ptr, key);

  if (parent == 0) {
    // empty tree
    return n;
  }

  if (parent > HEAP_SIZE - 100) {
    return 0;
  }
  struct bstnode *parentt = (struct bstnode *)(data_ptr + parent);
  if (key < parentt->key)
    parentt->left = n;
  else
    parentt->right = n;

  return root;
}

inline __u64 search(char *data_ptr, __u64 root, __u64 key) {
  __u64 cur = root;

  if (cur == 0)
    return 0;
  for (int i = 0; i < 1000; ++i) {
    if (cur <= 0 || cur > HEAP_SIZE - 100) {
      return 0;
    }
    struct bstnode *curt = (struct bstnode *)(data_ptr + cur);
    if (key < curt->key)
      cur = curt->left;
    else if (key > curt->key)
      cur = curt->right;
    else
      return cur; // found
  }
  return 0;
}

__noinline __u64 delete(__u64 root, __u64 key) {
  char *data_ptr = init_heap(HEAP_SIZE);
  if (data_ptr == NULL) {
    return 0;
  }
  long parent = 0, cur = root;

  if (cur == 0)
    return 0;
  for (int i = 0; i < 1000; ++i) {
    if (cur <= 0 || cur > HEAP_SIZE - 100) {
      return root;
    }
    struct bstnode *curt = (struct bstnode *)(data_ptr + cur);
    if (key == curt->key)
      break;
    parent = cur;
    if (key < curt->key)
      cur = curt->left;
    else
      cur = curt->right;
  }
  // Find node
  if (!cur)
    return root; // not found

  if (cur <= 0 || cur > HEAP_SIZE - 100) {
    return root;
  }
  struct bstnode *curt = (struct bstnode *)(data_ptr + cur);
  // Case 1: 0 or 1 child
  if (curt->left == 0 || curt->right == 0) {
    __u64 child = curt->left ? curt->left : curt->right;

    // If deleting root
    if (parent == 0) {
      free(cur);
      return child;
    }

    if (parent <= 0 || parent > HEAP_SIZE - 100) {
      return root;
    }
    struct bstnode *parentt = (struct bstnode *)(data_ptr + parent);
    if (parentt->left == cur)
      parentt->left = child;
    else
      parentt->right = child;

    free(cur);
    return root;
  }

  long succ_parent = cur;
  long succ = curt->right;

  for (int i = 0; i < 1000; i++) {
    if (succ <= 0 || succ > HEAP_SIZE - 100) {
      return root;
    }
    struct bstnode *succt = (struct bstnode *)(data_ptr + succ);
    if (succt->left == 0) {
      break;
    }
    succ_parent = succ;
    succ = succt->left;
  }

  if (succ <= 0 || succ > HEAP_SIZE - 100) {
    return root;
  }
  struct bstnode *succt = (struct bstnode *)(data_ptr + succ);

  curt->key = succt->key;

  if (succ_parent <= 0 || succ_parent > HEAP_SIZE - 100) {
    return root;
  }
  struct bstnode *succpt = (struct bstnode *)(data_ptr + succ_parent);
  // Delete successor (it has max 1 child)
  if (succpt->left == succ)
    succpt->left = succt->right;
  else
    succpt->right = succt->right;

  free(succ);
  return root;

  // return root;
}

SEC("tracepoint/syscalls/sys_enter_mount")

int init_bst(struct trace_event_raw_sys_enter *ctx) {

  unsigned long flags;
  flags = ctx->args[3];

  int mode = flags >> 32;
  __u64 num = flags & 0xffffffff;

  struct perf_data *p = bpf_map_lookup_elem(&perf, &(const __u32){0});
  if (!p) {
    return 0;
  }
  // bpf_printk("flag: %lu", flags);

  char *data_ptr = init_heap(HEAP_SIZE);
  if (data_ptr == NULL) {
    return 0;
  }

  if (mode == 0) {
    // insert
    long starttime = bpf_ktime_get_ns();
    p->root = insert(data_ptr, p->root, num);
    long endtime = bpf_ktime_get_ns();
    p->lat += endtime - starttime;
    p->times += 1;
  } else if (mode == 1) {
    // search
    long starttime = bpf_ktime_get_ns();
    __u64 res = search(data_ptr, p->root, num);
    long endtime = bpf_ktime_get_ns();
    p->se_lat += endtime - starttime;
    p->se_times += 1;
    if (res == 0) {
      p->__gar = 0;
    } else {

      if (res > HEAP_SIZE - 100) {
        return 0;
      }
      struct bstnode *curt = (struct bstnode *)(data_ptr + res);
      p->__gar = curt->key;
    }
  } else if (mode == 2) {
    // delete
    long starttime = bpf_ktime_get_ns();
    p->root = delete(p->root, num);
    long endtime = bpf_ktime_get_ns();
    p->del_lat += endtime - starttime;
    p->del_times += 1;
  }
  return 0;
}

char _license[] SEC("license") = "GPL";