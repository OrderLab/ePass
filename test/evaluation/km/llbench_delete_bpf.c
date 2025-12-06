#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#define META_SIZE 65000
#define META_BLOCK_SIZE 32
#define HEAP_SIZE ((META_SIZE + 1) * META_BLOCK_SIZE)

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

static __u64 gettop() {
  __u32 i = 0;
  __u32 *head = bpf_map_lookup_elem(&meta, &i);
  if (head == 0) {
    return 0;
  }
  return *head * META_BLOCK_SIZE;
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
  // for (int i = 0; i < 2; i++) {
  //   if (i >= blocks) {
  //     return;
  //   }
  //   __u32 cur_idx = block_idx + i;
  //   __u32 *cur_pos = bpf_map_lookup_elem(&meta, &cur_idx);
  //   if (cur_pos == 0) {
  //     return;
  //   }
  //   *cur_pos = 0;
  // }
}

struct test_struct {
  __u64 a;
  __u64 next;
};

SEC("tracepoint/syscalls/sys_enter_mount")
int delete_ll(void *ctx) {
  char *data_ptr = init_heap(HEAP_SIZE);
  if (data_ptr == NULL) {
    return 0;
  } // Lookup
  __u64 top = gettop();
  __u64 curr = top - META_BLOCK_SIZE;

  long starttime = bpf_ktime_get_ns();
  for (int i = 0; i < 2000; ++i) {
    if (curr > HEAP_SIZE - 100) {
      return 0;
    }
    struct test_struct *ts = (struct test_struct *)(data_ptr + curr);
    free(curr);
    curr = ts->next;
  }
  long endtime = bpf_ktime_get_ns();
  bpf_printk("delete: %ld\n", endtime - starttime);
  // bpf_printk("last curr: %llu\n", curr);

  return 0;
}

char _license[] SEC("license") = "GPL";
