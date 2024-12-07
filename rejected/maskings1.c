// https://stackoverflow.com/questions/74178703/ebpf-invalid-access-to-map-value-even-with-bounds-check

struct bpf_elf_map __section("maps") data_store = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = 1024,
    .max_elem = 4096,
    .pinning = PIN_GLOBAL_NS,
};

static __always_inline void read_data(__u32 idx, __u32 offset, void *dst,
                                      __u32 size) {
  if (size > 512 || offset >= 1024) {
    // for the ebpf verifier
    return;
  }
  void *b = bpf_map_lookup_elem(&data_store, &idx);
  if (!b) {
    // shouldn't happen
    return;
  }

  if (offset + size <= 1024) {
    for (__u32 i = 0; i < size && i < 512; ++i) {
      if (offset + i >= 1024) {
        return;
      }
      // !! where the verifier complains
      memcpy(dst + i, b + offset + i, sizeof(__u8));
    }
  } else {
    // ...
  }
}
