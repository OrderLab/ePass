#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mount.h>

void testcall() {
  const char *source = "tmpfs";
  const char *target = "/mnt/lol";
  const char *fstype = "tmpfs";
  unsigned long flags = 0;
  const char *data = "size=10M";
  
  mount(source, target, fstype, flags, data);
}


#define META_PIN_PATH "/sys/fs/bpf/meta"
#define DATA_PIN_PATH "/sys/fs/bpf/data"

/* detach programs and cleanup pinned maps */
void cleanup(struct bpf_link *link1, struct bpf_link *link2) {
  if (link1)
    bpf_link__destroy(link1);
  if (link2)
    bpf_link__destroy(link2);
  unlink(META_PIN_PATH);
  unlink(DATA_PIN_PATH);
}

int attach_prog(const char *filename, const char *prog_name,
                struct bpf_link **link_out) {
  struct bpf_object *obj = NULL;
  struct bpf_program *prog = NULL;
  int err;

  obj = bpf_object__open_file(filename, NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Failed to open %s\n", filename);
    return -1;
  }

  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "Failed to load %s\n", filename);
    return -1;
  }

  prog = bpf_object__find_program_by_name(obj, prog_name);
  if (!prog) {
    fprintf(stderr, "Program %s not found\n", prog_name);
    return -1;
  }

  *link_out =
      bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_mount");
  if (libbpf_get_error(*link_out)) {
    fprintf(stderr, "Failed to attach program %s\n", prog_name);
    return -1;
  }

  int meta_fd = bpf_object__find_map_fd_by_name(obj, "meta");
  int data_fd = bpf_object__find_map_fd_by_name(obj, "data");

  if (meta_fd < 0 || data_fd < 0)
    return -1;

  if (bpf_obj_pin(meta_fd, META_PIN_PATH))
    fprintf(stderr, "Pin meta failed\n");
  if (bpf_obj_pin(data_fd, DATA_PIN_PATH))
    fprintf(stderr, "Pin data failed\n");

  bpf_object__close(obj);
  return 0;
}

int reuse_pinned_maps(struct bpf_object *obj) {
//   struct bpf_map *meta_map = bpf_object__find_map_by_name(obj, "meta");
//   struct bpf_map *data_map = bpf_object__find_map_by_name(obj, "data");
//   if (!meta_map || !data_map)
//     return -1;

//   int meta_fd = bpf_obj_get(META_PIN_PATH);
//   int data_fd = bpf_obj_get(DATA_PIN_PATH);
//   if (meta_fd < 0 || data_fd < 0)
//     return -1;

//   bpf_map__reuse_fd(meta_map, meta_fd);
//   bpf_map__reuse_fd(data_map, data_fd);

/* Assign pin path BEFORE load */
    struct bpf_map *meta_map = bpf_object__find_map_by_name(obj, "meta");
    struct bpf_map *data_map = bpf_object__find_map_by_name(obj, "data");

    bpf_map__set_pin_path(meta_map, "/sys/fs/bpf/meta");
    bpf_map__set_pin_path(data_map, "/sys/fs/bpf/data");
  return 0;
}

int main() {
  cleanup(NULL, NULL);
  struct bpf_link *link1 = NULL, *link2 = NULL;
  struct bpf_object *obj2 = NULL;

  /* Step 1: Load first program and attach */
  if (attach_prog("init_ll.o", "init_ll", &link1) != 0)
    return 1;
  printf("init_ll attached\n");

  /* Optional: run program briefly */
  sleep(1);
  testcall();
  testcall();
  testcall();
  sleep(1);

  /* Step 3: Detach first program */
  bpf_link__destroy(link1);
  link1 = NULL;
  printf("init_ll detached, maps still alive\n");

  /* Step 4: Load second program */
  obj2 = bpf_object__open_file("lookup_ll.o", NULL);
  if (libbpf_get_error(obj2)) {
    fprintf(stderr, "Failed to open lookup_ll.o\n");
    cleanup(NULL, NULL);
    return 1;
  }
  /* Step 5: Reuse pinned maps */
  if (reuse_pinned_maps(obj2) != 0) {
    fprintf(stderr, "Failed to reuse pinned maps\n");
    cleanup(NULL, NULL);
    return 1;
  }
  printf("lookup_ll will use existing maps\n");

  if (bpf_object__load(obj2)) {
    fprintf(stderr, "Failed to load lookup_ll.o\n");
    cleanup(NULL, NULL);
    return 1;
  }


  /* Step 6: Attach second program */
  struct bpf_program *prog2 =
      bpf_object__find_program_by_name(obj2, "lookup_ll");
  if (!prog2) {
    fprintf(stderr, "lookup_ll program not found\n");
    cleanup(NULL, NULL);
    return 1;
  }

  link2 = bpf_program__attach_tracepoint(prog2, "syscalls", "sys_enter_mount");
  if (libbpf_get_error(link2)) {
    fprintf(stderr, "Failed to attach lookup_ll\n");
    cleanup(NULL, NULL);
    return 1;
  }
  printf("lookup_ll attached\n");

  /* Run for some time */
  sleep(1);
  for(int i = 0; i< 10;++i){
    testcall();
  }
  sleep(1);

  /* Step 7: Detach second program and cleanup maps */
  cleanup(NULL, link2);
  printf("lookup_ll detached, pinned maps removed\n");

  bpf_object__close(obj2);

  return 0;
}
