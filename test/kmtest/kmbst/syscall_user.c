#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
// #include <errno.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <sys/mount.h>

const char *source = "tmpfs";
const char *target = "/mnt/lol";
const char *fstype = "tmpfs";
const char *data = "size=10M";
unsigned long generate_flags(int mode, int num) {
  return ((unsigned long)mode << 32) | (unsigned long)num;
}

void insert(int key) {
  mount(source, target, fstype, generate_flags(0, key), data);
}

void search(int key) {
  mount(source, target, fstype, generate_flags(1, key), data);
}

void delete(int key) {
  mount(source, target, fstype, generate_flags(2, key), data);
}

static inline unsigned int lcg_next(unsigned int *state) {
    *state = (*state * 1664525 + 1013904223);
    return *state;
}

static inline unsigned int rand_range(unsigned int *state, unsigned int max) {
    return lcg_next(state) % max;
}

void shuffle(int *arr, int n, unsigned int seed) {
    unsigned int state = seed;
    for (int i = n - 1; i > 0; i--) {
        int j = rand_range(&state, i + 1);
        int tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

int main() {
  int num = 64 * 1024;
  int *arr = malloc(num * sizeof(int));
  for(int i = 0; i < num; i++) {
    arr[i] = i + 1;
  }
  shuffle(arr, num, 114514);

  for(int i = 0; i < num; i++) {
    insert(arr[i]);
  }


  for(int i = 0; i < num; i++) {
    search(arr[i]);
  }

  for(int i = 0; i < num; i++) {
    delete(arr[i]);
  }

  free(arr);
  return 0;
}
