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

int main() {

  for (int i = 1; i <= 10; i++) {
    insert(i);
  }
  // for (int i = 1; i <= 10; i++) {
    // search(6);
  // }
  
  search(6);
  delete(6);
  search(6);

  return 0;
}
