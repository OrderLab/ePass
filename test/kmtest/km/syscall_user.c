#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

int main() {
  const char *source = "tmpfs";
  const char *target = "/mnt/lol";
  const char *fstype = "tmpfs";
  unsigned long flags = 0;
  const char *data = "size=10M";
  
  int ret = mount(source, target, fstype, flags, data);
  if (ret < 0) {
    perror("mount");
    return 1;
  }

  return 0;
}
