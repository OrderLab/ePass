#define _GNU_SOURCE
// #include <errno.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <sys/mount.h>

void testcall() {
  const char *source = "tmpfs";
  const char *target = "/mnt/lol";
  const char *fstype = "tmpfs";
  unsigned long flags = 0;
  const char *data = "size=10M";
  
  mount(source, target, fstype, flags, data);
}
