#ifndef DEBUG_H
#define DEBUG_H

#include <stdlib.h>

#define CRITICAL(str) {printf("%s, %s, %d\n", str, __FUNCTION__, __LINE__); exit(1);}

#endif
