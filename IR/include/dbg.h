#ifndef DEBUG_H
#define DEBUG_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define CRITICAL(str)                                        \
    {                                                        \
        printf("<%s>:%d %s\n", __FUNCTION__, __LINE__, str); \
        exit(1);                                             \
    }

#define DBGASSERT(cond) assert(cond)

#endif
