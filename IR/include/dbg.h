#ifndef DEBUG_H
#define DEBUG_H

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#define CRITICAL(str)                                                     \
    {                                                                     \
        printf("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, str); \
        exit(1);                                                          \
    }

#define DBGASSERT(cond)               \
    if (!(cond)) {                    \
        CRITICAL("Assertion failed"); \
    }

#endif
