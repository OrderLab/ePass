#ifndef DEBUG_H
#define DEBUG_H

#include <stdlib.h>
#include <stdio.h>

#define CRITICAL(str)                                                       \
	{                                                                   \
		printf("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
		       str);                                                \
		exit(1);                                                    \
	}

#define RAISE_ERROR(str)                                                    \
	{                                                                   \
		printf("%s:%d <%s> %s\n", __FILE__, __LINE__, __FUNCTION__, \
		       str);                                                \
		return -ENOSYS;                                             \
	}

#define DBGASSERT(cond)                       \
	if (!(cond)) {                        \
		CRITICAL("Assertion failed"); \
	}

#endif
