#pragma once

#ifdef DEBUG
#include <stdio.h>

#define DPRINTF(fmt, args...)                             \
    {                                                     \
        printf("[DEBUG] %s: " fmt, __FUNCTION__, ##args); \
        fflush(stdout);                                   \
    }
#else
#define DPRINTF(msg, ...)
#endif