#define _GNU_SOURCE
#include "utils/memory.h"
#include <stdlib.h>
#include <string.h>

#ifdef USE_MIMALLOC
#include <mimalloc.h>
#endif

int rw_mem_init(void)
{
    /* mimalloc 3.1 is compiled with MI_SECURE; no runtime toggle needed. */
    (void)0;
    return 0;
}

void *rw_mem_alloc(size_t size)
{
    if (size == 0) {
        return nullptr;
    }
#ifdef USE_MIMALLOC
    return mi_malloc(size);
#else
    return malloc(size);
#endif
}

void *rw_mem_calloc(size_t count, size_t size)
{
    if (count == 0 || size == 0) {
        return nullptr;
    }
#ifdef USE_MIMALLOC
    return mi_calloc(count, size);
#else
    return calloc(count, size);
#endif
}

void *rw_mem_realloc(void *ptr, size_t new_size)
{
#ifdef USE_MIMALLOC
    return mi_realloc(ptr, new_size);
#else
    return realloc(ptr, new_size);
#endif
}

void rw_mem_free(void *ptr)
{
    if (ptr == nullptr) {
        return;
    }
#ifdef USE_MIMALLOC
    mi_free(ptr);
#else
    free(ptr);
#endif
}

void rw_mem_secure_zero(void *ptr, size_t len)
{
    explicit_bzero(ptr, len);
}
