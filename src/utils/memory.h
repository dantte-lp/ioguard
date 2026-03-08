#ifndef RINGWALL_UTILS_MEMORY_H
#define RINGWALL_UTILS_MEMORY_H

#include <stddef.h>

/* Initialize memory allocator (mimalloc if available) */
[[nodiscard]] int rw_mem_init(void);

/* Allocate memory. Returns nullptr for size == 0. */
[[nodiscard]] void *rw_mem_alloc(size_t size);

/* Allocate zeroed memory */
[[nodiscard]] void *rw_mem_calloc(size_t count, size_t size);

/* Reallocate memory */
[[nodiscard]] void *rw_mem_realloc(void *ptr, size_t new_size);

/* Free memory. Safe to call with nullptr. */
void rw_mem_free(void *ptr);

/* Securely zero memory (not optimized away by compiler) */
void rw_mem_secure_zero(void *ptr, size_t len);

#endif /* RINGWALL_UTILS_MEMORY_H */
