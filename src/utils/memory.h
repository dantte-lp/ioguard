#ifndef IOGUARD_UTILS_MEMORY_H
#define IOGUARD_UTILS_MEMORY_H

#include <stddef.h>

/* Initialize memory allocator (mimalloc if available) */
[[nodiscard]] int iog_mem_init(void);

/* Allocate memory. Returns nullptr for size == 0. */
[[nodiscard]] void *iog_mem_alloc(size_t size);

/* Allocate zeroed memory */
[[nodiscard]] void *iog_mem_calloc(size_t count, size_t size);

/* Reallocate memory */
[[nodiscard]] void *iog_mem_realloc(void *ptr, size_t new_size);

/* Free memory. Safe to call with nullptr. */
void iog_mem_free(void *ptr);

/* Securely zero memory (not optimized away by compiler) */
void iog_mem_secure_zero(void *ptr, size_t len);

#endif /* IOGUARD_UTILS_MEMORY_H */
