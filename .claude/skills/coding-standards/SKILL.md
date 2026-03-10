---
name: coding-standards
description: Use when writing ANY C code in ioguard — enforces file structure, naming, comments, error handling, memory, includes, tests. MANDATORY for all new and modified code.
---

# ioguard Coding Standards

## File Structure

### Header files (.h)

```c
#ifndef RINGWALL_MODULE_FILE_H
#define RINGWALL_MODULE_FILE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Public types, constants, function declarations only */
/* NO implementations except static inline cleanup functions */

#endif /* RINGWALL_MODULE_FILE_H */
```

Rules:
- Include guard: `RINGWALL_MODULE_FILE_H` (e.g., `RINGWALL_CORE_SESSION_H`)
- NO `#pragma once` — use traditional include guards
- Headers contain: typedefs, enums, constexpr constants, function declarations, `_Static_assert`
- Headers do NOT contain: function bodies (except `static inline` cleanup helpers), global variables, `#define _GNU_SOURCE`
- Every public function has `[[nodiscard]]` if it returns an error code or pointer

### Source files (.c)

```c
#define _GNU_SOURCE          /* 1. Feature test macros (if needed) */
#include "module/file.h"    /* 2. Matching project header */
#include <stdlib.h>          /* 3. Standard C headers */
#include <sys/socket.h>      /* 4. POSIX/Linux headers */
#include <wolfssl/ssl.h>     /* 5. Third-party headers (ifdef'd if optional) */
```

Rules:
- `_GNU_SOURCE` MUST be first line if needed (before any includes)
- Matching header included first (catches missing includes in .h)
- System headers sorted alphabetically within groups
- Third-party headers wrapped in `#ifdef USE_LIBRARY` if optional

---

## Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Functions (public) | `rw_module_verb_noun` | `rw_session_create`, `rw_io_prep_recv` |
| Functions (TLS layer) | `tls_noun_verb` | `tls_context_new`, `tls_session_free` |
| Functions (static) | `verb_noun` (no prefix) | `nop_complete_cb`, `timeout_cb` |
| Types (struct/enum) | `rw_module_name_t` | `rw_session_t`, `rw_io_ctx_t` |
| Enum values | `RW_MODULE_VALUE` | `RW_IPC_MSG_AUTH_REQUEST` |
| Constants (constexpr) | `RW_MODULE_NAME` | `RW_SESSION_COOKIE_SIZE` |
| Macros | `RW_MODULE_NAME` | `RW_HTTP_MAX_HEADERS` |
| Variables (local) | `snake_case` | `timeout_ms`, `queue_depth` |
| Variables (struct members) | `snake_case` | `listen_port`, `cert_file` |
| Variables (global static) | `g_name` | `g_initialized`, `g_init_count` |
| Callback types | `rw_module_cb` or `_func_t` | `rw_io_cb`, `tls_push_func_t` |

---

## Comments

### When to comment

- **DO comment:** security-critical decisions, non-obvious algorithms, API contracts, `MUST`/`NEVER` constraints
- **DO NOT comment:** obvious code, what the function name already says, boilerplate

### Function documentation (headers only, Doxygen-style)

```c
/**
 * Validate session cookie with constant-time comparison
 *
 * @param store  Session store to search
 * @param cookie Cookie bytes (must be RW_SESSION_COOKIE_SIZE)
 * @param len    Cookie length
 * @param out    Output session pointer (valid until delete/cleanup)
 * @return 0 on success, -ENOENT if not found, -ETIMEDOUT if expired
 *
 * Note: Uses wolfSSL_ConstantCompare — safe against timing attacks.
 */
[[nodiscard]] int rw_session_validate(rw_session_store_t *store,
                                       const uint8_t *cookie, size_t len,
                                       rw_session_t **out);
```

Rules:
- `@param` for every parameter
- `@return` with specific error codes
- `Note:` for security, threading, or lifetime constraints
- No Doxygen in .c files — only brief `/* Purpose */` above static functions

### Inline comments

```c
/* Correct: explains WHY, not WHAT */
io_uring_prep_timeout(sqe, &td->ts, 0, 0);  /* absolute timeout, no count limit */

/* Wrong: restates the code */
io_uring_prep_timeout(sqe, &td->ts, 0, 0);  /* prepare timeout */
```

### Section separators (for large files > 200 LOC)

```c
/* ============================================================================
 * Section Name
 * ============================================================================ */
```

---

## Error Handling

### Return convention

| Return type | Success | Error |
|-------------|---------|-------|
| `int` | `0` | negative errno (`-ENOMEM`, `-EAGAIN`, `-EINVAL`) |
| `ssize_t` | bytes count (>= 0) | negative errno |
| `void *` | valid pointer | `nullptr` |
| `struct *` | valid pointer | `nullptr` |
| Custom enum | `RW_*_SUCCESS = 0` | negative enum values |

### Error propagation pattern

```c
[[nodiscard]] int rw_foo_create(rw_foo_t **out)
{
    rw_foo_t *foo = calloc(1, sizeof(*foo));
    if (foo == nullptr) {
        return -ENOMEM;
    }

    int ret = rw_bar_init(&foo->bar);
    if (ret < 0) {
        goto cleanup;
    }

    ret = rw_baz_init(&foo->baz);
    if (ret < 0) {
        goto cleanup;
    }

    *out = foo;
    return 0;

cleanup:
    rw_foo_destroy(foo);
    return ret;
}
```

Rules:
- Check every return value (enforced by `[[nodiscard]]`)
- Use `goto cleanup` for multi-resource cleanup — NOT nested ifs
- Return negative errno, not `-1`
- Never ignore errors silently

---

## Memory Management

### Allocation

```c
/* CORRECT: sizeof(*ptr) — type-safe, survives refactoring */
rw_foo_t *foo = calloc(1, sizeof(*foo));

/* WRONG: sizeof(type) — can diverge from actual variable type */
rw_foo_t *foo = calloc(1, sizeof(rw_foo_t));
```

### Free

```c
/* All free functions MUST be null-safe */
void rw_foo_destroy(rw_foo_t *foo)
{
    if (foo == nullptr) {
        return;
    }
    /* cleanup members */
    free(foo);
}
```

### Secure zeroing (MANDATORY for secrets)

```c
/* Passwords, cookies, keys — zero before free */
explicit_bzero(session->cookie, RW_SESSION_COOKIE_SIZE);
explicit_bzero(password_buf, password_len);
free(session);
```

### Initialization

```c
/* Preferred: designated initializers */
struct __kernel_timespec ts = {
    .tv_sec = timeout_ms / 1000,
    .tv_nsec = (timeout_ms % 1000) * 1000000L,
};

/* Zero init */
struct msghdr msg = {0};
```

---

## C23 Features

### Mandatory (use everywhere)

| Feature | Usage | Example |
|---------|-------|---------|
| `nullptr` | All null pointer literals | `if (ptr == nullptr)` |
| `[[nodiscard]]` | All functions returning error/pointer | `[[nodiscard]] int rw_init(void);` |
| `constexpr` | Compile-time constants (replaces `#define` for values) | `constexpr size_t RW_MAX = 1024;` |
| `bool/true/false` | Boolean type (no `<stdbool.h>` needed in C23) | `bool running = true;` |
| `_Static_assert` | Struct size validation, array bounds | `_Static_assert(sizeof(cookie) == 32, "...");` |

### Recommended (use when appropriate)

| Feature | Usage | Example |
|---------|-------|---------|
| Digit separators | Large constants | `constexpr size_t BUF = 16'384;` |
| `typeof` | Type-safe macros | `typeof(a) _a = (a);` |
| `[[maybe_unused]]` | Callback params | `[[maybe_unused]] void *ctx` |
| `_Atomic` | Lock-free counters | `_Atomic uint64_t bytes_rx;` |
| `<stdckdint.h>` | Overflow-safe arithmetic | `if (ckd_add(&total, a, b)) ...` |
| Empty initializer `{}` | Zero-init structs | `rw_foo_t foo = {};` |
| `unreachable()` | Exhaustive switch default | `default: unreachable();` |

### Avoid

| Feature | Why |
|---------|-----|
| `auto` type inference | Harms readability in security code — always spell out the type |
| `_BitInt(N)` | Not needed in ioguard — standard `uint*_t` sufficient |
| `#embed` | Not yet stable across compilers |
| `[[deprecated]]` | Use only during planned API migration, not routinely |

---

## Function Signatures

### Style

```c
/* Return type on same line, parameters aligned */
[[nodiscard]] int rw_session_validate(rw_session_store_t *store,
                                       const uint8_t *cookie, size_t len,
                                       rw_session_t **out);

/* Short signatures on one line */
[[nodiscard]] int rw_mem_init(void);
void rw_mem_free(void *ptr);
```

### Pointer style (Linux kernel)

```c
int *ptr;           /* CORRECT: * with variable name */
int* ptr;           /* WRONG */
const char *name;   /* CORRECT */
```

### const correctness

- Input-only parameters: `const`
- Output parameters: non-const pointer
- Strings returned from static buffers: `const char *`

---

## Test Patterns (Unity)

### File structure

```c
#include <unity/unity.h>
#include <string.h>
#include "module/file.h"

void setUp(void) {}
void tearDown(void) {}

void test_module_action_expected_result(void)
{
    /* Arrange */
    rw_foo_t *foo = rw_foo_create();
    TEST_ASSERT_NOT_NULL(foo);

    /* Act */
    int ret = rw_foo_action(foo);

    /* Assert */
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Cleanup */
    rw_foo_destroy(foo);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_module_action_expected_result);
    return UNITY_END();
}
```

### Test naming

`test_<module>_<action>_<expected>` — e.g.:
- `test_rw_mem_init_returns_zero`
- `test_rw_session_validate_invalid_returns_enoent`
- `test_rw_io_init_zero_depth_returns_null`

### Assertions (use typed variants)

```c
TEST_ASSERT_EQUAL_INT(0, ret);                    /* int comparison */
TEST_ASSERT_NOT_NULL(ptr);                         /* pointer non-null */
TEST_ASSERT_NULL(ptr);                             /* pointer null */
TEST_ASSERT_EQUAL_STRING("hello", buf);            /* string comparison */
TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, n); /* byte array */
TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);          /* range check */
TEST_ASSERT_TRUE(condition);                       /* boolean */
```

### Conditional skips (for environment-dependent tests)

```c
if (ctx == nullptr) {
    TEST_IGNORE_MESSAGE("io_uring not available — skipping");
}
```

### Resource cleanup

Every test cleans up its own resources. No shared state between tests unless via setUp/tearDown.

---

## Banned Patterns

### Functions (NEVER use)

`strcpy`, `strcat`, `sprintf`, `gets`, `atoi`, `system()`, `mktemp`, `tmpnam`

### Replacements

| Banned | Use instead |
|--------|-------------|
| `strcpy(dst, src)` | `snprintf(dst, sizeof(dst), "%s", src)` |
| `sprintf(buf, ...)` | `snprintf(buf, sizeof(buf), ...)` |
| `strcat(dst, src)` | `snprintf(dst + len, remaining, "%s", src)` |
| `atoi(str)` | `strtol(str, &end, 10)` with error checking |
| `system(cmd)` | `posix_spawn` or `pidfd_spawn` |
| `memcmp` on secrets | `ConstantCompare` or manual constant-time loop |

### Anti-patterns

```c
/* WRONG: unchecked return */
rw_session_create(store, user, group, 300, &session);

/* CORRECT: [[nodiscard]] forces check */
int ret = rw_session_create(store, user, group, 300, &session);
if (ret < 0) { return ret; }

/* WRONG: sizeof(type) */
malloc(sizeof(rw_session_t));

/* CORRECT: sizeof(*ptr) */
malloc(sizeof(*session));

/* WRONG: NULL */
if (ptr == NULL) { ... }

/* CORRECT: nullptr */
if (ptr == nullptr) { ... }

/* WRONG: #define constant */
#define MAX_SESSIONS 1024

/* CORRECT: constexpr */
constexpr uint32_t RW_MAX_SESSIONS = 1024;
```

---

## Braces and Formatting

Enforced by `.clang-format` — key rules:
- **Braces**: Linux kernel style (`BreakBeforeBraces: Linux`)
- **Column limit**: 100
- **Indent**: 4 spaces (no tabs in source, tabs in Makefile only)
- **Pointer alignment**: Right (`int *ptr`)
- **Switch case**: no indent for case labels

```c
int rw_example(int value)
{
    switch (value) {
    case 0:
        return handle_zero();
    case 1:
        return handle_one();
    default:
        return -EINVAL;
    }
}

if (condition) {
    do_something();
} else {
    do_other();
}

for (int i = 0; i < n; i++) {
    process(i);
}
```
