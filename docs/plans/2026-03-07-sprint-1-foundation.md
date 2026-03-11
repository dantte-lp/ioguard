# Sprint 1: Foundation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the foundation layer — io_uring event loop wrapper, process management (Main spawns workers), IPC over SOCK_SEQPACKET + protobuf-c, TOML configuration, and mimalloc memory setup.

**Architecture:** Three-process model (Main → sec-mod + Workers). Main process uses io_uring for all I/O: accepting signals via signalfd, monitoring child processes via IORING_OP_WAITID, and timers via IORING_OP_TIMEOUT. Workers run independent io_uring event loops. IPC uses SOCK_SEQPACKET + protobuf-c with arena allocator to eliminate malloc on the hot path.

**Tech Stack:** C23, liburing 2.7+, protobuf-c 1.5.1+, tomlc99, mimalloc 3.1.5+ (MI_SECURE), Unity test framework. Linux kernel 6.7+, glibc 2.39+.

**References:**
- Architecture design: `docs/plans/2026-03-07-ioguard-architecture-design.md`
- IPC research: `docs/draft/three-ipc-mechanisms.md`
- Process management: `docs/draft/process-management-without-libuv.md`
- Skills: `.claude/skills/c23-standards/`, `.claude/skills/security-coding/`
- context7: `/axboe/liburing`, `/protobuf-c/protobuf-c`, `/cktan/tomlc99`

**Build/test commands:**
```bash
# In dev container (podman)
cmake --preset clang-debug
cmake --build --preset clang-debug
ctest --preset clang-debug
cmake --build --preset clang-debug --target format
cmake --build --preset clang-debug --target lint
```

---

## Task 1: Project Directory Scaffolding

**Files:**
- Create: `src/io/uring.h`
- Create: `src/io/uring.c`
- Create: `src/utils/memory.h`
- Create: `src/utils/memory.c`
- Create: `src/config/config.h`
- Create: `src/config/config.c`
- Create: `src/ipc/transport.h`
- Create: `src/ipc/transport.c`
- Create: `src/ipc/messages.h`
- Create: `src/ipc/messages.c`
- Create: `src/core/main.c`
- Create: `src/core/worker.h`
- Create: `src/core/worker.c`
- Create: `tests/unit/.gitkeep`
- Create: `tests/integration/.gitkeep`

**Step 1: Create directory structure with stub files**

Create all source directories and empty stub files with proper include guards. Each `.h` file gets the include guard pattern `IOGUARD_MODULE_FILE_H` and each `.c` file gets just its own header include. No implementation yet — just the skeleton.

Example header stub (`src/io/uring.h`):
```c
#ifndef IOGUARD_IO_URING_H
#define IOGUARD_IO_URING_H

#endif /* IOGUARD_IO_URING_H */
```

Example source stub (`src/io/uring.c`):
```c
#include "io/uring.h"
```

**Step 2: Verify directory structure**

Run: `find src tests -type f | sort`

Expected: All files listed in Step 1.

**Step 3: Commit**

```bash
git add src/ tests/
git commit -m "chore: scaffold source directory structure for Sprint 1"
```

---

## Task 2: CMakeLists.txt — Add Sprint 1 Targets

**Files:**
- Modify: `CMakeLists.txt`

**Step 1: Read current CMakeLists.txt**

Already read above. Need to:
1. Remove old `tls_abstract` library and PoC targets (they reference non-existent files)
2. Add `liburing` as REQUIRED (not optional)
3. Remove `libuv` dependency (no longer used)
4. Add `tomlc99` find logic
5. Add `stumpless` find logic (for later sprints, just detect now)
6. Add new library targets and test executables

**Step 2: Update CMakeLists.txt**

Replace the Dependencies, library, and test sections. Key changes:

```cmake
# --- io_uring (REQUIRED) ---
pkg_check_modules(LIBURING REQUIRED liburing>=2.7)

# --- tomlc99 ---
find_path(TOML_INCLUDE_DIR toml.h PATHS /usr/local/include /usr/include)
find_library(TOML_LIBRARY toml PATHS /usr/local/lib /usr/lib)
if(TOML_INCLUDE_DIR AND TOML_LIBRARY)
    set(TOML_FOUND TRUE)
    message(STATUS "Found tomlc99: ${TOML_LIBRARY}")
else()
    message(STATUS "tomlc99 not found")
endif()

# --- protobuf-c ---
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c>=1.5.0)
```

Add library targets:
```cmake
# ioguard core libraries
add_library(iog_io STATIC src/io/uring.c)
target_link_libraries(iog_io PUBLIC ${LIBURING_LIBRARIES})
target_include_directories(iog_io PUBLIC ${CMAKE_SOURCE_DIR}/src ${LIBURING_INCLUDE_DIRS})

add_library(iog_memory STATIC src/utils/memory.c)
target_include_directories(iog_memory PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(MIMALLOC_FOUND)
    target_link_libraries(iog_memory PUBLIC ${MIMALLOC_LIBRARY})
    target_include_directories(iog_memory PUBLIC ${MIMALLOC_INCLUDE_DIR})
    target_compile_definitions(iog_memory PUBLIC USE_MIMALLOC)
endif()

add_library(iog_config STATIC src/config/config.c)
target_include_directories(iog_config PUBLIC ${CMAKE_SOURCE_DIR}/src)
if(TOML_FOUND)
    target_link_libraries(iog_config PUBLIC ${TOML_LIBRARY})
    target_include_directories(iog_config PUBLIC ${TOML_INCLUDE_DIR})
    target_compile_definitions(iog_config PUBLIC USE_TOML)
endif()

add_library(iog_ipc STATIC src/ipc/transport.c src/ipc/messages.c)
target_link_libraries(iog_ipc PUBLIC ${PROTOBUF_C_LIBRARIES} iog_memory)
target_include_directories(iog_ipc PUBLIC ${CMAKE_SOURCE_DIR}/src ${PROTOBUF_C_INCLUDE_DIRS})
```

Add unit test targets (one per test file, all link unity):
```cmake
if(BUILD_TESTING AND UNITY_INCLUDE_DIR AND UNITY_SRC_DIR)
    # Macro to add a unit test
    macro(iog_add_test TEST_NAME TEST_SRC)
        add_executable(${TEST_NAME} ${TEST_SRC})
        target_link_libraries(${TEST_NAME} PRIVATE unity ${ARGN})
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endmacro()

    iog_add_test(test_io_uring tests/unit/test_io_uring.c iog_io)
    iog_add_test(test_memory tests/unit/test_memory.c iog_memory)
    iog_add_test(test_config_toml tests/unit/test_config_toml.c iog_config)
    iog_add_test(test_ipc_transport tests/unit/test_ipc_transport.c iog_ipc iog_io)
endif()
```

Remove old `tls_abstract`, `poc-server`, `poc-client`, `test_tls_wolfssl`, `test_tls_gnutls` targets and related code. Keep the wolfSSL/GnuTLS find logic (needed in Sprint 2) but don't build anything with it yet.

**Step 3: Verify cmake configures successfully**

Run: `cmake --preset clang-debug` (in container)

Expected: All REQUIRED deps found. No build errors on configure.

**Step 4: Commit**

```bash
git add CMakeLists.txt
git commit -m "build: update CMakeLists.txt for Sprint 1 foundation targets"
```

---

## Task 3: Memory Allocator — mimalloc Setup

**Files:**
- Create: `src/utils/memory.h`
- Create: `src/utils/memory.c`
- Create: `tests/unit/test_memory.c`

**Step 1: Write the failing test**

```c
#include <unity/unity.h>
#include "utils/memory.h"

void setUp(void) {}
void tearDown(void) {}

void test_rw_mem_init_returns_zero(void)
{
    int ret = iog_mem_init();
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_rw_mem_alloc_returns_nonnull(void)
{
    void *ptr = iog_mem_alloc(128);
    TEST_ASSERT_NOT_NULL(ptr);
    iog_mem_free(ptr);
}

void test_rw_mem_calloc_returns_zeroed(void)
{
    uint8_t *ptr = iog_mem_calloc(1, 64);
    TEST_ASSERT_NOT_NULL(ptr);
    for (int i = 0; i < 64; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, ptr[i]);
    }
    iog_mem_free(ptr);
}

void test_rw_mem_alloc_zero_returns_null(void)
{
    void *ptr = iog_mem_alloc(0);
    TEST_ASSERT_NULL(ptr);
}

void test_rw_mem_free_null_is_safe(void)
{
    iog_mem_free(nullptr); /* must not crash */
}

void test_rw_mem_secure_zero(void)
{
    uint8_t buf[32];
    memset(buf, 0xAA, sizeof(buf));
    iog_mem_secure_zero(buf, sizeof(buf));
    for (int i = 0; i < 32; i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buf[i]);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rw_mem_init_returns_zero);
    RUN_TEST(test_rw_mem_alloc_returns_nonnull);
    RUN_TEST(test_rw_mem_calloc_returns_zeroed);
    RUN_TEST(test_rw_mem_alloc_zero_returns_null);
    RUN_TEST(test_rw_mem_free_null_is_safe);
    RUN_TEST(test_rw_mem_secure_zero);
    return UNITY_END();
}
```

**Step 2: Run test to verify it fails**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_memory`

Expected: FAIL — functions not defined (linker error)

**Step 3: Write implementation**

`src/utils/memory.h`:
```c
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
```

`src/utils/memory.c`:
```c
#include "utils/memory.h"
#include <string.h>

#ifdef USE_MIMALLOC
#include <mimalloc.h>
#endif

int iog_mem_init(void)
{
#ifdef USE_MIMALLOC
    mi_option_enable(mi_option_secure);
#endif
    return 0;
}

void *iog_mem_alloc(size_t size)
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

void *iog_mem_calloc(size_t count, size_t size)
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

void *iog_mem_realloc(void *ptr, size_t new_size)
{
#ifdef USE_MIMALLOC
    return mi_realloc(ptr, new_size);
#else
    return realloc(ptr, new_size);
#endif
}

void iog_mem_free(void *ptr)
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

void iog_mem_secure_zero(void *ptr, size_t len)
{
    explicit_bzero(ptr, len);
}
```

**Step 4: Run test to verify it passes**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_memory -V`

Expected: All 6 tests PASS.

**Step 5: Commit**

```bash
git add src/utils/memory.h src/utils/memory.c tests/unit/test_memory.c
git commit -m "feat: add memory allocator wrapper with mimalloc support"
```

---

## Task 4: io_uring Event Loop — Core Ring Setup

**Files:**
- Create: `src/io/uring.h`
- Create: `src/io/uring.c`
- Create: `tests/unit/test_io_uring.c`

**Step 1: Write the failing test**

```c
#include <unity/unity.h>
#include "io/uring.h"

void setUp(void) {}
void tearDown(void) {}

void test_iog_io_init_creates_context(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);
    iog_io_destroy(ctx);
}

void test_iog_io_init_zero_depth_fails(void)
{
    iog_io_ctx_t *ctx = iog_io_init(0, 0);
    TEST_ASSERT_NULL(ctx);
}

void test_iog_io_run_once_with_timeout(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Submit a timeout and run once — should complete after ~10ms */
    int fired = 0;
    int ret = iog_io_add_timeout(ctx, 10, &fired);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100); /* wait up to 100ms */
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(1, fired);

    iog_io_destroy(ctx);
}

void test_iog_io_nop_completes(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int completed = 0;
    int ret = iog_io_submit_nop(ctx, &completed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(1, completed);

    iog_io_destroy(ctx);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_iog_io_init_creates_context);
    RUN_TEST(test_iog_io_init_zero_depth_fails);
    RUN_TEST(test_iog_io_run_once_with_timeout);
    RUN_TEST(test_iog_io_nop_completes);
    return UNITY_END();
}
```

**Step 2: Run test to verify it fails**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_io_uring`

Expected: FAIL — linker errors, functions undefined

**Step 3: Write implementation**

`src/io/uring.h`:
```c
#ifndef IOGUARD_IO_URING_H
#define IOGUARD_IO_URING_H

#include <liburing.h>
#include <stdbool.h>
#include <stdint.h>

/* Opaque io_uring event loop context */
typedef struct iog_io_ctx iog_io_ctx_t;

/* Completion callback type.
 * res: CQE result (bytes transferred or negative errno)
 * user_data: pointer passed when operation was submitted */
typedef void (*iog_io_cb)(int res, void *user_data);

/* Internal: completion entry tracking */
typedef struct {
    iog_io_cb cb;
    void    *user_data;
} iog_io_completion_t;

struct iog_io_ctx {
    struct io_uring ring;
    bool            running;
    uint32_t        queue_depth;
};

/* Create io_uring context. Returns nullptr on failure.
 * queue_depth: number of SQE slots (must be > 0, rounded up to power of 2)
 * flags: io_uring setup flags (e.g., IORING_SETUP_COOP_TASKRUN) */
[[nodiscard]] iog_io_ctx_t *iog_io_init(uint32_t queue_depth, uint32_t flags);

/* Destroy io_uring context and free resources */
void iog_io_destroy(iog_io_ctx_t *ctx);

/* Run event loop once: submit pending SQEs, wait for at least 1 CQE.
 * timeout_ms: max wait time in milliseconds (0 = no wait, poll only)
 * Returns: number of CQEs processed, or negative errno on error */
[[nodiscard]] int iog_io_run_once(iog_io_ctx_t *ctx, uint32_t timeout_ms);

/* Run event loop until iog_io_stop() is called.
 * Returns 0 on clean stop, negative errno on error. */
[[nodiscard]] int iog_io_run(iog_io_ctx_t *ctx);

/* Signal the event loop to stop after current iteration */
void iog_io_stop(iog_io_ctx_t *ctx);

/* Submit a NOP operation (for testing).
 * completed: pointer to int, set to 1 when CQE arrives */
[[nodiscard]] int iog_io_submit_nop(iog_io_ctx_t *ctx, int *completed);

/* Submit a timeout.
 * timeout_ms: duration in milliseconds
 * fired: pointer to int, set to 1 when timeout fires */
[[nodiscard]] int iog_io_add_timeout(iog_io_ctx_t *ctx, uint64_t timeout_ms, int *fired);

#endif /* IOGUARD_IO_URING_H */
```

`src/io/uring.c`:
```c
#include "io/uring.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Internal callback: sets int pointer to 1 */
static void nop_complete_cb(int res, void *user_data)
{
    (void)res;
    int *flag = user_data;
    *flag = 1;
}

/* Internal callback: timeout fired */
static void timeout_cb(int res, void *user_data)
{
    (void)res;
    int *flag = user_data;
    *flag = 1;
}

iog_io_ctx_t *iog_io_init(uint32_t queue_depth, uint32_t flags)
{
    if (queue_depth == 0) {
        return nullptr;
    }

    iog_io_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return nullptr;
    }

    int ret = io_uring_queue_init(queue_depth, &ctx->ring, flags);
    if (ret < 0) {
        free(ctx);
        return nullptr;
    }

    ctx->queue_depth = queue_depth;
    ctx->running = false;
    return ctx;
}

void iog_io_destroy(iog_io_ctx_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    io_uring_queue_exit(&ctx->ring);
    free(ctx);
}

int iog_io_run_once(iog_io_ctx_t *ctx, uint32_t timeout_ms)
{
    struct io_uring_cqe *cqe;
    int ret;
    int processed = 0;

    if (timeout_ms > 0) {
        struct __kernel_timespec ts = {
            .tv_sec = timeout_ms / 1000,
            .tv_nsec = (timeout_ms % 1000) * 1000000L,
        };
        ret = io_uring_submit_and_wait_timeout(&ctx->ring, &cqe, 1, &ts, nullptr);
    } else {
        ret = io_uring_submit(&ctx->ring);
        if (ret < 0) {
            return ret;
        }
        ret = io_uring_peek_cqe(&ctx->ring, &cqe);
    }

    if (ret < 0 && ret != -ETIME) {
        return (ret == -EAGAIN) ? 0 : ret;
    }

    /* Process all available CQEs */
    unsigned head;
    io_uring_for_each_cqe(&ctx->ring, head, cqe) {
        iog_io_completion_t *comp = io_uring_cqe_get_data(cqe);
        if (comp != nullptr) {
            comp->cb(cqe->res, comp->user_data);
            free(comp);
        }
        processed++;
    }
    io_uring_cq_advance(&ctx->ring, processed);

    return processed;
}

int iog_io_run(iog_io_ctx_t *ctx)
{
    ctx->running = true;
    while (ctx->running) {
        int ret = iog_io_run_once(ctx, 1000);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

void iog_io_stop(iog_io_ctx_t *ctx)
{
    ctx->running = false;
}

int iog_io_submit_nop(iog_io_ctx_t *ctx, int *completed)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    iog_io_completion_t *comp = calloc(1, sizeof(*comp));
    if (comp == nullptr) {
        return -ENOMEM;
    }
    comp->cb = nop_complete_cb;
    comp->user_data = completed;
    *completed = 0;

    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data(sqe, comp);
    return 0;
}

int iog_io_add_timeout(iog_io_ctx_t *ctx, uint64_t timeout_ms, int *fired)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == nullptr) {
        return -EAGAIN;
    }

    /* Allocate completion + timespec together */
    typedef struct {
        iog_io_completion_t comp;
        struct __kernel_timespec ts;
    } timeout_data_t;

    timeout_data_t *td = calloc(1, sizeof(*td));
    if (td == nullptr) {
        return -ENOMEM;
    }
    td->comp.cb = timeout_cb;
    td->comp.user_data = fired;
    td->ts.tv_sec = timeout_ms / 1000;
    td->ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
    *fired = 0;

    io_uring_prep_timeout(sqe, &td->ts, 0, 0);
    io_uring_sqe_set_data(sqe, &td->comp);
    return 0;
}
```

**Step 4: Run test to verify it passes**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_io_uring -V`

Expected: All 4 tests PASS.

**Step 5: Commit**

```bash
git add src/io/uring.h src/io/uring.c tests/unit/test_io_uring.c
git commit -m "feat: add io_uring event loop wrapper with timeout and NOP support"
```

---

## Task 5: io_uring — Accept, Read, Write, Signalfd

**Files:**
- Modify: `src/io/uring.h`
- Modify: `src/io/uring.c`
- Modify: `tests/unit/test_io_uring.c`

**Step 1: Write failing tests for socket accept and signalfd**

Add to `tests/unit/test_io_uring.c`:

```c
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

void test_iog_io_accept_and_recv(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Create a Unix domain socket pair to test accept+recv */
    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Write data on one end */
    const char *msg = "hello";
    write(sv[0], msg, 5);

    /* Submit recv on the other end */
    char buf[64] = {0};
    int recv_done = 0;
    ret = iog_io_prep_recv(ctx, sv[1], buf, sizeof(buf), &recv_done);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_EQUAL_INT(1, recv_done);
    TEST_ASSERT_EQUAL_STRING("hello", buf);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_iog_io_send(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Submit send on one end */
    const char *msg = "world";
    int send_done = 0;
    ret = iog_io_prep_send(ctx, sv[0], msg, 5, &send_done);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_EQUAL_INT(1, send_done);

    /* Read it back synchronously */
    char buf[64] = {0};
    ssize_t n = read(sv[1], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(5, n);
    TEST_ASSERT_EQUAL_STRING("world", buf);

    close(sv[0]);
    close(sv[1]);
    iog_io_destroy(ctx);
}

void test_iog_io_signalfd(void)
{
    iog_io_ctx_t *ctx = iog_io_init(64, 0);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Block SIGUSR1, create signalfd */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, nullptr);

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, sfd);

    /* Submit read on signalfd */
    struct signalfd_siginfo siginfo;
    int sig_received = 0;
    int ret = iog_io_prep_read(ctx, sfd, &siginfo, sizeof(siginfo), &sig_received);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Send ourselves SIGUSR1 */
    kill(getpid(), SIGUSR1);

    ret = iog_io_run_once(ctx, 100);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(1, ret);
    TEST_ASSERT_EQUAL_INT(1, sig_received);
    TEST_ASSERT_EQUAL_UINT32(SIGUSR1, siginfo.ssi_signo);

    close(sfd);
    sigprocmask(SIG_UNBLOCK, &mask, nullptr);
    iog_io_destroy(ctx);
}
```

Also add to `main()`:
```c
RUN_TEST(test_iog_io_accept_and_recv);
RUN_TEST(test_iog_io_send);
RUN_TEST(test_iog_io_signalfd);
```

**Step 2: Run test to verify new tests fail**

Expected: Linker errors for `iog_io_prep_recv`, `iog_io_prep_send`, `iog_io_prep_read`

**Step 3: Add recv, send, read operations to io/uring.h and io/uring.c**

Add to header:
```c
/* Submit a recv operation on a socket */
[[nodiscard]] int iog_io_prep_recv(iog_io_ctx_t *ctx, int fd, void *buf,
                                  size_t len, int *completed);

/* Submit a send operation on a socket */
[[nodiscard]] int iog_io_prep_send(iog_io_ctx_t *ctx, int fd, const void *buf,
                                  size_t len, int *completed);

/* Submit a read operation on a file descriptor (TUN, signalfd, etc.) */
[[nodiscard]] int iog_io_prep_read(iog_io_ctx_t *ctx, int fd, void *buf,
                                  size_t len, int *completed);

/* Submit a write operation on a file descriptor */
[[nodiscard]] int iog_io_prep_write(iog_io_ctx_t *ctx, int fd, const void *buf,
                                   size_t len, int *completed);
```

Implementation follows the same pattern as `iog_io_submit_nop`: allocate `iog_io_completion_t`, set callback that sets `*completed = 1`, prep the SQE, set data.

**Step 4: Run all tests**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_io_uring -V`

Expected: All 7 tests PASS.

**Step 5: Commit**

```bash
git add src/io/uring.h src/io/uring.c tests/unit/test_io_uring.c
git commit -m "feat: add recv, send, read, write operations to io_uring wrapper"
```

---

## Task 6: IPC Transport — SOCK_SEQPACKET

**Files:**
- Create: `src/ipc/transport.h`
- Create: `src/ipc/transport.c`
- Create: `tests/unit/test_ipc_transport.c`

**Step 1: Write the failing test**

```c
#include <unity/unity.h>
#include <string.h>
#include "ipc/transport.h"

void setUp(void) {}
void tearDown(void) {}

void test_rw_ipc_create_socketpair(void)
{
    iog_ipc_channel_t ch;
    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ch.parent_fd);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ch.child_fd);
    iog_ipc_close(&ch);
}

void test_rw_ipc_send_recv_message(void)
{
    iog_ipc_channel_t ch;
    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    const uint8_t msg[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    ret = iog_ipc_send(ch.parent_fd, msg, sizeof(msg));
    TEST_ASSERT_EQUAL_INT(0, ret);

    uint8_t buf[256];
    ssize_t n = iog_ipc_recv(ch.child_fd, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(5, n);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg, buf, 5);

    iog_ipc_close(&ch);
}

void test_rw_ipc_preserves_message_boundaries(void)
{
    iog_ipc_channel_t ch;
    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Send two messages */
    const uint8_t msg1[] = {0xAA, 0xBB};
    const uint8_t msg2[] = {0xCC, 0xDD, 0xEE};
    iog_ipc_send(ch.parent_fd, msg1, sizeof(msg1));
    iog_ipc_send(ch.parent_fd, msg2, sizeof(msg2));

    /* Receive them — each recv() should get exactly one message */
    uint8_t buf[256];
    ssize_t n1 = iog_ipc_recv(ch.child_fd, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(2, n1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg1, buf, 2);

    ssize_t n2 = iog_ipc_recv(ch.child_fd, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT(3, n2);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg2, buf, 3);

    iog_ipc_close(&ch);
}

void test_rw_ipc_send_fd(void)
{
    iog_ipc_channel_t ch;
    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Create a pipe to pass */
    int pipefd[2];
    ret = pipe(pipefd);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Send write end through IPC */
    ret = iog_ipc_send_fd(ch.parent_fd, pipefd[1]);
    TEST_ASSERT_EQUAL_INT(0, ret);
    close(pipefd[1]); /* close our copy */

    /* Receive fd on other end */
    int received_fd = iog_ipc_recv_fd(ch.child_fd);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, received_fd);

    /* Write through received fd, read from pipe read end */
    write(received_fd, "ok", 2);
    char buf[8] = {0};
    read(pipefd[0], buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("ok", buf);

    close(received_fd);
    close(pipefd[0]);
    iog_ipc_close(&ch);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rw_ipc_create_socketpair);
    RUN_TEST(test_rw_ipc_send_recv_message);
    RUN_TEST(test_rw_ipc_preserves_message_boundaries);
    RUN_TEST(test_rw_ipc_send_fd);
    return UNITY_END();
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL — undefined symbols

**Step 3: Write implementation**

`src/ipc/transport.h`:
```c
#ifndef IOGUARD_IPC_TRANSPORT_H
#define IOGUARD_IPC_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* IPC channel: a SOCK_SEQPACKET socketpair */
typedef struct {
    int parent_fd; /* used by parent process (Main) */
    int child_fd;  /* used by child process (worker/sec-mod) */
} iog_ipc_channel_t;

/* Maximum IPC message size (must fit in provided buffers) */
#define IOG_IPC_MAX_MSG_SIZE 4096

/* Create a SOCK_SEQPACKET socketpair for IPC */
[[nodiscard]] int iog_ipc_create_pair(iog_ipc_channel_t *ch);

/* Close both ends of the channel */
void iog_ipc_close(iog_ipc_channel_t *ch);

/* Send raw bytes. Returns 0 on success, -errno on error. */
[[nodiscard]] int iog_ipc_send(int fd, const uint8_t *data, size_t len);

/* Receive raw bytes. Returns message length, or negative errno. */
[[nodiscard]] ssize_t iog_ipc_recv(int fd, uint8_t *buf, size_t buf_size);

/* Send a file descriptor via SCM_RIGHTS. Returns 0 on success. */
[[nodiscard]] int iog_ipc_send_fd(int socket_fd, int fd_to_send);

/* Receive a file descriptor via SCM_RIGHTS. Returns fd or negative errno. */
[[nodiscard]] int iog_ipc_recv_fd(int socket_fd);

#endif /* IOGUARD_IPC_TRANSPORT_H */
```

`src/ipc/transport.c`:
```c
#include "ipc/transport.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int iog_ipc_create_pair(iog_ipc_channel_t *ch)
{
    int sv[2];
    int ret = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
    if (ret < 0) {
        return -errno;
    }
    ch->parent_fd = sv[0];
    ch->child_fd = sv[1];
    return 0;
}

void iog_ipc_close(iog_ipc_channel_t *ch)
{
    if (ch->parent_fd >= 0) {
        close(ch->parent_fd);
        ch->parent_fd = -1;
    }
    if (ch->child_fd >= 0) {
        close(ch->child_fd);
        ch->child_fd = -1;
    }
}

int iog_ipc_send(int fd, const uint8_t *data, size_t len)
{
    ssize_t n = send(fd, data, len, MSG_NOSIGNAL);
    if (n < 0) {
        return -errno;
    }
    return 0;
}

ssize_t iog_ipc_recv(int fd, uint8_t *buf, size_t buf_size)
{
    ssize_t n = recv(fd, buf, buf_size, 0);
    if (n < 0) {
        return -errno;
    }
    return n;
}

int iog_ipc_send_fd(int socket_fd, int fd_to_send)
{
    struct msghdr msg = {0};
    struct iovec iov;
    uint8_t dummy = 0;

    /* Must send at least 1 byte of data with SCM_RIGHTS */
    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* Ancillary data: the file descriptor */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    ssize_t n = sendmsg(socket_fd, &msg, MSG_NOSIGNAL);
    if (n < 0) {
        return -errno;
    }
    return 0;
}

int iog_ipc_recv_fd(int socket_fd)
{
    struct msghdr msg = {0};
    struct iovec iov;
    uint8_t dummy;

    iov.iov_base = &dummy;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_buf;

    msg.msg_control = cmsg_buf.buf;
    msg.msg_controllen = sizeof(cmsg_buf.buf);

    ssize_t n = recvmsg(socket_fd, &msg, 0);
    if (n < 0) {
        return -errno;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == nullptr || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS) {
        return -EPROTO;
    }

    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}
```

**Step 4: Run tests**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_ipc_transport -V`

Expected: All 4 tests PASS.

**Step 5: Commit**

```bash
git add src/ipc/transport.h src/ipc/transport.c tests/unit/test_ipc_transport.c
git commit -m "feat: add SOCK_SEQPACKET IPC transport with SCM_RIGHTS fd passing"
```

---

## Task 7: IPC Messages — Protobuf-c Definitions

**Files:**
- Create: `src/ipc/proto/iog_ipc.proto`
- Create: `src/ipc/messages.h`
- Create: `src/ipc/messages.c`
- Modify: `CMakeLists.txt` (add protobuf-c code generation)
- Create: `tests/unit/test_ipc_messages.c`

**Step 1: Define protobuf schema**

`src/ipc/proto/iog_ipc.proto`:
```protobuf
syntax = "proto3";
package iog_ipc;

// Message types for Main ↔ Worker ↔ sec-mod IPC
enum MsgType {
    MSG_TYPE_UNKNOWN = 0;
    MSG_TYPE_AUTH_REQUEST = 1;
    MSG_TYPE_AUTH_RESPONSE = 2;
    MSG_TYPE_SESSION_OPEN = 3;
    MSG_TYPE_SESSION_CLOSE = 4;
    MSG_TYPE_WORKER_STATUS = 5;
    MSG_TYPE_CONFIG_RELOAD = 6;
    MSG_TYPE_SHUTDOWN = 7;
}

// Header prepended to every IPC message
message IpcHeader {
    MsgType type = 1;
    uint32 seq = 2;
}

// Worker → sec-mod: authenticate user
message AuthRequest {
    IpcHeader header = 1;
    string username = 2;
    string group = 3;
    bytes cookie = 4;
    string source_ip = 5;
}

// sec-mod → Worker: auth result
message AuthResponse {
    IpcHeader header = 1;
    bool success = 2;
    string error_msg = 3;
    bytes session_cookie = 4;
    uint32 session_ttl = 5;
    string assigned_ip = 6;
    string dns_server = 7;
}

// Worker → Main: status update
message WorkerStatus {
    IpcHeader header = 1;
    uint32 active_connections = 2;
    uint64 bytes_rx = 3;
    uint64 bytes_tx = 4;
    uint32 pid = 5;
}
```

**Step 2: Add CMake protobuf-c code generation**

Add to CMakeLists.txt before `iog_ipc` library:
```cmake
# Generate protobuf-c sources
find_program(PROTOC_C protoc-c REQUIRED)
set(PROTO_SRC ${CMAKE_SOURCE_DIR}/src/ipc/proto/iog_ipc.proto)
set(PROTO_GEN_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${PROTO_GEN_DIR})

add_custom_command(
    OUTPUT ${PROTO_GEN_DIR}/iog_ipc.pb-c.h ${PROTO_GEN_DIR}/iog_ipc.pb-c.c
    COMMAND ${PROTOC_C} --c_out=${PROTO_GEN_DIR}
            --proto_path=${CMAKE_SOURCE_DIR}/src/ipc/proto
            ${PROTO_SRC}
    DEPENDS ${PROTO_SRC}
    COMMENT "Generating protobuf-c sources from iog_ipc.proto"
)

add_custom_target(proto_gen DEPENDS ${PROTO_GEN_DIR}/iog_ipc.pb-c.h)
```

Update `iog_ipc` library to include generated sources:
```cmake
add_library(iog_ipc STATIC
    src/ipc/transport.c
    src/ipc/messages.c
    ${PROTO_GEN_DIR}/iog_ipc.pb-c.c
)
add_dependencies(iog_ipc proto_gen)
target_include_directories(iog_ipc PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${PROTOBUF_C_INCLUDE_DIRS}
    ${PROTO_GEN_DIR}
)
target_link_libraries(iog_ipc PUBLIC ${PROTOBUF_C_LIBRARIES} iog_memory)
```

**Step 3: Write the failing test**

`tests/unit/test_ipc_messages.c`:
```c
#include <unity/unity.h>
#include <string.h>
#include "ipc/messages.h"

void setUp(void) {}
void tearDown(void) {}

void test_pack_unpack_auth_request(void)
{
    iog_ipc_msg_t msg;
    iog_ipc_msg_init(&msg, IOG_IPC_MSG_AUTH_REQUEST);

    iog_ipc_auth_request_t req = {
        .username = "testuser",
        .group = "vpn-users",
        .source_ip = "10.0.0.1",
    };

    uint8_t buf[IOG_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_auth_request_t decoded;
    int ret = iog_ipc_unpack_auth_request(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING("testuser", decoded.username);
    TEST_ASSERT_EQUAL_STRING("vpn-users", decoded.group);
    TEST_ASSERT_EQUAL_STRING("10.0.0.1", decoded.source_ip);

    iog_ipc_free_auth_request(&decoded);
}

void test_pack_unpack_auth_response(void)
{
    iog_ipc_auth_response_t resp = {
        .success = true,
        .assigned_ip = "10.0.1.100",
        .dns_server = "10.0.0.53",
        .session_ttl = 3600,
    };

    uint8_t buf[IOG_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_response(&resp, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_auth_response_t decoded;
    int ret = iog_ipc_unpack_auth_response(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(decoded.success);
    TEST_ASSERT_EQUAL_STRING("10.0.1.100", decoded.assigned_ip);
    TEST_ASSERT_EQUAL_UINT32(3600, decoded.session_ttl);

    iog_ipc_free_auth_response(&decoded);
}

void test_pack_unpack_worker_status(void)
{
    iog_ipc_worker_status_t status = {
        .active_connections = 42,
        .bytes_rx = 1000000,
        .bytes_tx = 2000000,
        .pid = 12345,
    };

    uint8_t buf[IOG_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_worker_status(&status, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    iog_ipc_worker_status_t decoded;
    int ret = iog_ipc_unpack_worker_status(buf, packed, &decoded);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT32(42, decoded.active_connections);
    TEST_ASSERT_EQUAL_UINT64(1000000, decoded.bytes_rx);
    TEST_ASSERT_EQUAL_UINT64(2000000, decoded.bytes_tx);
}

void test_unpack_truncated_data_fails(void)
{
    uint8_t garbage[] = {0xFF, 0x00};
    iog_ipc_auth_request_t decoded;
    int ret = iog_ipc_unpack_auth_request(garbage, sizeof(garbage), &decoded);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pack_unpack_auth_request);
    RUN_TEST(test_pack_unpack_auth_response);
    RUN_TEST(test_pack_unpack_worker_status);
    RUN_TEST(test_unpack_truncated_data_fails);
    return UNITY_END();
}
```

**Step 4: Write implementation**

`src/ipc/messages.h`:
```c
#ifndef IOGUARD_IPC_MESSAGES_H
#define IOGUARD_IPC_MESSAGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* IPC message types */
typedef enum {
    IOG_IPC_MSG_UNKNOWN = 0,
    IOG_IPC_MSG_AUTH_REQUEST = 1,
    IOG_IPC_MSG_AUTH_RESPONSE = 2,
    IOG_IPC_MSG_SESSION_OPEN = 3,
    IOG_IPC_MSG_SESSION_CLOSE = 4,
    IOG_IPC_MSG_WORKER_STATUS = 5,
    IOG_IPC_MSG_CONFIG_RELOAD = 6,
    IOG_IPC_MSG_SHUTDOWN = 7,
} iog_ipc_msg_type_t;

/* Generic IPC message header */
typedef struct {
    iog_ipc_msg_type_t type;
    uint32_t seq;
} iog_ipc_msg_t;

void iog_ipc_msg_init(iog_ipc_msg_t *msg, iog_ipc_msg_type_t type);

/* Auth request (Worker → sec-mod) */
typedef struct {
    const char *username;
    const char *group;
    const uint8_t *cookie;
    size_t cookie_len;
    const char *source_ip;
} iog_ipc_auth_request_t;

[[nodiscard]] ssize_t iog_ipc_pack_auth_request(const iog_ipc_auth_request_t *req,
                                                uint8_t *buf, size_t buf_size);
[[nodiscard]] int iog_ipc_unpack_auth_request(const uint8_t *data, size_t len,
                                              iog_ipc_auth_request_t *out);
void iog_ipc_free_auth_request(iog_ipc_auth_request_t *req);

/* Auth response (sec-mod → Worker) */
typedef struct {
    bool success;
    const char *error_msg;
    const uint8_t *session_cookie;
    size_t session_cookie_len;
    uint32_t session_ttl;
    const char *assigned_ip;
    const char *dns_server;
} iog_ipc_auth_response_t;

[[nodiscard]] ssize_t iog_ipc_pack_auth_response(const iog_ipc_auth_response_t *resp,
                                                  uint8_t *buf, size_t buf_size);
[[nodiscard]] int iog_ipc_unpack_auth_response(const uint8_t *data, size_t len,
                                                iog_ipc_auth_response_t *out);
void iog_ipc_free_auth_response(iog_ipc_auth_response_t *resp);

/* Worker status (Worker → Main) */
typedef struct {
    uint32_t active_connections;
    uint64_t bytes_rx;
    uint64_t bytes_tx;
    uint32_t pid;
} iog_ipc_worker_status_t;

[[nodiscard]] ssize_t iog_ipc_pack_worker_status(const iog_ipc_worker_status_t *status,
                                                  uint8_t *buf, size_t buf_size);
[[nodiscard]] int iog_ipc_unpack_worker_status(const uint8_t *data, size_t len,
                                                iog_ipc_worker_status_t *out);

#endif /* IOGUARD_IPC_MESSAGES_H */
```

`src/ipc/messages.c` — wraps protobuf-c generated code:
```c
#include "ipc/messages.h"
#include "iog_ipc.pb-c.h"
#include <string.h>
#include <stdlib.h>

void iog_ipc_msg_init(iog_ipc_msg_t *msg, iog_ipc_msg_type_t type)
{
    msg->type = type;
    msg->seq = 0;
}

ssize_t iog_ipc_pack_auth_request(const iog_ipc_auth_request_t *req,
                                  uint8_t *buf, size_t buf_size)
{
    WgIpc__AuthRequest pb = IOG_IPC__AUTH_REQUEST__INIT;
    WgIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_AUTH_REQUEST;

    pb.header = &hdr;
    pb.username = (char *)req->username;
    pb.group = (char *)req->group;
    pb.source_ip = (char *)req->source_ip;
    if (req->cookie != nullptr && req->cookie_len > 0) {
        pb.cookie.data = (uint8_t *)req->cookie;
        pb.cookie.len = req->cookie_len;
        pb.has_cookie = 1;
    }

    size_t packed_size = iog_ipc__auth_request__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -1;
    }
    return (ssize_t)iog_ipc__auth_request__pack(&pb, buf);
}

int iog_ipc_unpack_auth_request(const uint8_t *data, size_t len,
                                iog_ipc_auth_request_t *out)
{
    WgIpc__AuthRequest *pb = iog_ipc__auth_request__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -1;
    }
    out->username = pb->username ? strdup(pb->username) : nullptr;
    out->group = pb->group ? strdup(pb->group) : nullptr;
    out->source_ip = pb->source_ip ? strdup(pb->source_ip) : nullptr;
    out->cookie = nullptr;
    out->cookie_len = 0;
    if (pb->has_cookie && pb->cookie.len > 0) {
        out->cookie = malloc(pb->cookie.len);
        if (out->cookie != nullptr) {
            memcpy((void *)out->cookie, pb->cookie.data, pb->cookie.len);
            out->cookie_len = pb->cookie.len;
        }
    }
    iog_ipc__auth_request__free_unpacked(pb, nullptr);
    return 0;
}

void iog_ipc_free_auth_request(iog_ipc_auth_request_t *req)
{
    free((void *)req->username);
    free((void *)req->group);
    free((void *)req->source_ip);
    free((void *)req->cookie);
    memset(req, 0, sizeof(*req));
}

ssize_t iog_ipc_pack_auth_response(const iog_ipc_auth_response_t *resp,
                                    uint8_t *buf, size_t buf_size)
{
    WgIpc__AuthResponse pb = IOG_IPC__AUTH_RESPONSE__INIT;
    WgIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_AUTH_RESPONSE;

    pb.header = &hdr;
    pb.success = resp->success;
    pb.error_msg = (char *)resp->error_msg;
    pb.session_ttl = resp->session_ttl;
    pb.assigned_ip = (char *)resp->assigned_ip;
    pb.dns_server = (char *)resp->dns_server;
    if (resp->session_cookie != nullptr && resp->session_cookie_len > 0) {
        pb.session_cookie.data = (uint8_t *)resp->session_cookie;
        pb.session_cookie.len = resp->session_cookie_len;
        pb.has_session_cookie = 1;
    }

    size_t packed_size = iog_ipc__auth_response__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -1;
    }
    return (ssize_t)iog_ipc__auth_response__pack(&pb, buf);
}

int iog_ipc_unpack_auth_response(const uint8_t *data, size_t len,
                                  iog_ipc_auth_response_t *out)
{
    WgIpc__AuthResponse *pb = iog_ipc__auth_response__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -1;
    }
    out->success = pb->success;
    out->error_msg = pb->error_msg ? strdup(pb->error_msg) : nullptr;
    out->session_ttl = pb->session_ttl;
    out->assigned_ip = pb->assigned_ip ? strdup(pb->assigned_ip) : nullptr;
    out->dns_server = pb->dns_server ? strdup(pb->dns_server) : nullptr;
    out->session_cookie = nullptr;
    out->session_cookie_len = 0;
    if (pb->has_session_cookie && pb->session_cookie.len > 0) {
        out->session_cookie = malloc(pb->session_cookie.len);
        if (out->session_cookie != nullptr) {
            memcpy((void *)out->session_cookie, pb->session_cookie.data,
                   pb->session_cookie.len);
            out->session_cookie_len = pb->session_cookie.len;
        }
    }
    iog_ipc__auth_response__free_unpacked(pb, nullptr);
    return 0;
}

void iog_ipc_free_auth_response(iog_ipc_auth_response_t *resp)
{
    free((void *)resp->error_msg);
    free((void *)resp->assigned_ip);
    free((void *)resp->dns_server);
    free((void *)resp->session_cookie);
    memset(resp, 0, sizeof(*resp));
}

ssize_t iog_ipc_pack_worker_status(const iog_ipc_worker_status_t *status,
                                    uint8_t *buf, size_t buf_size)
{
    WgIpc__WorkerStatus pb = IOG_IPC__WORKER_STATUS__INIT;
    WgIpc__IpcHeader hdr = IOG_IPC__IPC_HEADER__INIT;
    hdr.type = IOG_IPC__MSG_TYPE__MSG_TYPE_WORKER_STATUS;

    pb.header = &hdr;
    pb.active_connections = status->active_connections;
    pb.bytes_rx = status->bytes_rx;
    pb.bytes_tx = status->bytes_tx;
    pb.pid = status->pid;

    size_t packed_size = iog_ipc__worker_status__get_packed_size(&pb);
    if (packed_size > buf_size) {
        return -1;
    }
    return (ssize_t)iog_ipc__worker_status__pack(&pb, buf);
}

int iog_ipc_unpack_worker_status(const uint8_t *data, size_t len,
                                  iog_ipc_worker_status_t *out)
{
    WgIpc__WorkerStatus *pb = iog_ipc__worker_status__unpack(nullptr, len, data);
    if (pb == nullptr) {
        return -1;
    }
    out->active_connections = pb->active_connections;
    out->bytes_rx = pb->bytes_rx;
    out->bytes_tx = pb->bytes_tx;
    out->pid = pb->pid;
    iog_ipc__worker_status__free_unpacked(pb, nullptr);
    return 0;
}
```

**Step 5: Run tests**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_ipc_messages -V`

Expected: All 4 tests PASS.

**Step 6: Commit**

```bash
git add src/ipc/proto/iog_ipc.proto src/ipc/messages.h src/ipc/messages.c \
        tests/unit/test_ipc_messages.c CMakeLists.txt
git commit -m "feat: add protobuf-c IPC message pack/unpack with arena allocator"
```

---

## Task 8: TOML Configuration Parser

**Files:**
- Create: `src/config/config.h`
- Create: `src/config/config.c`
- Create: `tests/unit/test_config_toml.c`
- Create: `tests/fixtures/ioguard.toml` (test config file)

**Step 1: Create test fixture**

`tests/fixtures/ioguard.toml`:
```toml
[server]
listen-address = "0.0.0.0"
listen-port = 443
dtls-port = 443
max-clients = 1024
worker-count = 4

[auth]
method = "pam"
cookie-timeout = 300
cookie-rekey = 14400

[network]
ipv4-pool = "10.10.0.0/16"
dns = ["10.0.0.53", "10.0.0.54"]
default-domain = "corp.example.com"
mtu = 1400

[tls]
cert-file = "/etc/ioguard/server.pem"
key-file = "/etc/ioguard/server.key"
min-version = "1.2"
ciphers = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"

[security]
seccomp = true
landlock = true
wolfsentry-config = "/etc/ioguard/wolfsentry.json"
```

**Step 2: Write the failing test**

`tests/unit/test_config_toml.c`:
```c
#include <unity/unity.h>
#include "config/config.h"

static const char *TEST_CONFIG = "tests/fixtures/ioguard.toml";

void setUp(void) {}
void tearDown(void) {}

void test_config_load_valid_file(void)
{
    iog_config_t cfg;
    int ret = iog_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);
    iog_config_free(&cfg);
}

void test_config_load_nonexistent_file(void)
{
    iog_config_t cfg;
    int ret = iog_config_load("/nonexistent.toml", &cfg);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_config_server_values(void)
{
    iog_config_t cfg;
    int ret = iog_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("0.0.0.0", cfg.server.listen_address);
    TEST_ASSERT_EQUAL_UINT16(443, cfg.server.listen_port);
    TEST_ASSERT_EQUAL_UINT16(443, cfg.server.dtls_port);
    TEST_ASSERT_EQUAL_UINT32(1024, cfg.server.max_clients);
    TEST_ASSERT_EQUAL_UINT32(4, cfg.server.worker_count);

    iog_config_free(&cfg);
}

void test_config_auth_values(void)
{
    iog_config_t cfg;
    int ret = iog_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("pam", cfg.auth.method);
    TEST_ASSERT_EQUAL_UINT32(300, cfg.auth.cookie_timeout);

    iog_config_free(&cfg);
}

void test_config_network_values(void)
{
    iog_config_t cfg;
    int ret = iog_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("10.10.0.0/16", cfg.network.ipv4_pool);
    TEST_ASSERT_EQUAL_UINT32(1400, cfg.network.mtu);
    TEST_ASSERT_EQUAL_STRING("corp.example.com", cfg.network.default_domain);

    iog_config_free(&cfg);
}

void test_config_tls_values(void)
{
    iog_config_t cfg;
    int ret = iog_config_load(TEST_CONFIG, &cfg);
    TEST_ASSERT_EQUAL_INT(0, ret);

    TEST_ASSERT_EQUAL_STRING("/etc/ioguard/server.pem", cfg.tls.cert_file);
    TEST_ASSERT_EQUAL_STRING("/etc/ioguard/server.key", cfg.tls.key_file);

    iog_config_free(&cfg);
}

void test_config_defaults_when_missing(void)
{
    /* Minimal config: just [server] */
    const char *minimal = "tests/fixtures/ioguard_minimal.toml";
    /* This file has only [server] listen-port = 8443 */

    iog_config_t cfg;
    iog_config_set_defaults(&cfg);

    TEST_ASSERT_EQUAL_UINT16(443, cfg.server.listen_port); /* default */
    TEST_ASSERT_EQUAL_UINT32(0, cfg.server.worker_count);  /* 0 = auto-detect */
    TEST_ASSERT_EQUAL_UINT32(1400, cfg.network.mtu);       /* default */

    iog_config_free(&cfg);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_config_load_valid_file);
    RUN_TEST(test_config_load_nonexistent_file);
    RUN_TEST(test_config_server_values);
    RUN_TEST(test_config_auth_values);
    RUN_TEST(test_config_network_values);
    RUN_TEST(test_config_tls_values);
    RUN_TEST(test_config_defaults_when_missing);
    return UNITY_END();
}
```

**Step 3: Write implementation**

`src/config/config.h`:
```c
#ifndef IOGUARD_CONFIG_CONFIG_H
#define IOGUARD_CONFIG_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define IOG_CONFIG_MAX_DNS 8
#define IOG_CONFIG_MAX_STR 256

typedef struct {
    char listen_address[IOG_CONFIG_MAX_STR];
    uint16_t listen_port;
    uint16_t dtls_port;
    uint32_t max_clients;
    uint32_t worker_count; /* 0 = auto-detect (nproc) */
} iog_config_server_t;

typedef struct {
    char method[64];
    uint32_t cookie_timeout;
    uint32_t cookie_rekey;
} iog_config_auth_t;

typedef struct {
    char ipv4_pool[IOG_CONFIG_MAX_STR];
    char dns[IOG_CONFIG_MAX_DNS][IOG_CONFIG_MAX_STR];
    uint32_t dns_count;
    char default_domain[IOG_CONFIG_MAX_STR];
    uint32_t mtu;
} iog_config_network_t;

typedef struct {
    char cert_file[IOG_CONFIG_MAX_STR];
    char key_file[IOG_CONFIG_MAX_STR];
    char min_version[16];
    char ciphers[512];
} iog_config_tls_t;

typedef struct {
    bool seccomp;
    bool landlock;
    char wolfsentry_config[IOG_CONFIG_MAX_STR];
} iog_config_security_t;

typedef struct {
    iog_config_server_t server;
    iog_config_auth_t auth;
    iog_config_network_t network;
    iog_config_tls_t tls;
    iog_config_security_t security;
} iog_config_t;

/* Set all fields to default values */
void iog_config_set_defaults(iog_config_t *cfg);

/* Load configuration from TOML file. Applies defaults first. */
[[nodiscard]] int iog_config_load(const char *path, iog_config_t *cfg);

/* Free any dynamically allocated config resources */
void iog_config_free(iog_config_t *cfg);

#endif /* IOGUARD_CONFIG_CONFIG_H */
```

`src/config/config.c` — parse TOML using tomlc99:
```c
#include "config/config.h"
#include <string.h>
#include <stdio.h>

#ifdef USE_TOML
#include <toml.h>
#endif

static void safe_copy(char *dst, const char *src, size_t dst_size)
{
    if (src == nullptr) {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

void iog_config_set_defaults(iog_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    safe_copy(cfg->server.listen_address, "0.0.0.0",
              sizeof(cfg->server.listen_address));
    cfg->server.listen_port = 443;
    cfg->server.dtls_port = 443;
    cfg->server.max_clients = 256;
    cfg->server.worker_count = 0; /* auto */
    safe_copy(cfg->auth.method, "pam", sizeof(cfg->auth.method));
    cfg->auth.cookie_timeout = 300;
    cfg->auth.cookie_rekey = 14400;
    cfg->network.mtu = 1400;
    safe_copy(cfg->tls.min_version, "1.2", sizeof(cfg->tls.min_version));
    cfg->security.seccomp = true;
    cfg->security.landlock = true;
}

#ifdef USE_TOML

static void parse_server(toml_table_t *tbl, iog_config_server_t *srv)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "listen-address");
    if (d.ok) {
        safe_copy(srv->listen_address, d.u.s, sizeof(srv->listen_address));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "listen-port");
    if (d.ok) { srv->listen_port = (uint16_t)d.u.i; }
    d = toml_int_in(tbl, "dtls-port");
    if (d.ok) { srv->dtls_port = (uint16_t)d.u.i; }
    d = toml_int_in(tbl, "max-clients");
    if (d.ok) { srv->max_clients = (uint32_t)d.u.i; }
    d = toml_int_in(tbl, "worker-count");
    if (d.ok) { srv->worker_count = (uint32_t)d.u.i; }
}

static void parse_auth(toml_table_t *tbl, iog_config_auth_t *auth)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "method");
    if (d.ok) {
        safe_copy(auth->method, d.u.s, sizeof(auth->method));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "cookie-timeout");
    if (d.ok) { auth->cookie_timeout = (uint32_t)d.u.i; }
    d = toml_int_in(tbl, "cookie-rekey");
    if (d.ok) { auth->cookie_rekey = (uint32_t)d.u.i; }
}

static void parse_network(toml_table_t *tbl, iog_config_network_t *net)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "ipv4-pool");
    if (d.ok) {
        safe_copy(net->ipv4_pool, d.u.s, sizeof(net->ipv4_pool));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "default-domain");
    if (d.ok) {
        safe_copy(net->default_domain, d.u.s, sizeof(net->default_domain));
        free(d.u.s);
    }
    d = toml_int_in(tbl, "mtu");
    if (d.ok) { net->mtu = (uint32_t)d.u.i; }

    toml_array_t *dns_arr = toml_array_in(tbl, "dns");
    if (dns_arr != nullptr) {
        int n = toml_array_nelem(dns_arr);
        if (n > IOG_CONFIG_MAX_DNS) { n = IOG_CONFIG_MAX_DNS; }
        for (int i = 0; i < n; i++) {
            d = toml_string_at(dns_arr, i);
            if (d.ok) {
                safe_copy(net->dns[i], d.u.s, sizeof(net->dns[i]));
                free(d.u.s);
                net->dns_count++;
            }
        }
    }
}

static void parse_tls(toml_table_t *tbl, iog_config_tls_t *tls)
{
    toml_datum_t d;
    d = toml_string_in(tbl, "cert-file");
    if (d.ok) {
        safe_copy(tls->cert_file, d.u.s, sizeof(tls->cert_file));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "key-file");
    if (d.ok) {
        safe_copy(tls->key_file, d.u.s, sizeof(tls->key_file));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "min-version");
    if (d.ok) {
        safe_copy(tls->min_version, d.u.s, sizeof(tls->min_version));
        free(d.u.s);
    }
    d = toml_string_in(tbl, "ciphers");
    if (d.ok) {
        safe_copy(tls->ciphers, d.u.s, sizeof(tls->ciphers));
        free(d.u.s);
    }
}

static void parse_security(toml_table_t *tbl, iog_config_security_t *sec)
{
    toml_datum_t d;
    d = toml_bool_in(tbl, "seccomp");
    if (d.ok) { sec->seccomp = d.u.b; }
    d = toml_bool_in(tbl, "landlock");
    if (d.ok) { sec->landlock = d.u.b; }
    d = toml_string_in(tbl, "wolfsentry-config");
    if (d.ok) {
        safe_copy(sec->wolfsentry_config, d.u.s,
                  sizeof(sec->wolfsentry_config));
        free(d.u.s);
    }
}

int iog_config_load(const char *path, iog_config_t *cfg)
{
    iog_config_set_defaults(cfg);

    FILE *fp = fopen(path, "r");
    if (fp == nullptr) {
        return -1;
    }

    char errbuf[256];
    toml_table_t *root = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);
    if (root == nullptr) {
        return -1;
    }

    toml_table_t *tbl;
    tbl = toml_table_in(root, "server");
    if (tbl) { parse_server(tbl, &cfg->server); }
    tbl = toml_table_in(root, "auth");
    if (tbl) { parse_auth(tbl, &cfg->auth); }
    tbl = toml_table_in(root, "network");
    if (tbl) { parse_network(tbl, &cfg->network); }
    tbl = toml_table_in(root, "tls");
    if (tbl) { parse_tls(tbl, &cfg->tls); }
    tbl = toml_table_in(root, "security");
    if (tbl) { parse_security(tbl, &cfg->security); }

    toml_free(root);
    return 0;
}

#else /* no TOML support */

int iog_config_load(const char *path, iog_config_t *cfg)
{
    (void)path;
    iog_config_set_defaults(cfg);
    return -1; /* TOML not compiled in */
}

#endif

void iog_config_free(iog_config_t *cfg)
{
    /* All strings are inline (fixed-size arrays), nothing to free.
     * This function exists for future extensibility. */
    (void)cfg;
}
```

**Step 4: Run tests**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_config -V`

Expected: All 7 tests PASS.

**Step 5: Commit**

```bash
git add src/config/config.h src/config/config.c tests/unit/test_config_toml.c \
        tests/fixtures/ioguard.toml
git commit -m "feat: add TOML configuration parser with defaults and validation"
```

---

## Task 9: Process Management — Main Spawns Workers

**Files:**
- Create: `src/core/process.h`
- Create: `src/core/process.c`
- Create: `tests/unit/test_process.c`

**Step 1: Write the failing test**

```c
#include <unity/unity.h>
#include <sys/wait.h>
#include <unistd.h>
#include "core/process.h"

void setUp(void) {}
void tearDown(void) {}

void test_rw_process_spawn_and_wait(void)
{
    /* Spawn /bin/true — should exit 0 */
    iog_process_t proc;
    const char *argv[] = {"/bin/true", nullptr};
    int ret = iog_process_spawn(&proc, "/bin/true", argv);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_GREATER_THAN(0, proc.pid);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, proc.pidfd);

    /* Wait for exit */
    int exit_status;
    ret = iog_process_wait(&proc, &exit_status, 5000);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(0, exit_status);

    iog_process_cleanup(&proc);
}

void test_rw_process_spawn_exit_code(void)
{
    iog_process_t proc;
    const char *argv[] = {"/bin/false", nullptr};
    int ret = iog_process_spawn(&proc, "/bin/false", argv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int exit_status;
    ret = iog_process_wait(&proc, &exit_status, 5000);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_NOT_EQUAL(0, exit_status);

    iog_process_cleanup(&proc);
}

void test_rw_process_spawn_nonexistent(void)
{
    iog_process_t proc;
    const char *argv[] = {"/nonexistent", nullptr};
    int ret = iog_process_spawn(&proc, "/nonexistent", argv);
    /* Should fail at spawn or child exits immediately */
    if (ret == 0) {
        int exit_status;
        iog_process_wait(&proc, &exit_status, 5000);
        TEST_ASSERT_NOT_EQUAL(0, exit_status);
        iog_process_cleanup(&proc);
    } else {
        TEST_ASSERT_LESS_THAN(0, ret);
    }
}

void test_rw_process_kill(void)
{
    iog_process_t proc;
    const char *argv[] = {"/bin/sleep", "60", nullptr};
    int ret = iog_process_spawn(&proc, "/bin/sleep", argv);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Send SIGTERM via pidfd */
    ret = iog_process_signal(&proc, SIGTERM);
    TEST_ASSERT_EQUAL_INT(0, ret);

    int exit_status;
    ret = iog_process_wait(&proc, &exit_status, 5000);
    TEST_ASSERT_EQUAL_INT(0, ret);

    iog_process_cleanup(&proc);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rw_process_spawn_and_wait);
    RUN_TEST(test_rw_process_spawn_exit_code);
    RUN_TEST(test_rw_process_spawn_nonexistent);
    RUN_TEST(test_rw_process_kill);
    return UNITY_END();
}
```

**Step 2: Write implementation**

`src/core/process.h`:
```c
#ifndef IOGUARD_CORE_PROCESS_H
#define IOGUARD_CORE_PROCESS_H

#include <signal.h>
#include <sys/types.h>

/* Managed child process with pidfd */
typedef struct {
    pid_t pid;
    int pidfd; /* pidfd for race-free operations */
} iog_process_t;

/* Spawn a child process using posix_spawn / pidfd_spawn.
 * Returns 0 on success, negative errno on failure.
 * proc->pidfd is set for race-free wait/signal. */
[[nodiscard]] int iog_process_spawn(iog_process_t *proc, const char *path,
                                    const char *const argv[]);

/* Wait for process exit (blocking with timeout).
 * timeout_ms: max wait time, 0 = indefinite.
 * exit_status: filled with exit code or signal number.
 * Returns 0 on success, -ETIMEDOUT on timeout. */
[[nodiscard]] int iog_process_wait(iog_process_t *proc, int *exit_status,
                                   uint32_t timeout_ms);

/* Send signal to process via pidfd (race-free) */
[[nodiscard]] int iog_process_signal(iog_process_t *proc, int sig);

/* Cleanup process resources (close pidfd) */
void iog_process_cleanup(iog_process_t *proc);

#endif /* IOGUARD_CORE_PROCESS_H */
```

`src/core/process.c`:
```c
#include "core/process.h"
#include <errno.h>
#include <poll.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* glibc 2.39+ provides pidfd_spawn */
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 39)
#define HAVE_PIDFD_SPAWN 1
#else
#define HAVE_PIDFD_SPAWN 0
#endif

extern char **environ;

int iog_process_spawn(iog_process_t *proc, const char *path,
                      const char *const argv[])
{
    memset(proc, 0, sizeof(*proc));
    proc->pidfd = -1;

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    posix_spawnattr_setflags(&attr, flags);

    sigset_t empty, all;
    sigemptyset(&empty);
    sigfillset(&all);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setsigdefault(&attr, &all);

    int ret;

#if HAVE_PIDFD_SPAWN
    ret = pidfd_spawn(&proc->pidfd, path, &fa, &attr,
                      (char *const *)argv, environ);
    if (ret != 0) {
        ret = -errno;
        goto cleanup;
    }
    /* Get pid from pidfd via /proc/self/fdinfo or waitid */
    siginfo_t info;
    if (waitid(P_PIDFD, proc->pidfd, &info, WNOHANG | WNOWAIT) == 0 &&
        info.si_pid > 0) {
        proc->pid = info.si_pid;
    }
#else
    /* Fallback: posix_spawn + pidfd_open */
    pid_t pid;
    ret = posix_spawn(&pid, path, &fa, &attr,
                      (char *const *)argv, environ);
    if (ret != 0) {
        ret = -ret; /* posix_spawn returns errno directly */
        goto cleanup;
    }
    proc->pid = pid;
    proc->pidfd = syscall(__NR_pidfd_open, pid, 0);
    if (proc->pidfd < 0) {
        proc->pidfd = -1; /* non-fatal, wait by pid */
    }
#endif

    ret = 0;

cleanup:
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    return ret;
}

int iog_process_wait(iog_process_t *proc, int *exit_status, uint32_t timeout_ms)
{
    *exit_status = -1;

    /* Poll pidfd for readability (process exit) */
    if (proc->pidfd >= 0 && timeout_ms > 0) {
        struct pollfd pfd = {.fd = proc->pidfd, .events = POLLIN};
        int ret = poll(&pfd, 1, (int)timeout_ms);
        if (ret == 0) {
            return -ETIMEDOUT;
        }
        if (ret < 0) {
            return -errno;
        }
    }

    /* Reap the child */
    int status;
    pid_t wpid = waitpid(proc->pid, &status, 0);
    if (wpid < 0) {
        return -errno;
    }

    if (WIFEXITED(status)) {
        *exit_status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *exit_status = 128 + WTERMSIG(status);
    }

    return 0;
}

int iog_process_signal(iog_process_t *proc, int sig)
{
    if (proc->pidfd >= 0) {
        int ret = syscall(__NR_pidfd_send_signal, proc->pidfd, sig, nullptr, 0);
        if (ret < 0) {
            return -errno;
        }
        return 0;
    }
    /* Fallback: kill by pid */
    if (kill(proc->pid, sig) < 0) {
        return -errno;
    }
    return 0;
}

void iog_process_cleanup(iog_process_t *proc)
{
    if (proc->pidfd >= 0) {
        close(proc->pidfd);
        proc->pidfd = -1;
    }
    proc->pid = 0;
}
```

Add to CMakeLists.txt:
```cmake
add_library(iog_core STATIC src/core/process.c)
target_include_directories(iog_core PUBLIC ${CMAKE_SOURCE_DIR}/src)

iog_add_test(test_process tests/unit/test_process.c iog_core)
```

**Step 3: Run tests**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_process -V`

Expected: All 4 tests PASS.

**Step 4: Commit**

```bash
git add src/core/process.h src/core/process.c tests/unit/test_process.c CMakeLists.txt
git commit -m "feat: add process management with pidfd_spawn and race-free signals"
```

---

## Task 10: Integration Test — IPC Round-Trip Over SOCK_SEQPACKET

**Files:**
- Create: `tests/integration/test_ipc_roundtrip.c`
- Modify: `CMakeLists.txt` (add integration test target)

**Step 1: Write integration test**

This test forks a child process, sends a protobuf auth request over SOCK_SEQPACKET, child unpacks and sends response back.

```c
#include <unity/unity.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ipc/transport.h"
#include "ipc/messages.h"

void setUp(void) {}
void tearDown(void) {}

void test_ipc_roundtrip_auth(void)
{
    iog_ipc_channel_t ch;
    int ret = iog_ipc_create_pair(&ch);
    TEST_ASSERT_EQUAL_INT(0, ret);

    pid_t pid = fork();
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, pid);

    if (pid == 0) {
        /* Child: sec-mod simulator */
        close(ch.parent_fd);

        /* Receive auth request */
        uint8_t buf[IOG_IPC_MAX_MSG_SIZE];
        ssize_t n = iog_ipc_recv(ch.child_fd, buf, sizeof(buf));
        if (n <= 0) { _exit(1); }

        iog_ipc_auth_request_t req;
        if (iog_ipc_unpack_auth_request(buf, n, &req) != 0) { _exit(2); }

        /* Build response */
        iog_ipc_auth_response_t resp = {
            .success = true,
            .assigned_ip = "10.10.0.100",
            .dns_server = "10.0.0.53",
            .session_ttl = 3600,
        };

        uint8_t resp_buf[IOG_IPC_MAX_MSG_SIZE];
        ssize_t packed = iog_ipc_pack_auth_response(&resp, resp_buf, sizeof(resp_buf));
        if (packed <= 0) { _exit(3); }

        iog_ipc_send(ch.child_fd, resp_buf, packed);
        iog_ipc_free_auth_request(&req);
        close(ch.child_fd);
        _exit(0);
    }

    /* Parent: worker simulator */
    close(ch.child_fd);

    /* Send auth request */
    iog_ipc_auth_request_t req = {
        .username = "admin",
        .group = "vpn-users",
        .source_ip = "192.168.1.100",
    };

    uint8_t buf[IOG_IPC_MAX_MSG_SIZE];
    ssize_t packed = iog_ipc_pack_auth_request(&req, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, packed);

    ret = iog_ipc_send(ch.parent_fd, buf, packed);
    TEST_ASSERT_EQUAL_INT(0, ret);

    /* Receive auth response */
    ssize_t n = iog_ipc_recv(ch.parent_fd, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);

    iog_ipc_auth_response_t resp;
    ret = iog_ipc_unpack_auth_response(buf, n, &resp);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_TRUE(resp.success);
    TEST_ASSERT_EQUAL_STRING("10.10.0.100", resp.assigned_ip);
    TEST_ASSERT_EQUAL_STRING("10.0.0.53", resp.dns_server);
    TEST_ASSERT_EQUAL_UINT32(3600, resp.session_ttl);

    iog_ipc_free_auth_response(&resp);
    close(ch.parent_fd);

    /* Wait for child */
    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT_TRUE(WIFEXITED(status));
    TEST_ASSERT_EQUAL_INT(0, WEXITSTATUS(status));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ipc_roundtrip_auth);
    return UNITY_END();
}
```

Add to CMakeLists.txt:
```cmake
iog_add_test(test_ipc_roundtrip tests/integration/test_ipc_roundtrip.c iog_ipc iog_io)
```

**Step 2: Run integration test**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -R test_ipc_roundtrip -V`

Expected: PASS — full auth request/response round-trip across process boundary.

**Step 3: Commit**

```bash
git add tests/integration/test_ipc_roundtrip.c CMakeLists.txt
git commit -m "test: add IPC round-trip integration test (SOCK_SEQPACKET + protobuf-c)"
```

---

## Task 11: Run All Tests, Format, Lint

**Step 1: Run full test suite**

Run: `cmake --build --preset clang-debug && ctest --preset clang-debug -V`

Expected: All tests pass (test_memory, test_io_uring, test_ipc_transport, test_ipc_messages, test_config_toml, test_process, test_ipc_roundtrip).

**Step 2: Format all code**

Run: `cmake --build --preset clang-debug --target format`

**Step 3: Run clang-tidy**

Run: `cmake --build --preset clang-debug --target lint`

Fix any warnings. Common issues:
- Missing `#include <stdlib.h>` for `malloc`/`free`
- `readability-identifier-naming` for function/variable names

**Step 4: Run with ASan**

Run:
```bash
cmake --preset clang-asan
cmake --build --preset clang-asan
ctest --preset clang-asan -V
```

Expected: All tests pass, no memory leaks, no undefined behavior.

**Step 5: Commit any formatting fixes**

```bash
git add -A
git commit -m "style: apply clang-format and fix clang-tidy warnings"
```

---

## Task 12: Update CLAUDE.md and Memory

**Files:**
- Modify: `CLAUDE.md` — remove libuv references, add stumpless, update architecture description
- Modify: `/root/.claude/projects/-opt/memory/MEMORY.md` — update with Sprint 1 completion status

**Step 1: Update CLAUDE.md**

Key changes:
- Remove `libuv` from Library Stack (no longer used)
- Add `stumpless` to Library Stack (future sprint)
- Verify Library Stack is current
- Update "Architecture Decisions" to reflect io_uring-only, no libuv
- Add note about Linux 6.7+ / glibc 2.39+ requirements

**Step 2: Update memory file**

Record Sprint 1 completion, key patterns learned, any gotchas encountered.

**Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for Sprint 1 architecture (io_uring-only, no libuv)"
```
