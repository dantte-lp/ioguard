# Sprint 6: Vertical Integration — Main Process, Worker Data Path, Security Activation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Wire all existing S1-S5 building blocks into a working VPN server — main process bootstrap, worker io_uring data path (TLS↔CSTP↔TUN), auth-mod storage integration, security module activation, and graceful shutdown.

**Architecture:** Main process loads config, creates IPC socketpairs, forks auth-mod and worker children. Workers run io_uring event loops: accept client fds via SCM_RIGHTS from main, perform wolfSSL TLS handshake (with wolfSentry pre-check), exchange OpenConnect HTTP auth via IPC to auth-mod, then enter CSTP tunnel mode: TLS recv → CSTP decode → decompress → TUN write (and reverse). Auth-mod stores sessions in libmdbx, audit in SQLite. Security modules (seccomp, Landlock) activate at fork time. nftables rules create/destroy per session.

**Tech Stack:** C23, liburing 2.7+, wolfSSL 5.8.4+, wolfSentry 1.6.3+, libmdbx 0.14+, SQLite 3.52.0+, libseccomp 2.5+, libmnl, libnftnl, Unity tests, Linux kernel 6.7+.

**Build/test:**
```bash
cmake --preset clang-debug
cmake --build --preset clang-debug
ctest --preset clang-debug
```

**Context:** S1-S4 built foundation (io_uring, TLS, CSTP, DTLS, compression, DPD, worker context, session). S5 added storage (libmdbx, SQLite) and security (seccomp, Landlock, wolfSentry, nftables). All modules work in isolation but nothing calls anything — `main.c` is a 4-line stub, worker has no event loop, storage and security are orphaned.

---

## Task 1: Extend io_uring with callback-based operations

**Files:**
- Modify: `src/io/uring.h`
- Modify: `src/io/uring.c`
- Create: `tests/unit/test_io_callback.c`
- Modify: `CMakeLists.txt`

**Why:** Current `rw_io_prep_*` functions take `int *completed` — fine for tests but the worker event loop needs proper callbacks with user_data to chain operations (TLS read → CSTP decode → TUN write).

**Step 1: Write failing tests (test_io_callback.c)**

```c
#include <unity/unity.h>
#include "io/uring.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Callback-based API tests */
void test_io_prep_recv_cb_roundtrip(void);      /* send on sv[0], recv_cb on sv[1] */
void test_io_prep_send_cb_roundtrip(void);      /* send_cb on sv[0], recv on sv[1] */
void test_io_prep_read_cb_fires(void);          /* pipe write, read_cb on read end */
void test_io_prep_write_cb_fires(void);         /* write_cb on pipe, read verify */
void test_io_prep_accept_cb(void);              /* listen socket, connect, accept_cb */
void test_io_add_timeout_cb_fires(void);        /* 10ms timeout, callback invoked */
void test_io_cancel_operation(void);            /* submit recv, cancel, get -ECANCELED */
void test_io_multiple_callbacks_concurrent(void); /* 3 concurrent ops, all complete */
```

**Step 2: Add callback-based API to uring.h**

```c
/* Callback-based operations — for production event loops.
 * cb is invoked with CQE result (bytes or negative errno) and user_data. */

[[nodiscard]] int rw_io_prep_recv_cb(rw_io_ctx_t *ctx, int fd, void *buf, size_t len,
                                      rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_prep_send_cb(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len,
                                      rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_prep_read_cb(rw_io_ctx_t *ctx, int fd, void *buf, size_t len,
                                      rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_prep_write_cb(rw_io_ctx_t *ctx, int fd, const void *buf, size_t len,
                                       rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_prep_accept_cb(rw_io_ctx_t *ctx, int fd,
                                        struct sockaddr *addr, socklen_t *addrlen,
                                        rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_add_timeout_cb(rw_io_ctx_t *ctx, uint64_t timeout_ms,
                                        rw_io_cb cb, void *user_data);

[[nodiscard]] int rw_io_cancel(rw_io_ctx_t *ctx, void *user_data);
```

**Step 3: Implement in uring.c**

The internal `rw_io_completion_t` already has `rw_io_cb cb` and `void *user_data` fields. The new functions allocate a completion, set `cb` and `user_data`, prep the SQE, and set `user_data` on the SQE. The existing CQE processing loop in `rw_io_run_once()` already dispatches to `cb(res, user_data)` — just verify it handles the new operations.

For `rw_io_cancel()`: use `io_uring_prep_cancel()` targeting the user_data pointer.

For `rw_io_prep_accept_cb()`: use `io_uring_prep_accept()`.

**Step 4: Build and run**

```bash
cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug -R test_io_callback
```

**Step 5: Commit**

```bash
git add src/io/uring.h src/io/uring.c tests/unit/test_io_callback.c CMakeLists.txt
git commit -m "feat: callback-based io_uring operations for event loop integration (8 tests)"
```

---

## Task 2: fd passing helpers (src/ipc/fdpass.{h,c})

**Files:**
- Create: `src/ipc/fdpass.h`
- Create: `src/ipc/fdpass.c`
- Create: `tests/unit/test_fdpass.c`
- Modify: `CMakeLists.txt`

**Why:** Main process accepts TCP connections and passes client fds to worker processes via SCM_RIGHTS over unix sockets. This is the standard unix mechanism for load-balancing connections across worker processes.

**Step 1: Write failing tests**

```c
void test_fdpass_send_recv_single_fd(void);       /* pass 1 fd over socketpair */
void test_fdpass_send_recv_with_data(void);       /* fd + small metadata payload */
void test_fdpass_recv_no_fd(void);                /* data-only message, fd_out = -1 */
void test_fdpass_invalid_fd(void);                /* send -1 → -EBADF */
void test_fdpass_send_multiple_fds(void);         /* pass 2 fds in one message */
void test_fdpass_received_fd_is_usable(void);     /* pass pipe, write/read through it */
```

**Step 2: Write fdpass.h**

```c
#ifndef RINGWALL_IPC_FDPASS_H
#define RINGWALL_IPC_FDPASS_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_FDPASS_MAX_FDS = 4;

/**
 * @brief Send file descriptor(s) over a unix socket via SCM_RIGHTS.
 *
 * @param sock_fd  Unix socket (SOCK_SEQPACKET or SOCK_STREAM).
 * @param fds      Array of fds to send.
 * @param nfds     Number of fds (1..RW_FDPASS_MAX_FDS).
 * @param data     Optional payload (may be nullptr if data_len == 0).
 * @param data_len Payload length. At least 1 byte required by some kernels.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_fdpass_send(int sock_fd, const int *fds, size_t nfds,
                                  const void *data, size_t data_len);

/**
 * @brief Receive file descriptor(s) from a unix socket.
 *
 * @param sock_fd   Unix socket.
 * @param fds_out   Array to receive fds (set to -1 if no fds in message).
 * @param max_fds   Capacity of fds_out array.
 * @param nfds_out  Number of fds actually received.
 * @param data      Buffer for payload.
 * @param data_len  [in] buffer size, [out] bytes received.
 * @return 0 on success, negative errno on error.
 */
[[nodiscard]] int rw_fdpass_recv(int sock_fd, int *fds_out, size_t max_fds,
                                  size_t *nfds_out, void *data, size_t *data_len);

#endif /* RINGWALL_IPC_FDPASS_H */
```

**Step 3: Implement fdpass.c**

- `rw_fdpass_send()`: build `msghdr` with `cmsghdr` for `SOL_SOCKET/SCM_RIGHTS`, `sendmsg()`
- `rw_fdpass_recv()`: `recvmsg()` with `CMSG_SPACE()` for max fds, extract fds from `cmsghdr`
- If no payload provided, send 1 byte dummy (some kernels require ancillary data to have a payload)

**Step 4: Add to CMakeLists.txt**

```cmake
add_library(rw_fdpass STATIC src/ipc/fdpass.c)
target_include_directories(rw_fdpass PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(rw_fdpass PUBLIC _GNU_SOURCE)

rw_add_test(test_fdpass tests/unit/test_fdpass.c rw_fdpass)
```

**Step 5: Build, test, commit**

```bash
git add src/ipc/fdpass.h src/ipc/fdpass.c tests/unit/test_fdpass.c CMakeLists.txt
git commit -m "feat: fd passing via SCM_RIGHTS for worker connection distribution (6 tests)"
```

---

## Task 3: Main process bootstrap (src/core/main.c)

**Files:**
- Modify: `src/core/main.c` (rewrite from 4-line stub)
- Create: `tests/unit/test_main_bootstrap.c`
- Modify: `CMakeLists.txt`

**Why:** The server needs a real entry point: parse CLI args, load TOML config, create IPC channels, fork child processes, run signal loop. This is the orchestrator that connects all modules.

**Step 1: Write failing tests**

Note: main() itself can't be unit-tested (it's the entry point). Extract testable functions into `main.c` and test them.

```c
void test_main_parse_args_default_config(void);     /* no args → default path */
void test_main_parse_args_custom_config(void);       /* --config /path → path */
void test_main_parse_args_help_flag(void);           /* --help → returns help code */
void test_main_create_ipc_socketpair(void);          /* creates SEQPACKET pair */
void test_main_create_accept_socketpair(void);       /* creates STREAM pair for fd passing */
void test_main_signalfd_creation(void);              /* creates signalfd with SIGTERM+SIGCHLD */
void test_main_fork_child_receives_fd(void);         /* fork, child reads from passed fd */
void test_main_signal_loop_sigterm_exits(void);      /* send SIGTERM, loop returns 0 */
```

**Step 2: Extract helper functions in main.c**

```c
#define _GNU_SOURCE
#include "core/main.h"  /* new: exported helpers for testing */
#include "config/config.h"
#include "core/secmod.h"
#include "io/uring.h"
#include "ipc/fdpass.h"
#include "security/sandbox.h"
#include "security/landlock.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

constexpr char RW_DEFAULT_CONFIG_PATH[] = "/etc/ringwall/ringwall.toml";

int rw_main_parse_args(int argc, char *argv[], const char **config_path)
{
    *config_path = RW_DEFAULT_CONFIG_PATH;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            *config_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return 1;  /* signal: print help */
        }
    }
    return 0;
}

int rw_main_create_ipc_pair(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0)
        return -errno;
    return 0;
}

int rw_main_create_accept_pair(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
        return -errno;
    return 0;
}

int rw_main_create_signalfd(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0)
        return -errno;
    int fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (fd < 0)
        return -errno;
    return fd;
}
```

**Step 3: Implement full main()**

```c
int main(int argc, char *argv[])
{
    const char *config_path;
    int rc = rw_main_parse_args(argc, argv, &config_path);
    if (rc == 1) { /* --help */
        fprintf(stdout, "Usage: ringwall [--config path]\n");
        return EXIT_SUCCESS;
    }

    /* Load configuration */
    rw_config_t config;
    rw_config_set_defaults(&config);
    rc = rw_config_load(config_path, &config);
    if (rc < 0) {
        fprintf(stderr, "Failed to load config: %s\n", strerror(-rc));
        return EXIT_FAILURE;
    }

    /* Create IPC socketpair for auth-mod */
    int authmod_sv[2];
    rc = rw_main_create_ipc_pair(authmod_sv);
    if (rc < 0) goto cleanup_config;

    /* Create accept socketpair for worker (fd passing) */
    int worker_sv[2];
    rc = rw_main_create_accept_pair(worker_sv);
    if (rc < 0) goto cleanup_authmod_sv;

    /* Fork auth-mod */
    pid_t authmod_pid = fork();
    if (authmod_pid < 0) { rc = -errno; goto cleanup_worker_sv; }
    if (authmod_pid == 0) {
        /* Child: auth-mod process */
        close(authmod_sv[0]);
        close(worker_sv[0]);
        close(worker_sv[1]);
        if (config.security.seccomp) rw_sandbox_apply(RW_SANDBOX_AUTHMOD);
        rw_secmod_ctx_t secmod;
        rw_secmod_init(&secmod, authmod_sv[1], &config);
        rc = rw_secmod_run(&secmod);
        rw_secmod_destroy(&secmod);
        rw_config_free(&config);
        _exit(rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
    }
    close(authmod_sv[1]);

    /* Fork worker */
    pid_t worker_pid = fork();
    if (worker_pid < 0) { rc = -errno; goto cleanup_authmod; }
    if (worker_pid == 0) {
        /* Child: worker process */
        close(worker_sv[0]);
        close(authmod_sv[0]);
        if (config.security.seccomp) rw_sandbox_apply(RW_SANDBOX_WORKER);
        /* rw_worker_loop_run() — implemented in Task 4 */
        _exit(EXIT_SUCCESS);
    }
    close(worker_sv[1]);

    /* Main: signal loop */
    if (config.security.seccomp) rw_sandbox_apply(RW_SANDBOX_MAIN);

    int sigfd = rw_main_create_signalfd();
    if (sigfd < 0) { rc = sigfd; goto cleanup_children; }

    /* Read signalfd in a loop */
    struct signalfd_siginfo ssi;
    bool running = true;
    while (running) {
        ssize_t n = read(sigfd, &ssi, sizeof(ssi));
        if (n != sizeof(ssi)) {
            if (errno == EAGAIN) continue;
            break;
        }
        if (ssi.ssi_signo == SIGTERM || ssi.ssi_signo == SIGINT) {
            running = false;
        } else if (ssi.ssi_signo == SIGCHLD) {
            /* Reap children, optionally restart */
            int status;
            waitpid(-1, &status, WNOHANG);
        }
    }

    /* Graceful shutdown */
    kill(worker_pid, SIGTERM);
    kill(authmod_pid, SIGTERM);
    waitpid(worker_pid, nullptr, 0);
    waitpid(authmod_pid, nullptr, 0);
    close(sigfd);
    rc = 0;

cleanup_children:
cleanup_authmod:
    close(authmod_sv[0]);
cleanup_worker_sv:
    close(worker_sv[0]);
cleanup_authmod_sv:
cleanup_config:
    rw_config_free(&config);
    return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```

**Step 4: Create main.h (exported helpers for testing)**

```c
#ifndef RINGWALL_CORE_MAIN_H
#define RINGWALL_CORE_MAIN_H

[[nodiscard]] int rw_main_parse_args(int argc, char *argv[], const char **config_path);
[[nodiscard]] int rw_main_create_ipc_pair(int sv[2]);
[[nodiscard]] int rw_main_create_accept_pair(int sv[2]);
[[nodiscard]] int rw_main_create_signalfd(void);

#endif /* RINGWALL_CORE_MAIN_H */
```

**Step 5: Add test to CMakeLists.txt, build, test, commit**

```bash
git add src/core/main.c src/core/main.h tests/unit/test_main_bootstrap.c CMakeLists.txt
git commit -m "feat: main process bootstrap — config, fork auth-mod/worker, signal loop (8 tests)"
```

---

## Task 4: Worker event loop (src/core/worker_loop.{h,c})

**Files:**
- Create: `src/core/worker_loop.h`
- Create: `src/core/worker_loop.c`
- Create: `tests/unit/test_worker_loop.c`
- Modify: `CMakeLists.txt`

**Why:** The worker process needs an io_uring event loop that accepts client fds from main (via fd passing), manages per-connection state, and drives the TLS + CSTP data path.

**Step 1: Write failing tests**

```c
void test_worker_loop_init_destroy(void);          /* lifecycle */
void test_worker_loop_stop_immediate(void);        /* init, stop, run returns 0 */
void test_worker_loop_accept_fd(void);             /* pass fd via socketpair, loop picks it up */
void test_worker_loop_reject_at_capacity(void);    /* fill connections, next fd gets rejected */
void test_worker_loop_connection_cleanup(void);    /* add conn, close peer, verify removed */
void test_worker_loop_multiple_connections(void);  /* add 3 conns, verify count */
void test_worker_loop_recv_data(void);             /* mock TLS fd, send bytes, verify received */
void test_worker_loop_tun_write(void);             /* write to TUN fd (socketpair mock) */
```

**Step 2: Write worker_loop.h**

```c
#ifndef RINGWALL_CORE_WORKER_LOOP_H
#define RINGWALL_CORE_WORKER_LOOP_H

#include "config/config.h"
#include "core/worker.h"
#include "io/uring.h"

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Worker event loop context.
 *
 * Wraps rw_worker_t (connection pool) with an io_uring event loop.
 * Receives new client fds from main via accept_fd (SCM_RIGHTS).
 * Drives TLS handshake, CSTP framing, and TUN I/O per connection.
 */
typedef struct {
    rw_worker_t *worker;
    rw_io_ctx_t *io;
    int accept_fd;             /* unix socket: main passes client fds here */
    int ipc_fd;                /* IPC to auth-mod */
    const rw_config_t *config;
    bool running;
} rw_worker_loop_t;

typedef struct {
    int accept_fd;
    int ipc_fd;
    const rw_config_t *config;
    const rw_worker_config_t *worker_cfg;
} rw_worker_loop_config_t;

/**
 * @brief Initialize worker event loop.
 * @return 0 on success, negative errno on failure.
 */
[[nodiscard]] int rw_worker_loop_init(rw_worker_loop_t *loop,
                                       const rw_worker_loop_config_t *cfg);

/**
 * @brief Run worker event loop (blocking). Returns on rw_worker_loop_stop().
 */
[[nodiscard]] int rw_worker_loop_run(rw_worker_loop_t *loop);

/**
 * @brief Signal worker event loop to stop.
 */
void rw_worker_loop_stop(rw_worker_loop_t *loop);

/**
 * @brief Destroy worker event loop and free resources.
 */
void rw_worker_loop_destroy(rw_worker_loop_t *loop);

#endif /* RINGWALL_CORE_WORKER_LOOP_H */
```

**Step 3: Implement worker_loop.c**

Core loop structure:
```c
int rw_worker_loop_init(rw_worker_loop_t *loop, const rw_worker_loop_config_t *cfg)
{
    loop->io = rw_io_init(cfg->worker_cfg->queue_depth, 0);
    if (!loop->io) return -ENOMEM;

    loop->worker = rw_worker_create(cfg->worker_cfg);
    if (!loop->worker) { rw_io_destroy(loop->io); return -ENOMEM; }

    loop->accept_fd = cfg->accept_fd;
    loop->ipc_fd = cfg->ipc_fd;
    loop->config = cfg->config;
    loop->running = false;
    return 0;
}

int rw_worker_loop_run(rw_worker_loop_t *loop)
{
    loop->running = true;

    /* Arm accept_fd for incoming fd-pass messages */
    rw_io_prep_recv_cb(loop->io, loop->accept_fd, loop->accept_buf,
                        sizeof(loop->accept_buf), on_accept_fd, loop);

    while (loop->running) {
        int rc = rw_io_run_once(loop->io, 1000);
        if (rc < 0 && rc != -ETIME) return rc;
    }
    return 0;
}
```

The `on_accept_fd` callback:
1. `rw_fdpass_recv()` to get client fd
2. `rw_worker_add_connection()` to allocate slot
3. Start TLS handshake (Task 6)
4. Re-arm accept_fd for next connection

**Step 4: Add to CMakeLists.txt**

```cmake
add_library(rw_worker_loop STATIC src/core/worker_loop.c)
target_include_directories(rw_worker_loop PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(rw_worker_loop PUBLIC rw_worker rw_io rw_fdpass rw_cstp rw_dpd)
target_compile_definitions(rw_worker_loop PUBLIC _GNU_SOURCE)

rw_add_test(test_worker_loop tests/unit/test_worker_loop.c rw_worker_loop rw_io rw_fdpass rw_cstp rw_dpd rw_worker)
```

**Step 5: Build, test, commit**

```bash
git add src/core/worker_loop.h src/core/worker_loop.c tests/unit/test_worker_loop.c CMakeLists.txt
git commit -m "feat: worker io_uring event loop with fd-pass connection accept (8 tests)"
```

---

## Task 5: Auth-mod storage integration

**Files:**
- Modify: `src/core/secmod.h`
- Modify: `src/core/secmod.c`
- Create: `tests/unit/test_secmod_storage.c`
- Modify: `CMakeLists.txt`

**Why:** Auth-mod currently uses `rw_session_store_t` (in-memory, max 1024). Replace with `rw_mdbx_ctx_t` (persistent, scalable) and add `rw_sqlite_ctx_t` for audit logging. This connects S2 (auth) with S5 (storage).

**Step 1: Write failing tests**

```c
void test_secmod_init_with_mdbx(void);              /* init with mdbx path, verify open */
void test_secmod_auth_creates_mdbx_session(void);   /* auth success → session in mdbx */
void test_secmod_auth_creates_audit_entry(void);    /* auth attempt → audit in sqlite */
void test_secmod_validate_reads_mdbx(void);         /* session validate → mdbx lookup */
void test_secmod_auth_failure_audit(void);           /* failed auth → audit with result=FAIL */
void test_secmod_session_delete_cleans_mdbx(void);  /* disconnect → mdbx delete */
void test_secmod_expired_session_cleanup(void);     /* iterate mdbx, delete expired */
void test_secmod_ban_check_before_auth(void);       /* banned IP → -EACCES, no PAM call */
```

**Step 2: Extend secmod.h**

Add storage fields to context:
```c
#include "storage/mdbx.h"
#include "storage/sqlite.h"

typedef struct {
    int ipc_fd;
    rw_pam_config_t pam_cfg;
    rw_mdbx_ctx_t mdbx;            /* replaces rw_session_store_t */
    rw_sqlite_ctx_t sqlite;         /* audit logging + user management */
    const rw_config_t *config;
    bool running;
} rw_secmod_ctx_t;
```

**Step 3: Update secmod.c**

- `rw_secmod_init()`: call `rw_mdbx_init()` + `rw_sqlite_init()`, remove `rw_session_store_create()`
- Auth success handler: `rw_mdbx_session_create()` instead of in-memory store, then `rw_sqlite_audit_insert()`
- Session validate: `rw_mdbx_session_lookup()` instead of in-memory lookup
- Disconnect: `rw_mdbx_session_delete()` + audit entry
- `rw_secmod_destroy()`: close both stores

**Step 4: Update CMakeLists.txt** — link rw_secmod against rw_mdbx and rw_sqlite

**Step 5: Build, test, commit**

```bash
git add src/core/secmod.h src/core/secmod.c tests/unit/test_secmod_storage.c CMakeLists.txt
git commit -m "feat: auth-mod storage integration — libmdbx sessions, SQLite audit (8 tests)"
```

---

## Task 6: TLS handshake in worker

**Files:**
- Create: `src/core/conn_tls.h`
- Create: `src/core/conn_tls.c`
- Create: `tests/unit/test_conn_tls.c`
- Modify: `CMakeLists.txt`

**Why:** After receiving a client fd, the worker must perform a wolfSSL TLS handshake. This bridges `tls_wolfssl.c` (crypto) with `worker_loop.c` (event loop). wolfSentry pre-check happens before handshake.

**Step 1: Write failing tests**

```c
void test_conn_tls_ctx_create_destroy(void);         /* wolfSSL context lifecycle */
void test_conn_tls_handshake_loopback(void);         /* self-signed cert, socketpair handshake */
void test_conn_tls_handshake_timeout(void);          /* no peer data → timeout → -ETIMEDOUT */
void test_conn_tls_read_after_handshake(void);       /* handshake, send data, read back */
void test_conn_tls_write_after_handshake(void);      /* handshake, write, peer reads */
void test_conn_tls_wolfsentry_reject(void);          /* banned IP → reject before handshake */
```

**Step 2: Write conn_tls.h**

```c
#ifndef RINGWALL_CORE_CONN_TLS_H
#define RINGWALL_CORE_CONN_TLS_H

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Per-worker TLS context (shared across connections).
 */
typedef struct {
    WOLFSSL_CTX *ctx;
} rw_tls_server_t;

/**
 * @brief Per-connection TLS state.
 */
typedef struct {
    WOLFSSL *ssl;
    int fd;
    bool handshake_done;
} rw_tls_conn_t;

typedef struct {
    const char *cert_file;
    const char *key_file;
    const char *ca_file;           /* may be nullptr */
    const char *ciphers;           /* may be nullptr for defaults */
} rw_tls_server_config_t;

[[nodiscard]] int rw_tls_server_init(rw_tls_server_t *srv, const rw_tls_server_config_t *cfg);
void rw_tls_server_destroy(rw_tls_server_t *srv);

[[nodiscard]] int rw_tls_conn_init(rw_tls_conn_t *conn, rw_tls_server_t *srv, int fd);
void rw_tls_conn_destroy(rw_tls_conn_t *conn);

/**
 * @brief Attempt TLS handshake (non-blocking).
 * @return 0 if complete, -EAGAIN if WANT_READ/WANT_WRITE, negative errno on error.
 */
[[nodiscard]] int rw_tls_conn_handshake(rw_tls_conn_t *conn);

/**
 * @brief Read decrypted data.
 * @return bytes read (>0), -EAGAIN, or negative errno.
 */
[[nodiscard]] int rw_tls_conn_read(rw_tls_conn_t *conn, void *buf, size_t len);

/**
 * @brief Write data to encrypt and send.
 * @return bytes written (>0), -EAGAIN, or negative errno.
 */
[[nodiscard]] int rw_tls_conn_write(rw_tls_conn_t *conn, const void *buf, size_t len);

#endif /* RINGWALL_CORE_CONN_TLS_H */
```

**Step 3: Implement conn_tls.c**

- `rw_tls_server_init()`: `wolfSSL_CTX_new(wolfTLSv1_3_server_method())`, load cert/key, set non-blocking
- `rw_tls_conn_init()`: `wolfSSL_new()`, `wolfSSL_set_fd()`, set non-blocking
- `rw_tls_conn_handshake()`: call `wolfSSL_accept()`, map `SSL_ERROR_WANT_READ/WRITE` to `-EAGAIN`
- `rw_tls_conn_read/write()`: wrap `wolfSSL_read/write()` with error mapping

**Note:** Tests use a self-signed cert generated at test time (`tests/fixtures/` or temp dir). Use wolfSSL's `wolfSSL_CTX_use_certificate_buffer()` with embedded test cert for hermetic tests.

**Step 4: Build, test, commit**

```bash
git add src/core/conn_tls.h src/core/conn_tls.c tests/unit/test_conn_tls.c CMakeLists.txt
git commit -m "feat: per-connection TLS handshake with wolfSSL non-blocking API (6 tests)"
```

---

## Task 7: CSTP data path (src/core/conn_data.{h,c})

**Files:**
- Create: `src/core/conn_data.h`
- Create: `src/core/conn_data.c`
- Create: `tests/unit/test_conn_data.c`
- Modify: `CMakeLists.txt`

**Why:** This is the core VPN data path — the reason the project exists. TLS recv → CSTP decode → decompress → TUN write (and reverse). Each step uses existing modules that have never been wired together.

**Step 1: Write failing tests**

```c
void test_data_path_tls_to_tun(void);                /* TLS read → CSTP decode → TUN write */
void test_data_path_tun_to_tls(void);                /* TUN read → CSTP encode → TLS write */
void test_data_path_dpd_request_response(void);      /* recv DPD_REQ → send DPD_RESP */
void test_data_path_keepalive_passthrough(void);     /* recv KEEPALIVE → no TUN write */
void test_data_path_disconnect_cleanup(void);        /* recv DISCONNECT → close connection */
void test_data_path_compressed_lz4(void);            /* compressed data round-trip with LZ4 */
void test_data_path_compressed_lzs(void);            /* compressed data round-trip with LZS */
void test_data_path_partial_cstp_reassembly(void);   /* receive split across 2 reads */
void test_data_path_max_payload_size(void);          /* 16384 byte payload round-trip */
void test_data_path_multiple_packets_batch(void);    /* 3 packets in one TLS read */
```

**Step 2: Write conn_data.h**

```c
#ifndef RINGWALL_CORE_CONN_DATA_H
#define RINGWALL_CORE_CONN_DATA_H

#include "core/conn_tls.h"
#include "core/worker.h"
#include "network/channel.h"
#include "network/compress.h"
#include "network/cstp.h"
#include "network/dpd.h"

/**
 * @brief Per-connection data path state.
 *
 * Drives the TLS ↔ CSTP ↔ TUN pipeline for one VPN client.
 * Owned by the worker event loop, one instance per active connection.
 */
typedef struct {
    rw_tls_conn_t *tls;
    int tun_fd;
    rw_dpd_ctx_t *dpd;
    rw_compress_ctx_t *compress;
    rw_channel_ctx_t channel;

    /* Receive buffer (accumulates partial CSTP frames from TLS) */
    uint8_t recv_buf[RW_CSTP_HEADER_SIZE + RW_CSTP_MAX_PAYLOAD];
    size_t recv_len;

    /* Send buffer (CSTP-encoded frame for TLS write) */
    uint8_t send_buf[RW_CSTP_HEADER_SIZE + RW_CSTP_MAX_PAYLOAD];
} rw_conn_data_t;

/**
 * @brief Initialize data path for a connection.
 */
void rw_conn_data_init(rw_conn_data_t *data, rw_tls_conn_t *tls, int tun_fd,
                        rw_dpd_ctx_t *dpd, rw_compress_ctx_t *compress);

/**
 * @brief Process data received from TLS.
 *
 * Reads from TLS, decodes CSTP, routes by packet type:
 * - DATA → decompress → write to tun_fd
 * - DPD_REQ → send DPD_RESP via TLS
 * - KEEPALIVE → ignore
 * - DISCONNECT → return -ECONNRESET
 *
 * @return 0 on success, -EAGAIN if incomplete, negative errno on error.
 */
[[nodiscard]] int rw_conn_data_process_tls(rw_conn_data_t *data);

/**
 * @brief Process data received from TUN.
 *
 * Reads from tun_fd, compresses, CSTP-encodes, sends via TLS.
 *
 * @param pkt    Raw IP packet from TUN.
 * @param pkt_len Packet length.
 * @return bytes sent via TLS, or negative errno.
 */
[[nodiscard]] int rw_conn_data_process_tun(rw_conn_data_t *data,
                                            const uint8_t *pkt, size_t pkt_len);

/**
 * @brief Send a DPD request via TLS.
 */
[[nodiscard]] int rw_conn_data_send_dpd_req(rw_conn_data_t *data);

/**
 * @brief Send a keepalive via TLS.
 */
[[nodiscard]] int rw_conn_data_send_keepalive(rw_conn_data_t *data);

#endif /* RINGWALL_CORE_CONN_DATA_H */
```

**Step 3: Implement conn_data.c**

Core logic for `rw_conn_data_process_tls()`:
```c
int rw_conn_data_process_tls(rw_conn_data_t *data)
{
    /* Read from TLS into recv_buf */
    int n = rw_tls_conn_read(data->tls,
                              data->recv_buf + data->recv_len,
                              sizeof(data->recv_buf) - data->recv_len);
    if (n < 0) return n;  /* -EAGAIN or error */
    data->recv_len += (size_t)n;

    /* Decode CSTP packets (may be multiple in buffer) */
    while (data->recv_len >= RW_CSTP_HEADER_SIZE) {
        rw_cstp_packet_t pkt;
        int consumed = rw_cstp_decode(data->recv_buf, data->recv_len, &pkt);
        if (consumed == -EAGAIN) break;  /* incomplete frame */
        if (consumed < 0) return consumed;

        /* Route by packet type */
        int rc = 0;
        switch (pkt.type) {
        case RW_CSTP_DATA:
            rc = handle_data_packet(data, &pkt);
            break;
        case RW_CSTP_DPD_REQ:
            rc = send_dpd_response(data);
            break;
        case RW_CSTP_KEEPALIVE:
            break;  /* no-op */
        case RW_CSTP_DISCONNECT:
            return -ECONNRESET;
        default:
            break;
        }
        if (rc < 0) return rc;

        /* Shift buffer */
        size_t remaining = data->recv_len - (size_t)consumed;
        if (remaining > 0) memmove(data->recv_buf, data->recv_buf + consumed, remaining);
        data->recv_len = remaining;
    }
    return 0;
}
```

For `handle_data_packet()`: decompress if compressed type, then write to TUN fd.
For `rw_conn_data_process_tun()`: compress payload, CSTP-encode with DATA type, TLS write.

**Testing approach:** Use socketpairs to mock both TLS and TUN. For TLS mock, create a thin wrapper that reads/writes plaintext (skip actual encryption in unit tests). The integration test (Task 10) will use real wolfSSL.

**Step 4: Build, test, commit**

```bash
git add src/core/conn_data.h src/core/conn_data.c tests/unit/test_conn_data.c CMakeLists.txt
git commit -m "feat: CSTP data path — TLS↔CSTP↔TUN routing with compression (10 tests)"
```

---

## Task 8: DPD timer integration

**Files:**
- Create: `src/core/conn_timer.h`
- Create: `src/core/conn_timer.c`
- Create: `tests/unit/test_conn_timer.c`
- Modify: `CMakeLists.txt`

**Why:** The DPD state machine (from S3) exists but has no timer driving it. Wire io_uring timeouts to DPD probes — when timer fires, send DPD request; if no response within retries, mark connection dead and clean up.

**Step 1: Write failing tests**

```c
void test_timer_dpd_probe_fires(void);            /* timer fires, need_send_request set */
void test_timer_dpd_response_resets(void);        /* response received, timer resets */
void test_timer_dpd_dead_callback(void);          /* 3 timeouts, dead callback invoked */
void test_timer_keepalive_fires(void);            /* keepalive timer sends packet */
void test_timer_connection_timeout(void);         /* idle timeout → disconnect */
void test_timer_reschedule_after_activity(void);  /* data received → reset idle timer */
```

**Step 2: Write conn_timer.h**

```c
#ifndef RINGWALL_CORE_CONN_TIMER_H
#define RINGWALL_CORE_CONN_TIMER_H

#include "core/conn_data.h"
#include "io/uring.h"
#include "network/dpd.h"

typedef void (*rw_conn_dead_cb)(uint64_t conn_id, void *user_data);

typedef struct {
    rw_io_ctx_t *io;
    rw_dpd_ctx_t *dpd;
    rw_conn_data_t *data;
    uint64_t conn_id;
    uint32_t keepalive_interval_s;
    uint32_t idle_timeout_s;
    rw_conn_dead_cb on_dead;
    void *on_dead_user_data;
    bool active;
} rw_conn_timer_t;

[[nodiscard]] int rw_conn_timer_start(rw_conn_timer_t *timer);
void rw_conn_timer_stop(rw_conn_timer_t *timer);
void rw_conn_timer_on_activity(rw_conn_timer_t *timer);

#endif /* RINGWALL_CORE_CONN_TIMER_H */
```

**Step 3: Implement conn_timer.c**

- `rw_conn_timer_start()`: arm DPD timeout via `rw_io_add_timeout_cb()`, arm keepalive timeout
- DPD timeout callback: call `rw_dpd_on_timeout()`, if DEAD → call `on_dead`, else send DPD request, re-arm
- Keepalive callback: `rw_conn_data_send_keepalive()`, re-arm
- `on_activity()`: reset idle timer, update DPD last_recv

**Step 4: Build, test, commit**

```bash
git add src/core/conn_timer.h src/core/conn_timer.c tests/unit/test_conn_timer.c CMakeLists.txt
git commit -m "feat: DPD and keepalive timer integration with io_uring (6 tests)"
```

---

## Task 9: Security activation hooks

**Files:**
- Create: `src/core/security_hooks.h`
- Create: `src/core/security_hooks.c`
- Create: `tests/unit/test_security_hooks.c`
- Modify: `CMakeLists.txt`

**Why:** All S5 security modules (seccomp, Landlock, wolfSentry, nftables) are implemented but never called. This task creates the activation points: at process fork, at connection accept, and at session create/destroy.

**Step 1: Write failing tests**

```c
void test_hooks_pre_accept_allowed(void);          /* clean IP → ACCEPT */
void test_hooks_pre_accept_banned(void);           /* banned IP → REJECT */
void test_hooks_post_auth_creates_fw_chain(void);  /* auth success → chain name built */
void test_hooks_disconnect_destroys_fw_chain(void); /* disconnect → cleanup batch built */
void test_hooks_sandbox_profile_selection(void);   /* worker→WORKER, authmod→AUTHMOD */
void test_hooks_landlock_paths_from_config(void);  /* config paths → landlock apply args */
```

**Step 2: Write security_hooks.h**

```c
#ifndef RINGWALL_CORE_SECURITY_HOOKS_H
#define RINGWALL_CORE_SECURITY_HOOKS_H

#include "config/config.h"
#include "security/wolfsentry.h"
#include "security/firewall.h"
#include "security/sandbox.h"
#include "security/landlock.h"
#include <netinet/in.h>

/**
 * @brief Apply process-level security restrictions.
 * Called immediately after fork(), before any I/O.
 */
[[nodiscard]] int rw_security_apply_process(rw_sandbox_profile_t profile,
                                             const rw_config_t *config);

/**
 * @brief Check incoming connection before TLS handshake.
 * @return 0 if allowed, -EACCES if blocked.
 */
[[nodiscard]] int rw_security_check_connection(rw_wolfsentry_ctx_t *ws,
                                                int af, const void *addr,
                                                uint16_t port);

/**
 * @brief Create per-session firewall rules after auth success.
 */
[[nodiscard]] int rw_security_session_create(const char *username,
                                              int af, uint32_t assigned_ip);

/**
 * @brief Remove per-session firewall rules on disconnect.
 */
[[nodiscard]] int rw_security_session_destroy(const char *username,
                                               int af, uint32_t assigned_ip);

#endif /* RINGWALL_CORE_SECURITY_HOOKS_H */
```

**Step 3: Implement security_hooks.c**

- `rw_security_apply_process()`: if `config->security.seccomp` → `rw_sandbox_apply()`, if `config->security.landlock` → `rw_landlock_apply()`
- `rw_security_check_connection()`: delegate to `rw_wolfsentry_check_connection()`
- `rw_security_session_create/destroy()`: build `rw_fw_session_t`, delegate to `rw_fw_session_create/destroy()`

**Step 4: Build, test, commit**

```bash
git add src/core/security_hooks.h src/core/security_hooks.c tests/unit/test_security_hooks.c CMakeLists.txt
git commit -m "feat: security activation hooks — sandbox, wolfSentry, nftables (6 tests)"
```

---

## Task 10: Graceful shutdown

**Files:**
- Modify: `src/core/worker_loop.c`
- Modify: `src/core/main.c`
- Create: `tests/unit/test_shutdown.c`
- Modify: `CMakeLists.txt`

**Why:** The server must shut down cleanly: stop accepting, drain active connections (send DISCONNECT, wait for TLS close), close TUN devices, free resources. Without this, connections drop abruptly and state leaks.

**Step 1: Write failing tests**

```c
void test_shutdown_worker_drains_connections(void);   /* stop → send DISCONNECT → close all */
void test_shutdown_worker_timeout_force_close(void);  /* drain timeout → force close */
void test_shutdown_main_signals_children(void);       /* main SIGTERM → children get SIGTERM */
void test_shutdown_cleanup_no_leaks(void);            /* destroy all contexts, no fd leaks */
```

**Step 2: Implement worker shutdown in worker_loop.c**

```c
void rw_worker_loop_stop(rw_worker_loop_t *loop)
{
    loop->running = false;
    rw_io_stop(loop->io);
}

/* Called from run loop when stopping */
static int drain_connections(rw_worker_loop_t *loop)
{
    /* For each active connection: send CSTP DISCONNECT */
    for (uint32_t i = 0; i < loop->worker->config.max_connections; i++) {
        rw_connection_t *conn = &loop->worker->conns[i];
        if (!conn->active) continue;

        uint8_t buf[RW_CSTP_HEADER_SIZE];
        int n = rw_cstp_encode(buf, sizeof(buf), RW_CSTP_DISCONNECT, nullptr, 0);
        if (n > 0) {
            /* Best-effort send — ignore errors during shutdown */
            rw_tls_conn_write(/* ... */, buf, (size_t)n);
        }
        rw_worker_remove_connection(loop->worker, conn->conn_id);
    }
    return 0;
}
```

**Step 3: Build, test, commit**

```bash
git add src/core/worker_loop.c src/core/main.c tests/unit/test_shutdown.c CMakeLists.txt
git commit -m "feat: graceful shutdown — drain connections, signal children (4 tests)"
```

---

## Task 11: End-to-end integration test

**Files:**
- Create: `tests/integration/test_vpn_flow.c`
- Modify: `CMakeLists.txt`

**Why:** Verify the full vertical path works: main forks worker, client connects, TLS handshake, auth via IPC, CSTP tunnel, data flows through TUN, DPD probe/response, clean disconnect.

**Step 1: Write integration tests**

```c
void test_vpn_flow_worker_accepts_connection(void);  /* fd pass → TLS → connected */
void test_vpn_flow_cstp_data_roundtrip(void);        /* client sends DATA → TUN → back */
void test_vpn_flow_dpd_probe_response(void);         /* DPD_REQ → DPD_RESP within timeout */
void test_vpn_flow_client_disconnect(void);          /* client sends DISCONNECT → cleanup */
void test_vpn_flow_multiple_clients(void);           /* 3 clients, independent data paths */
```

**Testing approach:**
- Use `socketpair()` for everything (no real network, no root needed)
- Mock TUN with socketpair (one end is "TUN", other end is test validator)
- Mock TLS with self-signed wolfSSL over socketpair
- Auth-mod runs in same process (call `rw_secmod_handle_message()` directly)
- Worker event loop runs in a separate thread (`pthread_create`), test drives the client side

**Step 2: Add to CMakeLists.txt**

```cmake
rw_add_test(test_vpn_flow tests/integration/test_vpn_flow.c
    rw_worker_loop rw_conn_data rw_conn_tls rw_conn_timer rw_security_hooks
    rw_worker rw_io rw_fdpass rw_cstp rw_dpd rw_compress rw_secmod
    rw_mdbx rw_sqlite rw_migrate ${WOLFSSL_LIBRARIES})
```

**Step 3: Build, run, commit**

```bash
git add tests/integration/test_vpn_flow.c CMakeLists.txt
git commit -m "test: end-to-end VPN flow integration test — TLS, CSTP, TUN, DPD (5 tests)"
```

---

## Task 12: Cleanup and finalization

**Step 1: Remove libuv dead code from CMakeLists.txt**

The CMakeLists.txt still checks for libuv despite io_uring-only architecture. Remove the dead `find_package(libuv)` and related blocks.

**Step 2: Run full test suite with sanitizers**

```bash
cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug --output-on-failure
```

**Step 3: Run clang-format**

```bash
cmake --build --preset clang-debug --target format
```

**Step 4: Verify test count**

```bash
ctest --preset clang-debug -N | tail -1
# Expected: ~120+ total tests (existing ~55 + ~67 new)
```

**Step 5: Run quality pipeline**

```bash
podman run --rm --security-opt seccomp=unconfined \
  -v /opt/projects/repositories/ringwall:/workspace:Z \
  localhost/ringwall-dev:latest bash -c "cd /workspace && ./scripts/quality.sh"
```

**Step 6: Commit**

```bash
git add -A
git commit -m "chore: Sprint 6 complete — vertical integration, cleanup"
```

---

## Summary

| Task | Component | New Tests | Key Integration |
|------|-----------|-----------|-----------------|
| 1 | io_uring callback API | 8 | Foundation for event loop |
| 2 | fd passing (SCM_RIGHTS) | 6 | Main → Worker connection distribution |
| 3 | Main process bootstrap | 8 | Config → fork → signal loop |
| 4 | Worker event loop | 8 | io_uring + fd accept + connection lifecycle |
| 5 | Auth-mod storage | 8 | secmod → libmdbx + SQLite |
| 6 | TLS handshake | 6 | wolfSSL in worker |
| 7 | CSTP data path | 10 | TLS ↔ CSTP ↔ TUN (the core) |
| 8 | DPD + timers | 6 | io_uring timeouts + DPD state machine |
| 9 | Security hooks | 6 | seccomp, wolfSentry, nftables activation |
| 10 | Graceful shutdown | 4 | Drain + signal + cleanup |
| 11 | Integration test | 5 | End-to-end VPN flow |
| 12 | Finalization | — | Quality pipeline |

**New tests: ~75. Total after Sprint 6: ~130.**
**New source files: 12 (6 .h + 6 .c). Modified: 6 existing files.**

## Critical Files

**Existing (wire together):**
- `src/io/uring.{h,c}` — extend with callback API
- `src/core/worker.{h,c}` — connection pool (unchanged, consumed by worker_loop)
- `src/core/secmod.{h,c}` — replace in-memory store with libmdbx
- `src/core/main.c` — rewrite from stub to real entry point
- `src/network/cstp.{h,c}` — consumed by conn_data
- `src/network/dpd.{h,c}` — consumed by conn_timer
- `src/network/compress.{h,c}` — consumed by conn_data
- `src/network/channel.{h,c}` — consumed by conn_data
- `src/crypto/tls_wolfssl.{h,c}` — consumed by conn_tls
- `src/storage/mdbx.{h,c}` — consumed by secmod
- `src/storage/sqlite.{h,c}` — consumed by secmod
- `src/security/sandbox.{h,c}` — consumed by security_hooks
- `src/security/landlock.{h,c}` — consumed by security_hooks
- `src/security/wolfsentry.{h,c}` — consumed by security_hooks
- `src/security/firewall.{h,c}` — consumed by security_hooks

**New:**
- `src/ipc/fdpass.{h,c}` — fd passing via SCM_RIGHTS
- `src/core/main.h` — exported bootstrap helpers (for testing)
- `src/core/worker_loop.{h,c}` — worker io_uring event loop
- `src/core/conn_tls.{h,c}` — per-connection TLS state
- `src/core/conn_data.{h,c}` — CSTP data path (the core pipeline)
- `src/core/conn_timer.{h,c}` — DPD + keepalive timers
- `src/core/security_hooks.{h,c}` — security module activation

**Reference:**
- `docs/architecture/PROTOCOL_REFERENCE.md` — OpenConnect protocol spec
- `.claude/skills/ocprotocol/SKILL.md` — connection flow, CSTP packet types
- `.claude/skills/security-coding/SKILL.md` — constant-time, zeroing, banned functions
- `.claude/skills/coding-standards/SKILL.md` — naming, errors, C23 patterns
- `.claude/skills/io-uring-patterns/SKILL.md` — SQE/CQE patterns, send serialization
- `.claude/skills/wolfssl-api/SKILL.md` — TLS API, non-blocking I/O, buffer callbacks
- `.claude/skills/wolfsentry-idps/SKILL.md` — wolfSentry integration, rate limiting

## Verification

After all tasks:
1. `ctest --preset clang-debug --output-on-failure` — all ~130 tests pass
2. `cmake --build --preset clang-debug --target format-check` — formatting clean
3. Main process: starts, forks auth-mod + worker, handles SIGTERM
4. Worker: accepts fd-passed connections, completes TLS handshake
5. Data path: TLS recv → CSTP decode → TUN write (and reverse)
6. Auth-mod: libmdbx session CRUD, SQLite audit entries created
7. Security: seccomp applied per process, wolfSentry checked pre-handshake
8. DPD: timer fires, probes sent, dead connections cleaned up
9. Shutdown: DISCONNECT sent to all clients, children reaped, no fd leaks
10. Quality pipeline: zero PVS errors, zero CodeChecker HIGH findings
