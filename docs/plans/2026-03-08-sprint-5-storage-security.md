# Sprint 5: Storage & Security Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add persistent storage (libmdbx + SQLite hybrid), IDPS (wolfSentry), kernel sandboxing (seccomp BPF + Landlock), per-user firewall (nftables), and fuzz testing targets.

**Architecture:** Hybrid two-DB model — libmdbx for per-packet session lookups (data plane, nanoseconds), SQLite WAL for user management and audit (control plane, milliseconds). Workers read-only to libmdbx, never touch SQLite. auth-mod is sole writer for both. wolfSentry checks connections at TLS ClientHello. seccomp BPF and Landlock restrict worker and auth-mod processes. nftables per-user chains via libmnl+libnftnl.

**Tech Stack:** C23, liburing 2.14+, wolfSSL 5.8+, wolfSentry 1.6+, libmdbx 0.14+, SQLite 3.40+, libseccomp 2.5+, libmnl, libnftnl, Unity tests, Linux kernel 6.7+.

**IMPORTANT:** This plan assumes the rebranding (ioguard -> ioguard) has been completed. All new code uses `rw_` prefix, `RW_` macros, `RINGWALL_` include guards.

**Build/test:**
```bash
cmake --preset clang-debug
cmake --build --preset clang-debug
ctest --preset clang-debug
```

---

## Pre-requisite: Update Container

Before starting Sprint 5, the dev container needs libmdbx and SQLite:

```dockerfile
# Add to Containerfile:

ARG LIBMDBX_VERSION=0.14.1

# Build libmdbx from source
RUN cd /tmp && \
    git clone --depth 1 --branch v${LIBMDBX_VERSION} https://gitflic.ru/project/erthink/libmdbx.git && \
    cd libmdbx && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DMDBX_BUILD_TOOLS=OFF \
        -DMDBX_BUILD_CXX=OFF && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf libmdbx

# SQLite from system packages
RUN dnf install -y sqlite-devel && dnf clean all
```

Rebuild container before starting tasks.

---

## Task 1: libmdbx session store (src/storage/mdbx.{h,c})

**Files:**
- Create: `src/storage/mdbx.h`
- Create: `src/storage/mdbx.c`
- Create: `tests/unit/test_storage_mdbx.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests (test_storage_mdbx.c)**

```c
#include <unity/unity.h>
#include "storage/mdbx.h"
#include <string.h>
#include <unistd.h>
#include <time.h>

static const char *TEST_DB_PATH = "/tmp/test_ringwall.mdbx";

void setUp(void) {}
void tearDown(void) {
    unlink(TEST_DB_PATH);
    // Also remove lock file
    char lck[256];
    snprintf(lck, sizeof(lck), "%s-lck", TEST_DB_PATH);
    unlink(lck);
}

void test_mdbx_env_create_and_close(void);          // init + close lifecycle
void test_mdbx_session_create(void);                // write session, return 0
void test_mdbx_session_lookup_found(void);           // create then lookup, verify fields
void test_mdbx_session_lookup_not_found(void);       // lookup missing key -> -ENOENT
void test_mdbx_session_delete(void);                // create, delete, lookup -> -ENOENT
void test_mdbx_session_duplicate(void);             // create same key twice -> -EEXIST
void test_mdbx_session_count(void);                 // create 3, count == 3
void test_mdbx_session_iterate(void);               // create 5, iterate all, count == 5
void test_mdbx_stale_reader_callback(void);         // verify HSR callback is set (env info)
void test_mdbx_geometry_limits(void);               // verify max size <= 1 GB
```

**Step 2: Write mdbx.h**

```c
#ifndef RINGWALL_STORAGE_MDBX_H
#define RINGWALL_STORAGE_MDBX_H

#include <mdbx.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

constexpr size_t RW_SESSION_ID_LEN = 32;
constexpr size_t RW_MDBX_MAX_READERS = 128;
constexpr size_t RW_MDBX_MAX_DBS = 8;
constexpr size_t RW_MDBX_SIZE_LOWER = 1 * 1024 * 1024;       // 1 MB
constexpr size_t RW_MDBX_SIZE_UPPER = 1024 * 1024 * 1024;    // 1 GB
constexpr size_t RW_MDBX_GROWTH_STEP = 16 * 1024 * 1024;     // 16 MB
constexpr size_t RW_MDBX_SHRINK_THRESHOLD = 64 * 1024 * 1024; // 64 MB

typedef struct {
    uint8_t  session_id[RW_SESSION_ID_LEN];
    uint8_t  cookie_hmac[32];
    uint8_t  dtls_master_secret[48];
    uint32_t assigned_ipv4;
    time_t   created_at;
    time_t   expires_at;
    char     username[256];
    char     groupname[256];
    uint32_t source_ip;
    uint16_t source_port;
    bool     deny_roaming;
} rw_session_record_t;

typedef struct {
    MDBX_env *env;
    MDBX_dbi  dbi_sessions;
} rw_mdbx_ctx_t;

[[nodiscard]] int rw_mdbx_init(rw_mdbx_ctx_t *ctx, const char *path);
void rw_mdbx_close(rw_mdbx_ctx_t *ctx);

[[nodiscard]] int rw_mdbx_session_create(rw_mdbx_ctx_t *ctx, const rw_session_record_t *session);
[[nodiscard]] int rw_mdbx_session_lookup(rw_mdbx_ctx_t *ctx, const uint8_t session_id[RW_SESSION_ID_LEN],
                                          rw_session_record_t *out);
[[nodiscard]] int rw_mdbx_session_delete(rw_mdbx_ctx_t *ctx, const uint8_t session_id[RW_SESSION_ID_LEN]);
[[nodiscard]] int rw_mdbx_session_count(rw_mdbx_ctx_t *ctx, uint32_t *count);

typedef int (*rw_mdbx_session_iter_fn)(const rw_session_record_t *session, void *userdata);
[[nodiscard]] int rw_mdbx_session_iterate(rw_mdbx_ctx_t *ctx, rw_mdbx_session_iter_fn fn, void *userdata);

#endif // RINGWALL_STORAGE_MDBX_H
```

**Step 3: Write mdbx.c**

Key implementation details:
- `rw_mdbx_init()`: create env, set geometry (1MB-1GB), set maxreaders(128), set maxdbs(8), open with `MDBX_NOSUBDIR | MDBX_SAFE_NOSYNC | MDBX_COALESCE | MDBX_LIFORECLAIM`, permissions 0600, set HSR callback, open "sessions" sub-db in a write txn
- `rw_mdbx_session_create()`: write txn, `mdbx_put()` with `MDBX_NOOVERWRITE`, commit
- `rw_mdbx_session_lookup()`: read-only txn, `mdbx_get()`, `memcpy()` data before abort
- `rw_mdbx_session_delete()`: write txn, `mdbx_del()`, commit
- `rw_mdbx_session_count()`: read-only txn, `mdbx_dbi_stat()`, return `ms_entries`
- `rw_mdbx_session_iterate()`: read-only txn, cursor, `MDBX_NEXT` loop, memcpy each record
- HSR callback: check `kill(pid, 0)`, evict dead readers

**Step 4: Add to CMakeLists.txt**

```cmake
# Sprint 5 — libmdbx session store
pkg_check_modules(MDBX REQUIRED mdbx)

add_library(rw_mdbx STATIC src/storage/mdbx.c)
target_include_directories(rw_mdbx PUBLIC ${CMAKE_SOURCE_DIR}/src ${MDBX_INCLUDE_DIRS})
target_link_libraries(rw_mdbx PUBLIC ${MDBX_LIBRARIES})
target_link_directories(rw_mdbx PUBLIC ${MDBX_LIBRARY_DIRS})
target_compile_definitions(rw_mdbx PUBLIC _GNU_SOURCE)

rw_add_test(test_storage_mdbx tests/unit/test_storage_mdbx.c rw_mdbx)
```

**Step 5: Build and run**

```bash
cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug -R test_storage_mdbx
```

**Step 6: Commit**

```bash
git add src/storage/mdbx.h src/storage/mdbx.c tests/unit/test_storage_mdbx.c CMakeLists.txt
git commit -m "feat: libmdbx session store — CRUD, iterate, HSR callback (10 tests)"
```

---

## Task 2: SQLite control plane (src/storage/sqlite.{h,c})

**Files:**
- Create: `src/storage/sqlite.h`
- Create: `src/storage/sqlite.c`
- Create: `tests/unit/test_storage_sqlite.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests**

```c
void test_sqlite_init_and_close(void);               // lifecycle with :memory:
void test_sqlite_user_create(void);                  // insert user, return 0
void test_sqlite_user_lookup_found(void);            // create then lookup
void test_sqlite_user_lookup_not_found(void);        // missing -> -ENOENT
void test_sqlite_user_duplicate(void);               // same username -> -EEXIST
void test_sqlite_audit_log_insert(void);             // insert audit entry
void test_sqlite_audit_log_query_by_username(void);  // query audit by user
void test_sqlite_ban_check_not_banned(void);         // clean IP -> not banned
void test_sqlite_ban_add_and_check(void);            // ban IP, check -> banned
void test_sqlite_injection_prevention(void);         // evil username -> -ENOENT, not all rows
```

**Step 2: Write sqlite.h**

```c
#ifndef RINGWALL_STORAGE_SQLITE_H
#define RINGWALL_STORAGE_SQLITE_H

#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char     username[256];
    char     password_hash[256];    // Argon2id encoded
    char     groups[1024];          // JSON array
    bool     enabled;
    uint32_t failed_attempts;
    char     locked_until[32];      // ISO 8601 or empty
    bool     totp_enabled;
} iog_user_record_t;

typedef struct {
    char     event_type[32];
    char     username[256];
    char     source_ip[46];         // INET6_ADDRSTRLEN
    uint16_t source_port;
    char     auth_method[16];
    char     result[16];
    char     details[1024];         // JSON
    char     session_id[65];        // hex
} rw_audit_entry_t;

typedef struct {
    sqlite3      *db;
    sqlite3_stmt *stmt_user_lookup;
    sqlite3_stmt *stmt_user_create;
    sqlite3_stmt *stmt_audit_insert;
    sqlite3_stmt *stmt_ban_check;
    sqlite3_stmt *stmt_ban_add;
    sqlite3_stmt *stmt_failed_increment;
} iog_sqlite_ctx_t;

[[nodiscard]] int iog_sqlite_init(iog_sqlite_ctx_t *ctx, const char *path);
void iog_sqlite_close(iog_sqlite_ctx_t *ctx);

[[nodiscard]] int iog_sqlite_user_create(iog_sqlite_ctx_t *ctx, const iog_user_record_t *user);
[[nodiscard]] int iog_sqlite_user_lookup(iog_sqlite_ctx_t *ctx, const char *username, iog_user_record_t *out);

[[nodiscard]] int iog_sqlite_audit_insert(iog_sqlite_ctx_t *ctx, const rw_audit_entry_t *entry);
[[nodiscard]] int iog_sqlite_ban_check(iog_sqlite_ctx_t *ctx, const char *ip, bool *is_banned);
[[nodiscard]] int iog_sqlite_ban_add(iog_sqlite_ctx_t *ctx, const char *ip, const char *reason, int duration_minutes);

#endif // RINGWALL_STORAGE_SQLITE_H
```

**Step 3: Write sqlite.c**

Key implementation:
- `iog_sqlite_init()`: open with `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX`, apply hardening PRAGMAs (WAL, synchronous=NORMAL, secure_delete=ON, foreign_keys=ON, max_page_count=262144, mmap_size=268435456), disable extensions, disable DQS, create schema tables, prepare all statements with `SQLITE_PREPARE_PERSISTENT`
- All queries use prepared statements with parameter binding — NO `sprintf` + `sqlite3_exec` with user data
- Schema: users, audit_log, ban_list (from the guide document)
- Each function: `sqlite3_reset()` + `sqlite3_clear_bindings()` before use

**Step 4: Add to CMakeLists.txt**

```cmake
# Sprint 5 — SQLite control plane
find_package(SQLite3 REQUIRED)

add_library(iog_sqlite STATIC src/storage/sqlite.c)
target_include_directories(iog_sqlite PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(iog_sqlite PUBLIC SQLite::SQLite3)
target_compile_definitions(iog_sqlite PUBLIC _GNU_SOURCE)

rw_add_test(test_storage_sqlite tests/unit/test_storage_sqlite.c iog_sqlite)
```

**Step 5: Build and run**

**Step 6: Commit**

```bash
git add src/storage/sqlite.h src/storage/sqlite.c tests/unit/test_storage_sqlite.c CMakeLists.txt
git commit -m "feat: SQLite control plane — users, audit, bans, prepared statements (10 tests)"
```

---

## Task 3: Schema migration (src/storage/migrate.{h,c})

**Files:**
- Create: `src/storage/migrate.h`
- Create: `src/storage/migrate.c`
- Create: `tests/unit/test_storage_migrate.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests**

```c
void test_migrate_fresh_db(void);                    // empty DB -> current version
void test_migrate_idempotent(void);                  // run twice -> no error
void test_migrate_version_check(void);               // verify version after migration
void test_mdbx_format_check_fresh(void);             // fresh mdbx -> set version
void test_mdbx_format_check_current(void);           // current version -> success
```

**Step 2: Write migrate.h**

```c
#ifndef RINGWALL_STORAGE_MIGRATE_H
#define RINGWALL_STORAGE_MIGRATE_H

#include "storage/sqlite.h"
#include "storage/mdbx.h"

constexpr uint32_t IOG_SQLITE_SCHEMA_VERSION = 1;
constexpr uint32_t RW_MDBX_FORMAT_VERSION = 1;

[[nodiscard]] int iog_sqlite_migrate(sqlite3 *db);
[[nodiscard]] int rw_mdbx_check_format(rw_mdbx_ctx_t *ctx);

#endif // RINGWALL_STORAGE_MIGRATE_H
```

**Step 3: Write migrate.c**

- SQLite: schema_version table, migrations array, apply in EXCLUSIVE transaction
- libmdbx: "meta" sub-db with "format_version" key, check on open

**Step 4: Add to CMakeLists.txt, build, test, commit**

```bash
git commit -m "feat: schema migration for SQLite and libmdbx format versioning (5 tests)"
```

---

## Task 4: wolfSentry IDPS (src/security/wolfsentry.{h,c})

**Files:**
- Create: `src/security/wolfsentry.h`
- Create: `src/security/wolfsentry.c`
- Create: `tests/unit/test_wolfsentry.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests**

```c
void test_wolfsentry_init_and_close(void);           // lifecycle
void test_wolfsentry_check_allowed(void);            // unknown IP -> ACCEPT (default)
void test_wolfsentry_add_ban_rule(void);             // ban IP, check -> REJECT
void test_wolfsentry_rate_limit(void);               // rapid connections -> REJECT after threshold
void test_wolfsentry_remove_ban(void);               // ban, remove, check -> ACCEPT
void test_wolfsentry_json_config_load(void);         // load JSON config string
void test_wolfsentry_get_action_result(void);        // verify action result codes
void test_wolfsentry_connection_event(void);         // simulate connect event
```

**Step 2: Write wolfsentry.h**

```c
#ifndef RINGWALL_SECURITY_WOLFSENTRY_H
#define RINGWALL_SECURITY_WOLFSENTRY_H

#include <wolfsentry/wolfsentry.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

typedef struct {
    struct wolfsentry_context *ws_ctx;
} iog_wolfsentry_ctx_t;

typedef enum : uint8_t {
    IOG_WS_ACCEPT = 0,
    IOG_WS_REJECT = 1,
    IOG_WS_ERROR  = 2,
} iog_ws_result_t;

[[nodiscard]] int iog_wolfsentry_init(iog_wolfsentry_ctx_t *ctx);
void iog_wolfsentry_close(iog_wolfsentry_ctx_t *ctx);

[[nodiscard]] int iog_wolfsentry_load_json(iog_wolfsentry_ctx_t *ctx, const char *json, size_t json_len);

[[nodiscard]] iog_ws_result_t iog_wolfsentry_check_connection(
    iog_wolfsentry_ctx_t *ctx,
    int af,                         // AF_INET or AF_INET6
    const void *remote_addr,        // struct in_addr or in6_addr
    uint16_t remote_port,
    const void *local_addr,
    uint16_t local_port,
    int protocol);                  // IPPROTO_TCP

[[nodiscard]] int iog_wolfsentry_ban_ip(iog_wolfsentry_ctx_t *ctx, int af, const void *addr);
[[nodiscard]] int iog_wolfsentry_unban_ip(iog_wolfsentry_ctx_t *ctx, int af, const void *addr);

#endif // RINGWALL_SECURITY_WOLFSENTRY_H
```

**Step 3: Write wolfsentry.c**

Use wolfSentry C API:
- `wolfsentry_init()` with allocator config
- `wolfsentry_config_json_oneshot()` for JSON config loading
- `wolfsentry_route_event_dispatch()` for connection checking
- Route insert/delete for ban/unban

**Step 4: Add to CMakeLists.txt**

```cmake
# Sprint 5 — wolfSentry IDPS
find_path(WOLFSENTRY_INCLUDE_DIR wolfsentry/wolfsentry.h PATHS /usr/local/include)
find_library(WOLFSENTRY_LIBRARY wolfsentry PATHS /usr/local/lib /usr/local/lib64)

if(WOLFSENTRY_INCLUDE_DIR AND WOLFSENTRY_LIBRARY)
    add_library(iog_wolfsentry STATIC src/security/wolfsentry.c)
    target_include_directories(iog_wolfsentry PUBLIC ${CMAKE_SOURCE_DIR}/src ${WOLFSENTRY_INCLUDE_DIR})
    target_link_libraries(iog_wolfsentry PUBLIC ${WOLFSENTRY_LIBRARY})
    target_compile_definitions(iog_wolfsentry PUBLIC _GNU_SOURCE)

    rw_add_test(test_wolfsentry tests/unit/test_wolfsentry.c iog_wolfsentry)
endif()
```

**Step 5: Build, test, commit**

```bash
git commit -m "feat: wolfSentry IDPS — connection checking, JSON config, ban/unban (8 tests)"
```

---

## Task 5: seccomp BPF sandbox (src/security/sandbox.{h,c})

**Files:**
- Create: `src/security/sandbox.h`
- Create: `src/security/sandbox.c`
- Create: `tests/unit/test_sandbox.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests**

```c
void test_sandbox_worker_filter_build(void);         // build filter, no error
void test_sandbox_authmod_filter_build(void);        // build auth-mod filter
void test_sandbox_main_filter_build(void);           // build main filter
void test_sandbox_filter_syscall_count(void);        // verify expected syscall count
void test_sandbox_worker_blocks_execve(void);        // fork, apply, execve -> KILLED (SIGKILL/SIGSYS)
void test_sandbox_worker_allows_read(void);          // fork, apply, read -> OK
```

**Step 2: Write sandbox.h**

```c
#ifndef RINGWALL_SECURITY_SANDBOX_H
#define RINGWALL_SECURITY_SANDBOX_H

#include <stdint.h>

typedef enum : uint8_t {
    RW_SANDBOX_WORKER,      // Most restrictive: read, write, io_uring, mmap (mdbx)
    RW_SANDBOX_AUTHMOD,     // Worker + pwrite, fdatasync, flock (sqlite + mdbx write)
    RW_SANDBOX_MAIN,        // Authmod + socket, bind, listen, pidfd_spawn, signalfd
} rw_sandbox_profile_t;

[[nodiscard]] int rw_sandbox_build(rw_sandbox_profile_t profile);
[[nodiscard]] int rw_sandbox_apply(rw_sandbox_profile_t profile);

#endif // RINGWALL_SECURITY_SANDBOX_H
```

**Step 3: Write sandbox.c**

Use libseccomp:
- `seccomp_init(SCMP_ACT_KILL_PROCESS)` — default kill
- Add allowed syscalls per profile via `seccomp_rule_add()`
- Worker: read, write, readv, writev, mmap, munmap, madvise, mprotect, brk, close, futex, io_uring_enter, io_uring_setup, io_uring_register, epoll_* (for mdbx), exit_group, rt_sigreturn
- Auth-mod: worker + open, openat, fstat, fcntl, flock, pread64, pwrite64, fdatasync, socket, sendmsg, recvmsg (IPC)
- Main: auth-mod + bind, listen, accept4, pidfd_open, pidfd_send_signal, clone3, waitid, signalfd4

**Step 4: Add to CMakeLists.txt, build, test, commit**

```bash
git commit -m "feat: seccomp BPF sandbox — worker/authmod/main profiles (6 tests)"
```

---

## Task 6: Landlock filesystem isolation (src/security/landlock.{h,c})

**Files:**
- Create: `src/security/landlock.h`
- Create: `src/security/landlock.c`
- Create: `tests/unit/test_landlock.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests**

```c
void test_landlock_supported(void);                  // check kernel support (may skip)
void test_landlock_worker_ruleset_build(void);       // build worker rules (read-only mdbx)
void test_landlock_authmod_ruleset_build(void);      // auth-mod rules (rw mdbx + sqlite)
void test_landlock_worker_blocks_write(void);        // fork, apply, open(O_WRONLY) -> EACCES
void test_landlock_worker_allows_read(void);         // fork, apply, open(O_RDONLY) -> OK
```

**Step 2: Write landlock.h**

```c
#ifndef RINGWALL_SECURITY_LANDLOCK_H
#define RINGWALL_SECURITY_LANDLOCK_H

#include <stdint.h>
#include <stdbool.h>

typedef enum : uint8_t {
    RW_LANDLOCK_WORKER,     // Read-only: mdbx file, /dev/net/tun
    RW_LANDLOCK_AUTHMOD,    // Read-write: mdbx + sqlite files, /dev/urandom
} rw_landlock_profile_t;

[[nodiscard]] bool rw_landlock_supported(void);
[[nodiscard]] int rw_landlock_apply(rw_landlock_profile_t profile,
                                     const char *mdbx_path,
                                     const char *sqlite_path);

#endif // RINGWALL_SECURITY_LANDLOCK_H
```

**Step 3: Write landlock.c**

Use Landlock ABI v1+ (kernel 5.13+):
- `landlock_create_ruleset()` with `LANDLOCK_ACCESS_FS_READ_FILE` + `LANDLOCK_ACCESS_FS_WRITE_FILE`
- Worker: read-only access to mdbx path and /dev/net/tun
- Auth-mod: read-write to mdbx + sqlite paths, read-only /dev/urandom
- `landlock_restrict_self()` to enforce
- Graceful degradation if kernel too old (log warning, return 0)

**Step 4: Add to CMakeLists.txt, build, test, commit**

```bash
git commit -m "feat: Landlock filesystem isolation — worker/authmod profiles (5 tests)"
```

---

## Task 7: nftables per-user firewall (src/security/firewall.{h,c})

**Files:**
- Create: `src/security/firewall.h`
- Create: `src/security/firewall.c`
- Create: `tests/unit/test_firewall.c`
- Modify: `CMakeLists.txt`

**Step 1: Write failing tests**

```c
void test_firewall_chain_name_format(void);          // verify chain naming pattern
void test_firewall_rule_build_ipv4(void);            // build nft rule struct for IPv4
void test_firewall_rule_build_ipv6(void);            // build for IPv6
void test_firewall_batch_build(void);                // build batch message (mnl)
void test_firewall_chain_create_requires_root(void); // non-root -> TEST_IGNORE
void test_firewall_cleanup_on_disconnect(void);      // verify cleanup builds delete batch
```

Note: Actual nftables operations require CAP_NET_ADMIN. Tests that need root use `TEST_IGNORE_MESSAGE("requires CAP_NET_ADMIN")` when `geteuid() != 0`.

**Step 2: Write firewall.h**

```c
#ifndef RINGWALL_SECURITY_FIREWALL_H
#define RINGWALL_SECURITY_FIREWALL_H

#include <stdint.h>
#include <netinet/in.h>

constexpr size_t IOG_FW_CHAIN_NAME_MAX = 64;
constexpr char RW_FW_TABLE_NAME[] = "ioguard";

typedef struct {
    char     chain_name[IOG_FW_CHAIN_NAME_MAX];
    int      af;                    // AF_INET or AF_INET6
    uint32_t assigned_ipv4;         // network byte order
    struct in6_addr assigned_ipv6;
    char     username[256];
} iog_fw_session_t;

[[nodiscard]] int iog_fw_chain_name(const iog_fw_session_t *session, char *out, size_t out_size);
[[nodiscard]] int iog_fw_session_create(const iog_fw_session_t *session);
[[nodiscard]] int iog_fw_session_destroy(const iog_fw_session_t *session);

#endif // RINGWALL_SECURITY_FIREWALL_H
```

**Step 3: Write firewall.c**

Use libmnl + libnftnl:
- Build nftnl_chain for per-user chain in `ioguard` table
- Add nftnl_rule for source IP filtering
- Batch via `mnl_nlmsg_batch_start()` / `mnl_socket_sendto()`
- Chain naming: `rw_<username>_<ipv4hex>` (max 64 chars)

**Step 4: Add to CMakeLists.txt, build, test, commit**

```bash
git commit -m "feat: nftables per-user firewall chains via libmnl+libnftnl (6 tests)"
```

---

## Task 8: Fuzz targets (tests/fuzz/)

**Files:**
- Create: `tests/fuzz/fuzz_cstp.c`
- Create: `tests/fuzz/fuzz_http.c`
- Create: `tests/fuzz/fuzz_toml.c`
- Create: `tests/fuzz/fuzz_ipc.c`
- Create: `tests/fuzz/fuzz_session_key.c`
- Modify: `CMakeLists.txt`

**Step 1: Write fuzz targets**

Each target: `LLVMFuzzerTestOneInput(data, size)` entry point.

- `fuzz_cstp.c`: feed random bytes to `rw_cstp_decode()`, verify no crash
- `fuzz_http.c`: feed to llhttp parser callbacks, verify no crash
- `fuzz_toml.c`: feed to `toml_parse()`, verify no crash and proper cleanup
- `fuzz_ipc.c`: feed to protobuf-c `rw_ipc__auth_request__unpack()`, verify no crash
- `fuzz_session_key.c`: feed 32+ bytes to `rw_mdbx_session_lookup()` against empty DB

**Step 2: Update CMakeLists.txt fuzz section**

The existing fuzz section uses `file(GLOB FUZZ_SOURCES tests/fuzz/fuzz_*.c)` and auto-discovers. Just need to link the right libraries per target:

```cmake
if(BUILD_FUZZ)
    # fuzz_cstp needs rw_cstp
    target_link_libraries(fuzz_cstp PRIVATE rw_cstp)
    # fuzz_http needs llhttp
    target_link_libraries(fuzz_http PRIVATE rw_http)
    # etc.
endif()
```

Actually, the glob approach won't handle per-target linking. Replace with explicit targets:

```cmake
if(BUILD_FUZZ)
    macro(rw_add_fuzz FUZZ_NAME FUZZ_SRC)
        add_executable(${FUZZ_NAME} ${FUZZ_SRC})
        target_compile_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address)
        target_link_options(${FUZZ_NAME} PRIVATE -fsanitize=fuzzer,address)
        target_link_libraries(${FUZZ_NAME} PRIVATE ${ARGN})
        target_include_directories(${FUZZ_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)
    endmacro()

    rw_add_fuzz(fuzz_cstp tests/fuzz/fuzz_cstp.c rw_cstp)
    rw_add_fuzz(fuzz_http tests/fuzz/fuzz_http.c rw_http)
    rw_add_fuzz(fuzz_toml tests/fuzz/fuzz_toml.c rw_config)
    rw_add_fuzz(fuzz_ipc tests/fuzz/fuzz_ipc.c rw_ipc)
    if(TARGET rw_mdbx)
        rw_add_fuzz(fuzz_session_key tests/fuzz/fuzz_session_key.c rw_mdbx)
    endif()
endif()
```

**Step 3: Verify build with fuzz preset**

```bash
cmake --preset clang-fuzz && cmake --build --preset clang-fuzz
```

**Step 4: Run quick smoke test (1000 iterations each)**

```bash
for f in build/clang-fuzz/fuzz_*; do timeout 10 $f -max_total_time=5 2>&1 | tail -1; done
```

**Step 5: Commit**

```bash
git add tests/fuzz/ CMakeLists.txt
git commit -m "feat: fuzz targets — CSTP, HTTP, TOML, IPC, session key (5 targets)"
```

---

## Task 9: Storage integration test

**Files:**
- Create: `tests/integration/test_storage.c`
- Modify: `CMakeLists.txt`

**Step 1: Write integration tests**

```c
void test_session_create_mdbx_audit_sqlite(void);   // create in mdbx, audit in sqlite
void test_session_lookup_after_create(void);         // full flow: create -> lookup -> verify
void test_session_delete_and_verify(void);           // delete from mdbx, verify audit remains
void test_ban_flow_mdbx_to_sqlite(void);             // ban in sqlite, check before session create
void test_crash_recovery_mdbx(void);                 // fork, write, SIGKILL, reopen, verify committed data
```

**Step 2: Add to CMakeLists.txt**

```cmake
rw_add_test(test_storage tests/integration/test_storage.c rw_mdbx iog_sqlite rw_migrate)
```

**Step 3: Build, run, commit**

```bash
git commit -m "test: storage integration — mdbx+sqlite lifecycle, crash recovery (5 tests)"
```

---

## Task 10: Sprint finalization

**Step 1: Run full suite with sanitizers**

```bash
cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug --output-on-failure
```

**Step 2: Run clang-format**

```bash
cmake --build --preset clang-debug --target format
```

**Step 3: Verify test count**

```bash
ctest --preset clang-debug -N | tail -1
# Expected: ~55+ new tests on top of existing
```

**Step 4: Update sprint documentation**

Update `docs/tmp/agile/SPRINTS.md`: mark S5 as COMPLETED, add velocity tracking.

**Step 5: Final commit**

```bash
git add -A
git commit -m "chore: Sprint 5 complete — storage & security hardening"
```

---

## Summary

| Task | Component | New Tests |
|------|-----------|-----------|
| 1 | libmdbx session store | 10 |
| 2 | SQLite control plane | 10 |
| 3 | Schema migration | 5 |
| 4 | wolfSentry IDPS | 8 |
| 5 | seccomp BPF sandbox | 6 |
| 6 | Landlock filesystem | 5 |
| 7 | nftables per-user FW | 6 |
| 8 | Fuzz targets (5) | -- |
| 9 | Storage integration | 5 |
| 10 | Sprint finalization | -- |

**New tests: ~55. New source files: ~14 (7 .h + 7 .c). Fuzz targets: 5.**

## Critical Files

**Existing (reuse after rename):**
- `src/io/uring.h` — `iog_io_*` for I/O operations
- `src/core/session.h` — session cookie pattern
- `src/core/secmod.h` — auth-mod process (will integrate storage)
- `src/core/worker.h` — worker process (will get read-only mdbx access)

**New:**
- `src/storage/mdbx.{h,c}` — libmdbx wrapper
- `src/storage/sqlite.{h,c}` — SQLite wrapper
- `src/storage/migrate.{h,c}` — schema migration
- `src/security/wolfsentry.{h,c}` — IDPS wrapper
- `src/security/sandbox.{h,c}` — seccomp BPF
- `src/security/landlock.{h,c}` — Landlock FS
- `src/security/firewall.{h,c}` — nftables per-user

**Reference:**
- `docs/tmp/draft/guide-to-the-secure-implementation-of-libmdbx-sqlite.md` — DB security guide
- `docs/plans/2026-03-08-ringwall-rebranding-and-s5-design.md` — approved design
- `.claude/skills/wolfsentry-idps/SKILL.md` — wolfSentry API patterns
- `.claude/skills/security-coding/SKILL.md` — security coding standards

## Verification

After all tasks:
1. `ctest --preset clang-debug --output-on-failure` — all tests pass
2. `cmake --build --preset clang-debug --target format-check` — formatting clean
3. libmdbx: session CRUD works, stale reader callback cleans dead processes
4. SQLite: prepared statements prevent injection, WAL mode active
5. wolfSentry: connection check returns ACCEPT/REJECT correctly
6. seccomp: worker can't execve, auth-mod can't fork
7. Landlock: worker can't write to mdbx file
8. Fuzz: all 5 targets build and run 1K iterations clean
