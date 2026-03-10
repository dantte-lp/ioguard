---
name: security-coding
description: Use when writing any security-sensitive code — crypto operations, input validation, memory handling, privilege management, seccomp filters, network parsing. MANDATORY for all VPN data path code.
---

# Security-Critical Coding for ioguard

## This is a VPN server handling untrusted network data. Every function is attack surface.

## Constant-Time Operations

ALL comparisons of secrets, tokens, cookies, MACs MUST be constant-time:

```c
// CORRECT: constant-time comparison
#include <wolfssl/wolfcrypt/misc.h>

bool rw_verify_cookie(const uint8_t *a, const uint8_t *b, size_t len) {
    return ConstantCompare(a, b, (int)len) == 0;
}

// WRONG: timing side-channel
bool rw_verify_cookie_INSECURE(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;  // NEVER for secrets
}
```

## Secret Zeroing

ALL sensitive data MUST be zeroed before freeing:

```c
#include <wolfssl/wolfcrypt/misc.h>

void rw_free_session(rw_session_t *sess) {
    if (sess == nullptr) return;
    ForceZero(sess->master_secret, sizeof(sess->master_secret));
    ForceZero(sess->cookie, sizeof(sess->cookie));
    ForceZero(sess, sizeof(*sess));
    mi_free(sess);
}
```

## Input Validation (Network Boundary)

ALL data from network is untrusted. Validate BEFORE processing:

```c
[[nodiscard]]
static int rw_parse_packet(const uint8_t *data, size_t len) {
    // Check minimum length
    if (len < RW_MIN_PACKET_SIZE) return RW_ERR_TOO_SHORT;
    if (len > RW_MAX_PACKET_SIZE) return RW_ERR_TOO_LONG;

    // Validate header fields with bounds
    uint16_t payload_len = ntohs(*(uint16_t *)(data + 2));
    if (payload_len > len - RW_HEADER_SIZE) return RW_ERR_INVALID;

    // Safe to process
    return RW_OK;
}
```

## Banned Functions

| Banned | Replacement | Reason |
|--------|-------------|--------|
| `strcpy` | `snprintf` or `memcpy` with size | Buffer overflow |
| `strcat` | `snprintf` | Buffer overflow |
| `sprintf` | `snprintf` | Buffer overflow |
| `gets` | `fgets` | Buffer overflow |
| `atoi` | `strtol` with error check | No error detection |
| `system()` | `posix_spawn` | Command injection |
| `memcmp` on secrets | `ConstantCompare` | Timing attack |

## Integer Overflow Protection (C23)

```c
#include <stdckdint.h>

[[nodiscard]]
static int rw_safe_add(size_t a, size_t b, size_t *result) {
    if (ckd_add(result, a, b)) {
        return RW_ERR_OVERFLOW;
    }
    return RW_OK;
}
```

## Privilege Separation

```c
// Drop privileges after binding to port 443
#include <sys/capability.h>

static void rw_drop_privileges(void) {
    // Set UID/GID to unprivileged user
    setgid(rw_config.gid);
    setuid(rw_config.uid);

    // Drop all capabilities except needed ones
    cap_t caps = cap_init();
    cap_set_proc(caps);
    cap_free(caps);
}
```

## Seccomp Filter (Worker Process)

Worker processes MUST have restricted syscalls:

```c
#include <seccomp.h>

static int rw_setup_seccomp(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

    // Allow only necessary syscalls
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    // io_uring_enter for data plane
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(io_uring_enter), 0);

    return seccomp_load(ctx);
}
```

## io_uring Ring Hardening (CRITICAL)

**WARNING:** io_uring operations bypass seccomp BPF filters — they use shared memory
ring, not direct syscalls. A compromised parser can issue ANY kernel operation through
the ring fd. MUST use `IORING_REGISTER_RESTRICTIONS` to allowlist opcodes.

```c
// After ring creation + buffer registration, BEFORE accepting connections:
struct io_uring_restriction restrictions[] = {
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_RECV },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_SEND },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_ACCEPT },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_READ },     // TUN
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_WRITE },    // TUN
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_TIMEOUT },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_LINK_TIMEOUT },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_CANCEL },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_CLOSE },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_MSG_RING },
    { .opcode = IORING_RESTRICTION_SQE_OP, .sqe_op = IORING_OP_NOP },
};
io_uring_register_restrictions(&ring, restrictions, ARRAY_SIZE(restrictions));
io_uring_enable_rings(&ring);
```

**sysctl hardening:** `io_uring_disabled=1` restricts ring creation to `CAP_SYS_ADMIN`
or `io_uring_group`. Document this in deployment guide.
```

## Memory Allocator Security

mimalloc with MI_SECURE=ON provides:
- Guard pages between allocations
- Randomized allocation addresses
- Encrypted free lists
- Double-free detection

```c
// Per-worker heap (isolated)
mi_heap_t *heap = mi_heap_new();
void *ptr = mi_heap_malloc(heap, size);
// ...
mi_heap_destroy(heap);  // Frees all allocations at once
```

## Checklist for Every New Function

- [ ] `[[nodiscard]]` on functions returning error codes
- [ ] Validate all input parameters (especially sizes)
- [ ] No buffer overflows possible (bounds-checked)
- [ ] No integer overflows (use `<stdckdint.h>`)
- [ ] Secrets zeroed before freeing
- [ ] No use of banned functions
- [ ] Error paths don't leak memory
- [ ] Timing-safe comparisons for secrets

## Database Security (libmdbx + SQLite)

All database access follows the principle of least privilege and defense-in-depth.

### libmdbx Rules

- **Read-only transactions in workers**, write transactions only in auth-mod process
- **NEVER store `data.iov_base` after `mdbx_txn_abort()`** — the pointer is invalidated. Always `memcpy` first
- Geometry: lower=1MB, upper=1GB, growth=16MB, shrink=64MB
- HSR (Handle-Slow-Readers) callback: check `kill(pid, 0)` to evict dead readers
- File permissions: `0600` (owner read/write only)

### SQLite Rules

- WAL mode mandatory: `PRAGMA journal_mode=WAL`
- Hardening PRAGMAs: `synchronous=NORMAL`, `secure_delete=ON`, `foreign_keys=ON`, `max_page_count=262144`, `mmap_size=268435456`
- **Prepared statements ONLY** with `SQLITE_PREPARE_PERSISTENT` — NO `sprintf` + `sqlite3_exec`
- `sqlite3_reset()` + `sqlite3_clear_bindings()` before reuse
- Disable extensions and double-quoted strings:
  - `sqlite3_enable_load_extension(db, 0)`
  - `sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DDL, 0, nullptr)`

```c
// Safe prepared statement usage pattern
[[nodiscard]]
static int rw_db_insert_user(sqlite3 *db, sqlite3_stmt *stmt,
                             const char *username, int group_id) {
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK)
        return -EIO;
    if (sqlite3_bind_int(stmt, 2, group_id) != SQLITE_OK)
        return -EIO;

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return -EIO;
    }
    return 0;
}

// Statement preparation (once at startup):
// sqlite3_prepare_v3(db,
//     "INSERT INTO users (username, group_id) VALUES (?1, ?2)",
//     -1, SQLITE_PREPARE_PERSISTENT, &stmt, nullptr);
```

## Session Cookie Security

Session cookies authenticate VPN clients after the initial TLS handshake.

```c
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/misc.h>

#define RW_COOKIE_LEN    32
#define RW_HMAC_LEN      32

[[nodiscard]]
static int rw_cookie_generate(WC_RNG *rng, const uint8_t *server_key,
                              size_t key_len, uint8_t *cookie_out,
                              uint8_t *hmac_out) {
    // 32 bytes of random from wolfCrypt RNG
    if (wc_RNG_GenerateBlock(rng, cookie_out, RW_COOKIE_LEN) != 0)
        return -EIO;

    // HMAC-SHA256 sign with server secret
    Hmac hmac;
    if (wc_HmacSetKey(&hmac, WC_SHA256, server_key, (word32)key_len) != 0)
        goto fail;
    if (wc_HmacUpdate(&hmac, cookie_out, RW_COOKIE_LEN) != 0)
        goto fail;
    if (wc_HmacFinal(&hmac, hmac_out) != 0)
        goto fail;

    ForceZero(&hmac, sizeof(hmac));
    return 0;

fail:
    ForceZero(&hmac, sizeof(hmac));
    ForceZero(cookie_out, RW_COOKIE_LEN);
    return -EIO;
}
```

**Key rules:**
- 32 bytes random from `wc_RNG_GenerateBlock` (not `rand()` or `/dev/urandom` directly)
- HMAC-SHA256 signed with long-lived server secret key
- Constant-time validation via `ConstantCompare` — never `memcmp`
- Configurable TTL, validated on every request (reject expired cookies)
- `ForceZero` all cookie material after session teardown

## dlopen Plugin Security

Plugins are loaded early and locked down before the worker event loop starts.

```c
#include <dlfcn.h>
#include <seccomp.h>

[[nodiscard]]
static int rw_plugin_load_and_lock(const char *path, void **handle_out) {
    // 1. Load plugin BEFORE seccomp is active
    void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (h == nullptr) return -ENOENT;
    *handle_out = h;

    // 2. After all plugins loaded, deny new executable mappings
    //    (add to existing seccomp filter before seccomp_load)
    //    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
    //        SCMP_SYS(mmap), 1,
    //        SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC));
    //    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
    //        SCMP_SYS(mprotect), 1,
    //        SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC));

    return 0;
}
```

**Key rules:**
- Load ALL plugins BEFORE enabling seccomp (`dlopen` needs `mmap(PROT_EXEC)`)
- Use `RTLD_LOCAL` for namespace isolation — plugin symbols don't leak
- After loading: deny `mmap(PROT_EXEC)` and `mprotect(PROT_EXEC)` via seccomp
- Plugin directory should be on a `noexec` mount (defense-in-depth)
- For untrusted code: `fork` + seccomp sandbox, NEVER in-process `dlopen`
