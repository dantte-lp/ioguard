---
name: storage-patterns
description: Use when implementing storage operations — libmdbx for sessions (hot path, ns latency), SQLite for users/audit (control plane). MANDATORY for src/storage/.
---

# Storage Patterns — Hybrid libmdbx + SQLite

## Architecture Overview

Ioguard uses a hybrid storage model:

- **libmdbx** — VPN session store (hot path). Nanosecond read latency, memory-mapped,
  zero-copy reads within a transaction. Keyed by 32-byte session ID.
- **SQLite WAL** — Control plane (users, audit log, IP ban list). Millisecond latency,
  SQL queries, ACID with WAL journaling.

### Process Access Rules

| Process   | libmdbx          | SQLite           |
|-----------|-------------------|-------------------|
| auth-mod  | read/write        | read/write        |
| Worker    | read-only ONLY    | NO ACCESS         |
| Main      | no direct access  | no direct access  |

Workers MUST NEVER write to libmdbx or open SQLite. All mutations go through auth-mod
via IPC (protobuf-c over `SOCK_SEQPACKET`).

## libmdbx Patterns

### Environment Setup

```c
constexpr size_t IOG_MDBX_SIZE_LOWER      = 1 * 1024 * 1024;   /* 1 MB */
constexpr size_t IOG_MDBX_SIZE_UPPER      = 1024 * 1024 * 1024; /* 1 GB */
constexpr size_t IOG_MDBX_GROWTH_STEP     = 16 * 1024 * 1024;   /* 16 MB */
constexpr size_t IOG_MDBX_SHRINK_THRESHOLD = 64 * 1024 * 1024;  /* 64 MB */
constexpr size_t IOG_MDBX_MAX_READERS     = 128;
constexpr size_t IOG_MDBX_MAX_DBS         = 8;
```

Open with `MDBX_NOSUBDIR | MDBX_SAFE_NOSYNC | MDBX_LIFORECLAIM`, mode `0600`.

### HSR (Handle Stale Readers) Callback

Register via `mdbx_env_set_hsr()`. The callback checks if a reader's process is alive:

```c
static int hsr_callback(const MDBX_env *env, const MDBX_txn *txn,
                         mdbx_pid_t pid, mdbx_tid_t tid,
                         uint64_t laggard, unsigned gap,
                         size_t space, int retry)
{
    if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) {
        return 2; /* process dead — reset reader slot */
    }
    return 0; /* still alive */
}
```

### Read Transaction (Worker — read-only)

```c
int iog_mdbx_session_lookup(iog_mdbx_ctx_t *ctx,
                            const uint8_t session_id[IOG_SESSION_ID_LEN],
                            iog_session_record_t *out)
{
    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(ctx->env, nullptr, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS) return mdbx_rc_to_errno(rc);

    MDBX_val key = {.iov_base = (void *)session_id, .iov_len = IOG_SESSION_ID_LEN};
    MDBX_val data = {0};

    rc = mdbx_get(txn, ctx->dbi_sessions, &key, &data);
    if (rc == MDBX_SUCCESS) {
        memcpy(out, data.iov_base, sizeof(*out));  /* CRITICAL: copy before abort */
    }

    int err = mdbx_rc_to_errno(rc);
    mdbx_txn_abort(txn);  /* data.iov_base is INVALID after this line */
    return err;
}
```

### Write Transaction (auth-mod only)

```c
int iog_mdbx_session_create(iog_mdbx_ctx_t *ctx,
                             const iog_session_record_t *session)
{
    MDBX_txn *txn = nullptr;
    int rc = mdbx_txn_begin(ctx->env, nullptr, 0, &txn);
    if (rc != MDBX_SUCCESS) return mdbx_rc_to_errno(rc);

    MDBX_val key = {.iov_base = (void *)session->session_id,
                     .iov_len = IOG_SESSION_ID_LEN};
    MDBX_val data = {.iov_base = (void *)session,
                      .iov_len = sizeof(*session)};

    rc = mdbx_put(txn, ctx->dbi_sessions, &key, &data, MDBX_NOOVERWRITE);
    if (rc != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return mdbx_rc_to_errno(rc);
    }

    rc = mdbx_txn_commit(txn);
    return mdbx_rc_to_errno(rc);
}
```

### Key Design

- **Key**: 32-byte `session_id` (raw bytes, NOT hex string)
- **Value**: `iog_session_record_t` struct stored as flat bytes
- **Sub-database**: named `"sessions"`, opened with `MDBX_CREATE` in init

### Error Mapping

Map MDBX return codes to negative errno for the rest of the codebase:
`MDBX_SUCCESS` to `0`, `MDBX_NOTFOUND` to `-ENOENT`, `MDBX_KEYEXIST` to `-EEXIST`,
`MDBX_MAP_FULL` to `-ENOSPC`, `MDBX_EINVAL` to `-EINVAL`, `MDBX_EACCESS` to `-EACCES`,
`MDBX_ENOMEM` to `-ENOMEM`, default to `-EIO`.

## SQLite Patterns

### Initialization PRAGMAs

Applied in `iog_sqlite_init()` after opening the database:

```c
/* Hardening config — disable before PRAGMAs */
sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DML, 0, nullptr);
sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DDL, 0, nullptr);
sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);

/* PRAGMAs */
"PRAGMA journal_mode=WAL"
"PRAGMA synchronous=NORMAL"
"PRAGMA secure_delete=ON"
"PRAGMA foreign_keys=ON"
"PRAGMA max_page_count=262144"   /* 1 GB limit */
"PRAGMA mmap_size=268435456"     /* 256 MB */
"PRAGMA trusted_schema=OFF"
"PRAGMA cell_size_check=ON"
```

Open flags: `SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX`.
For multi-threaded auth-mod, use `SQLITE_OPEN_FULLMUTEX` with one connection per thread.

### Prepared Statement Lifecycle

Always use `SQLITE_PREPARE_PERSISTENT` for long-lived statements:

```c
/* Prepare once at init */
sqlite3_prepare_v3(db, sql, -1, SQLITE_PREPARE_PERSISTENT, &stmt, nullptr);

/* Each use: reset, clear, bind, step, read */
sqlite3_reset(stmt);
sqlite3_clear_bindings(stmt);
sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

int rc = sqlite3_step(stmt);
if (rc == SQLITE_ROW) {
    /* extract columns */
} else if (rc == SQLITE_DONE) {
    /* no results */
}

/* Finalize only at shutdown */
sqlite3_finalize(stmt);
```

### Schema

**users** — username (PK), password_hash, groups (JSON), enabled, failed_attempts,
locked_until, totp_enabled.

**audit_log** — id (auto), event_type, username, source_ip, source_port,
auth_method, result, details (JSON), session_id, created_at (auto datetime).

**ban_list** — ip (PK), reason, banned_at (auto), expires_at.

### String Safety

Use a bounded copy helper for all `sqlite3_column_text()` results:

```c
static void safe_copy(char *dst, size_t dst_sz, const char *src)
{
    if (src == nullptr) { dst[0] = '\0'; return; }
    size_t len = strlen(src);
    if (len >= dst_sz) len = dst_sz - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}
```

## Anti-Patterns

- **NEVER** use `sqlite3_exec()` with string-formatted SQL (injection risk).
  Always use prepared statements with `sqlite3_bind_*()`.
- **NEVER** write to libmdbx from a worker process. Workers get read-only
  transactions via `MDBX_TXN_RDONLY`. All writes go through auth-mod.
- **NEVER** hold a libmdbx read transaction across an io_uring CQE boundary.
  Long-lived read txns block garbage collection for all writers.
  Pattern: begin txn, get, memcpy, abort txn — all synchronous.
- **NEVER** store or dereference `data.iov_base` after `mdbx_txn_abort()`.
  The pointer becomes invalid immediately. Always `memcpy` before abort.
- **NEVER** enable SQLite extension loading in production
  (`SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` must be 0).
- **NEVER** use `MDBX_WRITEMAP` in production — risk of corrupting the
  database on process crash.
- **NEVER** pass `sizeof(iog_session_record_t)` — always use `sizeof(*ptr)`.

## Testing Patterns

### libmdbx Tests

```c
void test_mdbx_session_create_and_lookup(void)
{
    iog_mdbx_ctx_t ctx;
    char path[] = "/tmp/iog_test_mdbx_XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    unlink(path);  /* MDBX creates its own file */

    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_init(&ctx, path));

    iog_session_record_t session = {0};
    memset(session.session_id, 0xAA, IOG_SESSION_ID_LEN);
    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_create(&ctx, &session));

    iog_session_record_t out = {0};
    TEST_ASSERT_EQUAL_INT(0, iog_mdbx_session_lookup(&ctx, session.session_id, &out));
    TEST_ASSERT_EQUAL_MEMORY(session.session_id, out.session_id, IOG_SESSION_ID_LEN);

    iog_mdbx_close(&ctx);
    unlink(path);
    /* Also remove lock file */
    char lock[PATH_MAX];
    snprintf(lock, sizeof(lock), "%s-lck", path);
    unlink(lock);
}
```

### SQLite Tests

```c
void test_sqlite_wal_mode_enabled(void)
{
    iog_sqlite_ctx_t ctx;
    TEST_ASSERT_EQUAL_INT(0, iog_sqlite_init(&ctx, ":memory:"));

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(ctx.db, "PRAGMA journal_mode", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    const char *mode = (const char *)sqlite3_column_text(stmt, 0);
    /* In-memory databases use "memory" mode, on-disk uses "wal" */
    TEST_ASSERT_NOT_NULL(mode);
    sqlite3_finalize(stmt);

    iog_sqlite_close(&ctx);
}
```

### Testing Checklist

- Use temporary paths (`mkstemp` or `:memory:`) for all test databases
- Clean up files with `unlink()` after each test (including `-lck` for libmdbx)
- Test HSR callback with mock dead PIDs (`kill(pid, 0)` returning `ESRCH`)
- Verify WAL mode is active after `iog_sqlite_init()`
- Test duplicate key rejection (`-EEXIST` from both stores)
- Test not-found returns (`-ENOENT` from both stores)
- Test nullptr/invalid input returns (`-EINVAL`)
