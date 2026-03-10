# Rebranding (ioguard -> ioguard) + S5 Storage & Security Design

**Date**: 2026-03-08
**Status**: Approved
**Version**: 1.0

---

## 1. Execution Order

1. **Rebrand** — single atomic commit renaming ioguard -> ioguard across entire codebase
2. **S5** — Storage & Security Hardening (all new code uses `rw_*` prefix)

---

## 2. Rebranding

### 2.1 Name Mapping

| Old | New | Scope |
|-----|-----|-------|
| `ioguard` | `ioguard` | Binary, strings, paths, comments, filenames |
| `rw_` | `rw_` | Function/variable prefixes |
| `RW_` | `RW_` | Enum values, macros, constexpr |
| `RINGWALL_` | `RINGWALL_` | Include guards |
| `iogctl` | `iogctl` | CLI binary |
| `ioguard.toml` | `ioguard.toml` | Config files |
| `/etc/ioguard/` | `/etc/ioguard/` | System paths |
| `localhost/ringwall-*` | `localhost/ringwall-*` | Container images |

### 2.2 Scope

- ~55 source files (`.c`, `.h`) with ~572 occurrences of `rw_`/`ioguard`
- ~32 test files with ~739 occurrences
- CMakeLists.txt, CMakePresets.json
- deploy/podman/ (Dockerfiles, scripts, Makefile)
- All documentation (README.md, docs/, CLAUDE.md)
- .proto files (protobuf namespace)

### 2.3 Execution

Single atomic commit: `rebrand: ioguard -> ioguard`

Approach:
1. `find + sed` for pattern replacement across all files
2. `git mv` for file/directory renames
3. Verify build: `cmake --preset clang-debug && cmake --build --preset clang-debug`
4. Verify tests: `ctest --preset clang-debug`
5. Verify no remnants: `grep -r "ioguard\|IOGUARD\|rw_" --include="*.c" --include="*.h" src/ tests/`

### 2.4 GitHub Operations (gh api graphql)

- Rename repository: `dantte-lp/ioguard` -> `dantte-lp/ioguard`
- Update description, topics, homepage URL
- Close issue #11 with completion comment

---

## 3. S5: Storage & Security Hardening

### 3.1 Sprint Goal

Add persistent storage (libmdbx + SQLite), IDPS (wolfSentry), kernel sandboxing (seccomp + Landlock), per-user firewall (nftables), and fuzz testing targets.

### 3.2 Storage Architecture

**Hybrid two-DB model** (from approved guide):

```
DATA PLANE (per-packet, nanoseconds)     CONTROL PLANE (per-connection, milliseconds)
+--------------------------+             +-------------------+
|  libmdbx                 |             |  SQLite (WAL)     |
|  /var/lib/ioguard/      |             |  /var/lib/        |
|    sessions.mdbx         |             |    ringwall/      |
|                          |             |    control.db     |
|  sub-db: sessions        |             |                   |
|  sub-db: ratelimits      |             |  users            |
|  sub-db: ban_scores      |             |  audit_log        |
|  sub-db: config_cache    |             |  certificates     |
|                          |             |  groups           |
|  Writer: auth-mod        |             |  ban_list         |
|  Readers: workers (RO)   |             |  config_archive   |
+--------------------------+             +-------------------+
```

**Rules:**
- Workers NEVER open SQLite, NEVER write to libmdbx
- libmdbx is source of truth for active sessions
- Reconciliation every 5 minutes (auth-mod syncs libmdbx -> SQLite audit)
- File permissions 0600, separate filesystem with quota

### 3.3 libmdbx Configuration

- Version: 0.14.x (latest stable)
- Geometry: 1 MB min, 1 GB max, 16 MB growth, 64 MB shrink threshold
- Max readers: 128 (workers + auth-mod + main + spare)
- Max sub-databases: 8
- Flags: MDBX_NOSUBDIR | MDBX_SAFE_NOSYNC | MDBX_COALESCE | MDBX_LIFORECLAIM
- Stale reader callback (HSR) with process liveness check
- New API: `mdbx_txn_refresh()` for worker read txn reuse

### 3.4 SQLite Configuration

- WAL mode, synchronous=NORMAL, mmap 256 MB
- Hardening: secure_delete=ON, foreign_keys=ON, max_page_count=262144
- Extensions disabled, double-quoted strings disabled
- Prepared statements only (cached in auth-mod context)
- Schema versioning with forward-only migrations

### 3.5 Security Components

| Component | Purpose | Key Detail |
|-----------|---------|------------|
| wolfSentry | Connection-level IDPS | Check on TLS ClientHello, JSON config |
| seccomp BPF | Syscall allowlist | Per-process: worker vs auth-mod vs main |
| Landlock | Filesystem restriction | Workers: read-only mdbx, TUN only |
| nftables | Per-user firewall | libmnl + libnftnl, chains created/destroyed on session lifecycle |

### 3.6 Fuzz Targets

1. CSTP parser (`fuzz_cstp.c`)
2. HTTP parser (`fuzz_http.c`)
3. TOML parser (`fuzz_toml.c`)
4. Protobuf IPC (`fuzz_ipc.c`)
5. Session key lookup (`fuzz_session_key.c`)

### 3.7 Container Updates

Add to Containerfile:
- libmdbx 0.14.x (build from source)
- sqlite3-dev (system package)
- wolfSentry 1.6.3+ (build from source)

### 3.8 Deliverables

| Component | Files | Est. Tests |
|-----------|-------|------------|
| libmdbx session store | `src/storage/mdbx.{h,c}` | ~10 |
| SQLite control plane | `src/storage/sqlite.{h,c}` | ~10 |
| Schema migration | `src/storage/migrate.{h,c}` | ~5 |
| wolfSentry IDPS | `src/security/wolfsentry.{h,c}` | ~8 |
| seccomp BPF | `src/security/sandbox.{h,c}` | ~6 |
| Landlock FS | `src/security/landlock.{h,c}` | ~5 |
| nftables per-user | `src/security/firewall.{h,c}` | ~6 |
| Fuzz targets | `tests/fuzz/fuzz_*.c` (5) | -- |
| Integration tests | `tests/integration/test_storage.c` | ~5 |

**Estimated: ~55 new tests, ~10 new source file pairs, 5 fuzz targets.**

### 3.9 Definition of Done

- [ ] libmdbx session CRUD works with read-only worker access
- [ ] SQLite schema migrates, prepared statements prevent injection
- [ ] Stale reader callback cleans dead processes
- [ ] wolfSentry checks connections on TLS ClientHello
- [ ] seccomp BPF restricts worker syscalls to allowlist
- [ ] Landlock restricts worker filesystem access
- [ ] nftables per-user chains created/destroyed on session lifecycle
- [ ] All fuzz targets build and run 100K+ iterations clean under ASan
- [ ] Crash-recovery test: SIGKILL during write preserves consistency
- [ ] All tests pass under ASan+UBSan

---

## 4. Decisions Record

| Decision | Choice | Rationale |
|----------|--------|-----------|
| New name | ioguard | ring=io_uring, wall=security; no conflicts |
| Function prefix | `rw_` | Avoids WireGuard `wg` conflict |
| Rename strategy | Single atomic commit | Pre-release, no external users |
| Rename timing | Before S5 | Avoid double-renaming new S5 code |
| DB sprint | S5 | DB is infrastructure S6 auth depends on |
| DB architecture | libmdbx + SQLite hybrid | Hot path + control plane separation |
| Repo operations | gh api graphql | User preference |

---

**Author**: ioguard architecture team
**Next step**: Implementation plan (writing-plans skill)
