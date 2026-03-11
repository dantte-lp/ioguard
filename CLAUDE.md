# ioguard - Project Instructions for Claude Code

## Quick Facts

- **Language**: C23 (ISO/IEC 9899:2024), `-std=c23`, `CMAKE_C_EXTENSIONS OFF`
- **Project**: VPN server (ocserv refactoring), wolfSSL native API
- **License**: GPLv3 (wolfSSL dependency requires GPLv3)
- **Status**: Pre-release (S1-S6 done, ~150+ tests, no tags). First release: 0.1.0 (tag pending)
- **Platform**: Linux only (kernel 6.7+, glibc 2.39+)

## Build Commands

```bash
# CMake (primary build system — builds everything)
cmake --preset clang-debug              # Configure with Clang debug
cmake --build --preset clang-debug      # Build
ctest --preset clang-debug              # Run tests

# Make (legacy — TLS abstraction layer only, src/crypto/)
make BACKEND=wolfssl                    # Build with wolfSSL
make BACKEND=gnutls                     # Build with GnuTLS
make test-both                          # Test both backends

# Code quality
cmake --build --preset clang-debug --target format    # clang-format
cmake --build --preset clang-debug --target lint      # clang-tidy
cmake --build --preset clang-debug --target cppcheck  # static analysis
```

## Compiler Strategy (dual-compiler)

- **Clang 22.1.0**: Primary dev (MSan, LibFuzzer, clang-tidy, fast builds with mold)
- **GCC 15.1.1**: Validation & release (gcc-toolset-15, LTO, -fanalyzer, unique warnings)
- **System GCC 14.3.1**: Used by some library builds in container
- **Debug linker**: mold (instant linking)
- **Release linker**: GNU ld (GCC LTO) or lld (Clang ThinLTO)
- Always use `-std=c23` explicitly for both compilers

## Key Directories

```
src/crypto/         # TLS abstraction layer (wolfSSL + GnuTLS backends)
src/io/             # io_uring abstraction layer
src/network/        # Network layer (CSTP, DTLS, TUN, DPD, compression)
src/ipc/            # Inter-process communication (protobuf-c)
src/auth/           # Authentication (PAM, TOTP; RADIUS, LDAP planned S7)
src/security/       # wolfSentry, seccomp, Landlock, nftables
src/config/         # TOML configuration (tomlc99)
src/core/           # Core VPN logic (worker, session, secmod, process)
src/utils/          # Utilities (memory)
src/storage/        # libmdbx + SQLite + crypto vault
src/log/            # Structured logging — stumpless (planned S7)
src/metrics/        # Prometheus metrics — custom (planned S7)
tests/unit/         # Unity-based unit tests (test_*.c)
tests/integration/  # Integration tests (multi-component)
tests/poc/          # Proof-of-concept server/client
tests/bench/        # Performance benchmarks
tests/fuzz/         # LibFuzzer targets (Clang only, planned S5)
docs/architecture/  # Architecture documentation
docs/plans/         # Sprint plans, ROADMAP, BACKLOG
docs/rfc/           # Local RFC copies (41 files)
deploy/podman/      # Container configurations
```

## Code Conventions

**Full reference: `.claude/skills/coding-standards/SKILL.md`** — MUST be followed for all code.

- **Naming**: `iog_module_verb_noun()` functions, `iog_module_name_t` types, `IOG_MODULE_VALUE` enums/macros
- **Prefix**: `iog_` public API, `tls_` TLS layer
- **Typedef suffix**: `_t` for all types
- **Include guards**: `IOGUARD_MODULE_FILE_H` (NOT `OCSERV_*`)
- **Pointer style**: `int *ptr` (right-aligned, Linux kernel style)
- **Column limit**: 100 characters
- **Braces**: Linux kernel style (`BreakBeforeBraces: Linux`)
- **Includes order**: `_GNU_SOURCE` → matching header → C stdlib → POSIX → third-party
- **No C++ dependencies**: Pure C ecosystem only
- **Errors**: return negative errno (`-ENOMEM`, `-EINVAL`), use `goto cleanup` for multi-resource
- **Allocation**: always `sizeof(*ptr)`, never `sizeof(type)`
- **Comments**: Doxygen `@param`/`@return` in headers only; inline comments explain WHY, not WHAT
- **Tests**: Unity framework, `test_module_action_expected()`, typed assertions, cleanup resources

### C23 (mandatory)

| Use everywhere | Use when appropriate | Avoid |
|----------------|---------------------|-------|
| `nullptr`, `[[nodiscard]]`, `constexpr`, `bool` keyword, `_Static_assert` | `typeof`, `[[maybe_unused]]`, `_Atomic`, `<stdckdint.h>`, digit separators, `unreachable()` | `auto` inference, `_BitInt`, `#embed` |

## Security Requirements (MANDATORY)

- Crypto comparisons: constant-time only (`ConstantCompare` from wolfCrypt)
- Secrets: zero after use (`explicit_bzero()`)
- Error returns: `[[nodiscard]]` on all public API functions
- Hardening: `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie`
- Linker: `-Wl,-z,relro -Wl,-z,now`
- Overflow checks: `<stdckdint.h>` for size/length arithmetic
- BANNED functions: `strcpy`, `sprintf`, `gets`, `strcat`, `atoi`, `system()`, `memcmp` on secrets
- Use bounded alternatives: `snprintf`, `strnlen`, `memcpy` with size checks

## io_uring Critical Rules (MANDATORY)

- **CQE errors**: `cqe->res < 0` is `-errno` (NOT global errno). Handle EVERY CQE.
- **Send serialization**: ONE active send per TCP connection. Per-connection send queue, next send only after CQE. Kernel may reorder concurrent sends.
- **fd close ordering**: cancel pending ops → wait ALL CQE (incl `-ECANCELED`) → close fd → cleanup. NEVER close fd with in-flight ops (kernel UB).
- **SQE batching**: NEVER `io_uring_submit()` per-SQE. Batch 16-64 minimum.
- **CQE batching**: use `io_uring_for_each_cqe` + `io_uring_cq_advance`, not single wait per CQE.
- **Multishot CQE_F_MORE**: ALWAYS check. Absence = operation terminated, must re-arm.
- **Memory domains**: control plane (mimalloc per-worker heap) vs data plane (fixed-size RX/TX buffer pools).
- **WANT_READ/WANT_WRITE**: NOT errors. Normal for non-blocking TLS — arm recv/send, resume later.
- **Async logging**: NEVER block event loop on log writes. Buffer entries, batch flush via `IORING_OP_WRITEV`.
- **Anti-patterns**: no blocking in CQE handler, no mixed sync/async on same fd, no unbounded queues, no per-connection threads.
- **io_uring + seccomp**: io_uring ops bypass seccomp BPF (shared memory ring). Use `IORING_REGISTER_RESTRICTIONS` to allowlist opcodes.
- **c-ares integration**: `ares_set_socket_functions()` for io_uring-based DNS, `ares_timeout()` → `IORING_OP_TIMEOUT`.
- **protobuf-c IPC**: length-prefix framing over `SOCK_SEQPACKET`, check `len > 0` (no `has_` for bytes fields in proto3).

## Library Stack

### Core Crypto & Security
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| wolfSSL       | 5.8.4+  | TLS 1.3 / DTLS 1.2     | /wolfssl/wolfssl    |
| wolfSentry    | 1.6.2+  | IDPS / dynamic firewall | /wolfssl/wolfsentry |

### Network & I/O
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| liburing      | 2.14+   | All I/O: network, TUN, timers, signals | /axboe/liburing     |
| iohttpparser  | 0.1.0+  | HTTP parser (pull-based, zero-copy, SIMD) | — |
| llhttp        | 9.3.1+  | HTTP parser (legacy, replacing with iohttpparser in S7) | /nodejs/llhttp |
| c-ares        | 1.34+   | Async DNS resolver      | /c-ares/c-ares      |

### Data & Configuration
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| yyjson        | 0.12+   | Fast JSON (API/metrics) | /ibireme/yyjson     |
| cJSON         | 1.7.19+ | Simple JSON (config)    | -                   |
| tomlc99       | latest  | TOML config parser      | /cktan/tomlc99      |
| protobuf-c    | 1.5.2+  | IPC serialization       | /protobuf-c/protobuf-c |

### Storage (S5)
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| libmdbx       | 0.14+   | Session store (hot path, ns latency) | /erthink/libmdbx |
| SQLite        | 3.52.0+ | Control plane (users, audit, WAL)    | /sqlite/sqlite   |

### System & Memory
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| mimalloc      | 3.2.8+  | Memory allocator (MI_SECURE) | -              |
| LZ4           | 1.10+   | Compression             | -                   |
| libseccomp    | 2.5+    | Syscall sandbox         | -                   |

### Logging & Monitoring
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| stumpless     | 2.2.0+  | Structured logging (RFC 5424) | /goatshriek/stumpless |
| (custom)      | -       | Prometheus metrics (text exposition) | -         |

### Authentication
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| PAM           | system  | Pluggable auth          | -                   |
| radcli        | 1.4+    | RADIUS client           | -                   |
| liboath       | 2.6+    | TOTP/HOTP               | -                   |
| libldap       | 2.6+    | LDAP authentication     | -                   |

### Networking & Firewall
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| libmnl        | 1.0.5+  | Netlink minimal         | -                   |
| libnftnl      | 1.3.1+  | nftables rules          | -                   |
| libnl3        | 3.9+    | Netlink protocol        | -                   |

## Storage Hardening Rules (MANDATORY)

### libmdbx
- Geometry: 1MB lower, 1GB upper, 16MB growth, 64MB shrink
- Max readers: 128, max DBs: 8
- HSR callback: check `kill(pid, 0)`, evict dead readers
- Workers: **read-only transactions ONLY** (never write from worker process)
- NEVER store `data.iov_base` pointer after `mdbx_txn_abort()` — always `memcpy` first
- File permissions: 0600 (owner read/write only)

### SQLite
- WAL mode mandatory: `PRAGMA journal_mode=WAL`
- Hardening PRAGMAs: `synchronous=NORMAL`, `secure_delete=ON`, `foreign_keys=ON`
- `max_page_count=262144` (1GB limit), `mmap_size=268435456` (256MB)
- **Prepared statements ONLY** with `SQLITE_PREPARE_PERSISTENT` — NO `sprintf` + `sqlite3_exec`
- Disable: `sqlite3_enable_load_extension(db, 0)`, `sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DDL, 0)`
- Each function: `sqlite3_reset()` + `sqlite3_clear_bindings()` before reuse

## Testing Rules

- All new code MUST have unit tests (Unity framework)
- Test files: `tests/unit/test_<module>.c`
- Run both backends before committing
- Sanitizers in CI: ASan+UBSan (every commit), MSan (Clang, every commit), TSan (before merge)
- Fuzzing: LibFuzzer targets in `tests/fuzz/` (Clang only)
- Coverage target: >= 80%

## Post-Sprint Quality Pipeline (MANDATORY)

After completing each sprint, run the **full quality pipeline** inside the container before considering the sprint done. Single command via `scripts/quality.sh` (6 stages: build → tests → format → cppcheck → PVS-Studio → CodeChecker).

```bash
podman run --rm --security-opt seccomp=unconfined \
  -v /opt/projects/repositories/ioguard:/workspace:Z \
  localhost/ioguard-dev:latest bash -c "cd /workspace && ./scripts/quality.sh"
```

**Rules:**
- Sprint code (new/modified files) MUST have **zero** PVS errors/warnings and **zero** CodeChecker HIGH/MEDIUM findings
- Pre-existing findings in other files: track but don't block sprint
- PVS-Studio license: loaded from `.env` file (`PVS_NAME` / `PVS_KEY`), NEVER commit credentials
- `.env` is in `.gitignore`, `.env.example` shows required variables

## MCP Documentation (context7)

Use context7 to fetch up-to-date documentation:
- wolfSSL API: `/wolfssl/wolfssl`
- wolfSentry IDPS: `/wolfssl/wolfsentry`
- liburing io_uring: `/axboe/liburing`
- iohttpparser HTTP: local at `/opt/projects/repositories/iohttpparser`
- llhttp HTTP parser (legacy): `/nodejs/llhttp`
- yyjson JSON: `/ibireme/yyjson`
- c-ares DNS: `/c-ares/c-ares`
- protobuf-c IPC: `/protobuf-c/protobuf-c`
- tomlc99 TOML config: `/cktan/tomlc99`
- stumpless logging: `/goatshriek/stumpless`
- libmdbx storage: `/erthink/libmdbx`
- libmdbx docs (ru): `/websites/libmdbx_dqdkfa_ru`
- SQLite storage: `/sqlite/sqlite`
- CMake build: `/websites/cmake_cmake_help`

## RFC References

Local copies in `docs/rfc/` — see `docs/rfc/README.md` for full index.

**Core (must-read for TLS/DTLS implementation):**
- RFC 8446 — TLS 1.3
- RFC 9147 — DTLS 1.3
- RFC 6347 — DTLS 1.2

**Security best practices:**
- RFC 9325 / RFC 7525 — BCP 195: Secure Use of TLS and DTLS
- RFC 7457 — Known Attacks on TLS and DTLS
- RFC 9151 — CNSA Suite Profile for TLS/DTLS

**Key extensions:**
- RFC 7366 — Encrypt-then-MAC
- RFC 7905 — ChaCha20-Poly1305 Cipher Suites
- RFC 8449 — Record Size Limit Extension
- RFC 8879 — TLS Certificate Compression
- RFC 9146 — Connection Identifier for DTLS 1.2
- RFC 9848/9849 — Deprecating obsolete key exchanges and cipher suites

## Authentication Tiers

| Tier | Methods | Sprint |
|------|---------|--------|
| **Tier 1 (MVP)** | mTLS/X.509, Username/Password (PAM), RADIUS (RadSec), TOTP, local DB | S5-S6 |
| **Tier 2** | LDAP/Active Directory, Kerberos/GSSAPI, SAML 2.0 | S7+ |
| **Tier 3** | OAuth 2.0/OIDC, WebAuthn/FIDO2 | Future |

- Auth-mod process handles ALL authentication (privilege separation)
- Circuit breaker pattern for backend failover (threshold 5 failures, half-open after 30s)
- Multi-factor via XML form exchange (AggAuth protocol)
- Session cookies: HMAC-SHA256 signed, 32-byte random, configurable TTL

## Architecture Decisions (DO NOT CHANGE)

- Keep protobuf-c for IPC (do not replace)
- Use wolfSSL Native API (not OpenSSL compat layer)
- Pure C libraries only (no C++ dependencies)
- Event-driven with io_uring (liburing) for ALL I/O — no libuv
- Linux only — kernel 6.7+, glibc 2.39+ (no BSD)
- pidfd_spawn + IORING_OP_WAITID for process management
- TOML for static config, JSON for wolfSentry rules and REST API
- stumpless for structured logging (RFC 5424)
- iohttpparser for VPN HTTP parsing (not llhttp)
- Dual TLS backend build (wolfSSL primary, GnuTLS fallback)
- mimalloc for memory (per-worker heaps, MI_SECURE=ON)
- Hybrid storage: libmdbx (sessions, hot path) + SQLite WAL (users, audit)
- Custom Prometheus metrics (~500-800 LOC, no cmetrics)

## HTTP Traffic Routing

### Dual-Port Architecture (production)
- **Port 443/TCP+UDP**: VPN clients (CSTP over TLS, DTLS), public-facing
- **Port 8443/TCP**: Admin SPA + REST API, management VLAN only, mTLS required

### Single-Port Classification (dev/MVP)
- VPN client detection: `X-Aggregate-Auth` header, `User-Agent` matching (AnyConnect, OpenConnect)
- Browser detection: standard `Accept: text/html` + no VPN headers
- Route: VPN clients → tunnel handler, browsers → admin SPA/API

### Graceful Shutdown
- SIGTERM → stop accepting → drain active VPN tunnels → close TUN devices → cleanup
- Drain timeout: 30s (configurable), force-close after timeout
- Send CSTP DISCONNECT to all connected clients during drain
- Auth-mod: finish pending auth requests, close storage handles
- SIGQUIT → immediate shutdown (skip drain)

## Git Workflow

- Branch naming: `feature/US-XXX-description`, `fix/issue-description`
- Commit style: conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)
- All commits must pass: clang-format, clang-tidy, unit tests
- Never commit `.deployment-credentials` or secrets
- **NEVER mention "Claude" or any AI assistant in commit messages, comments, or code** — no `Co-Authored-By` AI lines

## Skills Reference

See `.claude/skills/` for detailed guidance on:
- **`coding-standards/`** — File structure, naming, comments, errors, memory, tests (MANDATORY)
- **`io-uring-patterns/`** — SQE/CQE patterns, provided buffers, multishot, error handling, send serialization, fd lifecycle, backpressure, memory domains, anti-patterns (MANDATORY for src/io/, src/network/)
- `c23-standards/` — C23 features, conventions, compiler compatibility
- `security-coding/` — constant-time, zeroing, input validation, seccomp, io_uring ring hardening, database security, session cookies, plugin sandboxing
- `storage-patterns/` — libmdbx + SQLite hybrid storage, transaction patterns, anti-patterns (MANDATORY for src/storage/)
- `wolfssl-api/` — TLS/DTLS API patterns, FIPS constraints, buffer-based I/O with io_uring
- `ocprotocol/` — OpenConnect protocol, Cisco compatibility, cookies, traffic classification, graceful shutdown
- `wolfsentry-idps/` — IDPS firewall, rate limiting, connection tracking, nftables
- `rfc-reference/` — RFC index by category: TLS/DTLS, auth, PKI, crypto, DNS, transport, NAT (41+ RFCs in `docs/rfc/`)
