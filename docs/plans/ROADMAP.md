# Roadmap

Sprint-based development plan. Each sprint ~2 weeks.

## Status

| Sprint | Name | Status | Tests | Key Deliverables |
|--------|------|--------|-------|------------------|
| S1 | Foundation | **DONE** | 33 | io_uring, IPC, TOML config, pidfd_spawn, mimalloc |
| S2 | TLS & Auth | **DONE** | — | wolfSSL TLS 1.3, PAM, sessions, llhttp, XML auth |
| S3 | VPN Tunnel | **DONE** | 42 | CSTP framing, TUN, DPD, worker process |
| S4 | DTLS & Compression | **DONE** | 68 | DTLS 1.2, LZ4/LZS, channel switching |
| S5 | Storage & Security | **DONE** | 100+ | libmdbx, SQLite WAL, wolfSentry, seccomp, Landlock, nftables, 5 fuzz targets |
| S6 | Integration + TOTP MFA | **DONE** | 150+ | Main process, worker loop, IPAM, split DNS, TOTP/vault, MFA pipeline, security audit |
| S7 | Auth Backends + Observability | NEXT | ~60 | RADIUS, LDAP, cert auth, iohttpparser, stumpless, Prometheus, tech debt |
| S8 | Admin & iohttp | PLANNED | ~45 | REST API (iohttp), iogctl CLI, admin SPA, config reload |
| S9 | Production Hardening | PLANNED | ~35 | Mini CA, E2E tests, benchmarks, split tunnel enforcement, docs |

**Current:** S1-S6 done (~150+ tests). S7 next.
**Target at 1.0.0:** ~350+ tests, 5+ fuzz targets, E2E validated.

## Version Plan (SemVer)

All work is `[Unreleased]` until first tag.

| Version | Sprint | Criteria |
|---------|--------|----------|
| 0.1.0 | S6 | Working VPN tunnel + IPAM + split DNS + TOTP MFA |
| 0.2.0 | S7 | Multi-backend auth + observability + HTTP parser migration |
| 0.3.0 | S8 | Admin API (iohttp) + CLI |
| 1.0.0 | S9 | E2E tested, benchmarked, documented |

## Sprint Details

### S5: Storage & Security (DONE)

**Goal:** Persistent storage and kernel-level security hardening.

**Storage:**
- libmdbx — session store (per-packet lookups, ns latency)
- SQLite WAL — users, audit, bans (control plane, ms latency)
- Schema migration system (versioned, idempotent)

**Security:**
- wolfSentry IDPS — rate limiting, dynamic firewall rules
- seccomp BPF — syscall sandbox for workers
- Landlock — filesystem restriction for workers
- nftables — per-user firewall chains (libmnl + libnftnl)

**Fuzz targets (5):** CSTP, HTTP, TOML, IPC, session key

**Plan:** `docs/plans/2026-03-08-sprint-5-storage-security.md`

### S6: Integration + TOTP MFA (DONE)

**Goal:** Wire S1-S5 into a working VPN server. Add IPAM, split DNS, and TOTP multi-factor authentication.

**Vertical integration:**
- Main process bootstrap (config → fork auth-mod + workers → signal loop)
- Worker io_uring event loop (accept fd via SCM_RIGHTS → TLS → CSTP → TUN)
- Auth-mod storage integration (libmdbx sessions, SQLite audit)
- Security module activation (seccomp, Landlock, wolfSentry, nftables per-session)
- Per-connection TLS handshake via tls_abstract API
- CSTP data path + DPD/keepalive timers via io_uring timeouts
- Graceful shutdown (DISCONNECT → drain → cleanup)

**IPAM — IP address pool management:**
- `src/network/ipam.{h,c}` — dual-stack pool allocator (bitmap, O(1) alloc/free)
- Collision detection at startup via `getifaddrs()`
- RADIUS override support (`Framed-IP-Address`, `Framed-IPv6-Address`)

**Split DNS:**
- `src/network/dns.{h,c}` — three modes (split, tunnel-all, standard)
- Per-group domain lists, X-CSTP headers

**TOTP MFA (RFC 6238):**
- `src/auth/totp.{h,c}` — HMAC-SHA1 via wolfCrypt, Base32 codec, secret generation
- `src/storage/vault.{h,c}` — AES-256-GCM field encryption for SQLite TOTP secrets
- MFA challenge-response pipeline in secmod (PAM → requires_totp → OTP validation)
- TOTP config fields in `[auth]` section, vault key path in `[storage]`

**Security audit (P0-P2):**
- wolfSSL include order fix (unblocked 17 tests)
- explicit_bzero for OTP, session cookie, base32 buffers
- Constant-time session ID comparison
- Overflow checks (stdckdint.h) in base32, hex encoding, string concat
- sizeof(*ptr) fixes, [[nodiscard]], C23 stdbool.h cleanup

**Plans:** `docs/plans/2026-03-08-sprint-6-vertical-integration.md`

### S7: Auth Backends + Observability (NEXT)

**Goal:** Multi-backend authentication, production observability, HTTP parser migration, and tech debt cleanup.

**Authentication backends:**
- RADIUS client (radcli) — Access-Request/Accept/Reject, Cisco VSAs, Framed-IP integration with IPAM
- LDAP (libldap) — bind + search, group membership, StartTLS
- Certificate authentication — client certs via wolfSSL, Microsoft AD template filtering (OID 1.3.6.1.4.1.311.20.2)
- Auth plugin API — dlopen-based extensibility (load before seccomp, `RTLD_LOCAL`)
- Multi-factor combination via XML form exchange (AggAuth protocol)

**HTTP parser migration:**
- Replace llhttp → iohttpparser (`/opt/projects/repositories/iohttpparser`)
- Pull-based, zero-copy, SIMD-accelerated (SSE4.2/AVX2), C23 native
- Update `src/network/http.{h,c}`, CMakeLists.txt, fuzz_http, container
- Strict RFC 9112 policy (TE+CL rejection, obs-fold rejection, bare LF rejection)

**Observability:**
- Structured logging — stumpless (RFC 5424), async io_uring writes
- Prometheus metrics — custom text exposition (~500-800 LOC)
  - counters: connections, bytes, auth attempts/failures, IPAM allocations
  - gauges: active sessions, memory, fd count, pool utilization
  - histograms: TLS handshake latency, auth latency

**Tech debt:**
- Fix test_tls_wolfssl (3 failures) — wolfSSL session creation issues
- Fix test_priority_parser (6 failures) — priority string tokenization
- Complete worker_loop.c TODOs: TLS decrypt loop + CSTP framing + TUN forwarding

### S8: Admin & iohttp

**Goal:** Management interface using iohttp library.

- **REST API via iohttp** — HTTP/1.1+2, radix-trie router, middleware, mTLS (port 8443)
  - `/api/v1/sessions` — list, disconnect, ban
  - `/api/v1/users` — CRUD (SQLite backend)
  - `/api/v1/metrics` — Prometheus text exposition
  - `/api/v1/config` — runtime config view
  - `/api/v1/ipam` — pool status, utilization, collision report
- **iogctl CLI** — Juniper-style interactive + non-interactive, connects to REST API
- **Admin SPA skeleton** — static files served by iohttp (port 8443)
- **Config reload** — SIGHUP triggers config re-read (TLS certs, DNS, routes, wolfSentry rules)

### S9: Production Hardening

**Goal:** Release preparation — testing, performance, documentation.

- Mini CA (wolfCrypt) — self-signed cert generation for dev/test
- Split tunnel route enforcement — nftables FORWARD rules per-group (include/exclude)
- E2E tests — full VPN session with openconnect client (socketpair mock + real TUN)
- Performance benchmarks — iperf3 through tunnel, 1000 concurrent sessions
- Documentation — all `docs/en/` stubs filled, deployment guide, security hardening guide
- CHANGELOG.md — conventional-changelog from git history
- HashiCorp Vault research — external secrets backend evaluation (see BACKLOG)

## Cisco AnyConnect Compatibility

Ioguard implements the OpenConnect/AnyConnect protocol for interoperability with Cisco Secure Client.

| Feature | Cisco ASA/FTD | ioguard | Sprint |
|---------|---------------|----------|--------|
| SSL/TLS tunnel (CSTP) | Yes | Yes | S3 |
| DTLS tunnel | Yes | Yes (DTLS 1.2) | S4 |
| DPD + keepalive | Yes | Yes | S3 |
| LZ4/LZS compression | Yes | Yes | S4 |
| PAM auth | Yes | Yes | S2 |
| IP pool (IPv4+IPv6) | Yes | Yes | S6 |
| Split DNS | Yes | Yes | S6 |
| TOTP/MFA | Yes | Yes | S6 |
| Split tunneling (routes) | Yes | S6 (config), S9 (enforce) | S6/S9 |
| RADIUS + Cisco VSAs | Yes | S7 | S7 |
| LDAP/AD | Yes | S7 | S7 |
| Certificate auth + templates | Yes | S7 | S7 |
| REST API | ASA ASDM | iohttp | S8 |
| CLI management | Cisco CLI | iogctl | S8 |
| Per-group policies | Yes | S8 (config) | S8 |
| Dynamic split tunnel | 5.1.2.42+ | Future | — |
| IKEv2 Post-Quantum | 5.1.8.105+ | Future | — |
| NVM/eBPF telemetry | 5.1.11.388+ | Future | — |

**Reference:** `docs/architecture/CISCO_COMPATIBILITY_GUIDE.md`, `/opt/projects/repositories/ocproto-research/`

## iohttp Integration (S8)

The `iohttp` library (separate project, S1-S9 done) provides:
- HTTP/1.1 + HTTP/2 (nghttp2), HTTP/3 planned
- Radix-trie router with per-method trees
- Middleware pipeline (auth, CORS, rate-limit)
- wolfSSL native TLS + mTLS
- io_uring core runtime (same as ioguard)

Instead of building a hand-rolled REST API with llhttp, ioguard links iohttp as a library for the admin interface (port 8443). This avoids duplicating HTTP/2 support, routing, middleware, and TLS termination.

## Architecture Invariants

These decisions are final and MUST NOT change:

- io_uring for ALL I/O (no libuv, no epoll)
- wolfSSL native API (not OpenSSL compat layer)
- Pure C23 (no C++ dependencies)
- Linux only (kernel 6.7+, glibc 2.39+)
- Three-process model (Main, auth-mod, Workers)
- protobuf-c for IPC
- mimalloc MI_SECURE for memory
- TOML config + JSON dynamic rules
- Hybrid storage: libmdbx (sessions) + SQLite WAL (users, audit)
- iohttp for admin REST API (not hand-built)
- iohttpparser for VPN client HTTP parsing (not llhttp)
