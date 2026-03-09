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
| S6 | Vertical Integration | NEXT | ~90 | Main process, worker data path, IPAM (dual-stack), split DNS, security activation |
| S7 | Auth & Observability | PLANNED | ~50 | RADIUS, LDAP, TOTP, cert auth, stumpless, Prometheus |
| S8 | Admin & iohttp | PLANNED | ~45 | REST API (iohttp), rwctl CLI, admin SPA, config reload |
| S9 | Production Hardening | PLANNED | ~35 | Mini CA, E2E tests, benchmarks, split tunnel enforcement, docs |

**Current:** S1-S5 done (~130 tests, 13,852 LOC). S6 next.
**Target at 1.0.0:** ~350+ tests, 5 fuzz targets, E2E validated.

## Version Plan (SemVer)

All work is `[Unreleased]` until first tag.

| Version | Sprint | Criteria |
|---------|--------|----------|
| 0.1.0 | S6 | Working VPN tunnel with IPAM + split DNS |
| 0.2.0 | S7 | Multi-backend auth + observability |
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

### S6: Vertical Integration + IPAM + Split DNS (NEXT)

**Goal:** Wire S1-S5 into a working VPN server. Add IP address management (dual-stack, collision detection) and split DNS.

**Vertical integration (Tasks 1-12):**
- Main process bootstrap (config → fork auth-mod + workers → signal loop)
- Worker io_uring event loop (accept fd via SCM_RIGHTS → TLS → CSTP → TUN)
- Auth-mod storage integration (libmdbx sessions, SQLite audit)
- Security module activation (seccomp, Landlock, wolfSentry, nftables per-session)
- DPD + keepalive timers via io_uring timeouts
- Graceful shutdown (DISCONNECT → drain → cleanup)

**IPAM — IP address pool management (Task 13):**
- `src/network/ipam.{h,c}` — dual-stack pool allocator
- Multiple CIDR pools (IPv4 + IPv6), including external subnets
- Bitmap allocator: O(1) alloc/free per address
- **Collision detection at startup**: `getifaddrs()` to enumerate server interfaces, reject pools overlapping existing networks
- RADIUS override support (`Framed-IP-Address` attr 8, `Framed-IPv6-Address` attr 168)
- Integration: auth-mod allocates → libmdbx store → IPC to worker → firewall + TUN

**Split DNS (Task 14):**
- `src/network/dns.{h,c}` — DNS configuration module
- Three modes: `RW_DNS_SPLIT`, `RW_DNS_TUNNEL_ALL`, `RW_DNS_STANDARD`
- Per-group domain lists (suffix matching with `.` boundary)
- X-CSTP headers: `X-CSTP-DNS`, `X-CSTP-Default-Domain`, `X-CSTP-Split-DNS`
- Config: `[network.split-dns]` section with domain lists

**IPv6 MTU fix (Task 15):**
- `rw_tun_calc_mtu()` accepts `int af`: subtract 40 for IPv6 (currently only 20 for IPv4)

**Plan:** `docs/plans/2026-03-08-sprint-6-vertical-integration.md`

### S7: Auth & Observability

**Goal:** Multi-backend authentication and production observability.

**Authentication:**
- RADIUS client (radcli) — Access-Request/Accept/Reject, Cisco VSAs, Framed-IP integration with IPAM
- LDAP (libldap) — bind + search, group membership, TLS
- TOTP/HOTP (liboath) — RFC 6238, Google Authenticator compatible (Base32 + HMAC-SHA1)
- Certificate authentication — client certs via wolfSSL, Microsoft AD template filtering (OID 1.3.6.1.4.1.311.20.2)
- Auth plugin API — dlopen-based extensibility (load before seccomp, `RTLD_LOCAL`)
- Multi-factor via XML form exchange (AggAuth protocol)

**Observability:**
- Structured logging — stumpless (RFC 5424), async io_uring writes
- Prometheus metrics — custom text exposition (~500-800 LOC)
  - counters: connections, bytes, auth attempts/failures, IPAM allocations
  - gauges: active sessions, memory, fd count, pool utilization
  - histograms: TLS handshake latency, auth latency

### S8: Admin & iohttp

**Goal:** Management interface using iohttp library.

- **REST API via iohttp** — HTTP/1.1+2, radix-trie router, middleware, mTLS (port 8443)
  - `/api/v1/sessions` — list, disconnect, ban
  - `/api/v1/users` — CRUD (SQLite backend)
  - `/api/v1/metrics` — Prometheus text exposition
  - `/api/v1/config` — runtime config view
  - `/api/v1/ipam` — pool status, utilization, collision report
- **rwctl CLI** — Juniper-style interactive + non-interactive, connects to REST API
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

## Cisco AnyConnect Compatibility

Ringwall implements the OpenConnect/AnyConnect protocol for interoperability with Cisco Secure Client.

| Feature | Cisco ASA/FTD | ringwall | Sprint |
|---------|---------------|----------|--------|
| SSL/TLS tunnel (CSTP) | Yes | Yes | S3 |
| DTLS tunnel | Yes | Yes (DTLS 1.2) | S4 |
| DPD + keepalive | Yes | Yes | S3 |
| LZ4/LZS compression | Yes | Yes | S4 |
| PAM auth | Yes | Yes | S2 |
| IP pool (IPv4+IPv6) | Yes | S6 | S6 |
| Split DNS | Yes | S6 | S6 |
| Split tunneling (routes) | Yes | S6 (config), S9 (enforce) | S6/S9 |
| RADIUS + Cisco VSAs | Yes | S7 | S7 |
| LDAP/AD | Yes | S7 | S7 |
| TOTP/MFA | Yes | S7 | S7 |
| Certificate auth + templates | Yes | S7 | S7 |
| REST API | ASA ASDM | iohttp | S8 |
| CLI management | Cisco CLI | rwctl | S8 |
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
- io_uring core runtime (same as ringwall)

Instead of building a hand-rolled REST API with llhttp, ringwall links iohttp as a library for the admin interface (port 8443). This avoids duplicating HTTP/2 support, routing, middleware, and TLS termination.

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
