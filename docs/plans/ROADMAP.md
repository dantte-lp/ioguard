# Roadmap

Sprint-based development plan. Each sprint ~2 weeks.

## Status

| Sprint | Name | Status | Tests | Key Deliverables |
|--------|------|--------|-------|------------------|
| S1 | Foundation | **DONE** | 33 | io_uring, IPC, TOML config, pidfd_spawn, mimalloc |
| S2 | TLS & Auth | **DONE** | — | wolfSSL TLS 1.3, PAM, sessions, llhttp, XML auth |
| S3 | VPN Tunnel | **DONE** | 42 | CSTP framing, TUN, DPD, worker process |
| S4 | DTLS & Compression | **DONE** | 68 | DTLS 1.2, LZ4/LZS, channel switching |
| S5 | Storage & Security | NEXT | ~55 | libmdbx, SQLite WAL, wolfSentry, seccomp, Landlock |
| S6 | Auth Expansion | PLANNED | ~30 | RADIUS, LDAP, TOTP, cert auth, plugin API |
| S7 | Management | PLANNED | ~35 | rwctl CLI, REST API, Prometheus metrics, stumpless |
| S8 | PKI & Polish | PLANNED | ~25 | Mini CA, split tunnel, E2E tests, docs, benchmarks |

**Current test count:** 30 registered (28 pass, 2 pre-existing failures).
**Target at 0.1.0:** ~250 tests + 5 fuzz targets.

## Version Plan (SemVer)

All work is `[Unreleased]` until first tag.

| Version | Milestone | Criteria |
|---------|-----------|----------|
| 0.1.0 | S5 complete | Storage + security hardening, all tests pass |
| 0.2.0 | S6 complete | Multi-backend auth (RADIUS, LDAP, TOTP) |
| 0.3.0 | S7 complete | CLI + REST API + metrics + logging |
| 0.4.0 | S8 complete | PKI, split tunnel, E2E tested |
| 1.0.0 | Production | All sprints, performance validated, docs complete |

## Sprint Details

### S5: Storage & Security (NEXT)

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

### S6: Auth Expansion

**Goal:** Multiple authentication backends with plugin API.

- RADIUS client (radcli) — enterprise auth
- LDAP (libldap) — directory services
- TOTP/HOTP (liboath) — two-factor
- Certificate authentication — client certs via wolfSSL
- Auth plugin API — dlopen-based extensibility

### S7: Management

**Goal:** Operations tooling and observability.

- **rwctl CLI** — Juniper-style interactive + non-interactive
- **REST API** — llhttp + io_uring + wolfSSL (HTTPS only)
- **Prometheus metrics** — custom text exposition (~500-800 LOC)
  - counters: connections, bytes, auth attempts, errors
  - gauges: active sessions, memory, fd count
  - histograms: latency percentiles
- **Structured logging** — stumpless (RFC 5424)
- **cmetrics rejected** — see BACKLOG.md for rationale

### S8: PKI & Polish

**Goal:** Certificate management, advanced features, release prep.

- Mini CA (wolfCrypt) — self-signed cert generation
- Split tunnel routes — per-group route policies
- Split DNS — per-group DNS configuration
- E2E tests — full VPN session with openconnect client
- Performance benchmarks — iperf3 through tunnel
- Documentation — all `docs/en/` stubs filled

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
