# Sprint Planning - wolfguard

**Project**: wolfguard v2.0.0
**Team**: 1 developer + Claude AI
**Sprint Duration**: 2 weeks
**Total Sprints**: 8 (~16 weeks)
**Last Updated**: 2026-03-07

---

## Sprint Ceremonies

### Daily Async Standup (Claude)
- Developer posts progress, blockers, and next steps asynchronously
- Claude reviews and provides feedback, suggestions, and unblocking guidance
- Format: What I did / What I plan to do / Blockers

### Weekly Review
- End of each week: review completed work against sprint goals
- Demo working code (build, tests passing, functionality verified)
- Adjust remaining sprint scope if needed

### Retrospective
- End of each sprint (Friday, Week 2)
- What went well / What could be improved / Action items
- Update velocity tracking and adjust future sprint capacity

---

## Phase 0 -- Exploration (Completed)

### Sprint 0: Project Initialization (2025-10-29 to 2025-11-12)
**Status**: COMPLETED

Established project infrastructure, development environment, and agile framework.

**Completed**:
- [x] Repository created with project structure
- [x] Podman development containers built and tested
- [x] Release policy and documentation templates created
- [x] Agile framework documents established
- [x] Comprehensive refactoring plan written

### Sprint 1: Critical Analysis and PoC (2025-11-13 to 2025-11-27)
**Status**: COMPLETED

Analyzed upstream ocserv codebase. GnuTLS API audit identified 94 unique functions (457 occurrences). Developed wolfSSL proof-of-concept. GO decision made.

**Completed**:
- [x] GnuTLS API audit complete
- [x] Upstream ocserv architecture documented
- [x] wolfSSL TLS proof-of-concept developed
- [x] Performance baseline established
- [x] GO/NO-GO decision: GO

### Sprint 2: Architecture and Design (2025-11-28 to 2025-12-12)
**Status**: COMPLETED

Designed new architecture (three-process model, io_uring-only I/O, wolfSSL native API). Produced architecture design document.

**Completed**:
- [x] Three-process model designed (Main, sec-mod, Workers)
- [x] io_uring-only I/O subsystem designed
- [x] Technology stack finalized
- [x] Architecture design document approved

---

## Sprint Roadmap

| Sprint | Focus | Weeks |
|--------|-------|-------|
| S1 | Foundation: io_uring wrapper, process model, IPC (SOCK_SEQPACKET + protobuf-c), TOML config, mimalloc | 1-2 |
| S2 | TLS & Auth: wolfSSL integration (TLS 1.3, callback I/O), PAM auth, sec-mod process, session cookies, llhttp | 3-4 |
| S3 | VPN Tunnel: CSTP protocol (framing, packets), TUN I/O via io_uring, worker process, DPD state machine | 5-6 |
| S4 | DTLS & Compression: DTLS 1.2 (Cisco, master secret bootstrap), channel switching, LZ4/LZS | 7-8 |
| S5 | Security Hardening: wolfSentry IDPS, seccomp BPF, Landlock, nftables per-user chains, fuzz targets | 9-10 |
| S6 | Auth Expansion: RADIUS (radcli), LDAP (libldap), TOTP (liboath), cert auth, plugin API (dlopen) | 11-12 |
| S7 | Management: wgctl CLI (Juniper-style), REST API (llhttp+io_uring), Prometheus metrics, stumpless logging | 13-14 |
| S8 | PKI & Polish: wgctl pki mini CA (wolfCrypt), split tunnel/DNS, E2E tests, docs, benchmarks | 15-16 |

---

## S1 -- Foundation (Weeks 1-2)

**Status**: **COMPLETED** (2026-03-07, 1 day)

**Sprint Goal**: Build the core infrastructure -- io_uring event loop, process spawning, IPC, configuration, and memory allocation.

### Deliverables

- `src/io/` -- io_uring wrapper (accept, read, write, timeout, buffer rings)
- `src/core/main.c` -- Main process, pidfd_spawn workers, signalfd
- `src/ipc/` -- SOCK_SEQPACKET + protobuf-c message definitions
- `src/config/` -- TOML parser (tomlc99), config structures, validation
- `src/utils/memory.c` -- mimalloc setup, arena allocator for IPC
- Unit tests for all modules
- CI: CMake presets, sanitizers (ASan+UBSan, MSan), clang-format/tidy

### Definition of Done

- [ ] io_uring event loop handles accept, recv, send, timeout
- [ ] Main process spawns and monitors child processes via pidfd_spawn
- [ ] IPC messages serialize/deserialize correctly over SOCK_SEQPACKET
- [ ] TOML configuration loads and validates
- [ ] mimalloc integrated, all allocations routed through wg_ wrappers
- [ ] All unit tests pass under ASan+UBSan and MSan

---

## S2 -- TLS & Auth (Weeks 3-4)

**Status**: **COMPLETED** (2026-03-07, 1 day)

**Sprint Goal**: Integrate wolfSSL for TLS 1.3, implement PAM authentication via sec-mod, and establish session cookie management.

### Deliverables

- `src/crypto/tls_wolfssl.c` -- wolfSSL context, callback I/O, cipher config
- `src/auth/pam.c` -- PAM authentication via sec-mod
- `src/core/secmod.c` -- sec-mod process, auth request/response IPC
- `src/core/session.c` -- Session cookie create/validate (constant-time)
- `src/network/http.c` -- llhttp integration, CSTP HTTP negotiation
- Integration test: full TLS handshake + PAM auth flow

### Definition of Done

- [ ] wolfSSL TLS 1.3 handshake completes with callback I/O over io_uring
- [ ] sec-mod process handles PAM auth requests via IPC
- [ ] Session cookies generated, validated, and zeroed after use
- [ ] HTTP POST /auth and CONNECT /CSTPID parsed correctly via llhttp
- [ ] Integration test demonstrates end-to-end auth flow

---

## S3 -- VPN Tunnel + Docs Restructuring (Weeks 5-6)

**Sprint Goal**: Implement the CSTP VPN tunnel with TUN device I/O, worker process multiplexing, and Dead Peer Detection. Restructure documentation (gobfd-style README, bilingual docs, archive old docs).

**Status**: **COMPLETED** (2026-03-07 to 2026-03-08, 2 days)

### Deliverables

- `src/network/cstp.c` -- CSTP framing, packet encode/decode (zero-copy)
- `src/network/tun.c` -- TUN device allocation, MTU calculation
- `src/network/dpd.c` -- Dead Peer Detection state machine (pure, no I/O)
- `src/core/worker.c` -- Worker process context, connection tracking (flat array)
- `tests/integration/test_data_path.c` -- CSTP + io_uring round-trip integration
- `README.md` -- Complete redesign (gobfd-style, centered badges, mermaid)
- `docs/{en,ru}/` -- Bilingual documentation structure (24 files)

### Definition of Done

- [x] CSTP framing encodes/decodes data, DPD, and control packets (10 tests)
- [x] TUN device allocated with MTU calculation (7 tests)
- [x] Worker process multiplexes multiple client connections (10 tests)
- [x] DPD state machine detects dead peers (30s interval, 3 missed = dead) (10 tests)
- [x] Integration test: CSTP encode → io_uring send/recv → CSTP decode (5 tests)
- [x] Documentation restructured: README, bilingual docs, old docs archived

### Sprint Results

- **42 new tests** (all passing), 9 commits, 3515 LOC added
- **New source files**: cstp.h/c, tun.h/c, dpd.h/c, worker.h/c (995 LOC)
- **New test files**: test_cstp.c, test_tun.c, test_dpd.c, test_worker.c, test_data_path.c (865 LOC)
- See `docs/tmp/sprints/sprint-3/SPRINT_3_COMPLETION_REPORT.md` for full report

---

## S4 -- DTLS & Compression (Weeks 7-8)

**Sprint Goal**: Add DTLS 1.2 for Cisco client compatibility, implement channel switching, and integrate compression codecs.

### Deliverables

- `src/network/dtls.c` -- DTLS 1.2 with X-DTLS-Master-Secret bootstrap
- `src/network/channel.c` -- CSTP/DTLS channel switching logic
- `src/network/compress.c` -- Compression abstraction (LZ4, LZS)
- `src/network/compress_lzs.c` -- LZS implementation (Cisco compatibility)
- Integration test: DTLS session establishment, channel fallback

### Definition of Done

- [ ] DTLS 1.2 session established via master secret bootstrap
- [ ] Channel switching: DTLS primary, CSTP fallback, DPD-triggered transition
- [ ] LZ4 and LZS codecs compress/decompress correctly
- [ ] Compression negotiated via X-CSTP-Accept-Encoding headers
- [ ] Integration test: DTLS active, falls back to CSTP on DPD failure

---

## S5 -- Security Hardening (Weeks 9-10)

**Sprint Goal**: Harden the server with IDPS, kernel sandboxing, per-user firewall rules, and fuzz testing targets.

### Deliverables

- `src/security/wolfsentry.c` -- wolfSentry init, connection checking, JSON config
- `src/security/sandbox.c` -- seccomp BPF filter, Landlock filesystem rules
- `src/security/firewall.c` -- nftables per-user chains (libmnl + libnftnl)
- wolfSSL AcceptFilter integration
- Fuzz targets: CSTP parser, HTTP parser, TOML parser, protobuf, TLS ClientHello

### Definition of Done

- [ ] wolfSentry checks connections on TLS ClientHello (reject -> close)
- [ ] seccomp BPF restricts worker syscalls to allowlist
- [ ] Landlock restricts worker filesystem access
- [ ] nftables per-user chains created/destroyed on session lifecycle
- [ ] All fuzz targets build and run 100K+ iterations clean under ASan

---

## S6 -- Auth Expansion (Weeks 11-12)

**Sprint Goal**: Expand authentication backends and implement the plugin API for third-party auth modules.

### Deliverables

- `src/auth/radius.c` -- RADIUS authentication via radcli
- `src/auth/ldap.c` -- Direct LDAP/AD authentication via libldap
- `src/auth/totp.c` -- TOTP/HOTP via liboath
- `src/auth/cert.c` -- Certificate authentication with template filtering
- `src/auth/plugin.c` -- dlopen-based plugin API

### Definition of Done

- [ ] RADIUS auth completes against test server
- [ ] LDAP auth binds and authenticates against test directory
- [ ] TOTP validates time-based codes correctly
- [ ] Certificate auth extracts CN/SAN and applies template filters
- [ ] Plugin API loads, initializes, and authenticates via dlopen module

---

## S7 -- Management (Weeks 13-14)

**Sprint Goal**: Build the management layer -- CLI tool, REST API, Prometheus metrics, and structured logging.

### Deliverables

- `src/occtl/wgctl.c` -- Juniper-style CLI (operational + config mode)
- `src/occtl/cli_parser.c` -- Command parser with linenoise
- `src/network/rest.c` -- REST API (llhttp + io_uring + wolfSSL)
- `src/metrics/prometheus.c` -- Custom Prometheus text exposition
- `src/log/stumpless.c` -- Structured logging (RFC 5424)

### Definition of Done

- [ ] wgctl connects to running server, shows sessions, disconnects users
- [ ] CLI supports operational mode (show, disconnect) and config mode
- [ ] REST API serves JSON responses over TLS
- [ ] Prometheus /metrics endpoint exposes connection, throughput, and error counters
- [ ] Structured logs emitted in RFC 5424 format via stumpless

---

## S8 -- PKI & Polish (Weeks 15-16)

**Sprint Goal**: Complete the mini CA, split tunneling, end-to-end tests, documentation, and performance benchmarks.

### Deliverables

- `src/occtl/pki.c` -- Mini CA (wolfCrypt: keygen, CSR, sign, CRL)
- `src/network/split.c` -- Split tunnel routes, split DNS
- E2E tests with openconnect client
- Documentation: installation, configuration, deployment
- Performance benchmarks: handshake rate, throughput, latency

### Definition of Done

- [ ] wgctl pki generates CA, server certs, client certs, and CRLs
- [ ] Split tunnel routes and DNS pushed to clients via CSTP headers
- [ ] E2E test: full VPN session lifecycle with openconnect client
- [ ] Documentation covers installation, configuration, and deployment
- [ ] Benchmarks published: handshake/s, Gbps throughput, p99 latency

---

## Velocity Tracking

| Sprint | Planned SP | Completed SP | Velocity | Notes |
|--------|-----------|--------------|----------|-------|
| Phase 0 (S0-S2) | -- | -- | -- | Exploration complete |
| S1 | 20 | 20 | 20 | Foundation: io_uring, IPC, config, process (33 tests) |
| S2 | 16 | 16 | 16 | TLS & Auth: wolfSSL, PAM, sec-mod, sessions, llhttp |
| S3 | 16 | 16 | 16 | VPN Tunnel + Docs: CSTP, TUN, DPD, worker (42 tests) |
| S4 | 16 | -- | -- | DTLS & Compression |
| S5 | TBD | -- | -- | -- |
| S6 | TBD | -- | -- | -- |
| S7 | TBD | -- | -- | -- |
| S8 | TBD | -- | -- | -- |

**Average Velocity**: ~17 SP/sprint (S1-S3)

---

**Document Version**: 3.0
**Last Updated**: 2026-03-08
**Next Review**: After S4 sprint planning
