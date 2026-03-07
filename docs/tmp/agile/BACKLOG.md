# Product Backlog - wolfguard

**Project**: wolfguard v2.0.0
**Team**: 1 developer + Claude AI
**Last Updated**: 2026-03-07

---

## Backlog Management

### Priority Levels

- **P0 (Critical)**: Must have for release, blocks other work
- **P1 (High)**: Should have for release, important features
- **P2 (Medium)**: Nice to have, can be deferred if needed

### Story Point Scale (Fibonacci)

- **1 point**: Few hours, well-understood
- **2 points**: Half day to 1 day
- **3 points**: 1-2 days
- **5 points**: 2-4 days
- **8 points**: 1 week
- **13 points**: 2 weeks (should be split)

### Definition of Ready

Before a story enters a sprint:
- [ ] Story is clearly defined with acceptance criteria
- [ ] Story points assigned
- [ ] Dependencies identified
- [ ] Technical approach understood

### Definition of Done

For a story to be marked complete:
- [ ] All acceptance criteria met
- [ ] Code reviewed (Claude + self-review)
- [ ] Unit tests written and passing (>= 80% coverage)
- [ ] Integration tests passing (if applicable)
- [ ] Sanitizers clean (ASan+UBSan, MSan)
- [ ] clang-format and clang-tidy pass
- [ ] Merged to main branch

---

## Epic 1: Foundation (S1)

**Sprint**: S1 (Weeks 1-2)
**Focus**: io_uring, process model, IPC, config, memory
**Story Points**: 19

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-100 | io_uring event loop wrapper | 5 | P0 |
| US-101 | Process model with pidfd_spawn | 5 | P0 |
| US-102 | IPC over SOCK_SEQPACKET + protobuf-c | 3 | P0 |
| US-103 | TOML configuration parser and validation | 3 | P0 |
| US-104 | mimalloc integration and memory wrappers | 3 | P0 |

### User Stories

**US-100**: As a developer, I want an io_uring event loop wrapper so that all network, TUN, and timer I/O uses a single async subsystem.

**US-101**: As a developer, I want a process manager using pidfd_spawn and IORING_OP_WAITID so that child processes are spawned and monitored without signal races.

**US-102**: As a developer, I want IPC message serialization over SOCK_SEQPACKET so that processes exchange structured messages with automatic framing.

**US-103**: As a VPN administrator, I want TOML-based configuration so that the server is configured with a human-readable, well-structured file.

**US-104**: As a developer, I want mimalloc as the global allocator so that memory allocation is fast, secure (MI_SECURE), and per-worker isolated.

---

## Epic 2: TLS & Authentication (S2)

**Sprint**: S2 (Weeks 3-4)
**Focus**: wolfSSL, PAM, sec-mod, sessions, HTTP
**Story Points**: 19

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-105 | wolfSSL TLS 1.3 integration with callback I/O | 5 | P0 |
| US-106 | PAM authentication backend | 3 | P0 |
| US-107 | sec-mod authentication process | 5 | P0 |
| US-108 | Session cookie management | 3 | P0 |
| US-109 | HTTP parsing with llhttp | 3 | P0 |

### User Stories

**US-105**: As a VPN user, I want TLS 1.3 connections via wolfSSL so that my VPN tunnel is secured with modern cryptography.

**US-106**: As a VPN administrator, I want PAM authentication so that users authenticate against system accounts or PAM-compatible backends.

**US-107**: As a developer, I want a dedicated sec-mod process so that authentication is isolated from worker processes and sessions survive worker crashes.

**US-108**: As a VPN user, I want session cookies so that I can reconnect to any worker without re-authenticating after a transient failure.

**US-109**: As a developer, I want llhttp-based HTTP parsing so that CSTP HTTP negotiation (POST /auth, CONNECT /CSTPID) is handled safely.

---

## Epic 3: VPN Core (S3)

**Sprint**: S3 (Weeks 5-6)
**Focus**: CSTP, TUN, worker, DPD
**Story Points**: 18

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-110 | CSTP protocol framing | 5 | P0 |
| US-111 | TUN device I/O via io_uring | 5 | P0 |
| US-112 | Worker process with connection multiplexing | 5 | P0 |
| US-113 | Dead Peer Detection state machine | 3 | P0 |

### User Stories

**US-110**: As a VPN user, I want CSTP protocol support so that I can establish a VPN tunnel compatible with Cisco Secure Client.

**US-111**: As a developer, I want TUN device I/O driven by io_uring so that packets flow between the tunnel interface and the network without blocking.

**US-112**: As a developer, I want worker processes that multiplex many client connections via io_uring so that the server scales to thousands of concurrent sessions per core.

**US-113**: As a VPN user, I want Dead Peer Detection so that stale connections are detected and cleaned up automatically.

---

## Epic 4: DTLS & Compression (S4)

**Sprint**: S4 (Weeks 7-8)
**Focus**: DTLS 1.2, channel switch, codecs
**Story Points**: 16

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-114 | DTLS 1.2 with master secret bootstrap | 5 | P0 |
| US-115 | CSTP/DTLS channel switching | 3 | P0 |
| US-116 | LZ4 compression codec | 3 | P1 |
| US-117 | LZS compression for Cisco compatibility | 5 | P1 |

### User Stories

**US-114**: As a VPN user, I want DTLS 1.2 support so that my data path uses lower-overhead UDP when available, with Cisco Secure Client compatibility via X-DTLS-Master-Secret bootstrap.

**US-115**: As a VPN user, I want automatic channel switching so that data falls back from DTLS to CSTP when UDP is blocked, and recovers when UDP becomes available.

**US-116**: As a developer, I want LZ4 compression so that VPN throughput improves on compressible traffic.

**US-117**: As a Cisco client user, I want LZS compression so that my Cisco Secure Client can negotiate a compatible compression algorithm.

---

## Epic 5: Security (S5)

**Sprint**: S5 (Weeks 9-10)
**Focus**: wolfSentry, sandbox, firewall, fuzzing
**Story Points**: 18

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-118 | wolfSentry IDPS integration | 5 | P0 |
| US-119 | seccomp BPF and Landlock sandboxing | 5 | P0 |
| US-120 | Per-user nftables firewall chains | 5 | P1 |
| US-121 | Fuzz targets for all parsers | 3 | P1 |

### User Stories

**US-118**: As a VPN administrator, I want wolfSentry IDPS so that malicious connections are detected and rejected at the TLS ClientHello stage.

**US-119**: As a security engineer, I want seccomp BPF and Landlock sandboxing on worker processes so that a compromised worker cannot access unauthorized syscalls or filesystem paths.

**US-120**: As a VPN administrator, I want per-user nftables firewall chains so that each VPN user has isolated network access rules that are created on connect and destroyed on disconnect.

**US-121**: As a developer, I want LibFuzzer targets for CSTP, HTTP, TOML, protobuf, and TLS ClientHello parsers so that parsing bugs are discovered automatically.

---

## Epic 6: Auth Expansion (S6)

**Sprint**: S6 (Weeks 11-12)
**Focus**: RADIUS, LDAP, TOTP, certs, plugins
**Story Points**: 17

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-122 | RADIUS authentication via radcli | 3 | P1 |
| US-123 | Direct LDAP/AD authentication | 5 | P1 |
| US-124 | TOTP/HOTP two-factor authentication | 3 | P1 |
| US-125 | Certificate authentication with template filtering | 3 | P1 |
| US-126 | dlopen-based auth plugin API | 3 | P1 |

### User Stories

**US-122**: As a VPN administrator, I want RADIUS authentication so that users authenticate against enterprise RADIUS infrastructure.

**US-123**: As a VPN administrator, I want direct LDAP/AD authentication so that users authenticate against Active Directory without requiring sssd.

**US-124**: As a VPN user, I want TOTP/HOTP two-factor authentication so that my VPN login requires a time-based or counter-based one-time password.

**US-125**: As a VPN administrator, I want certificate-based authentication with template filtering so that only certificates matching specific CN/SAN patterns are accepted.

**US-126**: As a developer, I want a dlopen-based auth plugin API so that third-party authentication modules can be loaded at runtime.

---

## Epic 7: Management (S7)

**Sprint**: S7 (Weeks 13-14)
**Focus**: CLI, REST API, metrics, logging
**Story Points**: 18

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-127 | wgctl Juniper-style CLI | 5 | P1 |
| US-128 | REST API over TLS | 5 | P1 |
| US-129 | Prometheus metrics endpoint | 3 | P1 |
| US-130 | Structured logging via stumpless | 5 | P0 |

### User Stories

**US-127**: As a VPN administrator, I want a Juniper-style CLI (wgctl) so that I can manage the server interactively with operational and configuration modes.

**US-128**: As a VPN administrator, I want a REST API over TLS so that I can automate server management and integrate with orchestration tools.

**US-129**: As a monitoring engineer, I want a Prometheus /metrics endpoint so that I can collect connection counts, throughput, error rates, and latency metrics.

**US-130**: As a VPN administrator, I want structured RFC 5424 logging via stumpless so that logs are machine-parseable and compatible with centralized log aggregation.

---

## Epic 8: PKI & Integration (S8)

**Sprint**: S8 (Weeks 15-16)
**Focus**: mini CA, split tunnel, E2E, docs
**Story Points**: 18

| ID | Story | Points | Priority |
|----|-------|--------|----------|
| US-131 | wgctl pki mini CA with wolfCrypt | 5 | P1 |
| US-132 | Split tunnel and split DNS | 3 | P1 |
| US-133 | End-to-end tests with openconnect | 5 | P0 |
| US-134 | Documentation and deployment guide | 3 | P1 |
| US-135 | Performance benchmarks | 2 | P2 |

### User Stories

**US-131**: As a VPN administrator, I want a built-in mini CA (wgctl pki) so that I can generate CA certificates, server certificates, client certificates, and CRLs without external tools.

**US-132**: As a VPN administrator, I want split tunnel and split DNS support so that only designated traffic routes through the VPN while other traffic goes direct.

**US-133**: As a developer, I want end-to-end tests with the openconnect client so that the full VPN session lifecycle is validated automatically in CI.

**US-134**: As a VPN administrator, I want installation, configuration, and deployment documentation so that I can deploy wolfguard in production.

**US-135**: As a developer, I want published performance benchmarks (handshake/s, Gbps, p99 latency) so that wolfguard performance is quantified and tracked.

---

## Backlog Summary

| Epic | Sprint | Stories | Story Points |
|------|--------|---------|-------------|
| 1. Foundation | S1 | 5 | 19 |
| 2. TLS & Authentication | S2 | 5 | 19 |
| 3. VPN Core | S3 | 4 | 18 |
| 4. DTLS & Compression | S4 | 4 | 16 |
| 5. Security | S5 | 4 | 18 |
| 6. Auth Expansion | S6 | 5 | 17 |
| 7. Management | S7 | 4 | 18 |
| 8. PKI & Integration | S8 | 5 | 18 |
| **Total** | | **36** | **143** |

### Velocity Projection

Assuming velocity of ~18 SP/sprint (1 developer + Claude AI, 2-week sprints):
- **Estimated Sprints**: 8
- **Estimated Duration**: ~16 calendar weeks

---

**Document Version**: 2.0
**Last Updated**: 2026-03-07
**Next Review**: After S1 sprint planning
