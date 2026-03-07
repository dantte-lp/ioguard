# wolfguard

**Modern OpenConnect VPN Server -- wolfSSL Native API, io_uring, Linux**

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Version](https://img.shields.io/badge/version-2.0.0--alpha-orange)](https://github.com/dantte-lp/wolfguard/releases)
[![Build Status](https://img.shields.io/badge/build-setup-yellow)](https://github.com/dantte-lp/wolfguard/actions)

---

## Overview

wolfguard is a clean-room implementation of the OpenConnect VPN protocol, using ocserv as a protocol reference but not migrating its codebase. It replaces GnuTLS with wolfSSL native API, replaces libuv with io_uring (liburing 2.7+), and modernizes every layer of the stack.

A proof-of-concept in Sprint 1 validated a **50% TLS handshake performance improvement** over GnuTLS, leading to a GO decision for the full implementation.

### Key Features

- **wolfSSL Native API**: TLS 1.3, DTLS 1.2/1.3, FIPS 140-3 certification path
- **io_uring Everywhere**: All I/O via liburing -- network, TUN, timers, signals. No libuv.
- **Three-Process Model**: Main + sec-mod + Workers (1 per CPU, seccomp + Landlock)
- **OpenConnect Protocol v1.2**: Full Cisco Secure Client 5.x compatibility
- **TOML Configuration**: Static config via tomlc99, JSON for wolfSentry rules and REST API
- **wolfSentry IDPS**: Integrated intrusion detection and prevention
- **wgctl CLI**: Juniper-style operational and configuration mode
- **REST API**: llhttp + io_uring + wolfSSL with custom Prometheus metrics
- **Compression**: LZ4 + LZS (Cisco compatibility), disabled by default
- **Auth Pipeline**: PAM, RADIUS, LDAP, TOTP, certificate, plugin API

---

## Project Status

**Current Phase**: Clean implementation (Sprint 1)
**Release**: v2.0.0-alpha
**Timeline**: 8 sprints (~16 weeks)
**Status**: Pre-release, not ready for production

### Historical Sprints (PoC Validation)

These sprints validated the approach using ocserv code. The clean implementation starts fresh.

- **Sprint 0** (2025-10-15 to 2025-10-29): **COMPLETED** -- TLS abstraction + dual backends
  - GnuTLS backend (915 lines, 100% tests pass)
  - wolfSSL backend (1,287 lines, 100% tests pass)
  - Oracle Linux 10 migration
  - Unit testing infrastructure

- **Sprint 1** (2025-10-29): **COMPLETED** -- PoC validation + benchmarking
  - Fixed all wolfSSL implementation issues (100% tests passing)
  - Working PoC server and client
  - Validated TLS communication (75% success rate)
  - **GO DECISION: Proceed with wolfSSL** -- 50% performance improvement validated

- **Sprint 2** (2025-10-29 to 2025-11-13): **COMPLETED** -- Development tools + library evaluation
  - Modern development tools (CMake 4.1.2, Doxygen 1.15.0, Ceedling 1.0.1)
  - Library stack evaluation and selection
  - Architecture design finalized

### Implementation Sprints

| Sprint | Focus | Weeks |
|--------|-------|-------|
| S1 | Foundation: io_uring, process model, IPC, TOML config | 1-2 |
| S2 | TLS & Auth: wolfSSL, PAM, sec-mod, sessions | 3-4 |
| S3 | VPN Tunnel: CSTP, TUN I/O, data path, DPD | 5-6 |
| S4 | DTLS & Compression: DTLS 1.2, channel switching, LZ4/LZS | 7-8 |
| S5 | Security: wolfSentry, seccomp, Landlock, nftables | 9-10 |
| S6 | Auth Expansion: RADIUS, LDAP, TOTP, plugin API | 11-12 |
| S7 | Management: wgctl CLI, REST API, metrics, logging | 13-14 |
| S8 | PKI & Polish: mini CA, split tunnel/DNS, E2E tests, docs | 15-16 |

---

## Development Approach

- **Team**: 1 developer + Claude
- **Clean implementation**: ocserv used as protocol reference only, not as code base
- **Performance**: 50% TLS improvement already validated in PoC
- **Testing**: Unity (unit) + integration + E2E with openconnect client; ASan/UBSan/MSan/TSan; LibFuzzer targets
- **Security**: External security audit planned; seccomp + Landlock sandboxing from Sprint 5

---

## Architecture

### Three-Process Model

```
                    +---------------+
                    |     Main      |  (root -> drops to unprivileged)
                    |  pidfd_spawn  |
                    |  signalfd     |
                    +---+-------+---+
                        |       |
               SOCK_SEQPACKET  SOCK_SEQPACKET
               + protobuf-c    + protobuf-c
                        |       |
             +----------+      +---------------+
             v                                  v
     +---------------+              +-------------------+
     |   sec-mod     |              |  Worker (x N)     |
     | (unprivileged)|              | (unprivileged)    |
     |               |              |  + seccomp        |
     | PAM/RADIUS/   |              |  + Landlock       |
     | LDAP/TOTP/    |              |                   |
     | cert auth     |              |  io_uring loop    |
     | session store |              |  wolfSSL TLS      |
     +---------------+              |  TUN I/O          |
                                    |  wolfSentry       |
                                    +-------------------+
```

- **Main**: Privileged startup, then drops privileges. Spawns/monitors sec-mod and workers via `pidfd_spawn` (glibc 2.39+). Monitors child processes via `IORING_OP_WAITID` (kernel 6.7+). Config reload via signalfd.
- **sec-mod**: Authentication only. Holds session cookies (survives worker crashes). Communicates via SOCK_SEQPACKET + protobuf-c with arena allocator.
- **Workers**: 1 per CPU core. All client connections multiplexed via io_uring. Sandboxed with seccomp + Landlock. Stateless -- crash recovery via cookie-based reconnect to any worker.

### I/O Subsystem

All I/O goes through io_uring (liburing 2.7+). There is no libuv in the stack.

- Network: `IORING_OP_ACCEPT` (multishot), `IORING_OP_RECV`/`IORING_OP_SEND`
- TUN: `IORING_OP_READ`/`IORING_OP_WRITE`
- Timers: `IORING_OP_TIMEOUT`
- Signals: signalfd + `IORING_OP_READ`
- Buffer management: `IORING_OP_PROVIDE_BUFFERS` (kernel-managed)

### VPN Data Path

```
Network --> io_uring CQE --> wolfSSL_read() --> decompress --> TUN write
                                                                   |
TUN read <-- io_uring CQE <-- wolfSSL_write() <-- compress <------+
```

### Library Stack

#### Core

| Library | Version | Role |
|---------|---------|------|
| wolfSSL | 5.8.4+ | TLS 1.3 / DTLS 1.2 / DTLS 1.3 |
| wolfSentry | 1.6.3+ | IDPS / dynamic firewall |
| liburing | 2.7+ | All I/O (network, TUN, timers, signals) |
| mimalloc | 3.1.5+ | Memory allocator (MI_SECURE) |

#### Network and Protocol

| Library | Version | Role |
|---------|---------|------|
| llhttp | 9.3.1+ | HTTP parser (CSTP, REST API) |
| c-ares | 1.34+ | Async DNS resolver |
| LZ4 | 1.10+ | Real-time compression |

#### Data and Configuration

| Library | Version | Role |
|---------|---------|------|
| tomlc99 | latest | Static configuration (TOML) |
| yyjson | 0.12+ | Fast JSON (REST API, metrics) |
| cJSON | 1.7.19+ | Simple JSON (wolfSentry config) |
| protobuf-c | 1.5.1+ | IPC serialization |

#### Authentication

| Library | Version | Role |
|---------|---------|------|
| PAM | system | Pluggable auth (MVP) |
| radcli | 1.4+ | RADIUS client |
| libldap | 2.6+ | Direct LDAP/AD |
| liboath | 2.6+ | TOTP/HOTP |

#### Security and Firewall

| Library | Version | Role |
|---------|---------|------|
| libseccomp | 2.5+ | Syscall sandbox |
| libmnl | 1.0.5+ | Netlink minimal |
| libnftnl | 1.3.1+ | nftables per-user rules |

#### Management

| Library | Version | Role |
|---------|---------|------|
| stumpless | latest | Structured logging (RFC 5424) |
| linenoise | latest | CLI line editing (wgctl) |

### Directory Structure

```
wolfguard/
├── src/
│   ├── io/                # io_uring abstraction layer
│   ├── crypto/            # wolfSSL TLS/DTLS (+ GnuTLS fallback)
│   ├── network/           # CSTP, DTLS, HTTP, REST, compression, TUN
│   ├── ipc/               # SOCK_SEQPACKET + protobuf-c
│   ├── auth/              # PAM, RADIUS, LDAP, TOTP, cert, plugin API
│   ├── core/              # Main, sec-mod, worker, session management
│   ├── security/          # wolfSentry, seccomp, Landlock, nftables
│   ├── config/            # TOML parser, config structures
│   ├── log/               # stumpless structured logging
│   ├── metrics/           # Custom Prometheus text exposition
│   ├── utils/             # mimalloc setup, arena allocator
│   └── occtl/             # wgctl CLI, mini CA (wolfCrypt)
├── tests/
│   ├── unit/              # Unity-based unit tests
│   ├── integration/       # Multi-process integration tests
│   ├── e2e/               # Full VPN session tests
│   ├── fuzz/              # LibFuzzer targets (Clang only)
│   └── bench/             # Performance benchmarks
├── docs/                  # Documentation
│   ├── plans/             # Architecture and design documents
│   ├── sprints/           # Sprint documentation
│   └── architecture/      # Architecture reference
└── deploy/
    └── podman/            # Container configurations
```

---

## Getting Started

### Prerequisites

- **Operating System**: Linux only (kernel 6.7+, glibc 2.39+)
  - Oracle Linux 10, Fedora 41+, Ubuntu 24.10+, RHEL 10+
  - No BSD support (io_uring is Linux-only)
- **Compiler**: Clang 22+ (primary development) or GCC 15+ (validation/release)
  - **C Standard**: ISO/IEC 9899:2024 (C23) -- MANDATORY (`-std=c23`)
- **Build System**: CMake 4.1+
- **Container Runtime**: Podman 4.0+ (recommended for development)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/dantte-lp/wolfguard.git
cd wolfguard

# Configure with Clang (primary development)
cmake --preset clang-debug

# Build
cmake --build --preset clang-debug

# Run tests
ctest --preset clang-debug
```

### Code Quality

```bash
cmake --build --preset clang-debug --target format    # clang-format
cmake --build --preset clang-debug --target lint      # clang-tidy
cmake --build --preset clang-debug --target cppcheck  # static analysis
```

### Development Environment

Using the provided Podman container:

```bash
cd deploy/podman
docker-compose up -d dev
docker-compose exec dev /bin/bash
```

---

## Testing

### Running Tests

```bash
# Unit tests
ctest --preset clang-debug

# Integration tests
cd tests/integration
./run_integration_tests.sh

# Performance benchmarks
cd tests/bench
./run_benchmarks.sh
```

### Sanitizer Matrix

| Sanitizer | Compiler | When |
|-----------|----------|------|
| ASan + UBSan | Clang + GCC | Every commit |
| MSan | Clang only | Every commit |
| TSan | Clang | Before merge |

### Fuzz Targets (LibFuzzer, Clang only)

- CSTP parser, HTTP parser, TOML parser, protobuf, TLS ClientHello

### Coverage Target

- Unit tests: >= 80% line coverage
- Fuzz: 1M iterations per target in CI

---

## Security

### Reporting Vulnerabilities

**DO NOT** report security vulnerabilities via public GitHub issues.

Please report security issues privately to: security@wolfguard.org

We will respond within 48 hours and work with you on disclosure.

### Security Features

- FIPS 140-3 certified cryptography (wolfSSL)
- wolfSentry IDPS with connection-level filtering
- seccomp + Landlock sandbox on all worker processes
- Per-user nftables firewall rules (libmnl + libnftnl)
- Constant-time cryptographic comparisons
- Secrets zeroed after use (`ForceZero()` / `explicit_bzero()`)
- Hardening flags: `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie`
- External security audit planned

---

## Performance

### Validated Results (PoC)

| Metric | Result |
|--------|--------|
| TLS Handshake | **50% faster** than GnuTLS baseline |
| Decision | GO -- proceed with wolfSSL |

### Architecture Advantages

- io_uring: zero-copy receive with buffer rings, multishot accept, batched submissions
- 1 worker per CPU core: no cross-thread contention
- mimalloc with MI_SECURE: per-worker heaps
- Stateless workers: horizontal scaling, no sticky sessions

---

## Compatibility

### Client Compatibility

| Client | Version | Status | Notes |
|--------|---------|--------|-------|
| Cisco Secure Client | 5.0+ | Target | 100% compatibility required |
| OpenConnect CLI | 8.x, 9.x | Target | Full support |
| OpenConnect GUI | 1.5+ | Target | Full support |
| NetworkManager | 1.x | Target | GNOME integration |

### Platform Support

| Platform | Architectures | Status |
|----------|--------------|--------|
| Oracle Linux | x86_64, aarch64 | Primary development platform |
| Fedora | x86_64, aarch64 | Target |
| Ubuntu | x86_64, aarch64 | Target |
| RHEL | x86_64, aarch64 | Target |
| Debian | x86_64, aarch64 | Target |

---

## Contributing

We welcome contributions. Please note:

- This project is in early development
- All contributions must follow C23 conventions and security coding requirements
- All new code must have unit tests (Unity framework)
- Commits must pass: clang-format, clang-tidy, unit tests, sanitizers

### Development Process

1. Check the backlog
2. Create a feature branch: `feature/US-XXX-description`
3. Develop and test with sanitizers enabled
4. Submit PR with context
5. Code review and CI must pass
6. Merge after approval

---

## Documentation

- [Architecture Design](docs/plans/2026-03-07-wolfguard-architecture-design.md)
- [Refactoring Plan](docs/REFACTORING_PLAN.md)
- [Release Policy](docs/RELEASE_POLICY.md)
- [Sprint Planning](docs/agile/SPRINTS.md)
- [Product Backlog](docs/agile/BACKLOG.md)
- [Definition of Done](docs/agile/DEFINITION_OF_DONE.md)

---

## License

wolfguard is licensed under the **GNU General Public License v2.0** (GPLv2).

See [LICENSE](LICENSE) for full text.

### Third-Party Licenses

| Library | License |
|---------|---------|
| wolfSSL | GPLv3 (commercial licenses available from wolfSSL Inc.) |
| wolfSentry | GPLv2 |
| liburing | MIT / LGPL |
| mimalloc | MIT |
| llhttp | MIT |
| c-ares | MIT |
| LZ4 | BSD 2-Clause |
| yyjson | MIT |
| cJSON | MIT |
| tomlc99 | MIT |
| protobuf-c | BSD 2-Clause |
| stumpless | Apache 2.0 |
| linenoise | BSD 2-Clause |
| libseccomp | LGPL 2.1 |
| libmnl | LGPL 2.1+ |
| libnftnl | GPLv2 |
| radcli | BSD |
| liboath | LGPL 2.1+ |

---

## Acknowledgments

### Protocol Reference

This project implements the OpenConnect VPN protocol as documented in [ocserv](https://gitlab.com/openconnect/ocserv) by Nikos Mavrogiannopoulos and contributors. We are grateful for their foundational work on the protocol and server.

### Libraries

Special thanks to the teams behind:
- [wolfSSL](https://www.wolfssl.com/) -- High-performance TLS/DTLS library
- [wolfSentry](https://www.wolfssl.com/products/wolfsentry/) -- Embedded IDPS engine
- [liburing](https://github.com/axboe/liburing) -- io_uring interface library
- [llhttp](https://github.com/nodejs/llhttp) -- Fast HTTP parser
- [stumpless](https://github.com/goatshriek/stumpless) -- Structured logging
- [mimalloc](https://github.com/microsoft/mimalloc) -- Performance allocator
- [tomlc99](https://github.com/cktan/tomlc99) -- TOML parser
- [yyjson](https://github.com/ibireme/yyjson) -- Fast JSON library

---

## Disclaimer

**WARNING**: This project is in early development. It is NOT ready for production use.

- Expect breaking changes
- No security guarantees yet (external audit pending)
- Client compatibility not yet fully tested

For production deployments, use stable [ocserv](https://gitlab.com/openconnect/ocserv) releases.

---

## Contact

- **Security**: security@wolfguard.org
- **GitHub Issues**: [Bug reports and feature requests](https://github.com/dantte-lp/wolfguard/issues)
- **GitHub Discussions**: [Community discussions](https://github.com/dantte-lp/wolfguard/discussions)

---

**Generated with Claude Code**
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
