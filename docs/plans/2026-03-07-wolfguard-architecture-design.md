# ringwall Server Architecture Design

**Date**: 2026-03-07
**Status**: Approved
**Team**: 1 developer + Claude

## 1. System Architecture

### Three-Process Model

```
                    ┌─────────────┐
                    │    Main     │  (root → drops to unprivileged)
                    │  pidfd_spawn│
                    │  signalfd   │
                    └──┬──────┬───┘
                       │      │
              SOCK_SEQPACKET  SOCK_SEQPACKET
              + protobuf-c    + protobuf-c
                       │      │
            ┌──────────┘      └──────────────┐
            ▼                                ▼
    ┌───────────────┐              ┌─────────────────┐
    │   sec-mod     │              │  Worker (×N)    │
    │  (unprivileged)│              │  (unprivileged) │
    │               │              │  + seccomp      │
    │  PAM/RADIUS/  │              │  + Landlock     │
    │  LDAP/TOTP/   │              │                 │
    │  cert auth    │              │  io_uring loop  │
    │  session store│              │  wolfSSL TLS    │
    └───────────────┘              │  TUN I/O        │
                                   │  wolfSentry     │
                                   └─────────────────┘
```

- **Main**: Privileged startup, then drops privileges. Spawns/monitors sec-mod and workers via `pidfd_spawn` (glibc 2.39+). Monitors via `IORING_OP_WAITID` (kernel 6.7+). Handles SIGHUP config reload via signalfd.
- **sec-mod**: Authentication only. Holds session cookies (survives worker crashes). Communicates with Main/Workers via SOCK_SEQPACKET + protobuf-c.
- **Workers**: 1 per CPU core. All client connections multiplexed via io_uring. Sandboxed with seccomp + Landlock. Stateless — crash recovery via cookie-based reconnect to any worker.

### Platform Requirements

- Linux kernel 6.7+ (IORING_OP_WAITID)
- glibc 2.39+ (pidfd_spawn)
- No BSD support (io_uring is Linux-only)

### I/O Subsystem

Single I/O subsystem: **liburing everywhere**. No libuv.

- Network: `IORING_OP_ACCEPT` (multishot), `IORING_OP_RECV`/`IORING_OP_SEND`
- TUN: `IORING_OP_READ`/`IORING_OP_WRITE` (no SQPOLL — broken with TUN per liburing issue #239)
- Timers: `IORING_OP_TIMEOUT`
- Signals: signalfd + `IORING_OP_READ`
- Buffer management: `IORING_OP_PROVIDE_BUFFERS` (kernel picks buffers)

## 2. Components and Modules

### Source Tree Layout

```
src/
├── io/                    # io_uring abstraction layer
│   ├── uring.c/h         # Ring setup, SQE/CQE, event loop
│   ├── bufring.c/h       # Buffer ring management
│   └── timer.c/h         # Timeout management
├── crypto/                # TLS abstraction
│   ├── tls_wolfssl.c/h   # wolfSSL native API (TLS 1.3, DTLS 1.2/1.3)
│   └── tls_gnutls.c/h    # GnuTLS fallback backend
├── network/               # Network protocols
│   ├── http.c/h          # llhttp integration (CSTP HTTP phase)
│   ├── cstp.c/h          # CSTP framing and packet handling
│   ├── dtls.c/h          # DTLS channel (master secret bootstrap)
│   ├── dpd.c/h           # Dead Peer Detection state machine
│   ├── tun.c/h           # TUN device allocation and I/O
│   ├── channel.c/h       # CSTP/DTLS channel switching
│   ├── compress.c/h      # Compression abstraction (LZ4/LZS)
│   ├── compress_lzs.c/h  # LZS implementation (Cisco compat)
│   ├── rest.c/h          # REST API (llhttp + io_uring + wolfSSL)
│   └── split.c/h         # Split tunnel / split DNS
├── ipc/                   # Inter-process communication
│   ├── proto/            # .proto definitions
│   ├── messages.c/h      # Protobuf-c encode/decode
│   └── transport.c/h     # SOCK_SEQPACKET send/recv
├── auth/                  # Authentication backends
│   ├── pam.c/h           # PAM
│   ├── radius.c/h        # RADIUS (radcli)
│   ├── ldap.c/h          # Direct LDAP/AD (libldap)
│   ├── totp.c/h          # TOTP/HOTP (liboath)
│   ├── cert.c/h          # Certificate auth + template filtering
│   └── plugin.c/h        # dlopen-based plugin API
├── core/                  # Core VPN logic
│   ├── main.c            # Main process entry, process management
│   ├── secmod.c/h        # sec-mod process
│   ├── worker.c/h        # Worker process, connection multiplexing
│   └── session.c/h       # Session cookie management
├── security/              # Security subsystems
│   ├── wolfsentry.c/h    # wolfSentry IDPS integration
│   ├── sandbox.c/h       # seccomp + Landlock
│   └── firewall.c/h      # Per-user nftables (libmnl + libnftnl)
├── config/                # Configuration
│   ├── toml.c/h          # TOML parser (tomlc99)
│   └── config.c/h        # Config structures, validation, reload
├── log/                   # Logging
│   └── stumpless.c/h     # Structured logging (RFC 5424, stumpless)
├── metrics/               # Monitoring
│   └── prometheus.c/h    # Custom Prometheus text exposition
├── utils/                 # Utilities
│   └── memory.c/h        # mimalloc setup, arena allocator
└── occtl/                 # Control utility
    ├── rwctl.c           # CLI entry point
    ├── cli_parser.c/h    # Juniper-style command parser (linenoise)
    └── pki.c/h           # Mini CA (wolfCrypt)
```

### Key Interfaces

```c
// io_uring wrapper (src/io/uring.h)
rw_io_ctx_t *rw_io_init(uint32_t queue_depth, uint32_t flags);
void rw_io_prep_accept(rw_io_ctx_t *ctx, int fd, rw_io_cb cb);
void rw_io_prep_recv(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, rw_io_cb cb);
void rw_io_prep_timeout(rw_io_ctx_t *ctx, uint64_t ms, rw_io_cb cb);

// Auth plugin API (src/auth/plugin.h)
typedef struct {
    const char *name;
    int (*init)(const char *config);
    int (*authenticate)(const rw_auth_request_t *req, rw_auth_result_t *res);
    void (*cleanup)(void);
} rw_auth_plugin_t;
```

## 3. Data Flow and Protocol Handling

### Connection Lifecycle (Cisco Secure Client)

```
Client                    Main (Worker)                sec-mod
  |                           |                           |
  |--TLS ClientHello--------->|                           |
  |   wolfSentry check <------|                           |
  |   (REJECT -> close)       |                           |
  |                           |                           |
  |--TLS Handshake----------->|                           |
  |   wolfSSL_accept()        |                           |
  |                           |                           |
  |--HTTP POST /auth--------->|                           |
  |   llhttp parse            |                           |
  |                           |--SOCK_SEQPACKET---------->|
  |                           |  AUTH_REQUEST (protobuf)   |
  |                           |                           |
  |                           |<-AUTH_RESPONSE------------|
  |                           |  (cookie + config)        |
  |<-HTTP 200 + XML-----------|                           |
  |   (session cookie)        |                           |
  |                           |                           |
  |--HTTP CONNECT /CSTPID---->|                           |
  |   CSTP tunnel established |                           |
  |   TUN fd allocated        |                           |
  |                           |                           |
  |--DTLS ClientHello-------->|                           |
  |   X-DTLS-Master-Secret    |                           |
  |   DTLS 1.2 session        |                           |
  |                           |                           |
  |====CSTP/DTLS data========>|<====TUN read/write=======>|
```

### VPN Data Path (hot path)

```
Network --> io_uring CQE --> wolfSSL_read() --> decompress --> TUN write
                                                                  |
TUN read <-- io_uring CQE <-- wolfSSL_write() <-- compress <-----+
```

All I/O via io_uring:
- Multishot accept for new connections
- Buffer rings for zero-copy receive
- TUN I/O via IORING_OP_READ/WRITE (no SQPOLL)
- Batch SQE submission

### Channel Selection

```c
typedef enum {
    RW_CHANNEL_CSTP_ONLY,      // DTLS not established
    RW_CHANNEL_DTLS_PRIMARY,   // DTLS active, CSTP for control
    RW_CHANNEL_DTLS_FALLBACK,  // DTLS failed DPD, falling back
} rw_channel_state_t;
```

- Data prefers DTLS (lower overhead, UDP)
- CSTP always maintained as fallback
- DPD every 30s, 3 missed = channel dead
- Both dead = session timeout (default 5min)

### Split Tunneling

Routes from TOML per-group config, sent via CSTP headers:
```
X-CSTP-Split-Include: 10.0.0.0/255.0.0.0
X-CSTP-Split-Exclude: 10.0.1.0/255.255.255.0
X-CSTP-Split-DNS: corp.example.com
X-CSTP-DNS: 10.0.0.53
```

Client-side routing — no server-side decisions.

### Compression

```
Outbound: plaintext -> compress (LZ4/LZS) -> wolfSSL_write() -> network
Inbound:  network -> wolfSSL_read() -> decompress -> TUN
```

- Cisco clients: LZS (mandatory) or LZ4
- Own client: LZ4 (lowest latency, best for already-encrypted traffic)
- Negotiated via X-CSTP-Accept-Encoding headers
- Disabled for already-compressed data (entropy heuristic)

## 4. Error Handling and Resilience

### Error Categories

| Category | Examples | Action |
|----------|----------|--------|
| Fatal | OOM, io_uring setup fail, TUN alloc fail | Log, notify Main, worker exit (Main restarts) |
| Connection | TLS error, DPD timeout, auth fail | Close connection, cleanup session, log |
| Transient | EAGAIN, partial write, DNS timeout | Retry with backoff, continue |

### Worker Crash Recovery

1. Main detects via signalfd + IORING_OP_WAITID
2. Main logs crash reason (exit code, signal)
3. Main respawns worker via pidfd_spawn
4. Client detects DPD timeout, reconnects with cookie
5. sec-mod validates cookie, assigns to any worker (no sticky sessions)

### Resource Limits

```c
typedef struct {
    uint32_t max_connections;
    uint32_t max_handshakes;       // concurrent TLS handshakes
    size_t   max_rx_buffer;        // per-connection receive buffer
    uint64_t idle_timeout_ms;
    uint32_t max_routes_per_user;
} rw_worker_limits_t;
```

### Sandbox Failures

- seccomp: SECCOMP_RET_KILL_PROCESS -> worker dies -> Main restarts
- Landlock: EACCES -> logged as security event -> connection refused

## 5. Testing Strategy

### Test Pyramid

- **Unit (80%)**: Unity framework, `tests/unit/test_*.c`, one per module
- **Integration (15%)**: `tests/integration/`, multi-process with real sockets
- **E2E (5%)**: `tests/e2e/`, full VPN session with openconnect client

### Unit Test Files

- test_io_uring.c, test_tls_wolfssl.c, test_cstp.c, test_auth_pam.c
- test_config_toml.c, test_ipc_proto.c, test_session.c, test_compress.c
- test_firewall.c, test_wolfsentry.c, test_rest_api.c, test_metrics.c, test_pki.c

### Fuzz Targets (LibFuzzer, Clang only)

- fuzz_cstp_parser.c, fuzz_http_parser.c, fuzz_toml_parser.c
- fuzz_protobuf.c, fuzz_tls_client_hello.c

### Sanitizer Matrix

| Sanitizer | Compiler | When |
|-----------|----------|------|
| ASan + UBSan | Clang + GCC | Every commit |
| MSan | Clang only | Every commit |
| TSan | Clang | Before merge |

### Coverage Target

- Unit: >= 80% line coverage
- Fuzz: 1M iterations per target in CI

## 6. Sprint Roadmap

### Overview (8 sprints, ~2 weeks each)

| Sprint | Focus | Weeks |
|--------|-------|-------|
| S1 | Foundation: io_uring, process model, IPC, config | 1-2 |
| S2 | TLS & Auth: wolfSSL, PAM, sec-mod, sessions | 3-4 |
| S3 | VPN Tunnel: CSTP, TUN I/O, data path, DPD | 5-6 |
| S4 | DTLS & Compression: DTLS 1.2, channel switch, LZ4/LZS | 7-8 |
| S5 | Security: wolfSentry, seccomp, Landlock, nftables | 9-10 |
| S6 | Auth Expansion: RADIUS, LDAP, TOTP, plugin API | 11-12 |
| S7 | Management: rwctl CLI, REST API, metrics, logging | 13-14 |
| S8 | PKI & Polish: mini CA, split tunnel/DNS, E2E, docs | 15-16 |

### S1 — Foundation (weeks 1-2)

- `src/io/` — io_uring wrapper (accept, read, write, timeout, buffer rings)
- `src/core/main.c` — Main process, pidfd_spawn workers, signalfd
- `src/ipc/` — SOCK_SEQPACKET + protobuf-c message definitions
- `src/config/` — TOML parser (tomlc99), config structures
- `src/utils/memory.c` — mimalloc setup, arena allocator for IPC
- Unit tests for all above
- CI: CMake presets, sanitizers, clang-format/tidy

### S2 — TLS & Auth (weeks 3-4)

- `src/crypto/tls_wolfssl.c` — wolfSSL context, callback I/O, cipher config
- `src/auth/pam.c` — PAM authentication via sec-mod
- `src/core/secmod.c` — sec-mod process, auth request/response IPC
- `src/core/session.c` — session cookie create/validate (constant-time)
- `src/network/http.c` — llhttp integration, CSTP HTTP negotiation
- Integration test: full TLS handshake + PAM auth

### S3 — VPN Tunnel (weeks 5-6)

- `src/network/cstp.c` — CSTP framing, packet encode/decode
- `src/network/tun.c` — TUN device alloc, io_uring read/write
- `src/core/worker.c` — worker process, connection multiplexing
- `src/network/dpd.c` — Dead Peer Detection state machine
- Data path: network -> TLS -> TUN round-trip working
- Integration test: tunnel up, ping through

### S4 — DTLS & Compression (weeks 7-8)

- `src/network/dtls.c` — DTLS 1.2 with master secret bootstrap (Cisco)
- `src/network/channel.c` — CSTP/DTLS channel switching logic
- `src/network/compress.c` — LZ4, LZS codec abstraction
- `src/network/compress_lzs.c` — LZS implementation (Cisco compat)
- Integration test: DTLS session, channel fallback

### S5 — Security Hardening (weeks 9-10)

- `src/security/wolfsentry.c` — wolfSentry init, connection checking, JSON config
- `src/security/sandbox.c` — seccomp BPF filter, Landlock rules
- `src/security/firewall.c` — nftables per-user chains (libmnl + libnftnl)
- wolfSSL AcceptFilter integration
- Fuzz targets for all parsers

### S6 — Auth Expansion (weeks 11-12)

- `src/auth/radius.c` — RADIUS via radcli
- `src/auth/ldap.c` — Direct LDAP/AD via libldap
- `src/auth/totp.c` — TOTP/HOTP via liboath
- `src/auth/plugin.c` — Plugin API (dlopen-based)
- `src/auth/cert.c` — Certificate authentication, template filtering

### S7 — Management (weeks 13-14)

- `src/occtl/rwctl.c` — Juniper-style CLI (operational + config mode)
- `src/occtl/cli_parser.c` — Command parser with linenoise
- `src/network/rest.c` — REST API (llhttp + io_uring + wolfSSL)
- `src/metrics/prometheus.c` — Custom Prometheus text exposition
- `src/log/stumpless.c` — Structured logging (RFC 5424)

### S8 — PKI & Polish (weeks 15-16)

- `src/occtl/pki.c` — Mini CA (wolfCrypt: keygen, CSR, sign, CRL)
- `src/network/split.c` — Split tunnel routes, split DNS
- E2E tests with openconnect client
- Documentation, deployment guide
- Performance benchmarks

## 7. Technology Stack

### Core

| Library | Version | Role |
|---------|---------|------|
| wolfSSL | 5.8.4+ | TLS 1.3 / DTLS 1.2 / DTLS 1.3 |
| wolfSentry | 1.6.3+ | IDPS / dynamic firewall |
| liburing | 2.7+ | All I/O (network, TUN, timers, signals) |
| mimalloc | 3.1.5+ | Memory allocator (MI_SECURE) |

### Network & Protocol

| Library | Version | Role |
|---------|---------|------|
| llhttp | 9.3.1+ | HTTP parser (CSTP, REST API) |
| c-ares | 1.34+ | Async DNS resolver |
| LZ4 | 1.10+ | Real-time compression |

### Data & Config

| Library | Version | Role |
|---------|---------|------|
| tomlc99 | latest | Static configuration |
| yyjson | 0.12+ | Fast JSON (REST API, metrics) |
| cJSON | 1.7.19+ | Simple JSON (wolfSentry config) |
| protobuf-c | 1.5.1+ | IPC serialization |

### Auth

| Library | Version | Role |
|---------|---------|------|
| PAM | system | Pluggable auth (MVP) |
| radcli | 1.4+ | RADIUS client |
| libldap | 2.6+ | Direct LDAP/AD |
| liboath | 2.6+ | TOTP/HOTP |

### Security & Firewall

| Library | Version | Role |
|---------|---------|------|
| libseccomp | 2.5+ | Syscall sandbox |
| libmnl | 1.0.5+ | Netlink minimal |
| libnftnl | 1.3.1+ | nftables rules |

### Management

| Library | Version | Role |
|---------|---------|------|
| stumpless | latest | Structured logging (RFC 5424) |
| linenoise | latest | CLI line editing |

## 8. Key Design Decisions

1. **io_uring only** — no libuv, no BSD support, maximum performance on Linux 6.7+
2. **SOCK_SEQPACKET + protobuf-c** — message-boundary IPC, no framing code, arena allocator
3. **pidfd_spawn + IORING_OP_WAITID** — modern process management, no signal races
4. **Stateless workers** — any worker serves any client, cookie-based reconnect
5. **wolfSSL native API** — not OpenSSL compat layer
6. **DTLS 1.2 for Cisco** — Cisco Secure Client doesn't support DTLS 1.3
7. **stumpless for logging** — RFC 5424 structured, replaces zlog
8. **Custom Prometheus** — ~500-800 lines, no libprom dependency
9. **Direct LDAP** — no sssd dependency, cross-platform auth
10. **TOML + JSON config** — TOML for static, JSON for wolfSentry rules and REST API

## 9. Future Considerations (not in scope)

- **ringwall-connect** client (own VPN client, DTLS 1.3)
- **Cluster mode** (multi-server, session sync)
- **XDP** fast path (line-rate packet filtering)
- **WireGuard protocol** support (alternative to CSTP)
- **IPv6** full support (after IPv4 MVP)
