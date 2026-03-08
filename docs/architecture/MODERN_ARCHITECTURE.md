# ringwall: Modern VPN Architecture Design

**Document Version**: 2.0
**Date**: 2026-03-07
**Status**: Approved
**Target**: ringwall v2.0.0 (C23, ISO/IEC 9899:2024)
**Platform**: Linux only (kernel 6.7+, glibc 2.39+)

---

## Executive Summary

ringwall is a high-performance VPN server implementing the AnyConnect/OpenConnect protocol, built entirely in C23. The architecture is designed around three core decisions: io_uring as the single I/O subsystem (no libuv), a three-process privilege-separated model (Main, sec-mod, Workers), and Linux-only deployment targeting kernel 6.7+ with glibc 2.39+.

All network I/O, TUN I/O, timers, and signal handling flow through liburing. Workers are stateless and sandboxed with seccomp BPF and Landlock. Session state lives in sec-mod, enabling transparent worker crash recovery via cookie-based reconnection. The cryptographic layer uses wolfSSL's native API exclusively (not the OpenSSL compatibility shim), with wolfSentry providing pre-TLS intrusion detection.

---

## Architecture Philosophy

### Core Principles

1. **io_uring everywhere** -- Single I/O subsystem via liburing. No libuv, no epoll, no poll. All network I/O, TUN I/O, timers, and signals go through io_uring submission/completion queues.
2. **Linux only** -- Kernel 6.7+ for `IORING_OP_WAITID`, glibc 2.39+ for `pidfd_spawn`. No BSD, no macOS, no Windows.
3. **Three-process privilege separation** -- Main (process management), sec-mod (authentication and session cookies), Workers (VPN data plane). Each runs with minimal privileges.
4. **Stateless workers** -- Any worker serves any client. Session cookies live in sec-mod. Worker crashes are invisible to clients (cookie-based reconnect).
5. **Pure C23** -- No C++ dependencies. Modern C23 features: `[[nodiscard]]`, `nullptr`, `constexpr`, `typeof`, `_Atomic`, `_Static_assert`.
6. **Defense in depth** -- wolfSentry IDPS (pre-TLS filtering), seccomp BPF (syscall allowlist), Landlock (filesystem isolation), nftables (per-user firewall chains).

---

## System Architecture

### Three-Process Model

```
                    +---------------+
                    |     Main      |  (root -> drops to unprivileged)
                    |  pidfd_spawn  |
                    |   signalfd    |
                    +---+-------+---+
                        |       |
               SOCK_SEQPACKET  SOCK_SEQPACKET
               + protobuf-c    + protobuf-c
                        |       |
             +----------+       +----------------+
             v                                   v
    +-----------------+              +---------------------+
    |    sec-mod      |              |   Worker (x N)      |
    |  (unprivileged) |              |   (unprivileged)    |
    |                 |              |   + seccomp BPF     |
    |  PAM / RADIUS / |              |   + Landlock        |
    |  LDAP / TOTP /  |              |                     |
    |  cert auth      |              |   io_uring loop     |
    |  session store  |              |   wolfSSL TLS/DTLS  |
    +-----------------+              |   TUN I/O           |
                                     |   wolfSentry IDPS   |
                                     +---------------------+
```

#### Main Process

- Privileged startup, then drops privileges after binding sockets and allocating TUN devices.
- Spawns and monitors sec-mod and workers via `pidfd_spawn` (glibc 2.39+).
- Monitors child processes via `IORING_OP_WAITID` (kernel 6.7+) -- no signal races, no waitpid loops.
- Handles `SIGHUP` config reload via `signalfd` + `IORING_OP_READ`.
- Distributes listening sockets to workers.

#### sec-mod Process

- Sole owner of authentication logic and session cookie storage.
- Communicates with Main and Workers over `SOCK_SEQPACKET` + protobuf-c.
- Survives worker crashes -- session cookies are never lost.
- Runs unprivileged with no network access.

#### Worker Processes

- One per CPU core. All client connections multiplexed via a single io_uring event loop.
- Sandboxed with seccomp BPF (syscall allowlist) and Landlock (filesystem restriction).
- Stateless -- crash recovery works by client reconnecting with its session cookie, which sec-mod validates and assigns to any available worker (no sticky sessions).

---

## I/O Subsystem

### io_uring as the Universal I/O Layer

Every I/O operation in ringwall goes through io_uring. There is no libuv, no epoll fallback, no abstraction layer that hides the ring.

| Operation | io_uring Op | Notes |
|-----------|-------------|-------|
| TCP accept | `IORING_OP_ACCEPT` | Multishot -- one SQE, many CQEs |
| TCP/UDP recv | `IORING_OP_RECV` | With provided buffer rings |
| TCP/UDP send | `IORING_OP_SEND` | Batched SQE submission |
| TUN read | `IORING_OP_READ` | No SQPOLL (broken with TUN, liburing issue #239) |
| TUN write | `IORING_OP_WRITE` | No SQPOLL (same reason) |
| Timers | `IORING_OP_TIMEOUT` | DPD, idle timeout, handshake timeout |
| Signals | `signalfd` + `IORING_OP_READ` | Config reload, child monitoring |
| Process wait | `IORING_OP_WAITID` | Worker crash detection (kernel 6.7+) |

### Buffer Management

- `IORING_OP_PROVIDE_BUFFERS` -- kernel picks buffers from a provided buffer ring.
- Eliminates pre-allocated per-connection buffers for receive operations.
- Application refills the ring as buffers are consumed.

### Key Interface

```c
// src/io/uring.h
rw_io_ctx_t *rw_io_init(uint32_t queue_depth, uint32_t flags);
void rw_io_prep_accept(rw_io_ctx_t *ctx, int fd, rw_io_cb cb);
void rw_io_prep_recv(rw_io_ctx_t *ctx, int fd, void *buf, size_t len, rw_io_cb cb);
void rw_io_prep_timeout(rw_io_ctx_t *ctx, uint64_t ms, rw_io_cb cb);
```

---

## VPN Data Path

### Hot Path

```
Inbound:   Network -> io_uring CQE -> wolfSSL_read() -> decompress -> TUN write
Outbound:  TUN read -> io_uring CQE -> compress -> wolfSSL_write() -> Network
```

All steps in the hot path execute within a single worker process, on a single thread, driven by the io_uring completion queue. No locks, no cross-thread communication.

### Connection Lifecycle

```
Client                    Worker                     sec-mod
  |                         |                           |
  |--TLS ClientHello------->|                           |
  |   wolfSentry check      |                           |
  |   (REJECT -> close)     |                           |
  |                         |                           |
  |--TLS Handshake--------->|                           |
  |   wolfSSL_accept()      |                           |
  |                         |                           |
  |--HTTP POST /auth------->|                           |
  |   llhttp parse          |                           |
  |                         |--SOCK_SEQPACKET---------->|
  |                         |  AUTH_REQUEST (protobuf)   |
  |                         |                           |
  |                         |<-AUTH_RESPONSE------------|
  |                         |  (cookie + config)        |
  |<-HTTP 200 + XML---------|                           |
  |   (session cookie)      |                           |
  |                         |                           |
  |--HTTP CONNECT /CSTPID-->|                           |
  |   CSTP tunnel established                           |
  |   TUN fd allocated      |                           |
  |                         |                           |
  |--DTLS ClientHello------>|                           |
  |   X-DTLS-Master-Secret  |                           |
  |   DTLS 1.2 session      |                           |
  |                         |                           |
  |====CSTP/DTLS data======>|<====TUN read/write=======>|
```

---

## Protocol Handling

### CSTP (Cisco Secure Tunnel Protocol)

- Runs over TCP with TLS 1.3 (wolfSSL native API).
- Always maintained as the control channel and data fallback.
- HTTP negotiation phase parsed by llhttp.
- Framing: 8-byte header + payload.

### DTLS (Datagram TLS)

- Preferred channel for VPN data (lower overhead, UDP, no head-of-line blocking).
- DTLS 1.2 with master secret bootstrap for Cisco Secure Client compatibility.
- DTLS 1.3 reserved for future ringwall-connect client.
- Session bootstrapped from CSTP via `X-DTLS-Master-Secret` header.

### DPD State Machine

Dead Peer Detection runs on both CSTP and DTLS channels with three states:

```c
typedef enum {
    RW_CHANNEL_CSTP_ONLY,      // DTLS not established or not supported
    RW_CHANNEL_DTLS_PRIMARY,   // DTLS active, CSTP for control only
    RW_CHANNEL_DTLS_FALLBACK,  // DTLS failed DPD, falling back to CSTP
} rw_channel_state_t;
```

- DPD probes every 30 seconds.
- 3 consecutive missed probes = channel declared dead.
- Both channels dead = session timeout (default 5 minutes).

### Compression

```
Outbound: plaintext -> compress (LZ4/LZS) -> wolfSSL_write() -> network
Inbound:  network -> wolfSSL_read() -> decompress -> TUN
```

| Algorithm | Use Case | Notes |
|-----------|----------|-------|
| LZ4 | Real-time, lowest latency | Default for all clients |
| LZS | Cisco compatibility | Mandatory for Cisco Secure Client |

Negotiated via `X-CSTP-Accept-Encoding` headers. Disabled for already-compressed data using an entropy heuristic.

### Split Tunneling

Routes configured per-group in TOML, delivered via CSTP headers:
```
X-CSTP-Split-Include: 10.0.0.0/255.0.0.0
X-CSTP-Split-Exclude: 10.0.1.0/255.255.255.0
X-CSTP-Split-DNS: corp.example.com
X-CSTP-DNS: 10.0.0.53
```

Routing decisions are client-side. The server only distributes the route table.

---

## IPC Design

### Transport: SOCK_SEQPACKET

All inter-process communication uses `SOCK_SEQPACKET` Unix domain sockets.

- **Message boundaries preserved by the kernel** -- no application-level framing code needed.
- Each `send()` / `recv()` is one complete message.
- Reliable, ordered, connection-oriented.

### Serialization: protobuf-c

- All IPC messages defined in `.proto` files under `src/ipc/proto/`.
- Encoded/decoded with protobuf-c.
- Arena allocator for IPC message memory -- bulk free after processing, no per-field cleanup.

### Message Flow

| Direction | Message | Content |
|-----------|---------|---------|
| Worker -> sec-mod | `AUTH_REQUEST` | Username, password, certificate, client IP |
| sec-mod -> Worker | `AUTH_RESPONSE` | Session cookie, VPN config, routes, DNS |
| Worker -> Main | `WORKER_STATUS` | Connection count, memory usage, errors |
| Main -> Worker | `CONFIG_RELOAD` | Updated configuration after SIGHUP |

---

## Security Architecture

### Defense in Depth (ordered from outermost to innermost)

1. **wolfSentry IDPS** -- Pre-TLS connection filtering. Rate limiting, IP reputation, GeoIP blocking. Configured via JSON rules. Runs before `wolfSSL_accept()` so malicious connections never reach the TLS stack.

2. **nftables per-user chains** -- Dynamic firewall rules created per authenticated user via libmnl + libnftnl. Restrict VPN clients to authorized network segments.

3. **TLS 1.3 (wolfSSL)** -- All control and data channels encrypted. Native wolfSSL API (not OpenSSL compat). FIPS-capable configuration.

4. **seccomp BPF** -- Syscall allowlist per process type. Workers have a minimal set (read, write, io_uring_enter, close, mmap, etc.). Violation = `SECCOMP_RET_KILL_PROCESS`, Main restarts the worker.

5. **Landlock** -- Filesystem access restriction. Workers can only access their TUN device and Unix socket. No access to configuration files, certificates, or system directories.

6. **Process isolation** -- Each worker runs unprivileged. sec-mod has no network access. Main drops privileges after startup.

### Secure Coding Practices

- Constant-time comparisons: `wolfSSL_ConstantCompare()` for all crypto comparisons.
- Secret zeroing: `ForceZero()` / `explicit_bzero()` after use.
- `[[nodiscard]]` on all public API functions.
- Compiler hardening: `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie`.
- Linker hardening: `-Wl,-z,relro -Wl,-z,now`.
- Banned functions: `strcpy`, `sprintf`, `gets`, `strcat`, `atoi`, `system()`.

---

## Configuration System

### Dual-Format Design

| Format | Purpose | Library |
|--------|---------|---------|
| TOML | Static server configuration | tomlc99 |
| JSON | wolfSentry IDPS rules, REST API payloads | cJSON / yyjson |

### TOML Configuration

Static configuration loaded at startup, reloaded on `SIGHUP`:
- Server settings (bind address, ports, TLS certificates)
- Per-group VPN settings (routes, DNS, split tunnel, compression)
- Authentication backend selection and ordering
- Resource limits (max connections, timeouts, buffer sizes)

### JSON Configuration

- wolfSentry rules: IP allowlists/denylists, rate limits, GeoIP policies.
- REST API: Runtime queries and dynamic configuration changes.

---

## Management

### rwctl CLI

Juniper-style CLI with two modes:

- **Operational mode**: Show sessions, statistics, disconnect users, view logs.
- **Configuration mode**: Edit running configuration, commit changes.

Line editing via linenoise. Communicates with the server over a Unix socket.

### REST API

- HTTP parser: llhttp.
- I/O: io_uring.
- TLS: wolfSSL.
- Endpoints for session management, statistics, health checks, and dynamic configuration.
- JSON request/response via yyjson.

### Metrics

Custom Prometheus text exposition format (~500-800 lines of C). No libprom dependency. Exposes:
- Connection counts (active, total, by group)
- Handshake latency histogram
- Throughput counters (bytes in/out)
- Worker health and resource usage
- Authentication success/failure rates

### Logging

stumpless library providing RFC 5424 structured logging. Key fields:
- Severity, facility, timestamp, process ID
- Structured data elements for session ID, client IP, username, event type

### Mini CA (rwctl pki)

`rwctl pki` subcommands using wolfCrypt:
- Key generation (RSA, ECC)
- CSR creation and signing
- Certificate revocation list (CRL) management
- Suitable for small deployments without external PKI

---

## Technology Stack

### Core

| Library | Version | Role |
|---------|---------|------|
| wolfSSL | 5.8.4+ | TLS 1.3, DTLS 1.2, DTLS 1.3 |
| wolfSentry | 1.6.3+ | IDPS, dynamic firewall, pre-TLS filtering |
| liburing | 2.7+ | All I/O (network, TUN, timers, signals) |
| mimalloc | 3.1.5+ | Memory allocator (MI_SECURE mode) |

### Network and Protocol

| Library | Version | Role |
|---------|---------|------|
| llhttp | 9.3.1+ | HTTP parser (CSTP negotiation, REST API) |
| c-ares | 1.34+ | Async DNS resolver |
| LZ4 | 1.10+ | Real-time compression |

### Data and Configuration

| Library | Version | Role |
|---------|---------|------|
| tomlc99 | latest | Static TOML configuration |
| yyjson | 0.12+ | Fast JSON (REST API, metrics) |
| cJSON | 1.7.19+ | Simple JSON (wolfSentry config) |
| protobuf-c | 1.5.1+ | IPC serialization |

### Authentication

| Library | Version | Role |
|---------|---------|------|
| PAM | system | Pluggable auth (MVP) |
| radcli | 1.4+ | RADIUS client |
| libldap | 2.6+ | Direct LDAP/AD (no sssd) |
| liboath | 2.6+ | TOTP/HOTP |

### Security and Firewall

| Library | Version | Role |
|---------|---------|------|
| libseccomp | 2.5+ | Syscall sandbox (seccomp BPF) |
| libmnl | 1.0.5+ | Netlink minimal library |
| libnftnl | 1.3.1+ | nftables rule management |

### Management and Observability

| Library | Version | Role |
|---------|---------|------|
| stumpless | latest | Structured logging (RFC 5424) |
| linenoise | latest | CLI line editing (rwctl) |

---

## Platform Requirements

| Requirement | Minimum | Reason |
|-------------|---------|--------|
| Linux kernel | 6.7+ | `IORING_OP_WAITID` for process monitoring |
| glibc | 2.39+ | `pidfd_spawn` for process creation |
| C compiler | GCC 15+ or Clang 22+ | C23 standard support |
| Architecture | x86_64, aarch64 | Primary targets |

### Explicitly Not Supported

- **BSD** (FreeBSD, OpenBSD, NetBSD) -- io_uring is Linux-only.
- **macOS** -- No io_uring, no pidfd_spawn, no signalfd.
- **Windows** -- Not a target platform.
- **Kernels below 6.7** -- Missing `IORING_OP_WAITID`.
- **glibc below 2.39** -- Missing `pidfd_spawn`.

---

**Document Status**: Architecture Reference
**Maintainer**: ringwall architecture team
**Review Schedule**: Quarterly
**Next Review**: 2026-06-07
