# User Stories - wolfguard

**Project**: wolfguard v2.0.0
**Last Updated**: 2026-03-07
**Numbering**: US-100 series (Phase 1 implementation)

---

## S1: Foundation (Weeks 1-2)

### US-100: io_uring Event Loop Wrapper
**Sprint**: S1 | **Points**: 5 | **Priority**: P0
**As a** developer, **I want** an io_uring abstraction layer **so that** all network, TUN, timer, and signal I/O uses a single async event loop.
**Acceptance Criteria:**
- [ ] `wg_io_init()` creates io_uring context with configurable queue depth
- [ ] `wg_io_prep_accept()` supports multishot accept (IORING_OP_ACCEPT)
- [ ] `wg_io_prep_recv()` / `wg_io_prep_send()` handle network I/O with callbacks
- [ ] `wg_io_prep_timeout()` manages timers via IORING_OP_TIMEOUT
- [ ] Buffer ring management via IORING_OP_PROVIDE_BUFFERS implemented
- [ ] Unit tests pass under ASan+UBSan and MSan
**Dependencies:** None
**Technical Notes:** Uses liburing 2.7+. No SQPOLL (broken with TUN per liburing issue #239). Batch SQE submission for throughput.

---

### US-101: Process Model with pidfd_spawn
**Sprint**: S1 | **Points**: 5 | **Priority**: P0
**As a** developer, **I want** a process manager using pidfd_spawn and IORING_OP_WAITID **so that** child processes (sec-mod, workers) are spawned and monitored without signal races.
**Acceptance Criteria:**
- [ ] Main process spawns sec-mod and N worker processes via pidfd_spawn (glibc 2.39+)
- [ ] Child process exit detected via IORING_OP_WAITID (kernel 6.7+)
- [ ] Crashed workers automatically respawned with backoff
- [ ] SIGHUP config reload handled via signalfd + io_uring
- [ ] Privilege dropping after startup (root -> unprivileged)
**Dependencies:** US-100
**Technical Notes:** Main starts as root, drops privileges after binding sockets and allocating TUN devices. Workers get 1 per CPU core.

---

### US-102: IPC over SOCK_SEQPACKET + protobuf-c
**Sprint**: S1 | **Points**: 3 | **Priority**: P0
**As a** developer, **I want** IPC message serialization over SOCK_SEQPACKET **so that** Main, sec-mod, and workers exchange structured messages with automatic message boundaries.
**Acceptance Criteria:**
- [ ] .proto definitions for AUTH_REQUEST, AUTH_RESPONSE, SESSION_INFO messages
- [ ] protobuf-c encode/decode with arena allocator for zero-copy
- [ ] SOCK_SEQPACKET transport with send/recv helpers
- [ ] Message round-trip unit test passes
- [ ] Error handling for malformed/truncated messages
**Dependencies:** US-100
**Technical Notes:** SOCK_SEQPACKET provides message boundaries natively -- no framing code needed. Arena allocator from mimalloc for IPC buffers.

---

### US-103: TOML Configuration Parser
**Sprint**: S1 | **Points**: 3 | **Priority**: P0
**As a** VPN administrator, **I want** TOML-based configuration **so that** the server is configured with a human-readable file supporting sections for networking, auth, security, and per-group settings.
**Acceptance Criteria:**
- [ ] TOML file parsed via tomlc99
- [ ] Config structures populated and validated (IP ranges, ports, paths)
- [ ] Per-group configuration sections supported
- [ ] Config reload on SIGHUP without restart
- [ ] Invalid config produces clear error messages with line numbers
**Dependencies:** None
**Technical Notes:** TOML for static config. wolfSentry rules use JSON separately. Config structures defined in `src/config/config.h`.

---

### US-104: mimalloc Integration
**Sprint**: S1 | **Points**: 3 | **Priority**: P0
**As a** developer, **I want** mimalloc as the global allocator with MI_SECURE enabled **so that** memory allocation is fast, resistant to heap exploits, and isolated per worker.
**Acceptance Criteria:**
- [ ] mimalloc linked as global allocator (mi_malloc/mi_free)
- [ ] MI_SECURE=ON for guard pages and randomized allocation
- [ ] wg_malloc/wg_free/wg_realloc wrappers for all project allocations
- [ ] Arena allocator for IPC message buffers
- [ ] Memory leak check clean under ASan
**Dependencies:** None
**Technical Notes:** Per-worker heaps via mi_heap_new(). Arena allocator reduces fragmentation for protobuf-c encode/decode cycles.

---

## S2: TLS & Authentication (Weeks 3-4)

### US-105: wolfSSL TLS 1.3 Integration
**Sprint**: S2 | **Points**: 5 | **Priority**: P0
**As a** VPN user, **I want** TLS 1.3 connections via wolfSSL **so that** my VPN tunnel uses modern, high-performance cryptography.
**Acceptance Criteria:**
- [ ] wolfSSL context initialized with TLS 1.3 cipher suites
- [ ] Callback I/O (wolfSSL_SetIORecv/Send) integrates with io_uring
- [ ] Server certificate and key loaded from config paths
- [ ] Client certificate request optional (for cert auth in S6)
- [ ] TLS handshake completes successfully with openconnect client
- [ ] Session resumption via TLS 1.3 PSK
**Dependencies:** US-100, US-103
**Technical Notes:** Use wolfSSL native API, not OpenSSL compatibility layer. Callback I/O bridges wolfSSL reads/writes to io_uring completions.

---

### US-106: PAM Authentication Backend
**Sprint**: S2 | **Points**: 3 | **Priority**: P0
**As a** VPN administrator, **I want** PAM authentication **so that** VPN users authenticate against system accounts or any PAM-compatible backend.
**Acceptance Criteria:**
- [ ] PAM conversation function implemented for username/password
- [ ] PAM service name configurable (default: "wolfguard")
- [ ] Auth runs in sec-mod process (never in workers)
- [ ] PAM errors mapped to wolfguard auth result codes
- [ ] Passwords zeroed from memory after PAM call completes
**Dependencies:** US-107
**Technical Notes:** PAM calls are blocking -- acceptable because sec-mod is dedicated to auth. ForceZero() or explicit_bzero() for password cleanup.

---

### US-107: sec-mod Authentication Process
**Sprint**: S2 | **Points**: 5 | **Priority**: P0
**As a** developer, **I want** a dedicated sec-mod process **so that** authentication is isolated from data-plane workers and session state survives worker crashes.
**Acceptance Criteria:**
- [ ] sec-mod process spawned by Main via pidfd_spawn
- [ ] Receives AUTH_REQUEST messages from workers via IPC
- [ ] Dispatches to configured auth backend (PAM initially)
- [ ] Returns AUTH_RESPONSE with session cookie and config
- [ ] Session store persists cookies across worker restarts
- [ ] Runs unprivileged (no root)
**Dependencies:** US-101, US-102
**Technical Notes:** sec-mod holds all session state. Workers are stateless -- a crashed worker does not lose sessions. Cookie-based reconnect to any worker.

---

### US-108: Session Cookie Management
**Sprint**: S2 | **Points**: 3 | **Priority**: P0
**As a** VPN user, **I want** session cookies **so that** I can reconnect to any worker after a transient disconnect without re-authenticating.
**Acceptance Criteria:**
- [ ] Cookies generated with cryptographically random bytes (wolfCrypt RNG)
- [ ] Cookie validation uses constant-time comparison (wolfSSL_ConstantCompare)
- [ ] Cookies stored in sec-mod session table with expiry
- [ ] Expired cookies rejected; session cleaned up
- [ ] Cookie memory zeroed on deletion (ForceZero)
**Dependencies:** US-107
**Technical Notes:** Stateless workers rely entirely on sec-mod for session validation. Default session timeout: 5 minutes after last activity.

---

### US-109: HTTP Parsing with llhttp
**Sprint**: S2 | **Points**: 3 | **Priority**: P0
**As a** developer, **I want** llhttp-based HTTP parsing **so that** the CSTP HTTP negotiation phase (POST /auth, CONNECT /CSTPID) is parsed safely and efficiently.
**Acceptance Criteria:**
- [ ] llhttp parses HTTP POST requests for /auth endpoint
- [ ] llhttp parses HTTP CONNECT requests for tunnel establishment
- [ ] HTTP headers extracted: X-CSTP-*, X-DTLS-*, Cookie
- [ ] XML auth response body generated for Cisco client compatibility
- [ ] Request size limits enforced (prevent memory exhaustion)
**Dependencies:** US-105
**Technical Notes:** llhttp already used by upstream ocserv. Integration with wolfSSL_read() output -- parse decrypted HTTP from TLS stream.

---

## S3: VPN Tunnel (Weeks 5-6)

### US-110: CSTP Protocol Framing
**Sprint**: S3 | **Points**: 5 | **Priority**: P0
**As a** VPN user, **I want** CSTP protocol support **so that** I can establish a VPN tunnel compatible with Cisco Secure Client and openconnect.
**Acceptance Criteria:**
- [ ] CSTP frame header encode/decode (type, length, payload)
- [ ] DATA packets carry VPN traffic
- [ ] DPD-REQ / DPD-RESP packets for keepalive
- [ ] DISCONNECT and KEEPALIVE control packets handled
- [ ] Framing unit tests cover all packet types and edge cases
**Dependencies:** US-109
**Technical Notes:** CSTP runs over TLS (after HTTP CONNECT). 8-byte header: STX (1) + type (1) + length (2) + padding (4).

---

### US-111: TUN Device I/O via io_uring
**Sprint**: S3 | **Points**: 5 | **Priority**: P0
**As a** developer, **I want** TUN device I/O driven by io_uring **so that** IP packets flow between the tunnel interface and the encrypted network path without blocking.
**Acceptance Criteria:**
- [ ] TUN device allocated with IFF_TUN | IFF_NO_PI flags
- [ ] TUN reads submitted via IORING_OP_READ (no SQPOLL)
- [ ] TUN writes submitted via IORING_OP_WRITE
- [ ] MTU configured from TOML (default 1406 for CSTP overhead)
- [ ] IP address and routes assigned to TUN interface
**Dependencies:** US-100, US-103
**Technical Notes:** No SQPOLL for TUN -- broken per liburing issue #239. Use regular IORING_OP_READ/WRITE. TUN fd passed to worker after allocation by Main.

---

### US-112: Worker Process with Connection Multiplexing
**Sprint**: S3 | **Points**: 5 | **Priority**: P0
**As a** developer, **I want** worker processes that multiplex client connections via io_uring **so that** each worker handles thousands of concurrent VPN sessions on a single thread.
**Acceptance Criteria:**
- [ ] Worker process runs single io_uring event loop
- [ ] Multishot accept for new TLS connections
- [ ] Per-connection state machine: handshake -> auth -> tunnel -> disconnect
- [ ] Connection table with O(1) lookup by file descriptor
- [ ] Worker sandboxed with seccomp + Landlock (allowlist in S5)
- [ ] Graceful shutdown drains active connections
**Dependencies:** US-100, US-101, US-105, US-110
**Technical Notes:** 1 worker per CPU core. All connections multiplexed -- no thread-per-connection. Connection state allocated from mimalloc per-worker heap.

---

### US-113: Dead Peer Detection State Machine
**Sprint**: S3 | **Points**: 3 | **Priority**: P0
**As a** VPN user, **I want** Dead Peer Detection (DPD) **so that** stale connections are detected and cleaned up, and channel failover triggers automatically.
**Acceptance Criteria:**
- [ ] DPD-REQ sent every 30 seconds (configurable)
- [ ] DPD-RESP tracked; 3 consecutive misses = peer dead
- [ ] Dead peer triggers connection cleanup or channel fallback
- [ ] DPD timers managed via io_uring IORING_OP_TIMEOUT
- [ ] State machine handles: ALIVE -> PROBING -> DEAD transitions
**Dependencies:** US-110
**Technical Notes:** DPD applies to both CSTP and DTLS channels independently. Both channels dead for 5 minutes (configurable) = session timeout.

---

## S4: DTLS & Compression (Weeks 7-8)

### US-114: DTLS 1.2 with Master Secret Bootstrap
**Sprint**: S4 | **Points**: 5 | **Priority**: P0
**As a** VPN user, **I want** DTLS 1.2 support **so that** my data path uses lower-overhead UDP transport, compatible with Cisco Secure Client.
**Acceptance Criteria:**
- [ ] DTLS 1.2 context initialized via wolfSSL
- [ ] Master secret bootstrapped from CSTP TLS session (X-DTLS-Master-Secret)
- [ ] DTLS handshake completes over UDP
- [ ] Data packets flow over DTLS when active
- [ ] DTLS session survives moderate packet loss (<5%)
**Dependencies:** US-105, US-110
**Technical Notes:** Cisco Secure Client does not support DTLS 1.3 -- must use DTLS 1.2. Master secret bootstrap avoids separate DTLS auth. wolfSSL DTLS API: wolfDTLS_new(), wolfSSL_dtls_set_timeout().

---

### US-115: CSTP/DTLS Channel Switching
**Sprint**: S4 | **Points**: 3 | **Priority**: P0
**As a** VPN user, **I want** automatic channel switching **so that** data falls back from DTLS to CSTP when UDP is blocked and recovers when available.
**Acceptance Criteria:**
- [ ] Channel states: CSTP_ONLY, DTLS_PRIMARY, DTLS_FALLBACK
- [ ] Data prefers DTLS when active (lower overhead)
- [ ] CSTP always maintained as control channel
- [ ] DPD failure on DTLS triggers fallback to CSTP for data
- [ ] DTLS recovery re-promotes DTLS to primary
**Dependencies:** US-113, US-114
**Technical Notes:** Channel state enum defined in `src/network/channel.h`. CSTP carries control messages even when DTLS is primary.

---

### US-116: LZ4 Compression
**Sprint**: S4 | **Points**: 3 | **Priority**: P1
**As a** developer, **I want** LZ4 compression codec **so that** VPN throughput improves for compressible traffic.
**Acceptance Criteria:**
- [ ] Compression abstraction: compress()/decompress() with codec selection
- [ ] LZ4 codec: low-latency, streaming compression
- [ ] Negotiation via X-CSTP-Accept-Encoding headers
- [ ] Entropy heuristic disables compression for already-compressed data
**Dependencies:** US-110
**Technical Notes:** Outbound: plaintext -> compress -> wolfSSL_write(). Inbound: wolfSSL_read() -> decompress -> TUN. LZ4 for real-time, LZS for Cisco compatibility.

---

### US-117: LZS Compression for Cisco Compatibility
**Sprint**: S4 | **Points**: 5 | **Priority**: P1
**As a** Cisco client user, **I want** LZS compression **so that** Cisco Secure Client can negotiate a compatible compression algorithm.
**Acceptance Criteria:**
- [ ] LZS compress/decompress implemented (RFC 1974)
- [ ] Compatible with Cisco Secure Client LZS negotiation
- [ ] Integrated into compression abstraction (same interface as LZ4)
- [ ] Round-trip test: compress -> decompress matches original
- [ ] Performance acceptable (LZS is slower than LZ4 -- acceptable for compat)
**Dependencies:** US-116
**Technical Notes:** LZS is mandatory for Cisco compatibility. Custom implementation in `src/network/compress_lzs.c`. Sliding window, Lempel-Ziv-Stac algorithm.

---

## S5: Security Hardening (Weeks 9-10)

### US-118: wolfSentry IDPS Integration
**Sprint**: S5 | **Points**: 5 | **Priority**: P0
**As a** VPN administrator, **I want** wolfSentry IDPS **so that** malicious connections are detected and rejected at TLS ClientHello before consuming server resources.
**Acceptance Criteria:**
- [ ] wolfSentry initialized with JSON ruleset from config
- [ ] Incoming connections checked against wolfSentry on TLS ClientHello
- [ ] REJECT action closes connection immediately
- [ ] Rate limiting per source IP
- [ ] wolfSentry events logged as security events
- [ ] Rules reloadable without server restart
**Dependencies:** US-105, US-112
**Technical Notes:** wolfSentry 1.6.3+ with wolfSSL AcceptFilter integration. JSON config separate from TOML (wolfSentry uses its own JSON format). Connection checking in hot path -- must be fast.

---

### US-119: seccomp BPF and Landlock Sandboxing
**Sprint**: S5 | **Points**: 5 | **Priority**: P0
**As a** security engineer, **I want** seccomp BPF and Landlock sandboxing on worker processes **so that** a compromised worker cannot access unauthorized syscalls or filesystem paths.
**Acceptance Criteria:**
- [ ] seccomp BPF allowlist for worker processes (io_uring, read, write, mmap, etc.)
- [ ] Unauthorized syscalls trigger SECCOMP_RET_KILL_PROCESS
- [ ] Landlock restricts filesystem access to TUN device and config only
- [ ] Sandbox applied after worker initialization (before handling connections)
- [ ] Sandbox violation logged as security event by Main
**Dependencies:** US-112
**Technical Notes:** seccomp filter via libseccomp 2.5+. Landlock requires kernel 5.13+ (well within 6.7+ requirement). Worker death on seccomp violation -- Main restarts it.

---

### US-120: Per-User nftables Firewall Chains
**Sprint**: S5 | **Points**: 5 | **Priority**: P1
**As a** VPN administrator, **I want** per-user nftables firewall chains **so that** each VPN user has isolated network access rules enforced at the kernel level.
**Acceptance Criteria:**
- [ ] nftables chain created on user connect (libmnl + libnftnl)
- [ ] Chain destroyed on user disconnect
- [ ] Rules derived from per-group config in TOML
- [ ] Supports allow/deny by destination network, port, protocol
- [ ] Chain creation/destruction atomic (no race windows)
**Dependencies:** US-103, US-112
**Technical Notes:** libmnl for Netlink transport, libnftnl for nftables rule construction. Chain naming: `wg_user_{session_id}`. Atomic batch commit via NFT_MSG_NEWRULE.

---

### US-121: Fuzz Targets for Parsers
**Sprint**: S5 | **Points**: 3 | **Priority**: P1
**As a** developer, **I want** LibFuzzer targets for all parsers **so that** memory safety bugs in parsing code are discovered automatically.
**Acceptance Criteria:**
- [ ] fuzz_cstp_parser.c: fuzzes CSTP frame decode
- [ ] fuzz_http_parser.c: fuzzes llhttp with random HTTP input
- [ ] fuzz_toml_parser.c: fuzzes TOML config loading
- [ ] fuzz_protobuf.c: fuzzes protobuf-c decode
- [ ] fuzz_tls_client_hello.c: fuzzes TLS ClientHello parsing
- [ ] All targets run 100K+ iterations clean under ASan
**Dependencies:** US-102, US-103, US-109, US-110
**Technical Notes:** LibFuzzer (Clang only). Targets in `tests/fuzz/`. CI runs 1M iterations per target. Corpus seeded with valid inputs.

---

## S6: Auth Expansion (Weeks 11-12)

### US-122: RADIUS Authentication
**Sprint**: S6 | **Points**: 3 | **Priority**: P1
**As a** VPN administrator, **I want** RADIUS authentication **so that** users authenticate against enterprise RADIUS/AAA infrastructure.
**Acceptance Criteria:**
- [ ] radcli client sends Access-Request with username/password
- [ ] Access-Accept/Reject handled and mapped to auth results
- [ ] RADIUS server address, secret, and timeout configurable in TOML
- [ ] Failover to secondary RADIUS server supported
- [ ] RADIUS attributes (group membership) extracted for authorization
**Dependencies:** US-107
**Technical Notes:** radcli 1.4+ library. Runs in sec-mod process. RADIUS shared secret stored securely, zeroed after use.

---

### US-123: Direct LDAP/AD Authentication
**Sprint**: S6 | **Points**: 5 | **Priority**: P1
**As a** VPN administrator, **I want** direct LDAP/AD authentication **so that** users authenticate against Active Directory without requiring sssd or similar system-level integration.
**Acceptance Criteria:**
- [ ] LDAP bind with user DN and password (simple bind over TLS)
- [ ] Search for user DN by sAMAccountName or uid
- [ ] Group membership query for authorization
- [ ] LDAP server URL, base DN, bind DN configurable in TOML
- [ ] Connection pooling to LDAP server (reuse binds)
**Dependencies:** US-107
**Technical Notes:** libldap 2.6+ (OpenLDAP library). TLS required for LDAP connections (LDAPS or StartTLS). Runs in sec-mod.

---

### US-124: TOTP/HOTP Two-Factor Authentication
**Sprint**: S6 | **Points**: 3 | **Priority**: P1
**As a** VPN user, **I want** TOTP two-factor authentication **so that** my VPN login requires both a password and a time-based one-time code.
**Acceptance Criteria:**
- [ ] TOTP validation via liboath (RFC 6238)
- [ ] HOTP validation supported as fallback (RFC 4226)
- [ ] User secret stored securely (per-user config or LDAP attribute)
- [ ] Time window tolerance configurable (default: +/- 1 step)
- [ ] Two-factor flow: password first, then OTP prompt
**Dependencies:** US-107
**Technical Notes:** liboath 2.6+. OTP verified in sec-mod. Secrets stored outside TOML config (separate secrets file with restricted permissions).

---

### US-125: Certificate Authentication
**Sprint**: S6 | **Points**: 3 | **Priority**: P1
**As a** VPN administrator, **I want** certificate-based authentication with template filtering **so that** only client certificates matching configured CN/SAN patterns are accepted.
**Acceptance Criteria:**
- [ ] Client certificate extracted after TLS handshake (wolfSSL_get_peer_certificate)
- [ ] CN and SAN fields parsed and matched against templates
- [ ] Template patterns configurable per group in TOML
- [ ] Certificate revocation checked against CRL (if configured)
- [ ] Certificate-only auth (no password) supported as auth mode
**Dependencies:** US-105, US-107
**Technical Notes:** wolfSSL native API for cert extraction. Templates use glob-style patterns (e.g., `*.vpn.corp.example.com`). CRL loaded from file or distribution point.

---

### US-126: Auth Plugin API (dlopen)
**Sprint**: S6 | **Points**: 3 | **Priority**: P1
**As a** developer, **I want** a dlopen-based auth plugin API **so that** third-party authentication modules can be loaded at runtime without modifying wolfguard source.
**Acceptance Criteria:**
- [ ] Plugin interface: `wg_auth_plugin_t` with init/authenticate/cleanup
- [ ] Plugins loaded via dlopen from configured path
- [ ] Plugin init receives config string from TOML
- [ ] Plugin authenticate called with auth request, returns result
- [ ] Example plugin (stub) included as reference implementation
**Dependencies:** US-107
**Technical Notes:** Plugin shared objects (.so) loaded at sec-mod startup. `wg_auth_plugin_t` struct defined in `src/auth/plugin.h`. Plugins run in sec-mod address space.

---

## S7: Management (Weeks 13-14)

### US-127: wgctl Juniper-Style CLI
**Sprint**: S7 | **Points**: 5 | **Priority**: P1
**As a** VPN administrator, **I want** a Juniper-style CLI tool (wgctl) **so that** I can manage the server interactively with command completion and structured output.
**Acceptance Criteria:**
- [ ] Operational mode: `show sessions`, `show status`, `disconnect user`
- [ ] Config mode: `show running-config`, `reload`
- [ ] linenoise integration for line editing and history
- [ ] Tab completion for commands
- [ ] Connects to server via Unix domain socket
**Dependencies:** US-112
**Technical Notes:** wgctl communicates with Main process via Unix domain socket. Command parser in `src/occtl/cli_parser.c`. Output formatted as tables (operational) or TOML (config).

---

### US-128: REST API over TLS
**Sprint**: S7 | **Points**: 5 | **Priority**: P1
**As a** VPN administrator, **I want** a REST API over TLS **so that** I can automate server management and integrate with orchestration tools like Ansible or Terraform.
**Acceptance Criteria:**
- [ ] REST endpoints: GET /api/sessions, GET /api/status, DELETE /api/sessions/{id}
- [ ] JSON responses via yyjson
- [ ] TLS-protected with separate listener (configurable port)
- [ ] Bearer token authentication for API access
- [ ] Rate limiting on API endpoints
**Dependencies:** US-105, US-109
**Technical Notes:** llhttp for HTTP parsing, io_uring for async I/O, wolfSSL for TLS. Separate listener from VPN port. yyjson for fast JSON serialization.

---

### US-129: Prometheus Metrics Endpoint
**Sprint**: S7 | **Points**: 3 | **Priority**: P1
**As a** monitoring engineer, **I want** a Prometheus /metrics endpoint **so that** I can scrape connection counts, throughput, error rates, and latency percentiles.
**Acceptance Criteria:**
- [ ] GET /metrics returns Prometheus text exposition format
- [ ] Counters: connections_total, auth_failures_total, bytes_rx/tx
- [ ] Gauges: active_sessions, active_dtls_sessions
- [ ] Histograms: handshake_duration_seconds, dpd_rtt_seconds
- [ ] Per-worker metrics aggregated
**Dependencies:** US-128
**Technical Notes:** Custom implementation (~500-800 lines), no libprom dependency. Metrics collected via atomic counters in shared memory. Text exposition per Prometheus spec.

---

### US-130: Structured Logging via stumpless
**Sprint**: S7 | **Points**: 5 | **Priority**: P0
**As a** VPN administrator, **I want** structured RFC 5424 logging **so that** logs are machine-parseable and integrate with centralized log aggregation (ELK, Splunk, Graylog).
**Acceptance Criteria:**
- [ ] stumpless initialized with configurable targets (file, syslog, stdout)
- [ ] Log levels: EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG
- [ ] Structured data elements: session ID, user, source IP, event type
- [ ] Security events logged at NOTICE or higher with `[security]` SD-ID
- [ ] Log rotation support (file target)
**Dependencies:** None
**Technical Notes:** stumpless replaces zlog. RFC 5424 structured data enables machine parsing without regex. Security-relevant events (auth fail, sandbox violation, wolfSentry reject) always logged.

---

## S8: PKI & Integration (Weeks 15-16)

### US-131: wgctl pki Mini CA
**Sprint**: S8 | **Points**: 5 | **Priority**: P1
**As a** VPN administrator, **I want** a built-in mini CA via `wgctl pki` **so that** I can generate all required certificates without external PKI tools.
**Acceptance Criteria:**
- [ ] `wgctl pki ca create` generates self-signed CA certificate
- [ ] `wgctl pki server create` generates server cert signed by CA
- [ ] `wgctl pki client create` generates client cert signed by CA
- [ ] `wgctl pki crl generate` creates certificate revocation list
- [ ] Key types: RSA 2048/4096, ECDSA P-256/P-384
- [ ] Output formats: PEM (default), DER
**Dependencies:** US-127
**Technical Notes:** wolfCrypt for all crypto operations (wc_MakeRsaKey, wc_MakeCert, wc_SignCert). Private keys encrypted at rest with passphrase (PKCS#8).

---

### US-132: Split Tunnel and Split DNS
**Sprint**: S8 | **Points**: 3 | **Priority**: P1
**As a** VPN administrator, **I want** split tunnel and split DNS **so that** only designated traffic routes through the VPN while other traffic goes direct.
**Acceptance Criteria:**
- [ ] Split include/exclude routes configured per group in TOML
- [ ] Routes pushed to client via X-CSTP-Split-Include/Exclude headers
- [ ] Split DNS domains pushed via X-CSTP-Split-DNS headers
- [ ] DNS server pushed via X-CSTP-DNS header
- [ ] Client-side routing -- server does not make routing decisions
**Dependencies:** US-103, US-110
**Technical Notes:** Routes from TOML per-group config. Format: `X-CSTP-Split-Include: 10.0.0.0/255.0.0.0`. Client (Cisco or openconnect) handles route table updates.

---

### US-133: End-to-End Tests with openconnect
**Sprint**: S8 | **Points**: 5 | **Priority**: P0
**As a** developer, **I want** end-to-end tests using the openconnect client **so that** the full VPN session lifecycle is validated automatically in CI.
**Acceptance Criteria:**
- [ ] Test: connect, authenticate, establish tunnel, ping through, disconnect
- [ ] Test: reconnect with session cookie after disconnect
- [ ] Test: DTLS establishment and channel fallback
- [ ] Test: DPD timeout and session cleanup
- [ ] Tests run in CI (Podman containers with network namespaces)
**Dependencies:** US-110, US-113, US-114
**Technical Notes:** openconnect CLI client in test container. Server runs in separate container. Network namespace for isolated TUN/routing. Tests in `tests/e2e/`.

---

### US-134: Documentation and Deployment Guide
**Sprint**: S8 | **Points**: 3 | **Priority**: P1
**As a** VPN administrator, **I want** comprehensive documentation **so that** I can install, configure, and deploy wolfguard in production.
**Acceptance Criteria:**
- [ ] Installation guide: build from source, package install
- [ ] Configuration reference: all TOML options documented
- [ ] Deployment guide: systemd unit, firewall rules, TLS cert setup
- [ ] Troubleshooting: common issues and diagnostics
- [ ] Architecture overview for developers
**Dependencies:** US-131, US-132
**Technical Notes:** Documentation in `docs/`. Man pages for wolfguard(8) and wgctl(8). Configuration reference auto-generated from TOML schema comments.

---

### US-135: Performance Benchmarks
**Sprint**: S8 | **Points**: 2 | **Priority**: P2
**As a** developer, **I want** published performance benchmarks **so that** wolfguard throughput, latency, and scalability are quantified and tracked over time.
**Acceptance Criteria:**
- [ ] Benchmark: TLS handshakes per second (ECDSA P-256)
- [ ] Benchmark: VPN throughput in Gbps (iperf3 through tunnel)
- [ ] Benchmark: p99 latency under load (1000 concurrent sessions)
- [ ] Benchmark: memory usage per session
- [ ] Results published in docs with hardware spec
**Dependencies:** US-133
**Technical Notes:** Benchmarks in `tests/bench/`. Run on standardized hardware. Compare against ocserv+GnuTLS baseline from Phase 0. Track regressions in CI.

---

## Story Summary

| Sprint | Stories | Points | Priority Breakdown |
|--------|---------|--------|--------------------|
| S1: Foundation | US-100 to US-104 | 19 | 5x P0 |
| S2: TLS & Auth | US-105 to US-109 | 19 | 5x P0 |
| S3: VPN Tunnel | US-110 to US-113 | 18 | 4x P0 |
| S4: DTLS & Compress | US-114 to US-117 | 16 | 2x P0, 2x P1 |
| S5: Security | US-118 to US-121 | 18 | 2x P0, 2x P1 |
| S6: Auth Expansion | US-122 to US-126 | 17 | 5x P1 |
| S7: Management | US-127 to US-130 | 18 | 1x P0, 3x P1 |
| S8: PKI & Integration | US-131 to US-135 | 18 | 1x P0, 3x P1, 1x P2 |
| **Total** | **36 stories** | **143 points** | **19x P0, 15x P1, 1x P2** |

---

**Document Version**: 2.0
**Last Updated**: 2026-03-07
**Next Review**: After S1 sprint planning
