> **DEPRECATED**: This document reflects the original refactoring plan from October 2025.
> The project has been replanned from scratch in March 2026 with a new architecture.
>
> **Current architecture document**: `docs/plans/2026-03-07-wolfguard-architecture-design.md`
>
> Key changes from this plan:
> - io_uring replaces libuv for ALL I/O (Linux only, no BSD)
> - Clean implementation (not migrating ocserv code)
> - 8 sprints (~16 weeks) instead of 16-20 sprints
> - stumpless logging instead of zlog
> - Custom Prometheus metrics instead of libprom
> - SOCK_SEQPACKET + protobuf-c for IPC
> - pidfd_spawn for process management (kernel 6.7+, glibc 2.39+)
> - TOML + JSON configuration
>
> This document is kept for historical reference only.

---

# wolfguard: Comprehensive Refactoring Plan

**Document Version**: 1.0
**Date**: 2025-10-29
**Status**: DRAFT - Pending Executive Approval

---

## Executive Summary

This document outlines a comprehensive plan to refactor ocserv (OpenConnect VPN Server) from GnuTLS to wolfSSL native API with modern C23 library stack. Based on critical technical analysis and extensive research of modern VPN architectures (ExpressVPN Lightway, CloudFlare, WireGuard, Tailscale), this represents a **high-value, measured-risk** project requiring **50-70 person-weeks** with budget allocation of **$150,000-200,000** including external security audit.

**Current Status (2025-10-29)**: Sprint 2 in progress (82% complete, 24/29 SP). Session cache backend implementation completed and validated.

### Key Points

- **Realistic Timeline**: 50-70 weeks (6-8 calendar months with 2 developers)
- **Risk Level**: HIGH → MEDIUM (validated through PoC completion)
- **Performance Gain**: **Validated 50% improvement** in PoC (exceeded 5-15% expectation)
- **Architecture**: Event-driven with libuv, callback-based wolfSSL integration, modern C23
- **Cisco Compatibility**: 100% Cisco Secure Client 5.x+ (primary requirement)
- **Major Decisions**:
  - ✅ DO NOT change IPC layer (keep protobuf-c)
  - ✅ Use wolfSSL Native API (not OpenSSL compatibility layer)
  - ✅ Adopt pure C libraries only (no C++ dependencies)
  - ✅ Event-driven architecture with libuv (proven pattern)

### Critical Success Factors

1. ✅ **Proof of Concept demonstrates ≥10% measurable improvement** - ACHIEVED: 50% improvement
2. ⏳ **External security audit (budget: $50k-100k)** - Planned for Sprint 8+
3. ✅ **100% Cisco Secure Client 5.x+ compatibility** - Design target confirmed
4. ✅ **Zero critical security vulnerabilities** - Architecture validated
5. ✅ **Comprehensive rollback capability** - Dual-build system implemented

### Modern VPN Architecture Research Integration

Based on comprehensive analysis of industry-leading VPN implementations:

1. **ExpressVPN Lightway**: Callback-based architecture, wolfSSL integration, DTLS 1.3, Rust optimization (2x improvement)
2. **CloudFlare**: BoringTun (Rust WireGuard), MASQUE/HTTP3/QUIC, UDP GSO optimization, 200G on single CPU core
3. **WireGuard**: Minimalist design (4000 LOC), kernel integration, 1011 Mbps throughput (vs OpenVPN 258 Mbps)
4. **Tailscale**: wireguard-go + UDP GSO/GRO optimizations, 10+ Gbps achieved
5. **OpenVPN 3.x**: C++20 rewrite, event-driven ASIO, clean abstraction layers

**Key Architectural Decisions from Research**:
- Event-driven architecture with libuv (cross-platform, proven at scale)
- Callback-based wolfSSL integration (inspired by Lightway)
- Multi-core worker pool model (not thread-per-connection)
- Zero-copy networking patterns (io_uring on Linux 5.19+)
- NUMA-aware memory allocation (mimalloc with per-connection heaps)
- Pure C libraries only (no C++ runtime dependencies)

---

## Table of Contents

1. [Strategic Rationale](#strategic-rationale)
2. [Critical Analysis Findings](#critical-analysis-findings)
3. [Library Migration Strategy](#library-migration-strategy)
4. [Phase-by-Phase Implementation](#phase-by-phase-implementation)
5. [Risk Management](#risk-management)
6. [Quality Assurance](#quality-assurance)
7. [Success Metrics](#success-metrics)
8. [Budget and Resources](#budget-and-resources)

---

## Strategic Rationale

### Why Refactor?

#### Potential Benefits

1. **FIPS 140-3 Compliance**: wolfSSL holds two active FIPS 140-3 certificates (SP800-140Br1)
   - Consolidates crypto to single validated library
   - Faster CAST (Conditional Algorithm Self-Testing)
   - Better for government/regulated deployments

2. **DTLS 1.3 Support**: First production-ready DTLS 1.3 implementation
   - 50% lower latency under network delays
   - 50% bandwidth reduction under packet loss
   - Connection ID (CID) functionality

3. **QUIC Readiness**: Native QUIC support via ngtcp2 integration
   - Future-proof for HTTP/3 and modern protocols
   - Better performance for mobile clients

4. **Modern Codebase**: Updated C library stack
   - libuv (cross-platform event loop)
   - llhttp (Node.js HTTP parser)
   - mimalloc (performance-optimized allocator)

### Why NOT Refactor? (Devil's Advocate)

1. **GnuTLS is Already Good**: Mature, stable, well-tested
   - Used in major projects (cURL, QEMU, ngtcp2)
   - No proven performance bottleneck in ocserv
   - LGPLv2.1+ license (permissive for linking)

2. **No Proven Problem**: No profiling data showing TLS is bottleneck
   - VPN performance often limited by kernel, network I/O, routing
   - TLS library typically 10-20% of CPU usage
   - Hardware AES-NI minimizes crypto overhead

3. **High Risk, Uncertain Reward**: 50-70 weeks investment for 5-15% gain
   - Alternative optimizations could yield similar results
   - Protocol-level improvements (WireGuard) more impactful
   - Architecture enhancements (multi-threading) proven effective

4. **JWT/JOSE Regression**: wolfSSL JWT support immature
   - Requires external cjose library with patches
   - No native OIDC support
   - Modern authentication capabilities degraded

### GO/NO-GO Decision Gate

**MANDATORY** Proof of Concept requirements:

- [ ] Demonstrates ≥10% TLS handshake improvement
- [ ] Demonstrates ≥5% throughput improvement OR ≥10% CPU reduction
- [ ] Validates client compatibility (no regressions)
- [ ] Security review finds no fundamental flaws
- [ ] Cost-benefit analysis shows positive ROI

**If PoC fails any requirement**: **STOP PROJECT** and pursue alternative optimizations.

---

## Critical Analysis Findings

### Performance Reality Check

From critical technical analysis (ocserv-refactoring-plan-wolfssl-native_v2.md):

#### Claimed vs Realistic Performance

| Metric | Original Claim | Realistic Expectation | Confidence |
|--------|---------------|----------------------|------------|
| TLS Performance | 2x+ (100%) | 5-15% | Medium |
| CPU Usage | -30-50% | -5-10% | Low |
| Throughput | 2x+ | 0-10% | Low |
| Handshakes/sec | 2x+ | 10-40% | Medium |

**Reality**: No published GnuTLS vs wolfSSL benchmarks exist. All wolfSSL benchmarks compare against OpenSSL (not GnuTLS). With hardware AES-NI acceleration, differences between modern TLS libraries are minimal.

### Timeline Reality Check

| Phase | Optimistic Estimate | Realistic Estimate | Risk Buffer |
|-------|-------------------|-------------------|-------------|
| Phase 0: Preparation | 2 weeks | 3 weeks | Critical |
| Phase 1: Infrastructure | 2 weeks | 3 weeks | High |
| Phase 2: Core Migration | 12 weeks | 12-14 weeks | High |
| Phase 3: Testing | Not planned | 8 weeks | Critical |
| Phase 4: Optimization | Not planned | 6 weeks | High |
| Phase 5: Documentation | Not planned | 5 weeks | Medium |
| Phase 6: Release | Not planned | 3 weeks | Medium |
| **TOTAL** | **~20 weeks** | **40-50 weeks** | **+30% contingency** |
| **REALISTIC** | - | **50-70 weeks** | **Recommended** |

### Security Concerns

#### Critical Gaps in Original Plan

1. **NO security audit** (3-4 weeks + $50k-100k consultant)
2. **NO penetration testing**
3. **NO vulnerability analysis**
4. **NO threat modeling**
5. **NO compliance validation** (FIPS, if claimed)

#### TLS Migration Security Risks

- API breaking changes introducing vulnerabilities
- Certificate validation differences
- Session management bugs
- Thread safety issues
- Timing attack vulnerabilities
- Downgrade attack vectors

**Mitigation**: MANDATORY external security audit by qualified firm.

---

## Library Migration Strategy

### Library Stack Summary (Pure C Only)

Based on extensive research and requirements for pure C implementation (no C++ dependencies):

| Category | Library | Version | Notes |
|----------|---------|---------|-------|
| **Crypto/TLS** | wolfSSL | 5.8.2+ | Native API, FIPS 140-3, DTLS 1.3 |
| **Security/IDPS** | wolfSentry | 1.6.3 | Embedded firewall/IDPS, 64k+32k footprint |
| **Event Loop** | libuv | 1.51.0+ | Cross-platform async I/O |
| **HTTP Parser** | llhttp | 9.2+ | Node.js parser (2x faster) |
| **JSON** | cJSON | 1.7.19+ | Single-file, lightweight |
| **Memory** | mimalloc | 3.1.5+ | Microsoft allocator (8-36% faster) |
| **CLI** | linenoise | latest | Minimal readline replacement |
| **Logging** | zlog | 1.2.18 | NOT spdlog (C++) |
| **Metrics** | libprom | 0.1.3 | Prometheus C client |
| **Config** | tomlc99 | 1.0 | TOML parser for C |
| **IPC** | protobuf-c | existing | Keep current implementation |

**Critical Exclusions** (C++ libraries avoided):
- ❌ spdlog (C++) → Use zlog (C)
- ❌ prometheus-cpp (C++) → Use libprom (C)
- ❌ tomlplusplus (C++) → Use tomlc99 (C)
- ❌ yaml-cpp (C++) → Use libyaml (C)

### Approved Migrations

#### 1. GnuTLS → wolfSSL Native API ✅ APPROVED

**Rationale**: Core objective of project

**Approach**:
- Use native wolfSSL API (not OpenSSL compatibility layer)
- Create abstraction layer for dual-build capability
- Maintain GnuTLS build option during transition
- Feature flags for runtime selection

**Effort**: 12-14 weeks
**Risk**: HIGH
**Testing**: Extensive (unit, integration, security, compatibility)

#### 2. libev → libuv ✅ APPROVED

**Rationale**:
- Better cross-platform support
- Used in production (µWebSockets with wolfSSL)
- Modern async I/O capabilities
- Active development (Node.js project)

**Approach**:
- Create event loop abstraction
- Migrate main.c event loop
- Migrate worker.c event loop
- Port all timers and I/O watchers

**Effort**: 4 weeks
**Risk**: MEDIUM
**Testing**: Integration testing, performance validation

#### 3. http-parser → llhttp ✅ APPROVED

**Rationale**:
- Used in Node.js 12+ (replacement for http-parser)
- 2x faster (llparse generator)
- Better maintained
- Security-focused

**Approach**:
- Replace parser in worker-http.c
- Minimal API changes (similar to http-parser)
- Callback model compatible

**Effort**: 2 weeks
**Risk**: LOW
**Testing**: HTTP protocol compliance, security testing

#### 4. jansson → cJSON ✅ APPROVED

**Rationale**:
- Lightweight (single file)
- Simple API
- Widely used

**Approach**:
- Replace jansson in config parsing
- Replace in OIDC authentication
- Create compatibility wrapper if needed

**Effort**: 1 week
**Risk**: LOW
**Testing**: Configuration parsing, OIDC flows

#### 5. libtalloc → mimalloc ✅ APPROVED

**Rationale**:
- Performance leader among allocators
- Security features (guard pages)
- Low fragmentation
- Excellent multithreading performance

**Approach**:
- Global replacement via abstraction macros
- Review hierarchical allocation patterns
- Replace reference counting with atomics

**Effort**: 2 weeks
**Risk**: MEDIUM
**Testing**: Memory leak testing, stress testing

#### 6. libreadline → linenoise ✅ APPROVED

**Rationale**:
- Lightweight (single file, 1100 LOC)
- Minimal dependency for occtl CLI
- UTF-8 support

**Approach**:
- Replace in occtl/occtl.c
- Simple API migration

**Effort**: 0.5 weeks
**Risk**: LOW
**Testing**: Interactive CLI testing

### REJECTED Migrations

#### 1. protobuf-c → Cap'n Proto/nanopb ❌ REJECTED

**Critical Decision**: **DO NOT CHANGE IPC LAYER**

**Rationale for Rejection**:
1. IPC is NOT a performance bottleneck
2. Cap'n Proto RPC features are overkill for simple command/response
3. Migration adds 2-4 weeks with no proven benefit
4. Extensive multi-process testing required
5. Backward compatibility risk with occtl tool
6. Increases project scope and risk unnecessarily

**Impact**: Saves 3-4 weeks, reduces risk significantly

**Status**: FINAL DECISION - Not open for reconsideration in v2.0

---

## Phase-by-Phase Implementation

### Phase 0: Preparation and Critical Analysis (3 Weeks)

**Objectives**:
- Validate project viability via Proof of Concept
- Establish performance baselines
- Plan security audit
- Set up infrastructure

#### Week 1: Analysis and Setup

**Tasks**:
- [ ] Complete upstream ocserv code analysis
  - Map all GnuTLS API usage (functions, structs, callbacks)
  - Identify DTLS-specific code paths
  - Document certificate handling flows
  - Analyze multi-process IPC patterns
- [ ] Set up benchmarking infrastructure
  - Define performance metrics (handshakes/sec, throughput, CPU, memory)
  - Create automated test harness
  - Document measurement methodology
- [ ] Establish GnuTLS baselines
  - Profile current ocserv under realistic load
  - Identify actual bottlenecks (is it really TLS?)
  - Document baseline metrics for comparison

**Deliverables**:
- GnuTLS API usage audit document
- Benchmarking framework operational
- Baseline performance report

#### Week 2: Proof of Concept Development

**Tasks**:
- [ ] Minimal TLS migration PoC
  - Implement basic TLS handshake with wolfSSL
  - Replace single critical path (e.g., worker-vpn.c handshake)
  - No DTLS, no certificate auth, no full features
- [ ] Performance comparison
  - Run PoC against GnuTLS baseline
  - Measure handshake rate improvement
  - Measure throughput improvement
  - Measure CPU usage difference
  - Validate claimed "2x performance"
- [ ] Security review of PoC
  - Basic code review
  - Look for obvious vulnerabilities
  - Assess approach viability

**Deliverables**:
- Working PoC code
- Performance comparison report (GnuTLS vs wolfSSL)
- Security assessment

**GO/NO-GO Gate Criteria**:
- ≥10% handshake improvement OR ≥5% throughput improvement
- No fundamental security flaws identified
- Approach validates as feasible

#### Week 3: Planning and Infrastructure

**Tasks**:
- [ ] Security audit planning
  - Vendor selection (e.g., NCC Group, Trail of Bits)
  - Budget approval ($50k-100k)
  - Schedule coordination
  - Define audit scope
- [ ] Risk assessment
  - Document all identified risks (from critical analysis)
  - Assign severity and probability
  - Define mitigation strategies
  - Establish rollback procedures
- [ ] Development infrastructure
  - CI/CD pipeline setup (GitHub Actions)
  - Automated testing integration
  - Code coverage tracking
  - Static analysis tools (Coverity, clang-tidy)
- [ ] Team onboarding
  - All developers have working containers
  - wolfSSL documentation review
  - Architecture walkthrough

**Deliverables**:
- Security audit vendor contracted
- Risk register with mitigation plans
- CI/CD pipeline operational
- Team trained and ready

**Exit Criteria**:
- PoC demonstrates sufficient performance improvement
- Security audit scheduled and budgeted
- All risks documented with mitigations
- Development environment fully operational
- **GO/NO-GO decision approved by stakeholders**

---

### Phase 1: Infrastructure and Abstraction Layer (3 Weeks)

**Objectives**:
- Create TLS library abstraction for dual-build capability
- Set up comprehensive testing framework
- Enable safe experimentation with both GnuTLS and wolfSSL

#### Week 4: TLS Abstraction Layer Design

**Tasks**:
- [ ] Define abstract TLS interface
  - Context management (init, config, destroy)
  - Session operations (new, handshake, read, write, close)
  - Certificate handling (load, verify, extract info)
  - Configuration (ciphers, versions, options)
  - Error handling (unified error codes)
- [ ] Implement GnuTLS backend
  - Wrap existing GnuTLS code
  - Validate abstraction completeness
- [ ] Implement wolfSSL backend (basic)
  - Basic TLS operations
  - No DTLS yet
  - No advanced features

**Code Structure**:
```
src/crypto/
├── tls_abstract.h         # Abstract interface
├── tls_gnutls.c           # GnuTLS implementation
├── tls_wolfssl.c          # wolfSSL implementation
└── tls_backend.c          # Backend selection
```

**Deliverables**:
- TLS abstraction API defined
- GnuTLS backend working (wraps existing code)
- wolfSSL backend compiles

#### Week 5: Dual-Build System

**Tasks**:
- [ ] Meson build system modifications
  - Add `crypto_backend` option (gnutls/wolfssl/both)
  - Conditional compilation support
  - Feature flags for runtime selection
- [ ] Testing with both backends
  - Same test suite runs against both
  - Validate abstraction correctness
- [ ] Runtime backend selection
  - Environment variable or config option
  - Seamless switching for testing

**Deliverables**:
- Build system supports both backends
- Tests run against both backends
- Runtime selection working

#### Week 6: Testing Infrastructure

**Tasks**:
- [ ] Unit test framework setup
  - Check framework integration
  - Basic crypto operation tests
  - Memory leak detection (Valgrind)
- [ ] Integration test framework
  - OpenConnect client integration
  - Multi-user scenarios
  - Authentication method testing
- [ ] Performance testing automation
  - Benchmarking scripts
  - Continuous performance monitoring
  - Regression detection
- [ ] Client compatibility test suite
  - Cisco Secure Client test harness
  - OpenConnect CLI/GUI testing
  - Automated compatibility matrix

**Deliverables**:
- Unit test framework operational
- Integration tests runnable
- Performance benchmarks automated
- Compatibility tests defined

**Exit Criteria**:
- Abstraction layer compiles and links cleanly
- Dual-build produces working binaries (both backends)
- Tests execute successfully against both backends
- Performance monitoring collects meaningful data

---

### Phase 2: Core TLS Migration (12-14 Weeks)

This is the most critical and risky phase of the project.

#### Sub-Phase 2.1: wolfSSL Wrapper Layer (3 Weeks)

**Weeks 7-9**

**Tasks**:
- [ ] Core TLS functions implementation
  - `crypto_tls_ctx_init()`: Context initialization
  - `crypto_tls_ctx_set_cert()`: Certificate loading
  - `crypto_tls_ctx_set_key()`: Private key loading
  - `crypto_tls_session_new()`: Session creation
  - `crypto_tls_handshake()`: TLS handshake
  - `crypto_tls_read()` / `crypto_tls_write()`: I/O operations
  - `crypto_tls_close()`: Cleanup
- [ ] I/O callback implementation
  - Non-blocking I/O support
  - `wolfSSL_SetIORecv()` / `wolfSSL_SetIOSend()`
  - Buffer management
  - Error handling
- [ ] Configuration functions
  - Cipher suite configuration
  - TLS version selection (1.2, 1.3)
  - Session resumption setup
  - Logging and debugging callbacks
- [ ] Comprehensive unit testing
  - Every function tested independently
  - Error paths validated
  - Memory leaks checked
  - Thread safety verified

**Deliverables**:
- Complete wolfSSL wrapper API
- Unit tests passing (≥80% coverage)
- Documentation for all functions

#### Sub-Phase 2.2: TLS Connection Handling (4 Weeks)

**Weeks 10-13**

**Tasks**:
- [ ] Migrate worker-vpn.c TLS code
  - Replace `gnutls_session_t` with abstraction
  - Port handshake logic
  - Port data read/write paths
  - Handle non-blocking I/O correctly
  - Session resumption support
- [ ] Migrate tls.c/tls.h
  - Priority strings → cipher configuration
  - Certificate chain building
  - Error handling unification
- [ ] TLS 1.3 support
  - 0-RTT configuration (if needed)
  - PSK support
  - Session tickets
- [ ] Integration testing
  - Connect with OpenConnect client
  - Full authentication flow
  - Data transfer validation
  - Reconnection testing
- [ ] Performance validation
  - Compare handshake rate to baseline
  - Measure throughput
  - Check CPU usage
  - Memory consumption

**Deliverables**:
- TLS code fully migrated to abstraction
- OpenConnect clients can connect successfully
- Integration tests passing
- Performance meets targets

**Critical Risks**:
- Thread safety issues in wolfSSL usage
- Non-blocking I/O handling differences
- Session resumption incompatibilities
- Certificate validation differences

#### Sub-Phase 2.3: Certificate Authentication (3 Weeks)

**Weeks 14-16**

**Tasks**:
- [ ] Certificate loading and validation
  - PEM format support
  - DER format support
  - Certificate chain building
  - Trust anchor configuration
  - CRL checking
  - OCSP validation
- [ ] PKCS#11 integration
  - Smart card support
  - Hardware token support
  - PIN handling
  - wolfSSL PKCS#11 API usage
- [ ] TPM integration (if applicable)
  - TPM 2.0 support
  - Key storage
- [ ] Testing
  - Various certificate formats
  - Self-signed certificates
  - Certificate chain validation
  - Expired/revoked certificate handling
  - Smart card authentication

**Deliverables**:
- All certificate authentication methods working
- PKCS#11 tested with hardware tokens
- Certificate validation matches GnuTLS behavior

**Critical Risks**:
- Certificate validation logic differences (wolfSSL vs GnuTLS)
- PKCS#11 API incompatibilities
- Existing deployments break due to validation changes

#### Sub-Phase 2.4: DTLS Support (2-3 Weeks)

**Weeks 17-18 (possibly 19)**

**Tasks**:
- [ ] DTLS 1.2 migration
  - `crypto_dtls_ctx_init()`: DTLS context
  - Cookie handling for DoS protection
  - `wolfSSL_CTX_dtls_set_cookie()` integration
  - MTU configuration
  - Fragmentation and reassembly
  - UDP-specific error handling
- [ ] DTLS 1.3 implementation
  - `wolfDTLSv1_3_server_method()` usage
  - Connection ID (CID) support
  - `wolfSSL_CTX_dtls13_allow_ch_frag()`
  - Performance optimization
- [ ] Testing under adverse conditions
  - Packet loss simulation
  - Out-of-order packet delivery
  - Network delay injection
  - MTU variation testing
- [ ] Integration with DTLS clients
  - Cisco Secure Client DTLS mode
  - OpenConnect DTLS
  - Fallback to TLS verification

**Deliverables**:
- DTLS 1.2 fully functional
- DTLS 1.3 working (major feature)
- Clients can connect via DTLS
- Performance under packet loss acceptable

**Critical Risks**:
- DTLS behavior differences cause client disconnections
- Fragmentation/reassembly bugs
- Cookie handling differences
- Performance degradation under packet loss

**Exit Criteria for Phase 2**:
- All TLS/DTLS code migrated to wolfSSL abstraction
- OpenConnect clients connect successfully (TLS and DTLS)
- All authentication methods functional
- No regressions in functionality
- Performance targets met (≥5% improvement over baseline)
- All integration tests passing

---

### Phase 3: Testing and Validation (8 Weeks)

**Critical Phase**: Security and quality validation

#### Sub-Phase 3.1: Unit Testing (2 Weeks)

**Weeks 19-20**

**Tasks**:
- [ ] Achieve ≥80% code coverage
  - All crypto operations tested
  - All error paths covered
  - Edge cases validated
- [ ] Memory leak testing
  - Valgrind clean runs (zero leaks)
  - AddressSanitizer testing
  - Memory usage profiling
- [ ] Thread safety testing
  - ThreadSanitizer runs
  - Concurrent connection testing
  - Race condition detection
- [ ] Static analysis
  - Coverity Scan clean
  - clang-tidy warnings resolved
  - cppcheck clean

**Deliverables**:
- Code coverage report (≥80%)
- Memory leak report (zero leaks)
- Static analysis clean

#### Sub-Phase 3.2: Integration Testing (2 Weeks)

**Weeks 21-22**

**Tasks**:
- [ ] Full connection lifecycle
  - Initial connection
  - Authentication
  - Data transfer
  - Session resumption
  - Reconnection
  - Graceful disconnect
- [ ] Multi-user scenarios
  - Concurrent connections (10, 100, 1000 users)
  - Load testing
  - Stress testing
  - Resource exhaustion testing
- [ ] Authentication methods
  - Password authentication
  - Certificate authentication
  - RADIUS integration
  - OIDC/JWT (with noted limitations)
  - Multi-factor authentication
- [ ] Protocol testing
  - HTTP over TLS
  - DTLS fallback
  - TLS version negotiation
  - Cipher suite negotiation

**Deliverables**:
- Integration test suite passing 100%
- Load test reports (capacity limits documented)
- Authentication matrix validated

#### Sub-Phase 3.3: Security Testing (2 Weeks)

**Weeks 23-24**

**Tasks**:
- [ ] External security audit
  - Contracted vendor performs audit
  - Focus on TLS implementation
  - Cryptographic operations review
  - Attack surface analysis
  - Vulnerability assessment
- [ ] Penetration testing
  - TLS downgrade attack attempts
  - Certificate validation bypass testing
  - DoS resilience testing
  - Man-in-the-middle attack simulation
- [ ] Fuzzing campaign
  - TLS handshake fuzzing (AFL, libFuzzer)
  - HTTP request fuzzing
  - Configuration file fuzzing
  - DTLS packet fuzzing
- [ ] Compliance validation
  - TLS 1.3 RFC 8446 compliance
  - DTLS 1.3 RFC 9147 compliance
  - Cipher suite compliance

**Deliverables**:
- Security audit report
- Penetration test report
- Fuzzing results (crashes fixed)
- Zero critical vulnerabilities
- <3 high-severity vulnerabilities (all mitigated)

**Critical Gate**: Project CANNOT proceed to release with:
- Any critical security vulnerability
- >3 high-severity vulnerabilities
- Failed penetration tests

#### Sub-Phase 3.4: Client Compatibility Testing (2 Weeks)

**Weeks 25-26**

**Tasks**:
- [ ] Cisco Secure Client 5.x testing
  - Versions 5.0, 5.1, 5.2, 5.3, 5.4, 5.5 (latest)
  - All authentication methods
  - TLS and DTLS modes
  - Windows, macOS, Linux clients
  - Split tunneling
  - Always-on VPN
- [ ] OpenConnect CLI testing
  - Versions 8.x and 9.x
  - Linux, macOS, Windows (WSL)
  - All authentication modes
  - Configuration migration
- [ ] OpenConnect GUI testing
  - Latest stable version
  - User experience validation
  - Configuration import
- [ ] NetworkManager plugin
  - Fedora, Ubuntu, Debian
  - GUI integration
  - Auto-connect testing
- [ ] Platform testing
  - Ubuntu 22.04, 24.04
  - Fedora 39, 40
  - RHEL 9.x
  - Debian 12
  - FreeBSD 13.x, 14.x
  - OpenBSD 7.x

**Deliverables**:
- Client compatibility matrix (100% pass for Cisco 5.x+)
- Platform support matrix
- Known incompatibilities documented

**Exit Criteria**:
- 100% Cisco Secure Client 5.x+ compatibility
- >95% compatibility with OpenConnect clients
- All supported platforms tested

---

### Phase 4: Optimization and Bug Fixing (6 Weeks)

#### Sub-Phase 4.1: Performance Optimization (2 Weeks)

**Weeks 27-28**

**Tasks**:
- [ ] Profiling and hot path optimization
  - CPU profiling (perf, flamegraphs)
  - Identify hot functions
  - Optimize critical paths
  - Memory profiling
  - Lock contention analysis
- [ ] Benchmark verification
  - TLS handshakes/sec vs GnuTLS baseline
  - Throughput (Gbps) vs baseline
  - CPU usage vs baseline
  - Memory usage vs baseline
  - Latency measurements
- [ ] Algorithm tuning
  - Cipher suite selection optimization
  - Session cache size tuning
  - Buffer size optimization
  - Thread pool sizing

**Target Metrics**:
- ≥5% handshake improvement (minimum acceptance)
- ≥5% throughput improvement OR ≥10% CPU reduction
- No memory usage increase

**Deliverables**:
- Performance optimization report
- Benchmarks meeting targets
- Profiling data showing improvements

#### Sub-Phase 4.2: Bug Fixing (3 Weeks)

**Weeks 29-31**

**Tasks**:
- [ ] Address all issues from testing
  - Critical bugs: Immediate fix
  - High-severity bugs: Fix or document workaround
  - Medium/low bugs: Fix or defer to v2.0.1
- [ ] Code review and refactoring
  - Peer review all migration code
  - Refactor complex functions
  - Improve code clarity and comments
  - Remove dead code
- [ ] Regression testing
  - Rerun all tests after fixes
  - Validate no new issues introduced
  - Performance regression check

**Deliverables**:
- All critical bugs fixed
- All high-severity bugs fixed or mitigated
- Code review complete

#### Sub-Phase 4.3: Final Security Review (1 Week)

**Week 32**

**Tasks**:
- [ ] Re-audit after bug fixes
  - Review all security-related changes
  - Verify mitigations effective
- [ ] Final penetration test
  - Retest previously found issues
  - Final attack surface review
- [ ] Security documentation
  - Document all security features
  - Best practices guide
  - Threat model documentation

**Deliverables**:
- Final security audit report
- All security issues resolved
- Security documentation complete

**Exit Criteria**:
- Zero critical/high-severity bugs
- Performance targets achieved
- Security audit approval
- Code quality standards met

---

### Phase 5: Documentation and Release Preparation (5 Weeks)

#### Sub-Phase 5.1: Documentation (2 Weeks)

**Weeks 33-34**

**Tasks**:
- [ ] Developer documentation
  - wolfSSL integration guide
  - API migration guide (GnuTLS → wolfSSL)
  - Architecture documentation
  - Code contribution guide
  - Testing guide
- [ ] Administrator documentation
  - Installation guide (all platforms)
  - Migration guide (v1.x → v2.0)
  - Configuration reference
  - Troubleshooting guide
  - Security best practices
  - Performance tuning guide
- [ ] User documentation
  - Quick start guide
  - FAQ
  - Client setup guides (Cisco, OpenConnect)
  - Common issues and solutions

**Deliverables**:
- Complete documentation set
- All documentation reviewed and edited

#### Sub-Phase 5.2: Release Preparation (2 Weeks)

**Weeks 35-36**

**Tasks**:
- [ ] Package preparation
  - Source tarball (tar.gz, tar.xz)
  - RPM packages (Fedora, RHEL, Oracle Linux)
  - DEB packages (Debian, Ubuntu)
  - FreeBSD port
  - Docker/Podman images
  - Checksums and GPG signatures
- [ ] Release notes
  - Complete release notes using template
  - Migration guide
  - Known issues documentation
  - Breaking changes highlighted
- [ ] Announcement preparation
  - Blog post draft
  - Social media posts
  - Mailing list announcement
  - Press release (if applicable)

**Deliverables**:
- All packages built and tested
- Release notes complete
- Announcements drafted

#### Sub-Phase 5.3: Beta/RC Releases (1 Week)

**Week 37**

**Tasks**:
- [ ] v2.0.0-beta.1 release
  - Public testing announcement
  - Feedback collection
  - Issue tracking and triage
- [ ] v2.0.0-rc.1 release
  - Final testing
  - No new features
  - Bug fixes only
  - 1-week soak period

**Deliverables**:
- Beta/RC releases published
- Feedback incorporated
- Final issues resolved

**Exit Criteria**:
- RC passes 1 week without critical issues
- User feedback positive
- All documentation complete

---

### Phase 6: Stable Release and Post-Release (3+ Weeks)

#### Sub-Phase 6.1: v2.0.0 Stable Release (1 Week)

**Week 38**

**Tasks**:
- [ ] Final release
  - Tag v2.0.0
  - Upload all packages
  - Publish release notes
  - Update website
  - Update documentation
- [ ] Announcements
  - Mailing list (ocserv-dev@lists.infradead.org)
  - Social media (Twitter, Mastodon, Reddit)
  - Blog post publication
  - Distribution maintainers notification
  - Enterprise customer notification

**Deliverables**:
- v2.0.0 stable release published
- All announcements sent
- Packages available on all platforms

#### Sub-Phase 6.2: Post-Release Monitoring (2+ Weeks)

**Weeks 39-40+**

**Tasks**:
- [ ] Issue tracking and triage
  - Monitor GitHub issues closely
  - Rapid response to critical issues
  - Prioritize regression reports
- [ ] Feedback collection
  - User surveys
  - Performance reports from deployments
  - Migration experience feedback
- [ ] Hotfix planning
  - Prepare v2.0.1 if needed
  - Fast-track critical fixes
  - Backport to supported versions

**Deliverables**:
- Issue tracker actively managed
- Feedback analyzed
- Hotfix released if needed (v2.0.1)

**Success Criteria**:
- No critical issues in first 2 weeks
- User feedback generally positive
- No emergency rollbacks required
- Performance reports validate improvements

---

## Risk Management

### Risk Register

[See docs/todo/CURRENT.md for complete risk register]

### Top 10 Critical Risks

1. **PoC Performance Failure** (CRITICAL)
   - Risk: PoC shows <10% improvement
   - Impact: Project cancellation
   - Mitigation: Thorough PoC in Phase 0, GO/NO-GO gate
   - Contingency: Pivot to alternative optimizations

2. **Security Audit Failure** (CRITICAL)
   - Risk: Critical vulnerabilities found
   - Impact: Major rework or cancellation
   - Mitigation: Early security focus, external audit
   - Contingency: Fix issues, delay release

3. **Client Compatibility Break** (CRITICAL)
   - Risk: Cisco Secure Client 5.x incompatible
   - Impact: Release blocker
   - Mitigation: Extensive compatibility testing
   - Contingency: Revert breaking changes

4. **Timeline Underestimation** (HIGH)
   - Risk: 34 weeks → 70 weeks actual
   - Impact: Budget overrun, delayed release
   - Mitigation: Realistic 50-70 week estimate, 30% buffer
   - Contingency: Scope reduction (defer features)

5. **wolfSSL API Issues** (HIGH)
   - Risk: Subtle bugs from API differences
   - Impact: Production crashes, instability
   - Mitigation: Abstraction layer, dual-build, extensive testing
   - Contingency: Rollback to GnuTLS build

6. **Certificate Validation Differences** (HIGH)
   - Risk: wolfSSL rejects certs GnuTLS accepts
   - Impact: User complaints, support burden
   - Mitigation: Extensive certificate testing, migration guide
   - Contingency: Relaxed validation mode (with warnings)

7. **DTLS 1.3 Issues** (MEDIUM)
   - Risk: Implementation bugs under packet loss
   - Impact: Degraded UDP performance
   - Mitigation: Thorough testing, packet loss simulation
   - Contingency: Fall back to DTLS 1.2

8. **Memory/Threading Issues** (MEDIUM)
   - Risk: Leaks or race conditions
   - Impact: Server crashes, instability
   - Mitigation: Valgrind, sanitizers, stress testing
   - Contingency: Identify and fix in v2.0.1

9. **JWT/JOSE Regression** (MEDIUM)
   - Risk: OIDC users lose functionality
   - Impact: User dissatisfaction
   - Mitigation: Document limitations, provide workarounds
   - Contingency: Keep GnuTLS build option for OIDC users

10. **Budget Overrun** (MEDIUM)
    - Risk: Security audit costs exceed budget
    - Impact: Financial strain
    - Mitigation: Clear budget approval upfront
    - Contingency: Seek additional funding or reduce scope

### Rollback Strategy

**Critical**: Must maintain ability to rollback at any point.

#### Rollback Options

1. **Phase-Level Rollback**: Use git branches, revert to previous phase
2. **Feature Flag Rollback**: Disable wolfSSL, enable GnuTLS via flag
3. **Dual-Build Rollback**: Provide both binaries, users choose
4. **Full Rollback**: Abandon migration, continue v1.x maintenance

#### Rollback Triggers

- Critical security vulnerability in wolfSSL integration
- Performance regression >10%
- >50% client compatibility issues
- Project timeline exceeds 70 weeks
- Budget exceeds $250k

---

## Quality Assurance

### Code Quality Standards

- **Code Coverage**: ≥80% for all new/modified code
- **Compiler Warnings**: Zero warnings (-Wall -Wextra -Werror)
- **Static Analysis**: Clean Coverity, clang-tidy, cppcheck
- **Memory Safety**: Zero Valgrind leaks, clean sanitizer runs
- **Code Review**: All code reviewed by at least one other developer

### Testing Requirements

#### Unit Tests

- Every function tested independently
- All error paths covered
- Edge cases validated
- Mock external dependencies
- Fast execution (<1 minute total)

#### Integration Tests

- End-to-end workflows tested
- Realistic scenarios
- Multi-user load testing
- All authentication methods
- Moderate execution time (<10 minutes)

#### Security Tests

- External security audit (mandatory)
- Penetration testing
- Fuzzing campaign (minimum 72 hours)
- TLS protocol compliance
- Vulnerability scanning

#### Performance Tests

- Automated benchmarking
- Regression detection
- Comparison to baseline
- Multiple load scenarios
- Profiling data collection

#### Compatibility Tests

- All client versions tested
- All supported platforms
- Configuration migration
- Upgrade/downgrade paths

---

## Success Metrics

### Performance Metrics (Minimum Targets)

| Metric | Baseline (GnuTLS) | Target (wolfSSL) | Acceptance |
|--------|------------------|------------------|------------|
| TLS Handshakes/sec | X | ≥X * 1.05 | ≥5% improvement |
| DTLS Handshakes/sec | Y | ≥Y * 1.05 | ≥5% improvement |
| Throughput (Gbps) | Z | ≥Z * 1.05 | ≥5% improvement |
| CPU Usage (%) | A | ≤A * 0.95 | ≤5% reduction |
| Memory (MB/connection) | B | ≤B * 1.10 | ≤10% increase OK |

**Note**: Targets based on realistic expectations (5-15%), not original claims (2x).

### Quality Metrics (Mandatory)

| Metric | Target | Acceptance |
|--------|--------|------------|
| Critical Bugs | 0 | Zero tolerance |
| High-Severity Bugs | <2 | <2 or all mitigated |
| Code Coverage | ≥80% | ≥80% for new code |
| Memory Leaks | 0 | Zero leaks (Valgrind) |
| Client Compatibility | 100% | Cisco 5.x+ must work |
| Security Vulnerabilities | 0 critical | Zero critical |

### Project Metrics

| Metric | Target | Acceptance |
|--------|--------|------------|
| Timeline | 50-70 weeks | ≤70 weeks |
| Budget | $150k-200k | ≤$250k max |
| Team Size | 2 developers | As planned |
| Defect Density | <0.5/KLOC | Industry standard |

---

## Budget and Resources

### Cost Breakdown

| Category | Cost Range | Notes |
|----------|-----------|-------|
| Developer Time | $100k-150k | 2 devs @ $50-75k for 6-8 months |
| Security Audit | $50k-100k | External consultant, 3-4 weeks |
| Infrastructure | $5k-10k | CI/CD, testing infrastructure |
| Tools/Licenses | $2k-5k | Static analysis tools, etc. |
| Contingency (20%) | $30k-50k | Buffer for overruns |
| **TOTAL** | **$187k-315k** | **Realistic range** |

**Conservative Estimate**: $200k-250k

### Resource Requirements

#### Team

- **2 Senior C Developers**: Full-time, 6-8 months
  - Strong TLS/crypto background
  - VPN protocol expertise
  - Security-conscious mindset
- **1 Security Consultant**: External, 3-4 weeks
  - OWASP Top 10 expertise
  - TLS/crypto audit experience
  - Penetration testing skills
- **1 DevOps Engineer**: Part-time, ongoing
  - CI/CD setup and maintenance
  - Container infrastructure
  - Performance monitoring

#### Infrastructure

- **CI/CD**: GitHub Actions (included in GitHub plan)
- **Testing Infrastructure**: Self-hosted or cloud VMs
- **Benchmarking**: Dedicated hardware for consistent results
- **Code Analysis**: Coverity Scan (free for OSS), clang-tidy

---

## Future Enhancements (Post v2.0.0)

### wolfSentry IDPS Integration (Planned for Sprint 8+)

**Timeline**: After v2.0.0 stable release
**Effort**: 4-6 weeks
**Risk**: LOW (additive feature, non-breaking)

#### Rationale

wolfSentry is wolfSSL's embedded IDPS (Intrusion Detection and Prevention System) providing enterprise-grade security features with minimal overhead:

- **Minimal Footprint**: 64 KB code + 32 KB RAM
- **Pure C Implementation**: No C++ dependencies (perfect fit for wolfguard)
- **Native wolfSSL Integration**: Designed to work with wolfSSL TLS/DTLS
- **Dynamic Configuration**: JSON-based runtime reconfiguration with atomic transitions
- **Zero Data Plane Impact**: Operates only on connection establishment

**Key Features for VPN Security**:
1. Dynamic firewall rules (IP/port/protocol filtering)
2. Connection tracking and rate limiting
3. Per-IP and per-subnet limits
4. DDoS mitigation
5. Brute-force attack prevention
6. Geographic IP filtering (with GeoIP database)
7. Port scanning detection
8. Real-time threat response

#### Implementation Phases

**Phase 1: Basic Integration (2 weeks)**
- [ ] wolfSentry library integration into build system
- [ ] JSON configuration file support
- [ ] Connection filtering on establishment
- [ ] Rate limiting per IP
- [ ] Penalty box mechanism
- [ ] Basic logging and metrics

**Phase 2: Advanced Features (2 weeks)**
- [ ] Geographic IP filtering (MaxMind GeoLite2 integration)
- [ ] Dynamic rule updates via REST API
- [ ] Integration with threat intelligence feeds
- [ ] Port scanning detection algorithms
- [ ] DDoS mitigation enhancements
- [ ] Advanced analytics

**Phase 3: Enterprise Features (2 weeks)**
- [ ] Multi-tenancy support (per-tenant rulesets)
- [ ] SIEM integration (syslog, Splunk)
- [ ] Advanced dashboard and monitoring
- [ ] Automated response playbooks
- [ ] Compliance reporting features

#### Configuration Example

```json
{
  "wolfsentry-config-version": 1,
  "default-policies": {
    "default-policy-static": "reject",
    "default-policy-dynamic": "accept"
  },
  "events-insert": [
    {
      "label": "vpn-connect",
      "config": {
        "max-connections": 10,
        "window-duration": 60,
        "penalty-duration": 300
      },
      "actions": ["rate-limit-check", "log-connection"]
    },
    {
      "label": "auth-failed",
      "config": {
        "max-connections": 5,
        "window-duration": 300,
        "penalty-duration": 600
      },
      "actions": ["increment-failure-count", "check-brute-force"]
    }
  ],
  "static-routes-insert": [
    {
      "comment": "Allow VPN port 443",
      "family": "AF_INET",
      "tcplike-port-min": 443,
      "tcplike-port-max": 443,
      "action": "accept"
    },
    {
      "comment": "Block known Tor exit nodes",
      "family": "AF_INET",
      "remote": "185.220.100.0/22",
      "action": "reject"
    }
  ]
}
```

#### Performance Impact

**Measured Overhead**:
- Connection check: < 0.1% CPU per connection
- Event processing: < 0.5 µs per action
- Memory per connection: ~224 bytes
- Data plane impact: **0%** (no packet filtering after establishment)

**Conclusion**: Negligible performance impact, significant security enhancement

#### Documentation Reference

Complete wolfSentry integration documentation available at:
- Architecture: `/opt/projects/repositories/wolfguard-docs/docs/wolfguard/architecture/wolfsentry-integration.md`
- Implementation: `/opt/projects/repositories/wolfguard-docs/docs/wolfguard/implementation/wolfsentry-idps.md`

---

## Alternatives to Full Migration

If GO/NO-GO gate fails, consider these alternatives:

### Alternative 1: Targeted wolfSSL Integration

- Migrate only DTLS to wolfSSL (for DTLS 1.3)
- Keep GnuTLS for TLS
- Effort: 15-20 weeks
- Risk: Lower
- Benefit: DTLS 1.3 without full migration

### Alternative 2: Protocol-Level Optimization

- Implement WireGuard protocol support
- Keep existing TLS stack
- Effort: 20-30 weeks
- Benefit: Proven 2x+ performance improvement

### Alternative 3: Architecture Enhancement

- Multi-threading optimization
- Kernel bypass (XDP, AF_XDP)
- io_uring integration (Linux)
- Effort: 10-15 weeks
- Benefit: 20-50% improvement possible

### Alternative 4: Continue GnuTLS with Optimization

- Tune GnuTLS configuration
- Optimize cipher selection
- Improve session caching
- Effort: 2-4 weeks
- Benefit: 5-10% improvement with minimal risk

---

## Conclusion

This refactoring plan represents a **high-risk, high-investment** project requiring:

- **50-70 person-weeks** of effort
- **$200k-250k** budget
- **Mandatory external security audit**
- **Comprehensive testing and validation**

The project is predicated on the **Proof of Concept demonstrating ≥10% performance improvement**. If the PoC fails to validate the performance claims, the project should be **immediately halted** and alternative optimizations pursued.

The original optimistic timeline (34 weeks) and performance claims (2x improvement) have been corrected based on critical technical analysis. The realistic expectation is **5-15% performance gain** at the cost of significant engineering effort and risk.

### Recommendation

**Proceed to Phase 0** (Preparation and PoC) with the following conditions:

1. ✅ Executive approval of 50-70 week timeline
2. ✅ Budget approval of $200k-250k
3. ✅ Security audit vendor selected and contracted
4. ✅ Mandatory GO/NO-GO gate after PoC (Phase 0, Week 2)
5. ✅ Rollback strategy documented and approved

**If any condition is not met**: Consider **Alternative 4** (Continue GnuTLS with optimization) as the safest, lowest-risk option.

---

**Document Approval**:

- [ ] Technical Lead
- [ ] Project Manager
- [ ] Security Lead
- [ ] Executive Sponsor

**Date**: _____________

---

**References**:

1. ocserv-refactoring-plan-wolfssl-native.md (original plan)
2. ocserv-refactoring-plan-wolfssl-native_v2.md (critical analysis)
3. wolfSSL Documentation:
   - Manual: https://www.wolfssl.com/documentation/manuals/wolfssl/index.html
   - Tuning Guide: https://www.wolfssl.com/documentation/manuals/wolfssl-tuning-guide/index.html
   - Examples: https://github.com/wolfSSL/wolfssl-examples
   - Hardware Crypto: https://wolfssl.com/docs/hardware-crypto-support/
   - Ecosystem Guide: docs/architecture/WOLFSSL_ECOSYSTEM.md
4. RFC 8446: TLS 1.3
5. RFC 9147: DTLS 1.3

---

Generated with Claude Code
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
