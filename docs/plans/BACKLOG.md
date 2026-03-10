# Backlog

Items to investigate or implement, not yet assigned to a sprint.

## Research

- [x] **SQLite version analysis** (resolved 2026-03-08): Build from source,
  **SQLite 3.52.0** (2026-03-06). OL10 has 3.46.1 (6 releases behind).
  Critical: WAL-reset corruption fix in 3.52.0. Build flags:
  `DQS=0 SECURE_DELETE OMIT_DEPRECATED OMIT_SHARED_CACHE WAL_SYNCHRONOUS=1
  FTS5 ENABLE_COLUMN_METADATA THREADSAFE=1`. Amalgamation build.

- [x] **cmetrics evaluation** (rejected 2026-03-08): fluent/cmetrics brings
  ~35 source files + 3 bundled libraries (mpack, CFL, fluent-otel-proto)
  for a need that requires ~500-800 LOC. Foreign allocator (`cfl_sds_t`)
  conflicts with mimalloc MI_SECURE. No io_uring integration. Massive dead
  code (OTLP, InfluxDB, Splunk HEC, CloudWatch, StatsD). Custom Prometheus
  text exposition remains the correct approach (S7).

## Container Updates

- [x] **Containerfile library updates** (done 2026-03-08, commit `52c15c3`):
  wolfSSL 5.8.2→5.8.4, cppcheck 2.18.3→2.20.0, mold pinned v2.40.4.
  Added: PVS-Studio (b4all), flawfinder, ccache, lcov. Image rebuild pending.

- [x] **glibc 2.40–2.43 review** (done 2026-03-08):
  Container runs glibc 2.39 (OL10). No upgrade needed now.
  Relevant features for future:
  - 2.40: FORTIFY_SOURCE improvements for Clang builds
  - 2.41: `sched_setattr()`/`sched_getattr()` — SCHED_DEADLINE for workers;
    `abort()` async-signal-safe; `dlopen` no longer makes stack executable
  - 2.42: `pthread_gettid_np()` (cleaner than `syscall(SYS_gettid)`);
    stack guard pages via `MADV_GUARD_INSTALL` in `pthread_create`;
    malloc tcache large block caching (we use mimalloc though)
  - 2.43: C23 const-preserving macros (`strchr` et al.) — **test before
    upgrading**, may break code expecting mutable returns
  No io_uring changes in any release. OL10 may ship updates via `dnf`.

## Research (Open)

- [ ] **HashiCorp Vault integration** — evaluate adding Vault as an external
  secrets backend (alternative to local file-based vault key). Use cases:
  auto-unseal, dynamic TOTP secret rotation, centralized key management for
  multi-node deployments. Assess: Vault Agent sidecar vs direct HTTP API,
  AppRole auth, transit secrets engine for AES-256-GCM key wrapping,
  latency impact on auth-mod hot path. Target: S9+.

## Technical Debt

- [ ] Fix pre-existing test failures: `test_tls_wolfssl` (3 failures),
  `test_priority_parser` (6 failures) — wolfSSL session creation and
  priority string tokenization issues.

## Decided

| Decision | Choice | Sprint | Rationale |
|----------|--------|--------|-----------|
| Metrics library | Custom (~500-800 LOC) | S7 | No external deps, mimalloc, io_uring buffers |
| Session storage | libmdbx (hot) + SQLite WAL (control) | S5 | Hybrid: ns-latency lookups + SQL audit |
| IDPS | wolfSentry 1.6.3+ | S5 | Rate limiting, dynamic firewall, nftables |
| Sandbox | seccomp BPF + Landlock | S5 | Kernel 6.7+, stateless workers |
| Logging | stumpless (RFC 5424) | S7 | Structured, no zlog |
| CLI | rwctl (Juniper-style) | S7 | Interactive + non-interactive |
