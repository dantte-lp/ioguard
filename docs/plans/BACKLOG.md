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
