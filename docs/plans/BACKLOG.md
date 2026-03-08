# Backlog

Items to investigate or implement, not yet assigned to a sprint.

## Research

- [x] **SQLite version analysis** (resolved 2026-03-08): Build from source,
  **SQLite 3.52.0** (2026-03-06). OL10 has 3.46.1 (6 releases behind).
  Critical: WAL-reset corruption fix in 3.52.0. Build flags:
  `DQS=0 SECURE_DELETE OMIT_DEPRECATED OMIT_SHARED_CACHE WAL_SYNCHRONOUS=1
  FTS5 JSON1 ENABLE_COLUMN_METADATA THREADSAFE=1`. Amalgamation build.

## Technical Debt

- [ ] Fix pre-existing test failures: `test_tls_wolfssl` (3 failures),
  `test_priority_parser` (6 failures) — wolfSSL session creation and
  priority string tokenization issues.
