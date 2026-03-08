# Backlog

Items to investigate or implement, not yet assigned to a sprint.

## Research

- [ ] **SQLite version analysis**: Analyze SQLite release notes at
  https://sqlite.org/changes.html and decide which version to target for
  development (system package vs build from source, minimum version requirements).

## Technical Debt

- [ ] Fix pre-existing test failures: `test_tls_wolfssl` (3 failures),
  `test_priority_parser` (6 failures) — wolfSSL session creation and
  priority string tokenization issues.
