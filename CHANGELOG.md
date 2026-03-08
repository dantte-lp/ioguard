# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CodeChecker and PVS-Studio static analyzer integration.
- libmdbx and SQLite added to dev container for Sprint 5.

### Changed

- Project renamed from wolfguard to ringwall (`rw_` prefix, `RINGWALL_` guards).

## [2.0.0-alpha.4] - 2026-03-08

### Added

- DTLS 1.2 Cisco-compatible handshake and session management.
- Channel state machine (CSTP-only, DTLS-primary, DTLS-fallback).
- LZ4 and LZS compression with CSTP integration.
- DTLS keying material extraction and header parsing.
- Data path integration tests (68 total tests).

## [2.0.0-alpha.3] - 2026-03-07

### Added

- CSTP packet framing (encode/decode with zero-copy).
- TUN device allocation and MTU calculation.
- DPD state machine with channel tracking.
- Worker process context and connection tracking.
- Data path integration test (CSTP + io_uring round-trip).
- Documentation restructuring: bilingual docs (en/ru), README indexes.

## [2.0.0-alpha.2] - 2026-03-07

### Added

- wolfSSL TLS 1.3 backend with native API.
- GnuTLS TLS backend (dual-backend support).
- TLS priority string parser for cipher suite selection.
- PAM authentication module.
- sec-mod (authentication manager) process.
- Session cookie generation and validation (wolfCrypt HMAC-SHA256).
- HTTP parser integration (llhttp) for OpenConnect protocol.
- XML auth request/response builder.
- TLS session cache with configurable limits.

## [2.0.0-alpha.1] - 2026-03-07

### Added

- mimalloc memory allocator wrapper (MI_SECURE).
- io_uring abstraction layer (init, timeout, NOP, recv, send, read, signalfd).
- IPC transport (SOCK_SEQPACKET, SCM_RIGHTS fd passing).
- IPC messages (protobuf-c pack/unpack: auth_request, auth_response, worker_status).
- TOML configuration parser (tomlc99).
- Process management (pidfd_spawn, pidfd_send_signal, poll-based wait).
- Integration test: IPC round-trip auth request/response across fork.
- Unity test framework (33 tests, ASan+UBSan clean).

[Unreleased]: https://github.com/dantte-lp/ringwall/compare/v2.0.0-alpha.4...HEAD
[2.0.0-alpha.4]: https://github.com/dantte-lp/ringwall/compare/v2.0.0-alpha.3...v2.0.0-alpha.4
[2.0.0-alpha.3]: https://github.com/dantte-lp/ringwall/compare/v2.0.0-alpha.2...v2.0.0-alpha.3
[2.0.0-alpha.2]: https://github.com/dantte-lp/ringwall/compare/v2.0.0-alpha.1...v2.0.0-alpha.2
[2.0.0-alpha.1]: https://github.com/dantte-lp/ringwall/releases/tag/v2.0.0-alpha.1
