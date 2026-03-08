# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- io_uring abstraction layer for all I/O (network, TUN, timers, signals).
- mimalloc memory allocator wrapper (MI_SECURE mode).
- IPC transport over SOCK_SEQPACKET with SCM_RIGHTS fd passing.
- IPC message serialization via protobuf-c (auth, worker status).
- TOML configuration parser (tomlc99).
- Process management with pidfd_spawn, pidfd_send_signal, signalfd.
- wolfSSL TLS 1.3 backend (native API, not OpenSSL compat).
- GnuTLS TLS backend (dual-backend build support).
- TLS priority string parser for cipher suite selection.
- TLS session cache with configurable limits.
- PAM authentication module.
- sec-mod (authentication manager) process.
- Session cookie generation and validation (wolfCrypt HMAC-SHA256).
- HTTP parser integration (llhttp) for OpenConnect protocol.
- XML auth request/response builder.
- CSTP packet framing (encode/decode with zero-copy).
- TUN device allocation and MTU calculation.
- DPD state machine with channel tracking.
- Worker process context and connection tracking.
- DTLS 1.2 Cisco-compatible handshake and session management.
- Channel state machine (CSTP-only, DTLS-primary, DTLS-fallback).
- LZ4 and LZS compression with CSTP integration.
- DTLS keying material extraction and header parsing.
- CodeChecker and PVS-Studio static analyzer integration.
- libmdbx and SQLite added to dev container.
- Community health files (CONTRIBUTING, SECURITY, SUPPORT, CHANGELOG).
- GitHub issue templates (YAML forms), PR template, CODEOWNERS, dependabot.
- Bilingual documentation structure (docs/en/, docs/ru/).
- Unity test framework (100+ tests, ASan+UBSan clean).

### Changed

- Project renamed from wolfguard to ringwall (`rw_` prefix, `RINGWALL_` guards).
- License changed from GPLv2 to GPLv3 (wolfSSL dependency requirement).

[Unreleased]: https://github.com/dantte-lp/ringwall/commits/master
