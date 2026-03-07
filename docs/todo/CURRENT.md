# wolfguard v2.0.0 Development TODO

## Current Sprint: S1 — Foundation
Status: NOT STARTED

### Sprint 1 Tasks
- [ ] Directory scaffolding (src/, tests/)
- [ ] CMakeLists.txt update for Sprint 1 targets
- [ ] Memory allocator wrapper (mimalloc)
- [ ] io_uring event loop wrapper (init, timeout, NOP)
- [ ] io_uring I/O operations (recv, send, read, write, signalfd)
- [ ] IPC transport (SOCK_SEQPACKET, SCM_RIGHTS)
- [ ] IPC messages (protobuf-c pack/unpack)
- [ ] TOML configuration parser (tomlc99)
- [ ] Process management (pidfd_spawn, pidfd signals)
- [ ] Integration test: IPC round-trip
- [ ] Full test suite + format + lint + ASan
- [ ] Update CLAUDE.md and memory

## Sprint Roadmap
| Sprint | Focus | Status |
|--------|-------|--------|
| S1 | Foundation: io_uring, process model, IPC, config | NOT STARTED |
| S2 | TLS & Auth: wolfSSL, PAM, sec-mod, sessions | PLANNED |
| S3 | VPN Tunnel: CSTP, TUN I/O, data path, DPD | PLANNED |
| S4 | DTLS & Compression: DTLS 1.2, channel switch, LZ4/LZS | PLANNED |
| S5 | Security: wolfSentry, seccomp, Landlock, nftables | PLANNED |
| S6 | Auth Expansion: RADIUS, LDAP, TOTP, plugin API | PLANNED |
| S7 | Management: wgctl CLI, REST API, metrics, logging | PLANNED |
| S8 | PKI & Polish: mini CA, split tunnel, E2E, docs | PLANNED |

## Completed (Historical)
### Phase 0 — Exploration (2025)
- [x] Sprint 0: TLS abstraction + dual backends (GnuTLS + wolfSSL)
- [x] Sprint 1 (old): PoC validation + benchmarking (50% performance improvement)
- [x] Sprint 2 (old): Development tools, library stack, mimalloc testing
- [x] GO DECISION: Proceed with wolfSSL
- [x] Architecture replanning: io_uring-only, Linux-only, clean implementation

## Architecture Decisions Log
- 2026-03-07: Replanned from scratch — 8 sprints, io_uring only, no libuv, no BSD
- 2026-03-07: stumpless for logging (replacing zlog)
- 2026-03-07: Custom Prometheus metrics (no libprom)
- 2026-03-07: SOCK_SEQPACKET + protobuf-c for IPC
- 2026-03-07: pidfd_spawn + IORING_OP_WAITID for process management
- 2026-03-07: TOML + JSON configuration
- 2026-03-07: wgctl with Juniper-style CLI

## Design Documents
- `docs/plans/2026-03-07-wolfguard-architecture-design.md` — Full architecture
- `docs/plans/2026-03-07-sprint-1-foundation.md` — Sprint 1 implementation plan

## Key References
- `docs/architecture/CISCO_COMPATIBILITY_GUIDE.md` — Protocol reference
- `docs/architecture/WOLFSSL_ECOSYSTEM.md` — wolfSSL integration
- `docs/draft/three-ipc-mechanisms.md` — IPC design research
- `docs/draft/process-management-without-libuv.md` — Process management research
- `docs/draft/comparison-of-libuv-and-liburing.md` — io_uring vs libuv analysis
- `docs/draft/alternatives-to-zlog-and-libprom.md` — Logging/metrics research
