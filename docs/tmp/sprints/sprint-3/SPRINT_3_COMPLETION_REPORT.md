# Sprint 3 Completion Report - WolfGuard

**Sprint**: Sprint 3 (VPN Tunnel + Documentation Restructuring)
**Duration**: 2026-03-07 to 2026-03-08 (2 days, planned 2 weeks)
**Status**: COMPLETE (100%)
**Outcome**: SUCCESS -- AHEAD OF SCHEDULE

---

## Executive Summary

Sprint 3 delivered the complete VPN tunnel data path and a full documentation restructuring in **2 days** instead of the planned **2 weeks**. The sprint produced 42 new tests across 5 test targets, all passing clean under ASan+UBSan. The documentation was reorganized into a bilingual (en/ru) structure with archived legacy content and a redesigned README.

### Key Achievements

1. **CSTP Packet Framing** -- Zero-copy encode/decode with 1-byte type + 3-byte BE length wire format (10 tests)
2. **TUN Device Allocation** -- `/dev/net/tun` ioctl with IFF_TUN | IFF_NO_PI and MTU calculation (7 tests)
3. **DPD State Machine** -- Pure state machine (IDLE/PENDING/DEAD) with channel tracking, no I/O dependencies (10 tests)
4. **Worker Process Context** -- Connection pool with flat array tracking and explicit_bzero cleanup (10 tests)
5. **Data Path Integration** -- CSTP + io_uring round-trip validation (5 tests)
6. **Documentation Overhaul** -- Bilingual docs structure, README redesign, legacy archive

---

## Sprint Backlog Completion

### Part 1: Documentation Restructuring

| Task | Status | Notes |
|------|--------|-------|
| README.md redesign (gobfd-style) | Complete | Centered badges, mermaid architecture diagram, concise |
| Bilingual docs/{en,ru}/ structure | Complete | 24 files (11 stubs + 1 index per language) |
| Archive old docs to docs/tmp/ | Complete | 8 dirs + 5 files moved, .gitignore updated |
| README indexes for kept dirs | Complete | docs/architecture/README.md, docs/plans/README.md |

### Part 2: VPN Tunnel Implementation

| Task | Status | LOC | Tests |
|------|--------|-----|-------|
| CSTP packet framing (cstp.c/h) | Complete | 132 | 10 |
| TUN device allocation (tun.c/h) | Complete | 169 | 7 |
| DPD state machine (dpd.c/h) | Complete | 201 | 10 |
| Worker process context (worker.c/h) | Complete | 216 | 10 |
| Data path integration test | Complete | 277 | 5 |

---

## Deliverables

### 1. CSTP Packet Framing (`src/network/cstp.c/h`)

Wire format: 1-byte type + 3-byte big-endian length + payload. Zero-copy decode returns a payload pointer directly into the input buffer, eliminating allocation overhead on the hot path.

**Files**: `src/network/cstp.h` (69 lines), `src/network/cstp.c` (63 lines)

### 2. TUN Device Allocation (`src/network/tun.c/h`)

Linux TUN device creation via `/dev/net/tun` ioctl with `IFF_TUN | IFF_NO_PI`. MTU calculation subtracts 81 bytes of overhead (20 IP + 20 TCP + 37 TLS + 4 CSTP) from the base MTU, yielding a default of 1406 for standard 1500-byte links.

**Files**: `src/network/tun.h` (78 lines), `src/network/tun.c` (91 lines)

### 3. DPD State Machine (`src/network/dpd.c/h`)

Pure state machine with three states (IDLE, PENDING, DEAD) and no I/O or timer dependencies. The caller drives transitions via `on_timeout`, `on_response`, and `on_request`. Output flags (`need_send_request`, `need_send_response`) tell the caller what to emit. Includes channel state tracking (CSTP_ONLY, DTLS_PRIMARY, DTLS_FALLBACK) ready for Sprint 4 DTLS integration.

**Files**: `src/network/dpd.h` (114 lines), `src/network/dpd.c` (87 lines)

### 4. Worker Process Context (`src/core/worker.c/h`)

Opaque worker context with flat-array connection pool supporting up to 256 connections. Linear scan is sufficient at this scale. Connection removal uses `explicit_bzero` to scrub `recv_buf` contents that may contain partial packet data.

**Files**: `src/core/worker.h` (80 lines), `src/core/worker.c` (136 lines)

### 5. Data Path Integration Test

End-to-end validation of CSTP framing over io_uring, exercising the encode-send-receive-decode path. Gracefully skips when io_uring is unavailable (container environments).

**Files**: `tests/integration/test_data_path.c` (277 lines)

### 6. Documentation

- **README.md** -- Complete rewrite with centered badges and mermaid architecture diagram
- **docs/README.md** -- Bilingual index
- **docs/en/** -- 11 stub pages + README index
- **docs/ru/** -- 11 stub pages + README index
- **docs/architecture/README.md** -- Section index
- **docs/plans/README.md** -- Section index

---

## Git Commits

| Commit | Type | Description | Key Changes |
|--------|------|-------------|-------------|
| `98728e2` | test | Data path integration test | CSTP + io_uring round-trip (5 tests) |
| `d902711` | feat | Worker process context and connection tracking | worker.c/h (10 tests) |
| `5947def` | feat | DPD state machine with channel tracking | dpd.c/h (10 tests) |
| `5eac257` | feat | TUN device allocation and MTU calculation | tun.c/h (7 tests) |
| `19add82` | feat | CSTP packet framing -- encode/decode with zero-copy | cstp.c/h (10 tests) |
| `66e7f2c` | docs | README indexes for architecture/ and plans/ | 2 index files |
| `7339a17` | docs | Archive old docs to docs/tmp/, add to .gitignore | 8 dirs + 5 files moved |
| `fee8aa9` | docs | Bilingual docs structure with en/ru stubs | 24 files |
| `5db9366` | docs | Redesign README.md with badges and mermaid | Full rewrite |
| `1a01d36` | docs | 41 TLS/DTLS RFC references with skill and index | RFC reference library |
| `c119e54` | docs | Mark Sprint 2 (TLS & Auth) complete | Status update |

**Total**: 92 files changed, 3,515 insertions, 449 deletions

---

## Test Results

| Test Target | Tests | Status |
|-------------|-------|--------|
| test_cstp | 10 | PASS |
| test_tun | 7 | PASS (TUN alloc skips in container -- expected) |
| test_dpd | 10 | PASS |
| test_worker | 10 | PASS |
| test_data_path | 5 | PASS (io_uring graceful skip if unavailable) |
| **Sprint 3 Total** | **42** | **ALL PASS** |

All Sprint 3 tests pass clean under ASan+UBSan with zero warnings.

**Overall project**: 21 test targets (19 pass, 2 pre-existing Sprint 2 failures).

---

## Technical Decisions

### 1. CSTP Wire Format

**Decision**: 1-byte type + 3-byte big-endian length + payload

**Rationale**: Minimal overhead (4 bytes per packet). The 3-byte length field supports payloads up to 16 MiB, well beyond any realistic VPN MTU. Zero-copy decode avoids allocation on the receive path.

### 2. TUN MTU Calculation

**Decision**: `base_mtu - 81` (20 IP + 20 TCP + 37 TLS + 4 CSTP overhead), default 1406

**Rationale**: Matches OpenConnect client expectations. Conservative estimate avoids fragmentation. The 37-byte TLS overhead accounts for TLS 1.3 record headers and AEAD tag.

### 3. DPD Pure State Machine

**Decision**: No I/O, no timers inside the DPD module. Caller-driven transitions with output flags.

**Rationale**: Testable without mocking I/O. Composable with any event loop (io_uring timers, manual polling). The flag-based output (`need_send_request`, `need_send_response`) decouples state logic from transport.

### 4. Worker Connection Tracking

**Decision**: Flat array with linear scan, capped at 256 connections per worker.

**Rationale**: At 256 entries, linear scan is faster than hash table due to cache locality. No dynamic allocation after initialization. `explicit_bzero` on removal ensures partial packet data in `recv_buf` is scrubbed.

### 5. Channel State Enum

**Decision**: Define `CSTP_ONLY / DTLS_PRIMARY / DTLS_FALLBACK` in the DPD module.

**Rationale**: DPD behavior varies by channel state (different timeouts, different fallback logic). Placing the enum in DPD avoids circular dependencies and prepares the API surface for Sprint 4 DTLS integration.

---

## Known Issues / Deferred

### Pre-existing Sprint 2 Failures (unchanged)

| Test Target | Failures | Root Cause |
|-------------|----------|------------|
| test_tls_wolfssl | 3/22 fail | session_creation, session_set_get_ptr, dtls_set_get_mtu -- wolfSSL API quirks |
| test_priority_parser | 6/34 fail | Tokenizer version handling, parser version removal edge cases |

These are tracked from Sprint 2 and do not block Sprint 3 deliverables.

### Expected Test Skips

- **TUN allocation test**: Skips in container (no `/dev/net/tun`) -- expected behavior
- **io_uring integration test**: Gracefully skips if io_uring unavailable -- expected behavior

---

## Sprint Metrics

### Velocity

- **Planned**: 2 weeks
- **Actual**: 2 days
- **Delivery**: AHEAD OF SCHEDULE

### Code Statistics

- **New source code**: 995 lines (cstp 132 + tun 169 + dpd 201 + worker 216 + integration 277)
- **New tests**: 42 (across 5 test targets)
- **Test pass rate**: 100% (Sprint 3 tests), ASan+UBSan clean
- **Files changed**: 92
- **Total insertions**: 3,515
- **Total deletions**: 449

---

## Next Sprint

### Sprint 4: DTLS & Compression

1. **DTLS 1.2 with master secret bootstrap** -- Cisco compatibility mode, wolfSSL DTLS API
2. **CSTP/DTLS channel switching** -- Integrate with DPD channel state enum from Sprint 3
3. **LZ4 compression codec** -- Fast compression for tunnel data
4. **LZS compression** -- Cisco compatibility (RFC 1974)

---

**Report Date**: 2026-03-08
**Sprint Duration**: 2 days (planned: 2 weeks)
**Final Status**: COMPLETE -- SUCCESS
