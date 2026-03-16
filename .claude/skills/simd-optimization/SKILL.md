---
name: simd-optimization
description: Use when optimizing hot-path code with SIMD — LZS compression, IPAM bitmap, buffer scanning, CRC32, byte classification. Covers x86 (SSE4.2/AVX2) and ARM64 (NEON/SVE2) with runtime dispatch and scalar fallback.
---

# SIMD Optimization for ioguard

## Strategy: Three Levels

1. **Autovectorization first** — write scalar C23, let compiler vectorize with `-O2 -march=native -fopenmp-simd`
2. **Compiler-guided SIMD** — `#pragma omp simd`, `restrict`, `alignas(32)`, `constexpr` loop bounds
3. **Manual intrinsics last** — only where compiler fails and profiling proves the need

## Architecture Targets

| Target | Minimum | Optimal | Flags |
|--------|---------|---------|-------|
| x86-64 | SSE4.2 (2008+) | AVX2 (2013+) | `-march=x86-64-v3 -mprefer-vector-width=256` |
| ARM64 | NEON (mandatory ARMv8-A) | SVE2 (ARMv9-A, Graviton4) | `-mcpu=neoverse-v1` |

**Avoid AVX-512 on Intel Skylake-SP** — frequency throttling (3.7→2.9 GHz) hurts all parallel VPN sessions. Safe on AMD Zen 4+ and Intel Rocket Lake+.

## wolfSSL Crypto SIMD (DO NOT reimplement)

wolfSSL already has optimized AES-NI, SHA-NI, ChaCha20, Poly1305. Ensure built with:
- x86: `--enable-aesni --enable-intelasm --enable-sp --enable-sp-asm`
- ARM: `--enable-armasm CFLAGS="-mcpu=generic+crypto"`

## Hot-Path SIMD Candidates in ioguard

### 1. LZS Compression — `find_match()` (src/network/compress_lzs.c)
**Current:** O(window*input) brute-force. **Target:** hash-chain + SIMD first-byte filter.
- Algorithmic: hash-chain (like zlib) → **50-100x**
- x86: `_mm256_cmpeq_epi8` first-byte filter, `__builtin_ctz(mask)` → **8-16x** additional
- ARM: `vceqq_u8` + `vgetq_lane_u64` + `__builtin_ctzll` → **8x** additional

### 2. IPAM Bitmap Scan (src/network/ipam.c)
**Current:** bit-at-a-time. **Target:** word-level scan + free hint.
- Scalar: `__builtin_ctzll(~word)` on uint64_t → **32-64x**
- x86 AVX2: `_mm256_cmpeq_epi8(block, 0xFF_vec)` → find non-full byte in 32 bytes
- ARM NEON: `vceqq_u8` + reduction

### 3. Buffer Scanning (byte search, delimiter finding)
Pattern: load 32 bytes → compare → movemask → bit scan.
```c
// x86 AVX2 pattern
[[gnu::target("avx2")]]
static ptrdiff_t find_byte_avx2(const uint8_t *buf, size_t len, uint8_t target) {
    __m256i needle = _mm256_set1_epi8((char)target);
    for (size_t i = 0; i + 32 <= len; i += 32) {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)(buf + i));
        uint32_t mask = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(chunk, needle));
        if (mask) return (ptrdiff_t)(i + __builtin_ctz(mask));
    }
    /* scalar tail */
    for (size_t i = (len & ~31u); i < len; i++)
        if (buf[i] == target) return (ptrdiff_t)i;
    return -1;
}
```

### 4. CRC32 (hardware)
- x86: `_mm_crc32_u64` (SSE4.2) — ~20 GB/s theoretical
- ARM: `__crc32d` — hardware CRC32C

## Runtime Dispatch

Use `target_clones` for automatic multi-versioning (GCC 6+, Clang 14+):
```c
[[gnu::target_clones("avx2", "sse4.2", "default")]]
void process_packets(const uint8_t *buf, size_t len) { /* ... */ }
```

For ARM, use `getauxval(AT_HWCAP)`:
```c
#include <sys/auxv.h>
static process_fn resolve(void) {
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_SVE) return process_sve;
    return process_neon;  /* NEON always available on ARMv8-A */
}
```

## Portable SIMD via SIMDe

**SIMDe** (SIMD Everywhere) — header-only, pure C, MIT license. Write x86 intrinsics, runs on ARM via NEON translation.
```c
#define SIMDE_ENABLE_NATIVE_ALIASES
#include "simde/x86/avx2.h"
/* Same code works on x86 (native) and ARM (SIMDe translates to NEON) */
```

## Autovectorization Helpers (C23)

| Feature | Purpose | Example |
|---------|---------|---------|
| `restrict` | Prove no pointer aliasing | `void f(float *restrict out, const float *restrict in)` |
| `alignas(32)` | AVX2-aligned buffers | `alignas(32) uint8_t buf[4096]` |
| `constexpr` | Compile-time loop bounds | `constexpr size_t N = 1024` |
| `#pragma omp simd` | Force vectorization | Before hot loop, with `-fopenmp-simd` |
| `_Static_assert` | Verify alignment | `_Static_assert(alignof(buf) >= 32)` |

## Anti-Patterns

- **Do NOT** use `_BitInt(N)` with non-power-of-2 widths — breaks vectorization
- **Do NOT** call opaque functions inside hot loops — prevents vectorization
- **Do NOT** use `-ffast-math` globally — use `-fno-math-errno` or `-fassociative-math` selectively
- **Do NOT** mix SSE (non-VEX) and AVX (VEX) without `VZEROUPPER` — performance penalty
- **Do NOT** assume SIMD helps for <32 bytes — setup overhead exceeds gain
- **Do NOT** replace glibc `memcpy`/`memcmp` — they already use SIMD via ifunc

## Build Flags

```bash
# x86-64 server (AVX2, no AVX-512 throttling risk)
CFLAGS="-std=c23 -O2 -march=x86-64-v3 -mprefer-vector-width=256 -fopenmp-simd"

# ARM64 server (Graviton3/4)
CFLAGS="-std=c23 -O2 -mcpu=neoverse-v1 -fopenmp-simd"
```

## Profiling SIMD Code

- **Compiler reports:** GCC `-fopt-info-vec-missed`, Clang `-Rpass=loop-vectorize -Rpass-missed=loop-vectorize`
- **Godbolt:** verify generated instructions contain `vmovdqu`, `vpcmpeqb`, `vpaddd`, etc.
- **LLVM-MCA:** `llvm-mca --bottleneck-analysis` for throughput analysis
- **perf:** `perf stat -e cycles,instructions,cache-misses` for real measurements
- **uftrace:** function-level tracing for io_uring event loop profiling
