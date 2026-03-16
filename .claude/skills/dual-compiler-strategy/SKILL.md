---
name: dual-compiler-strategy
description: Use when configuring builds, writing compiler-specific code, or debugging vectorization issues. Covers Clang 22 vs GCC 15 differences for C23, autovectorization, SIMD builtins, sanitizers, FMV, and production flag recommendations.
---

# Dual-Compiler Strategy: Clang 22 + GCC 15

## Core Principle

Use **both compilers in CI**, exploit each compiler's strengths. Neither is universally better.

## When to Use Which

| Task | Preferred | Why |
|------|-----------|-----|
| Primary dev builds | **Clang 22** | Faster compilation (5-10%), MSan exclusive, ThinLTO |
| Release validation | **GCC 15** | `-fanalyzer`, `declare simd`, unique warnings |
| SIMD hot-path modules | **GCC 15 -O3** | Vectorizes 54% of loops vs Clang 46% |
| ARM/AArch64 servers | **Clang 22** | 69% faster SVE codegen than GCC |
| Crypto/security code | **Clang 22** | Stricter FP defaults, no accidental `-ffp-contract=fast` |
| Sanitizer testing | **Both** | ASan+UBSan both; MSan Clang-only |

## C23 Differences

| Feature | GCC 15 | Clang 22 |
|---------|--------|----------|
| Default standard | `-std=gnu23` | `-std=gnu17` (must set `-std=c23` explicitly) |
| `constexpr` objects | Full | Has bugs (#101499, #115845) |
| TS 18661 (IEC 60559) | Partial | Not supported |
| `alignas` on arrays | Works | Bug #106551 |

**Always use `-std=c23` explicitly in both compilers** — do not rely on GCC default.

## Autovectorization Differences

### GCC 15 SLP-Only Vectorizer
- Revolutionary: unified SLP-graph for all loops
- Vectorizes early-exit loops (break/return)
- `vpternlog` optimization: 3 logic ops → 1 instruction
- +11% on SPEC FP at `-O2` (vs GCC 14)
- **Risk:** `-O3` can regress vs `-O2` on grouped stores (bug #119960, fixed in 15.2)
- Rollback: `--param vect-force-slp=0`

### Clang 22 SLP Improvements
- Copyable elements: models missing lanes as `add <val>, 0`
- FMA/FMAD pattern recognition in SLP
- `__builtin_masked_load/store/gather/scatter` (6 new builtins)
- SSE/AVX/AVX-512 intrinsics usable in `constexpr` context

### OpenMP SIMD (CRITICAL DIFFERENCE)
```c
/* Works in both: */
#pragma omp simd
for (int i = 0; i < n; i++) { ... }

/* Works in GCC ONLY (Clang parses but ignores): */
#pragma omp declare simd
void process_packet(const uint8_t *buf, size_t len);
```

Use `#pragma omp simd` on loops (portable). Do NOT rely on `declare simd`.

## Vectorization Diagnostics

```bash
# GCC — see what was NOT vectorized and why
gcc-15 -O3 -fopt-info-vec-missed -fopt-info-vec-all

# Clang — see vectorization decisions
clang -O3 -Rpass=loop-vectorize -Rpass-missed=loop-vectorize -Rpass-analysis=loop-vectorize
```

## Production Flags

```bash
# GCC 15 release build
CFLAGS="-std=c23 -O2 -march=x86-64-v3 -mtune=native \
        -flto=auto -fno-math-errno \
        -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=3"
# For SIMD hot modules: -O3 -fopenmp-simd

# Clang 22 release build
CFLAGS="-std=c23 -O2 -march=x86-64-v3 -mtune=native \
        -flto=thin -fno-math-errno \
        -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=3"
# For SIMD hot modules: -O3 -fopenmp-simd
```

## Floating-Point Contract (CRITICAL for crypto)

| Setting | GCC 15 default | Clang 22 default | With `-std=c23` |
|---------|---------------|-----------------|-----------------|
| `-ffp-contract` | `fast` (FMA across expressions) | `on` (FMA within expression) | GCC: `off`, Clang: `on` |

**NEVER use `-ffast-math`** for crypto/security code:
- Changes float results
- LLVM can transform branchless → conditional (timing side-channel!)
- Use `#pragma STDC FP_CONTRACT ON` locally if FMA needed

## Function Multi-Versioning (FMV)

```c
/* Works in both (portable) */
[[gnu::target_clones("arch=x86-64-v3", "arch=x86-64-v2", "default")]]
void process_packets(const uint8_t *restrict buf, size_t len) { ... }
```

**Caution:**
- GCC and Clang FMV resolvers are **binary-incompatible** — never mix LTO objects
- ARM FMV: Clang 22 = Release status; GCC 15 = experimental (`-Wexperimental-fmv-target`)
- Both support `x86-64-v2/v3/v4` microarchitecture levels

## Sanitizers Compatibility

| Sanitizer | GCC 15 | Clang 22 | Notes |
|-----------|--------|----------|-------|
| ASan | Yes | Yes | **Cannot mix** — link all objects with same compiler |
| UBSan | Yes | Yes | `-fno-sanitize=alignment` to suppress SIMD false positives |
| MSan | **No** | **Yes** | Clang exclusive — critical for uninitialized SIMD buffers |
| TSan | Yes | Yes | Before merge, not every commit |

## `restrict` for Vectorization

The single most impactful keyword for autovectorization:

```c
/* Without restrict: runtime alias checks, may refuse to vectorize */
void process(uint8_t *out, const uint8_t *in, size_t n);

/* With restrict: both compilers vectorize aggressively */
void process(uint8_t *restrict out, const uint8_t *restrict in, size_t n);
```

Always use `restrict` on non-overlapping pointer parameters in hot functions.

## Anti-Patterns

- **Do NOT** mix GCC and Clang LTO objects in same binary
- **Do NOT** rely on `#pragma GCC ivdep` or `#pragma clang loop` — use `#pragma omp simd`
- **Do NOT** assume same vectorization behavior across compilers — always check with `-Rpass`/`-fopt-info`
- **Do NOT** use `-ffast-math` globally — even `-fassociative-math` can break timing guarantees
- **Do NOT** use GCC's `-O3` blindly — it can regress vs `-O2` on some patterns (SLP cost model)
