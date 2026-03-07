# wolfguard - Project Instructions for Claude Code

## Quick Facts

- **Language**: C23 (ISO/IEC 9899:2024), `-std=c23`, `CMAKE_C_EXTENSIONS OFF`
- **Project**: VPN server (ocserv refactoring), wolfSSL native API
- **License**: GPLv2 (server), wolfSSL GPLv3 (dependency)
- **Status**: v2.0.0-alpha, Sprint 1 complete, Sprint 2 next
- **Platform**: Linux only (kernel 6.7+, glibc 2.39+)

## Build Commands

```bash
# CMake (primary build system)
cmake --preset clang-debug              # Configure with Clang debug
cmake --build --preset clang-debug      # Build
ctest --preset clang-debug              # Run tests

# Make (legacy, for quick iteration)
make BACKEND=wolfssl                    # Build with wolfSSL
make BACKEND=gnutls                     # Build with GnuTLS
make test-both                          # Test both backends

# Code quality
cmake --build --preset clang-debug --target format    # clang-format
cmake --build --preset clang-debug --target lint      # clang-tidy
cmake --build --preset clang-debug --target cppcheck  # static analysis
```

## Compiler Strategy (dual-compiler)

- **Clang 22+**: Primary dev (MSan, LibFuzzer, clang-tidy, fast builds with mold)
- **GCC 15+**: Validation & release (LTO, -fanalyzer, PGO, unique warnings)
- **Debug linker**: mold (instant linking)
- **Release linker**: GNU ld (GCC LTO) or lld (Clang ThinLTO)
- Always use `-std=c23` explicitly for both compilers

## Key Directories

```
src/crypto/         # TLS abstraction layer (wolfSSL + GnuTLS backends)
src/io/             # io_uring abstraction layer
src/network/        # Network layer (llhttp, liburing)
src/ipc/            # Inter-process communication (protobuf-c)
src/auth/           # Authentication (PAM, RADIUS, LDAP, TOTP, certs)
src/security/       # wolfSentry, seccomp, Landlock, nftables
src/config/         # TOML/JSON configuration
src/log/            # Structured logging (stumpless)
src/metrics/        # Prometheus metrics
src/core/           # Core VPN logic
src/utils/          # Utilities
src/occtl/          # Control utility
tests/unit/         # Unity-based unit tests (test_*.c)
tests/poc/          # Proof-of-concept server/client
tests/bench/        # Performance benchmarks
tests/fuzz/         # LibFuzzer targets (Clang only)
docs/architecture/  # Architecture documentation
docs/draft/         # Research and recommendations
deploy/podman/      # Container configurations
```

## Code Conventions

**Full reference: `.claude/skills/coding-standards/SKILL.md`** — MUST be followed for all code.

- **Naming**: `wg_module_verb_noun()` functions, `wg_module_name_t` types, `WG_MODULE_VALUE` enums/macros
- **Prefix**: `wg_` public API, `tls_` TLS layer
- **Typedef suffix**: `_t` for all types
- **Include guards**: `WOLFGUARD_MODULE_FILE_H` (NOT `OCSERV_*`)
- **Pointer style**: `int *ptr` (right-aligned, Linux kernel style)
- **Column limit**: 100 characters
- **Braces**: Linux kernel style (`BreakBeforeBraces: Linux`)
- **Includes order**: `_GNU_SOURCE` → matching header → C stdlib → POSIX → third-party
- **No C++ dependencies**: Pure C ecosystem only
- **Errors**: return negative errno (`-ENOMEM`, `-EINVAL`), use `goto cleanup` for multi-resource
- **Allocation**: always `sizeof(*ptr)`, never `sizeof(type)`
- **Comments**: Doxygen `@param`/`@return` in headers only; inline comments explain WHY, not WHAT
- **Tests**: Unity framework, `test_module_action_expected()`, typed assertions, cleanup resources

### C23 (mandatory)

| Use everywhere | Use when appropriate | Avoid |
|----------------|---------------------|-------|
| `nullptr`, `[[nodiscard]]`, `constexpr`, `bool` keyword, `_Static_assert` | `typeof`, `[[maybe_unused]]`, `_Atomic`, `<stdckdint.h>`, digit separators, `unreachable()` | `auto` inference, `_BitInt`, `#embed` |

## Security Requirements (MANDATORY)

- Crypto comparisons: constant-time only (`ConstantCompare` from wolfCrypt)
- Secrets: zero after use (`explicit_bzero()`)
- Error returns: `[[nodiscard]]` on all public API functions
- Hardening: `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie`
- Linker: `-Wl,-z,relro -Wl,-z,now`
- Overflow checks: `<stdckdint.h>` for size/length arithmetic
- BANNED functions: `strcpy`, `sprintf`, `gets`, `strcat`, `atoi`, `system()`, `memcmp` on secrets
- Use bounded alternatives: `snprintf`, `strnlen`, `memcpy` with size checks

## Library Stack

### Core Crypto & Security
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| wolfSSL       | 5.8.4+  | TLS 1.3 / DTLS 1.3     | /wolfssl/wolfssl    |
| wolfSentry    | 1.6.3+  | IDPS / dynamic firewall | /wolfssl/wolfsentry |

### Network & I/O
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| liburing      | 2.7+    | All I/O: network, TUN, timers, signals | /axboe/liburing     |
| llhttp        | 9.3.1+  | HTTP parser             | /nodejs/llhttp      |
| c-ares        | 1.34+   | Async DNS resolver      | /c-ares/c-ares      |

### Data & Configuration
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| yyjson        | 0.12+   | Fast JSON (API/metrics) | /ibireme/yyjson     |
| cJSON         | 1.7.19+ | Simple JSON (config)    | -                   |
| tomlc99       | latest  | TOML config parser      | /cktan/tomlc99      |
| protobuf-c    | 1.5.1+  | IPC serialization       | /protobuf-c/protobuf-c |

### System & Memory
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| mimalloc      | 3.1.5+  | Memory allocator (MI_SECURE) | -              |
| LZ4           | 1.10+   | Compression             | -                   |
| libseccomp    | 2.5+    | Syscall sandbox         | -                   |

### Logging & Monitoring
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| stumpless     | latest  | Structured logging (RFC 5424) | /goatshriek/stumpless |
| (custom)      | -       | Prometheus metrics (text exposition) | -         |

### Authentication
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| PAM           | system  | Pluggable auth          | -                   |
| radcli        | 1.4+    | RADIUS client           | -                   |
| liboath       | 2.6+    | TOTP/HOTP               | -                   |
| libldap       | 2.6+    | LDAP authentication     | -                   |

### Networking & Firewall
| Library       | Version | Role                    | Context7 ID        |
|---------------|---------|-------------------------|---------------------|
| libmnl        | 1.0.5+  | Netlink minimal         | -                   |
| libnftnl      | 1.3.1+  | nftables rules          | -                   |
| libnl3        | 3.9+    | Netlink protocol        | -                   |

## Testing Rules

- All new code MUST have unit tests (Unity framework)
- Test files: `tests/unit/test_<module>.c`
- Run both backends before committing
- Sanitizers in CI: ASan+UBSan (every commit), MSan (Clang, every commit), TSan (before merge)
- Fuzzing: LibFuzzer targets in `tests/fuzz/` (Clang only)
- Coverage target: >= 80%

## MCP Documentation (context7)

Use context7 to fetch up-to-date documentation:
- wolfSSL API: `/wolfssl/wolfssl`
- wolfSentry IDPS: `/wolfssl/wolfsentry`
- liburing io_uring: `/axboe/liburing`
- llhttp HTTP parser: `/nodejs/llhttp`
- yyjson JSON: `/ibireme/yyjson`
- c-ares DNS: `/c-ares/c-ares`
- protobuf-c IPC: `/protobuf-c/protobuf-c`
- tomlc99 TOML config: `/cktan/tomlc99`
- stumpless logging: `/goatshriek/stumpless`
- CMake build: `/websites/cmake_cmake_help`

## Architecture Decisions (DO NOT CHANGE)

- Keep protobuf-c for IPC (do not replace)
- Use wolfSSL Native API (not OpenSSL compat layer)
- Pure C libraries only (no C++ dependencies)
- Event-driven with io_uring (liburing) for ALL I/O — no libuv
- Linux only — kernel 6.7+, glibc 2.39+ (no BSD)
- pidfd_spawn + IORING_OP_WAITID for process management
- TOML for static config, JSON for wolfSentry rules and REST API
- stumpless for structured logging (RFC 5424)
- Dual TLS backend build (wolfSSL primary, GnuTLS fallback)
- mimalloc for memory (per-worker heaps, MI_SECURE=ON)

## Git Workflow

- Branch naming: `feature/US-XXX-description`, `fix/issue-description`
- Commit style: conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)
- All commits must pass: clang-format, clang-tidy, unit tests
- Never commit `.deployment-credentials` or secrets
- **NEVER mention "Claude" or any AI assistant in commit messages, comments, or code** — no `Co-Authored-By` AI lines

## Skills Reference

See `.claude/skills/` for detailed guidance on:
- **`coding-standards/`** — File structure, naming, comments, errors, memory, tests (MANDATORY)
- `c23-standards/` — C23 features, conventions, compiler compatibility
- `security-coding/` — constant-time, zeroing, input validation, seccomp
- `wolfssl-api/` — TLS/DTLS API patterns, FIPS constraints, callbacks
- `ocprotocol/` — OpenConnect protocol, Cisco compatibility, cookies
- `wolfsentry-idps/` — IDPS firewall, rate limiting, connection tracking, nftables
