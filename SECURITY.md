# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ioguard, please report it
responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub Security Advisories](https://github.com/dantte-lp/ioguard/security/advisories/new)
to report the vulnerability privately.

When reporting, please include:

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Affected versions
- Potential impact

## Scope

ioguard is a VPN server that processes untrusted network input. Security-relevant
areas include:

- **CSTP/DTLS packet parsing** (`src/network/cstp.c`, `src/network/dtls.c`):
  Buffer handling, length validation, malformed packet handling
- **TLS operations** (`src/crypto/tls_wolfssl.c`): Certificate validation,
  session management, key material handling
- **Authentication** (`src/auth/pam.c`, `src/core/secmod.c`): PAM integration,
  session cookies, credential handling
- **TUN device I/O** (`src/network/tun.c`): Packet injection, MTU validation
- **IPC** (`src/ipc/`): Protobuf deserialization, fd passing

## Security Measures

- Constant-time comparison for all secrets (wolfCrypt `ConstantCompare`)
- Secrets zeroed after use (`explicit_bzero()`)
- `[[nodiscard]]` on all public API functions returning errors
- Hardening flags: `-fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie`
- RELRO: `-Wl,-z,relro -Wl,-z,now`
- Overflow checks via `<stdckdint.h>` for size/length arithmetic
- Banned functions enforced: no `strcpy`, `sprintf`, `gets`, `strcat`, `system()`
- Worker processes sandboxed with seccomp BPF and Landlock
- Static analysis: CodeChecker (clang-sa + clang-tidy) and PVS-Studio
- Sanitizers in CI: ASan+UBSan (every commit), MSan (Clang)
- Fuzz testing: LibFuzzer targets for protocol parsers

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Acknowledgments

We appreciate responsible disclosure and will acknowledge reporters in
release notes (unless anonymity is requested).
