---
name: rfc-reference
description: Use when implementing TLS/DTLS features, cipher suites, extensions, or security policies. Provides RFC numbers, locations, and key sections for ringwall protocol implementation.
---

# RFC Reference for ringwall

All RFCs are available locally in `docs/rfc/rfcNNNN.txt`.

## When to Consult RFCs

- Implementing TLS/DTLS handshake logic → RFC 8446, RFC 9147
- Configuring cipher suites → RFC 7905, RFC 9849, RFC 9848
- Adding TLS extensions → RFC 8449, RFC 8879, RFC 9146
- Security policy decisions → RFC 9325, RFC 7457
- DTLS connection ID support → RFC 9146
- Certificate handling → RFC 7250, RFC 8773, RFC 9345
- EAP-TLS authentication → RFC 9190

## Core Protocol RFCs

### TLS 1.3 (RFC 8446)
- **Key sections:** Section 4 (Handshake Protocol), Section 5 (Record Protocol), Section 7 (Cryptographic Computations)
- **ringwall usage:** Primary TLS protocol, wolfSSL native API
- **Related:** RFC 8448 (example traces — useful for debugging)

### DTLS 1.3 (RFC 9147)
- **Key sections:** Section 3 (DTLS overview), Section 4 (Record Layer), Section 5 (Handshake Protocol)
- **ringwall usage:** UDP tunnel transport, anti-replay window
- **Related:** RFC 6347 (DTLS 1.2 — fallback support)

### QUIC (RFC 9000, RFC 9001)
- **ringwall usage:** Future consideration only. Not currently implemented.

## Security Policy RFCs

### BCP 195 — Secure Use of TLS/DTLS (RFC 9325, supersedes RFC 7525)
- **MUST implement:** TLS 1.2+ only, no SSL 3.0/TLS 1.0/1.1
- **MUST implement:** Forward secrecy (ECDHE, DHE)
- **MUST NOT:** RC4, 3DES, export ciphers, static RSA key exchange
- **SHOULD:** TLS 1.3 preferred, AEAD ciphers only

### Known Attacks (RFC 7457)
- **Covered attacks:** BEAST, CRIME, Lucky13, RC4 biases, Triple Handshake, POODLE
- **ringwall mitigation:** Encrypt-then-MAC (RFC 7366), AEAD-only in TLS 1.3

### CNSA Suite (RFC 9151)
- **Profile:** AES-256, SHA-384, P-384, RSA-3072+
- **ringwall usage:** Reference for government/high-security deployments

## Extension RFCs

| RFC | Extension | ringwall Relevance |
|-----|-----------|-------------------|
| 7366 | Encrypt-then-MAC | Enable for TLS 1.2 connections |
| 7905 | ChaCha20-Poly1305 | Preferred cipher for mobile/ARM clients |
| 8449 | Record Size Limit | Constrain record sizes for DTLS over lossy networks |
| 8879 | Certificate Compression | Reduce handshake size (Brotli/zlib) |
| 9146 | DTLS Connection ID | Maintain DTLS sessions across NAT rebinding |
| 9345 | Delegated Credentials | Short-lived credentials for CDN/edge |
| 8773 | External PSK Auth | Certificate + PSK combination for TLS 1.3 |

## Deprecation RFCs (enforce these)

| RFC | What's Deprecated |
|-----|-------------------|
| 9848 | Obsolete key exchange methods in TLS 1.2 (static RSA, DH) |
| 9849 | Obsolete cipher suites (RC4, 3DES, SEED, IDEA, CAMELLIA-CBC, NULL) |
| 9847 | IANA registry cleanup for TLS/DTLS |

## Authentication RFCs

| RFC | Topic | ringwall Relevance |
|-----|-------|-------------------|
| 7250 | Raw Public Keys | Alternative to X.509 for IoT/constrained |
| 8492 | Secure Password Ciphersuites | SRP-like auth over TLS |
| 8705 | OAuth 2.0 Mutual-TLS | mTLS client certificate binding |
| 8737 | ACME TLS-ALPN | Automated certificate provisioning |
| 9190 | EAP-TLS 1.3 | Enterprise auth (RADIUS → EAP-TLS) |

## How to Read an RFC for Implementation

1. Read the **Abstract** and **Introduction** for scope
2. Read the **Security Considerations** section (usually near the end)
3. Find the specific section for the feature you're implementing
4. Check **MUST/SHOULD/MAY** requirements (RFC 2119 keywords)
5. Cross-reference with wolfSSL API — most RFCs map to specific `wolfSSL_*` functions
