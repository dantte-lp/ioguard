---
name: rfc-reference
description: Use when implementing TLS/DTLS features, cipher suites, extensions, or security policies. Provides RFC numbers, locations, and key sections for ringwall protocol implementation.
---

# RFC Reference for ringwall

Local copies in `docs/rfc/rfcNNNN.txt`. This is a P0/P1 quick-reference — not exhaustive.

## 1. TLS / DTLS

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 8446 | TLS 1.3 | §4 Handshake, §5 Record, §7 Crypto | Primary protocol, wolfSSL native API |
| 9147 | DTLS 1.3 | §3 Overview, §4 Record, §5 Handshake | UDP tunnel transport, anti-replay |
| 6347 | DTLS 1.2 | §3 Record, §4 Handshake | Fallback for older clients |
| 7301 | ALPN | §3 Protocol negotiation | `rw_tls_set_alpn()` — negotiate CSTP vs HTTP |
| 6066 | TLS Extensions | §3 SNI, §4 Max Fragment | SNI routing, fragment limits |
| 9325 | BCP 195 (TLS/DTLS) | §3 Protocol, §4 Cipher | TLS 1.2+, AEAD-only, forward secrecy |
| 7525 | (superseded by 9325) | — | Legacy reference only |
| 8996 | Deprecating TLS 1.0/1.1 | All | MUST reject TLS <1.2 |
| 8701 | Grease for TLS | §3 Values | Tolerate unknown values from clients |
| 7457 | Known TLS Attacks | All | BEAST, CRIME, Lucky13, POODLE mitigations |
| 9151 | CNSA Suite Profile | §3 Algorithms | High-security deployment reference |

## 2. TLS Extensions

| RFC | Extension | ringwall Relevance |
|-----|-----------|-------------------|
| 7366 | Encrypt-then-MAC | Enable for TLS 1.2 connections |
| 7905 | ChaCha20-Poly1305 | Preferred cipher for mobile/ARM clients |
| 8449 | Record Size Limit | Constrain records for DTLS over lossy networks |
| 8879 | Certificate Compression | Reduce handshake size (Brotli/zlib) |
| 9146 | DTLS Connection ID | Maintain sessions across NAT rebinding |
| 9345 | Delegated Credentials | Short-lived credentials for edge deployments |

## 3. TLS Deprecation (enforce these)

| RFC | What's Deprecated |
|-----|-------------------|
| 9848 | Obsolete key exchange (static RSA, DH) in TLS 1.2 |
| 9849 | Obsolete ciphers (RC4, 3DES, SEED, NULL, CAMELLIA-CBC) |
| 9847 | IANA registry cleanup for TLS/DTLS |

## 4. Authentication

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 2865 | RADIUS | §3 Packet, §5 Attributes | `rw_auth_radius_*()` via radcli |
| 2866 | RADIUS Accounting | §4 Packet types | Session accounting (Start/Stop/Interim) |
| 9765 | RADIUS/1.1 over TLS | §3 Transport | RadSec transport (TLS-wrapped RADIUS) |
| 4511 | LDAP Protocol | §4 Operations | `rw_auth_ldap_bind()` via libldap |
| 4513 | LDAP Auth Methods | §5 SASL, §6 TLS | SASL bind + StartTLS |
| 4515 | LDAP Search Filters | §3 String repr | User/group lookups |
| 6238 | TOTP | §4 Algorithm | `rw_auth_totp_verify()` via liboath |
| 4226 | HOTP | §5 Algorithm | HOTP fallback via liboath |
| 7519 | JWT | §3 Claims, §4 Header | Session token format |
| 7515 | JWS | §3 Serialization | Token signature verification |
| 6749 | OAuth 2.0 | §4 Grant types | Future: OIDC integration (Tier 3) |
| 7636 | PKCE | §4 Protocol | OAuth public client protection |
| 9190 | EAP-TLS 1.3 | §2 Protocol | Enterprise RADIUS→EAP-TLS chain |

## 5. Certificates & PKI

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 5280 | X.509 PKI | §4 Cert format, §6 Validation | `rw_tls_verify_peer()`, CRL checks |
| 6960 | OCSP | §2 Protocol, §4 Response | Real-time certificate revocation |
| 8555 | ACME | §7 Order, §8 Challenge | Automated cert provisioning |
| 8737 | ACME TLS-ALPN-01 | §3 Challenge | Port-443 cert validation |
| 7292 | PKCS#12 | §4 PFX PDU | Client cert import/export |
| 7468 | PEM Textual Encoding | §5 Cert, §10 Private Key | Config file cert format |
| 5958 | PKCS#8 Asymmetric Key | §2 Format | Private key storage |

## 6. Crypto Primitives

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 5116 | AEAD Interface | §2 Interface | `rw_crypto_aead_*()` abstraction |
| 8439 | ChaCha20-Poly1305 | §2 Algorithm | CSTP/DTLS cipher (wolfCrypt) |
| 5288 | AES-GCM for TLS | §3 Cipher suites | Default cipher suite |
| 7748 | X25519/X448 | §5 Diffie-Hellman | Key exchange (wolfSSL) |
| 8032 | Ed25519/Ed448 | §5 Signing | Certificate signatures |
| 5869 | HKDF | §2 Extract-and-Expand | TLS key derivation |
| 2104 | HMAC | §2 Definition | Session cookies (HMAC-SHA256) |
| 8017 | PKCS#1 RSA | §7 OAEP, §8 PSS | RSA key operations |
| 9106 | Argon2 | §3 Algorithm | Password hashing in `rw_auth_local_*()` |

## 7. HTTP (Control Channel)

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 9110 | HTTP Semantics | §8 Methods, §15 Status | REST API + VPN control (llhttp) |
| 9112 | HTTP/1.1 | §6 Message body, §9 Connection | CSTP tunnel upgrade base |
| 6455 | WebSocket | §4 Handshake, §5 Framing | Future: admin real-time updates |
| 7235 | HTTP Authentication | §2 Framework, §4 Challenges | Bearer/Basic for REST API |
| 6797 | HSTS | §6 Policy | Force HTTPS on admin interface |

## 8. DNS

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 1035 | DNS Implementation | §3 Names, §4 Messages | `rw_dns_*()` via c-ares |
| 7858 | DNS over TLS (DoT) | §3 Connection | Encrypted upstream resolution |
| 8484 | DNS over HTTPS (DoH) | §4 Protocol | Alternative encrypted DNS |
| 9460 | SVCB/HTTPS Records | §2 SVCB RDATA | Service endpoint discovery |

## 9. IP & Transport

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 791 | IPv4 | §3 Specification | TUN device, IP header parsing |
| 8200 | IPv6 | §3 Format, §8 Upper-layer | Dual-stack VPN support |
| 9293 | TCP | §3 Functional spec | CSTP transport, connection mgmt |
| 768 | UDP | §1 Format | DTLS transport |
| 8085 | UDP Usage Guidelines | §3 Congestion, §5 Checksum | DTLS tunnel best practices |
| 8899 | DPLPMTUD | §4 Search algorithm | MTU discovery for DTLS tunnel |
| 8305 | Happy Eyeballs v2 | §5 Algorithm | Dual-stack client connection |

## 10. Compression

| RFC | Title | ringwall Relevance |
|-----|-------|-------------------|
| 1951 | DEFLATE | Reference only (LZ4/LZS preferred for VPN) |
| 1952 | gzip | HTTP response compression for REST API |

Note: LZ4 and LZS (Cisco) are the primary VPN data compression — no RFCs, see library docs.

## 11. NAT Traversal

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 8489 | STUN | §6 Message structure | NAT type detection for DTLS |
| 9443 | DTLS/QUIC Demux | §3 Demultiplexing | Port-sharing DTLS + future QUIC |
| 7983 | Multiplexing Scheme | §3 Algorithm | STUN/DTLS/TURN demux on same port |

## 12. Security & Operations

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 2827 | BCP38 Ingress Filtering | §2 Method | `rw_nft_*()` — anti-spoofing rules |
| 5424 | Syslog Protocol | §6 Message format | `rw_log_*()` via stumpless (RFC 5424) |
| 7258 | Pervasive Monitoring | §2 Threat model | Design principle: encrypt everything |
| 9505 | Censorship Survey | §2 Techniques | VPN tunnel obfuscation awareness |

## 13. Data Formats

| RFC | Title | Key Sections | ringwall Relevance |
|-----|-------|-------------|-------------------|
| 8259 | JSON | §2 Grammar | REST API, wolfSentry config (yyjson) |
| 4648 | Base64 | §4 Encoding | Cookie encoding, cert PEM data |
| 3986 | URI | §3 Syntax components | HTTP routing, REST API paths |

## 14. Post-Quantum (Future)

| RFC/Draft | Title | ringwall Relevance |
|-----------|-------|-------------------|
| draft-ietf-tls-ecdhe-mlkem | ML-KEM Hybrid Key Exchange | Future: PQ key exchange in TLS 1.3 |
| 9180 | HPKE | Hybrid Public Key Encryption primitive |
| 9849 | ECH (Encrypted Client Hello) | Future: hide SNI from network observers |

## How to Read an RFC for Implementation

1. Read the **Abstract** and **Introduction** for scope
2. Read the **Security Considerations** section (usually near the end)
3. Find the specific section for the feature you're implementing
4. Check **MUST/SHOULD/MAY** requirements (RFC 2119 keywords)
5. Cross-reference with wolfSSL API — most TLS/crypto RFCs map to `wolfSSL_*` functions
6. Check `docs/rfc/README.md` for the full local RFC index (41+ files)
