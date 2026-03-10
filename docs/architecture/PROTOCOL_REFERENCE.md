# OpenConnect VPN Protocol Reference

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Project**: ioguard v2.0.0

---

## Overview

This document provides references and analysis of the OpenConnect VPN protocol specification, which ioguard implements with 100% Cisco AnyConnect compatibility as a core requirement.

---

## Official Protocol Specification

### OpenConnect VPN Protocol (IETF Draft)

**Document**: draft-mavrogiannopoulos-openconnect-04
**Version**: 1.2 (Protocol Version)
**Status**: Expired Internet-Draft (individual submission)
**Last Updated**: July 23, 2023
**Author**: Nikos Mavrogiannopoulos (ocserv maintainer)

**URL**: https://datatracker.ietf.org/doc/draft-mavrogiannopoulos-openconnect/

**Abstract**:
> "This document describes the OpenConnect VPN protocol version 1.2 that provides communications privacy over the Internet. The protocol is believed to be compatible with CISCO's AnyConnect VPN protocol. The protocol provides prevention of eavesdropping, tampering, and message forgery."

**Key Characteristics**:
- **Compatible** with Cisco AnyConnect VPN Protocol
- **Security Objectives**:
  - Prevention of eavesdropping (encryption)
  - Prevention of tampering (integrity)
  - Prevention of message forgery (authentication)
- **Transport**: TLS/DTLS over TCP/UDP
- **Authentication**: Multiple methods (certificate, password, SAML, etc.)

**Important Note**:
⚠️ This draft is **expired** and has **no formal standing** in IETF standards processes. However, it remains the authoritative reference for the OpenConnect protocol implementation.

---

## Protocol Components

### 1. Transport Layer

**Primary Transport: TLS 1.2/1.3**
- TCP-based VPN tunnel
- HTTPS control channel (TCP port 443)
- Modern cipher suites (AES-GCM, ChaCha20-Poly1305)

**Secondary Transport: DTLS 1.0/1.2/1.3**
- UDP-based VPN tunnel for reduced latency
- Fallback mechanism if UDP blocked
- Stateless cookie for DoS protection

### 2. Authentication Methods

The protocol supports multiple authentication mechanisms:

1. **Certificate-based authentication**
   - X.509 client certificates
   - Smart card (PKCS#11) support
   - Mutual TLS authentication

2. **Password-based authentication**
   - Plain password (over TLS)
   - RADIUS backend
   - PAM integration
   - LDAP/Active Directory

3. **Multi-factor authentication (MFA)**
   - OTP (One-Time Password)
   - TOTP (Time-based OTP)
   - SMS/push notifications
   - Duo, Google Authenticator support

4. **Modern authentication**
   - SAML 2.0
   - OAuth 2.0
   - OIDC (OpenID Connect)

### 3. Protocol Messages

**XML-based control protocol**:
- Client → Server: Authentication credentials
- Server → Client: Configuration (IP, DNS, routes)
- Keepalive messages
- Session management

**Binary data tunnel**:
- IP packets encapsulated in TLS/DTLS
- Compression support (LZ4, deflate)
- MTU handling

---

## Cisco AnyConnect Compatibility

### Target Version

**Cisco Secure Client 5.x+** (formerly AnyConnect)
- Latest protocol features (v5.1.2.42 analyzed)
- Modern cipher suites (TLS 1.3, ChaCha20-Poly1305)
- DTLS 1.2 primary, DTLS 1.3 support (future)
- CiscoSSL wrapper around OpenSSL 1.1.1+

### Cryptographic Implementation Analysis

Based on reverse engineering of Cisco Secure Client 5.1.2.42:

**TLS Protocol Support**:
- TLS 1.3 (primary, default for new connections)
- TLS 1.2 (full fallback support)
- TLS 1.1 (legacy, minimal support)
- TLS 1.0 (not supported, removed)

**DTLS Protocol Support**:
- DTLS 1.2 (primary for UDP tunnel)
- DTLS 1.0 (legacy, minimal support)

**Cipher Suites (Priority Order)**:
1. TLS_AES_256_GCM_SHA384 (TLS 1.3)
2. TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
3. TLS_AES_128_GCM_SHA256 (TLS 1.3)
4. ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2)
5. ECDHE-RSA-CHACHA20-POLY1305 (TLS 1.2)
6. ECDHE-RSA-AES128-GCM-SHA256 (TLS 1.2)

**Key Exchange**:
- ECDHE with P-256 (secp256r1) preferred
- ECDHE with P-384 (secp384r1) alternative
- X25519 support (modern deployments)

**Certificate Requirements**:
- X.509 v3 certificates
- RSA-PSS signatures preferred
- Subject Alternative Name (SAN) mandatory
- Certificate chain validation (strict)

### Compatibility Requirements

For ioguard v2.0.0:
- ✅ 100% protocol message compatibility
- ✅ XML response format matching
- ✅ Session cookie format
- ✅ DTLS handshake quirks
- ✅ Keepalive timing
- ✅ Banner/message display

### Known Cisco Client Quirks

1. **Certificate validation strictness**
   - Must match exact Cisco expectations
   - Subject Alternative Name (SAN) requirements
   - Certificate chain validation order
   - RSA-PSS signature algorithm preferred
   - Minimum key lengths: RSA 2048-bit, ECC 256-bit

2. **XML response parsing**
   - Specific tag ordering expected
   - Case sensitivity in some fields
   - Whitespace handling
   - DOCTYPE and encoding declarations

3. **DTLS fallback behavior**
   - Must attempt DTLS before TCP-only mode
   - Specific timeout values (implementation-dependent)
   - Cookie exchange timing (HelloVerifyRequest)
   - MTU discovery and fragmentation handling

4. **Session persistence**
   - Session ID format requirements
   - Cookie expiration handling
   - Reconnection behavior
   - Session resumption with tickets (TLS 1.3)
   - Master secret preservation for DTLS

5. **HTTP Headers (Critical)**
   - `X-CSTP-Version: 1` (protocol v1.2 indicator)
   - `X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.` (exact string)
   - `X-CSTP-Address-Type: IPv6,IPv4` (dual-stack)
   - `X-CSTP-Full-IPv6-Capability: true`
   - `X-DTLS-Master-Secret` for UDP tunnel establishment
   - `X-DTLS12-CipherSuite` for cipher negotiation

6. **Authentication Flow**
   - Aggregate authentication framework
   - Multi-factor authentication support
   - XML-based credential exchange
   - Session cookie format: `webvpn=<encrypted-token>`
   - SAML/OAuth 2.0/OIDC integration points

---

## Related RFCs and Standards

### TLS/DTLS Standards

**RFC 8446**: Transport Layer Security (TLS) 1.3
https://datatracker.ietf.org/doc/html/rfc8446
- Modern TLS protocol
- 0-RTT support
- Improved security and performance

**RFC 9147**: Datagram Transport Layer Security (DTLS) 1.3
https://datatracker.ietf.org/doc/html/rfc9147
- DTLS protocol for UDP
- Connection ID extension
- Post-quantum readiness

**RFC 6347**: Datagram Transport Layer Security Version 1.2
https://datatracker.ietf.org/doc/html/rfc6347
- Current DTLS implementation
- Compatibility baseline

### Authentication Standards

**RFC 7292**: PKCS #12: Personal Information Exchange Syntax
https://datatracker.ietf.org/doc/html/rfc7292
- Certificate/key storage format

**RFC 7468**: Textual Encodings of PKIX, PKCS, and CMS Structures
https://datatracker.ietf.org/doc/html/rfc7468
- PEM encoding format

**RFC 5280**: Internet X.509 Public Key Infrastructure Certificate
https://datatracker.ietf.org/doc/html/rfc5280
- Certificate format and validation

### HTTP/HTTPS

**RFC 9110**: HTTP Semantics
https://datatracker.ietf.org/doc/html/rfc9110
- HTTP protocol semantics (replaces RFC 7230-7235)

**RFC 9112**: HTTP/1.1
https://datatracker.ietf.org/doc/html/rfc9112
- HTTP/1.1 message syntax

---

## OpenConnect Client Implementation

### Official Client

**Repository**: https://gitlab.com/openconnect/openconnect
**Language**: C
**License**: LGPL v2.1
**Maintainer**: David Woodhouse

The official OpenConnect client is the reference implementation for the client side of the protocol.

### Protocol Versions Supported

- OpenConnect Protocol v1.0 (legacy)
- OpenConnect Protocol v1.1
- OpenConnect Protocol v1.2 (current, draft-04)

### Client Compatibility Matrix

| Client Version | Protocol | Server Compatibility |
|----------------|----------|---------------------|
| OpenConnect 9.x | v1.2 | ocserv 1.x, Cisco ASA |
| OpenConnect 8.x | v1.1 | ocserv 0.12.x+ |
| Cisco Secure Client 5.x | v1.2 | ocserv 1.x+ (target) |
| Cisco AnyConnect 4.x | v1.1 | ocserv 0.11.x+ |

---

## Implementation Guidelines for ioguard

### Critical Requirements

1. **Strict Cisco Compatibility**
   - Test with actual Cisco Secure Client 5.x
   - Capture and analyze protocol traces
   - Replicate exact message formats
   - Handle all client quirks

2. **Protocol State Machine**
   - Implement exact state transitions
   - Handle error conditions as Cisco does
   - Timeout values must match expectations
   - Reconnection logic compatibility

3. **Certificate Handling**
   - Support all certificate types Cisco uses
   - Validate according to Cisco expectations
   - Handle certificate chains correctly
   - Smart card (PKCS#11) support

4. **DTLS Implementation**
   - Cookie exchange must work with Cisco
   - Connection ID support (RFC 9146)
   - Replay protection
   - Retransmission logic

### Testing Strategy

**Unit Tests**:
- Protocol message parsing
- XML generation and validation
- State machine transitions
- Error handling

**Integration Tests**:
- Full handshake with OpenConnect client
- Full handshake with Cisco Secure Client
- DTLS fallback scenarios
- Reconnection handling

**Compatibility Tests**:
- Cisco Secure Client 5.0
- Cisco Secure Client 5.1
- Cisco Secure Client 5.2 (latest)
- OpenConnect client 9.x

**Regression Tests**:
- Ensure no breaking changes
- Version compatibility matrix
- Protocol version negotiation

---

## User Stories Related to Protocol

### Cisco Compatibility Stories

**US-017**: Cisco Client Testing - Basic (5 points, P1)
- Basic connectivity with Cisco Secure Client 5.x
- Authentication methods (certificate, password)
- Session establishment

**US-029**: Cisco Client Testing - Advanced (8 points, P1)
- Advanced features (compression, MTU)
- DTLS fallback scenarios
- Multi-factor authentication
- Session persistence

### Protocol Implementation Stories

**US-003**: GnuTLS API Audit (COMPLETE, 8 points)
- Mapped 94 GnuTLS functions to wolfSSL equivalents
- Identified protocol-level considerations

**US-013**: DTLS Support (8 points, P1)
- DTLS 1.2 implementation
- Future: DTLS 1.3 upgrade

**US-026**: DTLS 1.3 Support (8 points, P3)
- RFC 9147 compliance
- Connection ID support
- Post-quantum readiness

---

## Migration Considerations

### From GnuTLS to wolfSSL

**Protocol-Level Impact**:
- ✅ Minimal - protocol is transport-agnostic
- ⚠️ TLS handshake details may differ
- ⚠️ Certificate validation order/strictness
- ⚠️ Session resumption mechanisms

**Testing Requirements**:
- Verify exact protocol behavior with Cisco clients
- Packet capture comparison (GnuTLS vs wolfSSL)
- Ensure no protocol regressions
- Timing-sensitive operations validation

**Risk Mitigation**:
- Dual-build support (GnuTLS + wolfSSL)
- A/B testing framework
- Rollback capability
- Extensive Cisco client testing

---

## Packet Capture Analysis

### Recommended Tools

1. **Wireshark** - Protocol analysis
2. **tcpdump** - Packet capture
3. **ssldump** - TLS/DTLS decryption
4. **mitmproxy** - HTTPS inspection

### Key Protocol Traces to Capture

**Authentication Flow**:
```
Client → Server: HTTPS GET /
Server → Client: 302 Redirect to /auth
Client → Server: POST /auth (credentials)
Server → Client: Session cookie
Client → Server: CONNECT /tunnel (with cookie)
Server → Client: 200 OK, start tunnel
```

**DTLS Establishment**:
```
Client → Server: UDP DTLS ClientHello + Cookie Request
Server → Client: DTLS HelloVerifyRequest (cookie)
Client → Server: DTLS ClientHello + Cookie
Server → Client: DTLS ServerHello
[DTLS handshake continues...]
```

---

## References

### Primary

1. **OpenConnect Protocol Draft**
   https://datatracker.ietf.org/doc/draft-mavrogiannopoulos-openconnect/
   - Authoritative protocol specification
   - Version 1.2 (draft-04)

2. **ocserv Documentation**
   https://ocserv.gitlab.io/www/
   - Official ocserv documentation
   - Configuration examples
   - Deployment guides

3. **OpenConnect Client**
   https://www.infradead.org/openconnect/
   - Client implementation
   - Protocol details
   - Compatibility notes

### Secondary

4. **Cisco AnyConnect Documentation** (proprietary)
   - Official Cisco documentation
   - Requires Cisco login
   - Protocol details not publicly available

5. **Reverse Engineering Resources**
   - OpenConnect source code analysis
   - Network protocol captures
   - Community knowledge

### wolfSSL Implementation

6. **wolfSSL Manual**
   https://www.wolfssl.com/documentation/manuals/wolfssl/index.html
   - TLS/DTLS implementation
   - API reference

7. **wolfSSL Examples**
   https://github.com/wolfSSL/wolfssl-examples
   - TLS server/client examples
   - DTLS implementations

---

## Compliance Checklist

For ioguard v2.0.0 to be compliant:

### Protocol Requirements
- [ ] OpenConnect Protocol v1.2 full compliance
- [ ] TLS 1.3 support (RFC 8446)
- [ ] DTLS 1.2 support (RFC 6347)
- [ ] DTLS 1.3 support (RFC 9147) - future
- [ ] HTTP/1.1 control channel (RFC 9112)

### Cisco Compatibility
- [ ] Cisco Secure Client 5.0 tested
- [ ] Cisco Secure Client 5.1 tested
- [ ] Cisco Secure Client 5.2 tested
- [ ] All authentication methods work
- [ ] DTLS fallback functions correctly
- [ ] Session persistence works
- [ ] No protocol-level regressions

### Security Requirements
- [ ] Encryption (eavesdropping prevention)
- [ ] Integrity (tampering prevention)
- [ ] Authentication (message forgery prevention)
- [ ] Forward secrecy (PFS cipher suites)
- [ ] Certificate validation strictness

---

**Document Maintainer**: ioguard protocol team
**Review Schedule**: Monthly during implementation
**Next Review**: 2025-11-29
