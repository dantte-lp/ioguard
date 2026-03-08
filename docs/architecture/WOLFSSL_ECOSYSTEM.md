# wolfSSL Ecosystem Integration Guide

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Project**: ringwall v2.0.0

---

## Overview

This document provides comprehensive analysis of the wolfSSL ecosystem components and how they can enhance ringwall VPN server security, performance, and functionality.

---

## 📚 Official Documentation Links

### Core Documentation

**wolfSSL Manual** (PRIMARY REFERENCE)
https://www.wolfssl.com/documentation/manuals/wolfssl/index.html
- Complete API reference
- TLS 1.3 and DTLS 1.3 implementation
- Cipher suite configuration
- Certificate handling
- Session management

**wolfSSL Tuning Guide** (PERFORMANCE)
https://www.wolfssl.com/documentation/manuals/wolfssl-tuning-guide/index.html
- Performance optimization techniques
- Memory footprint reduction
- CPU optimization strategies
- Benchmark methodology

**Hardware Cryptography Support** (ACCELERATION)
https://wolfssl.com/docs/hardware-crypto-support/
- Intel AES-NI
- ARM Crypto Extensions
- Intel QuickAssist
- AMD Zen optimizations
- HSM integration

**Static Buffer Allocation** (EMBEDDED)
https://wolfssl.com/docs/static-buffer-allocation/
- Zero malloc() usage
- Predictable memory footprint
- Embedded systems optimization

### Component Documentation

**wolfSentry Manual**
https://wolfssl.com/documentation/manuals/wolfsentry/
- Embedded IDPS/firewall
- Network filtering rules
- Connection tracking
- Threat detection

**wolfCLU Manual**
https://wolfssl.com/documentation/manuals/wolfclu/
- Command-line utilities
- Certificate generation
- Key management
- Testing tools

### Code Examples

**wolfSSL Examples Repository**
https://github.com/wolfSSL/wolfssl-examples
- TLS server/client examples
- DTLS implementations
- Certificate authentication
- PSK (Pre-Shared Key) examples
- IoT/embedded examples

---

## 🛡️ wolfSentry - Embedded IDPS Integration

### What is wolfSentry?

**Version**: v1.6.3 (January 2025)
**License**: GPLv2 (compatible with ocserv GPLv2+)
**Repository**: https://github.com/wolfSSL/wolfsentry

wolfSentry is a lightweight, embeddable Intrusion Detection and Prevention System (IDPS) and firewall engine, designed to work seamlessly with wolfSSL.

### Key Features

1. **Dynamic Firewall Rules**
   - Runtime rule modification without restart
   - Prefix-based IP/netblock lookup
   - Wildcard-capable matching
   - Interface/protocol/port filtering

2. **Connection Tracking**
   - Per-connection state management
   - Session counting and limits
   - Automatic expiration with grace periods
   - Connection ID (CID) support

3. **Threat Detection**
   - Rate limiting per IP/subnet
   - Brute-force attack prevention
   - DDoS mitigation
   - Custom event triggers

4. **Address Family Support**
   - IPv4 and IPv6
   - **NEW in v1.6.3**: CAN bus address family
   - Bitmask-based address matching

### Use Cases for ringwall

#### 1. VPN Connection Rate Limiting

**Problem**: Brute-force authentication attacks
**Solution**: wolfSentry can limit connection attempts per IP

```c
// Example: Rate limit VPN connections
struct wolfsentry_config config = {
    .max_connect_per_min = 5,      // Max 5 connections per minute
    .penalty_duration_sec = 300,    // 5-minute penalty for violators
    .blacklist_threshold = 10       // Permanent blacklist after 10 violations
};

// Integrate with ocserv authentication
int handle_vpn_connection(const char *client_ip) {
    wolfsentry_action_res_t action;

    // Check if client is allowed to connect
    if (wolfsentry_route_event_dispatch(&config, client_ip,
                                        &action) == 0) {
        if (action & WOLFSENTRY_ACTION_REJECT) {
            log_security_event("Connection blocked: %s (rate limit)", client_ip);
            return -1;  // Reject connection
        }
    }

    // Proceed with normal authentication
    return authenticate_client(client_ip);
}
```

**Benefits**:
- ✅ Prevents brute-force attacks
- ✅ Automatic IP blacklisting
- ✅ No external dependencies
- ✅ Minimal overhead (~10KB memory)

#### 2. Geographic Filtering

**Problem**: Restrict VPN access by country/region
**Solution**: wolfSentry prefix-based filtering

```c
// Block entire subnets (e.g., specific countries)
struct {
    const char *subnet;
    const char *description;
} blocked_subnets[] = {
    {"185.220.0.0/16", "Tor exit nodes"},
    {"194.169.0.0/16", "Known malicious range"},
    // Add GeoIP-based blocks
};

// Dynamic rule insertion at runtime
for (int i = 0; i < ARRAY_SIZE(blocked_subnets); i++) {
    wolfsentry_route_insert(&config,
                           blocked_subnets[i].subnet,
                           WOLFSENTRY_ACTION_REJECT);
}
```

**Benefits**:
- ✅ Compliance with regional restrictions
- ✅ Reduce attack surface
- ✅ Runtime configuration updates

#### 3. Per-User Connection Limits

**Problem**: Users creating too many simultaneous sessions
**Solution**: Connection counting per authenticated user

```c
// Track connections per user (after successful auth)
int track_user_connection(const char *username, const char *client_ip) {
    uint32_t current_connections;

    // Query wolfsentry for current user connection count
    wolfsentry_user_connection_count(username, &current_connections);

    // Check against max-same-clients configuration
    if (current_connections >= config->max_same_clients) {
        log_warning("User %s exceeded connection limit (%u/%u)",
                   username, current_connections, config->max_same_clients);
        return -1;  // Reject new connection
    }

    // Register new connection
    wolfsentry_user_connection_add(username, client_ip);
    return 0;
}
```

**Benefits**:
- ✅ Fixes issue #372 (max-same-clients not working)
- ✅ Fine-grained user limits
- ✅ Per-IP and per-user tracking

#### 4. DTLS DoS Protection

**Problem**: DTLS handshake floods
**Solution**: Stateless cookie verification + wolfSentry rate limiting

```c
// DTLS connection rate limiting
int dtls_handshake_handler(const char *client_ip, uint16_t client_port) {
    // wolfSentry checks before expensive DTLS operations
    if (wolfsentry_check_udp_rate(client_ip, client_port) != 0) {
        // Too many handshake attempts, silently drop
        stats_increment("dtls.handshake.rate_limited");
        return -1;
    }

    // Proceed with DTLS cookie verification
    return dtls_verify_cookie_and_handshake(client_ip, client_port);
}
```

**Benefits**:
- ✅ Protects against DTLS amplification attacks
- ✅ Complements wolfSSL's built-in cookie mechanism
- ✅ Minimal CPU overhead

### Integration Architecture

```
┌─────────────────────────────────────────────┐
│         ringwall VPN Server            │
│                                             │
│  ┌─────────────┐        ┌──────────────┐   │
│  │ Connection  │───────>│  wolfSentry  │   │
│  │   Handler   │<───────│    Engine    │   │
│  └─────────────┘        └──────────────┘   │
│         │                      │            │
│         │                      │            │
│         v                      v            │
│  ┌─────────────┐        ┌──────────────┐   │
│  │   wolfSSL   │        │   Firewall   │   │
│  │  TLS/DTLS   │        │    Rules     │   │
│  └─────────────┘        └──────────────┘   │
└─────────────────────────────────────────────┘
```

**Integration Points**:
1. **Pre-authentication**: Check IP/rate limits before TLS handshake
2. **Post-authentication**: Track authenticated sessions
3. **Active connections**: Monitor and enforce limits
4. **Disconnect**: Update connection counts

### Performance Impact

**Overhead**: ~5-10% CPU for rule evaluation
**Memory**: ~10-50 KB depending on rule count
**Latency**: <1ms per connection check

**Recommendation**: ✅ **HIGH VALUE** - Addresses multiple security issues (#372, DoS protection)

---

## 🔧 wolfCLU - Command-Line Utilities

### What is wolfCLU?

**Version**: v0.1.8 (April 2025)
**License**: GPLv2
**Repository**: https://github.com/wolfSSL/wolfCLU

wolfCLU provides OpenSSL-compatible command-line tools built on wolfSSL, useful for certificate management, testing, and debugging.

### Key Tools

1. **wolfssl** - General purpose tool
2. **wolfssl genkey** - Key generation
3. **wolfssl gencert** - Certificate generation
4. **wolfssl req** - Certificate signing requests
5. **wolfssl x509** - Certificate inspection
6. **wolfssl dgst** - Hash/digest operations
7. **wolfssl enc** - Encryption/decryption

### Use Cases for ringwall

#### 1. Certificate Generation for Testing

**Problem**: Need to generate test certificates for PoC and integration tests
**Solution**: Automated certificate generation with wolfCLU

```bash
#!/bin/bash
# tests/poc/generate_certs.sh (simplified with wolfCLU)

# Generate CA key and certificate
wolfssl genkey -out ca-key.pem -keytype rsa -size 4096
wolfssl gencert -key ca-key.pem -out ca-cert.pem \
    -subject "/CN=ringwall Test CA" \
    -days 3650 -ca

# Generate server key and certificate
wolfssl genkey -out server-key.pem -keytype rsa -size 2048
wolfssl req -key server-key.pem -out server.csr \
    -subject "/CN=vpn.example.com"
wolfssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -out server-cert.pem -days 365

# Generate client certificate
wolfssl genkey -out client-key.pem -keytype rsa -size 2048
wolfssl req -key client-key.pem -out client.csr \
    -subject "/CN=test-user"
wolfssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -out client-cert.pem -days 365
```

**Benefits**:
- ✅ Simpler than OpenSSL commands
- ✅ Consistent with wolfSSL library behavior
- ✅ Same crypto backend (no OpenSSL dependency for testing)

#### 2. Certificate Validation and Debugging

**Problem**: Debug certificate issues in production
**Solution**: wolfCLU certificate inspection

```bash
# Inspect server certificate
wolfssl x509 -in server-cert.pem -text -noout

# Verify certificate chain
wolfssl verify -CAfile ca-cert.pem server-cert.pem

# Check certificate dates
wolfssl x509 -in server-cert.pem -dates -noout

# Extract public key
wolfssl x509 -in server-cert.pem -pubkey -noout
```

**Benefits**:
- ✅ Debugging tool for Cisco client compatibility
- ✅ Validate certificate chains
- ✅ No OpenSSL installation required

#### 3. Performance Benchmarking

**Problem**: Benchmark crypto operations
**Solution**: wolfCLU speed tests

```bash
# Benchmark RSA operations
wolfssl speed rsa

# Benchmark AES encryption
wolfssl speed aes-256-gcm

# Benchmark key exchange
wolfssl speed ecdhe

# Benchmark hash functions
wolfssl speed sha256
```

**Benefits**:
- ✅ Validate hardware acceleration (AES-NI)
- ✅ Compare with OpenSSL benchmarks
- ✅ Identify performance bottlenecks

### Integration Recommendations

**Build System Integration**:
```makefile
# Makefile target for certificate generation
.PHONY: test-certs
test-certs:
	@which wolfssl >/dev/null 2>&1 || \
		(echo "wolfCLU not found, using fallback" && ./scripts/openssl_certs.sh)
	./tests/poc/generate_certs_wolfclu.sh
```

**CI/CD Integration**:
```yaml
# .github/workflows/tests.yml
- name: Generate test certificates
  run: |
    wolfssl genkey -out ca-key.pem -keytype rsa -size 4096
    wolfssl gencert -key ca-key.pem -out ca-cert.pem -ca
```

**Recommendation**: ✅ **MEDIUM VALUE** - Useful for testing/debugging, not critical for production

---

## 🔐 wolfPKCS11 - Hardware Security Module Support

### What is wolfPKCS11?

**Repository**: https://github.com/wolfSSL/wolfPKCS11
**License**: GPLv2
**Purpose**: PKCS#11 interface for wolfSSL to support Hardware Security Modules (HSMs)

PKCS#11 (Cryptoki) is the standard API for hardware security modules, smart cards, and USB tokens.

### Key Features

1. **HSM Integration**
   - Store private keys in hardware
   - Hardware-accelerated crypto operations
   - Tamper-resistant key storage

2. **Smart Card Support**
   - PIV (Personal Identity Verification) cards
   - CAC (Common Access Card)
   - OpenSC compatible tokens

3. **USB Token Support**
   - YubiKey
   - Nitrokey
   - SoftHSM (software emulation)

### Use Cases for ringwall

#### 1. Enterprise PKI Integration

**Problem**: Enterprise deployments require HSM-backed certificates
**Solution**: wolfPKCS11 for server certificate private key protection

```c
// Load server private key from HSM
#include <wolfssl/wolfcrypt/pkcs11.h>

int load_server_key_from_hsm(WOLFSSL_CTX *ctx) {
    Pkcs11Dev dev;
    Pkcs11Token token;
    int ret;

    // Initialize PKCS#11 device
    ret = wc_Pkcs11_Initialize(&dev, "/usr/lib/libpkcs11.so", NULL);
    if (ret != 0) {
        log_error("Failed to initialize PKCS#11: %d", ret);
        return -1;
    }

    // Open token slot
    ret = wc_Pkcs11Token_Init(&token, &dev, 0, "VPN Server Key",
                              (byte*)"1234", 4);  // PIN
    if (ret != 0) {
        log_error("Failed to open HSM token: %d", ret);
        return -1;
    }

    // Load private key from token (key stays in HSM!)
    ret = wolfSSL_CTX_use_PrivateKey_Id(ctx,
                                        (unsigned char*)"server-key",
                                        10, &token);
    if (ret != WOLFSSL_SUCCESS) {
        log_error("Failed to load HSM key: %d", ret);
        return -1;
    }

    log_info("Server private key loaded from HSM (never in RAM)");
    return 0;
}
```

**Benefits**:
- ✅ Private key NEVER in server RAM/disk
- ✅ FIPS 140-2/140-3 Level 2+ compliance
- ✅ Meets enterprise security requirements

#### 2. Certificate-Based Client Authentication

**Problem**: Support smart card authentication for VPN clients
**Solution**: wolfPKCS11 for client certificate validation

```c
// Validate client certificate from smart card
int validate_client_smartcard(WOLFSSL *ssl) {
    X509 *cert = wolfSSL_get_peer_certificate(ssl);
    if (!cert) {
        return -1;
    }

    // Extract subject DN from smart card certificate
    char subject[256];
    wolfSSL_X509_NAME_oneline(
        wolfSSL_X509_get_subject_name(cert),
        subject, sizeof(subject)
    );

    // Check certificate was issued by trusted HSM CA
    // Verify against CAC/PIV requirements
    if (verify_government_pki_cert(cert) != 0) {
        log_security("Invalid CAC/PIV certificate from client");
        return -1;
    }

    log_info("Client authenticated with smart card: %s", subject);
    return 0;
}
```

**Benefits**:
- ✅ Government/military deployment support
- ✅ CAC/PIV card compatibility
- ✅ Multi-factor authentication (card + PIN)

#### 3. Key Ceremony and Rotation

**Problem**: Secure key generation and rotation
**Solution**: Generate and rotate keys in HSM

```bash
# Generate server key pair in HSM (never exported)
pkcs11-tool --module /usr/lib/libpkcs11.so \
    --login --pin 1234 \
    --keypairgen --key-type rsa:4096 \
    --label "ocserv-2025-key"

# Generate CSR using HSM key
wolfssl req -engine pkcs11 \
    -key "pkcs11:object=ocserv-2025-key" \
    -out server-2025.csr

# After CA signing, import certificate
pkcs11-tool --module /usr/lib/libpkcs11.so \
    --login --pin 1234 \
    --write-object server-2025-cert.pem \
    --type cert --label "ocserv-2025-cert"
```

**Benefits**:
- ✅ Keys generated in hardware, never exported
- ✅ Audit trail for key operations
- ✅ Secure key rotation

### Compatibility Considerations

**Upstream ocserv PKCS#11 Support**:
- Current ocserv uses GnuTLS PKCS#11 integration
- Migration issue #585 and critical analysis identified this as **HIGH RISK**

**Migration Strategy**:
```c
// Abstraction layer for PKCS#11
typedef struct {
    void *handle;        // HSM handle
    int (*load_cert)(void *ctx, const char *id);
    int (*load_key)(void *ctx, const char *id);
    int (*sign)(void *ctx, const byte *data, byte *sig);
} pkcs11_backend_t;

// GnuTLS backend (for migration compatibility)
pkcs11_backend_t gnutls_pkcs11_backend = {
    .load_cert = gnutls_pkcs11_load_cert,
    .load_key = gnutls_pkcs11_load_key,
    .sign = gnutls_pkcs11_sign
};

// wolfSSL backend (target)
pkcs11_backend_t wolfssl_pkcs11_backend = {
    .load_cert = wolfssl_pkcs11_load_cert,
    .load_key = wolfssl_pkcs11_load_key,
    .sign = wolfssl_pkcs11_sign
};
```

**Recommendation**: ✅ **CRITICAL for Enterprise** - Must support for FIPS/HSM deployments

---

## 📊 Comparison Matrix

| Component | Priority | Complexity | Value | Use Case |
|-----------|----------|------------|-------|----------|
| **wolfSentry** | HIGH | Medium | ⭐⭐⭐⭐⭐ | Security, rate limiting, DoS protection |
| **wolfCLU** | MEDIUM | Low | ⭐⭐⭐ | Testing, debugging, certificate mgmt |
| **wolfPKCS11** | HIGH | High | ⭐⭐⭐⭐⭐ | Enterprise PKI, HSM, compliance |

---

## 🎯 Integration Roadmap

### Phase 1: Core TLS/DTLS (Sprint 0-4)
- ✅ wolfSSL TLS 1.3 / DTLS 1.3
- ⏳ Certificate handling
- ⏳ Session management

### Phase 2: Security Enhancements (Sprint 5-7)
- [ ] **wolfSentry integration** (US-042, 13 points)
  - Rate limiting implementation
  - Connection tracking
  - IP blacklisting
  - **Fixes**: Issue #372 (max-same-clients)

### Phase 3: HSM Support (Sprint 8-10)
- [ ] **wolfPKCS11 integration** (US-043, 21 points)
  - HSM private key loading
  - Smart card client auth
  - **Addresses**: High-risk PKCS#11 migration

### Phase 4: Testing Tools (Sprint 11-12)
- [ ] **wolfCLU integration** (US-044, 5 points)
  - Automated certificate generation
  - Build system integration
  - CI/CD improvements

---

## 🔗 Additional Resources

### Official Documentation
- **wolfSSL Manual**: https://www.wolfssl.com/documentation/manuals/wolfssl/index.html
- **Tuning Guide**: https://www.wolfssl.com/documentation/manuals/wolfssl-tuning-guide/index.html
- **wolfSentry Manual**: https://wolfssl.com/documentation/manuals/wolfsentry/
- **wolfCLU Manual**: https://wolfssl.com/documentation/manuals/wolfclu/
- **Hardware Crypto**: https://wolfssl.com/docs/hardware-crypto-support/
- **Static Buffers**: https://wolfssl.com/docs/static-buffer-allocation/

### Code Examples
- **wolfSSL Examples**: https://github.com/wolfSSL/wolfssl-examples
  - TLS server/client
  - DTLS examples
  - PSK (Pre-Shared Key)
  - Certificate authentication
  - IoT examples

### Community
- **Support Forum**: https://www.wolfssl.com/forums/
- **Stack Overflow**: [wolfssl] tag
- **GitHub Issues**: https://github.com/wolfSSL/wolfssl/issues

---

## 📝 Action Items

### Immediate (Sprint 0-1)
- [x] Document wolfSSL ecosystem components
- [ ] Create User Story US-042 (wolfSentry integration)
- [ ] Create User Story US-043 (wolfPKCS11 support)
- [ ] Create User Story US-044 (wolfCLU testing tools)

### Short-term (Sprint 2-4)
- [ ] Design wolfSentry integration architecture
- [ ] Prototype rate limiting with wolfSentry
- [ ] Test wolfCLU for certificate generation

### Long-term (Sprint 5+)
- [ ] Implement full wolfSentry IDPS
- [ ] Add HSM support via wolfPKCS11
- [ ] Document enterprise deployment with HSM

---

**Document Maintainer**: ringwall team
**Review Schedule**: Monthly
**Next Review**: 2025-11-29
