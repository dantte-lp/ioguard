---
name: wolfssl-api
description: Use when writing or modifying code that interacts with wolfSSL/wolfCrypt APIs — TLS/DTLS handshakes, certificate management, session caching, FIPS 140-3 constraints, callback-based I/O integration with libuv
---

# wolfSSL API Patterns for ringwall

## Context7 Reference
Always fetch latest docs: library ID `/wolfssl/wolfssl`

## Initialization Pattern

```c
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

[[nodiscard]]
static int rw_tls_init(void) {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return -1;
    }
    return 0;
}

static void rw_tls_cleanup(void) {
    wolfSSL_Cleanup();
}
```

## Context Creation

```c
[[nodiscard]]
static WOLFSSL_CTX *rw_create_ctx(bool is_server, bool use_dtls) {
    WOLFSSL_METHOD *method;

    if (use_dtls) {
        method = is_server ? wolfDTLSv1_3_server_method()
                           : wolfDTLSv1_3_client_method();
    } else {
        method = is_server ? wolfTLSv1_3_server_method()
                           : wolfTLSv1_3_client_method();
    }

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (ctx == nullptr) return nullptr;

    // Load certificates
    // Enable session tickets
    // Set I/O callbacks

    return ctx;
}
```

## Callback-Based I/O (libuv integration)

wolfSSL MUST use custom I/O callbacks for non-blocking operation with libuv:

```c
// Set callbacks on context
wolfSSL_CTX_SetIORecv(ctx, rw_tls_recv_cb);
wolfSSL_CTX_SetIOSend(ctx, rw_tls_send_cb);

// Callback signatures
static int rw_tls_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    rw_connection_t *conn = (rw_connection_t *)ctx;
    // Read from libuv buffer, return WOLFSSL_CBIO_ERR_WANT_READ if no data
}

static int rw_tls_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    rw_connection_t *conn = (rw_connection_t *)ctx;
    // Write via libuv uv_write, return sz on success
}
```

## Session Caching

```c
// Enable server-side session cache
wolfSSL_CTX_set_session_cache_mode(ctx, WOLFSSL_SESS_CACHE_SERVER);

// Session ticket support (TLS 1.3)
wolfSSL_CTX_UseSessionTicket(ctx);
```

## FIPS 140-3 Constraints

When `HAVE_FIPS` is defined:
- Only FIPS-approved algorithms (AES-GCM, SHA-256/384/512, ECDHE P-256/P-384)
- No ChaCha20-Poly1305 in FIPS mode
- wolfCrypt_SetCb_fips() for FIPS callback
- Must call wolfCrypt_GetStatus_fips() to verify module status

## DTLS 1.3 Specifics

- Use `wolfDTLSv1_3_server_method()` / `wolfDTLSv1_3_client_method()`
- Cookie exchange: `wolfSSL_send_hrr_cookie(ssl, NULL, 0)`
- Connection ID: `wolfSSL_dtls_cid_use(ssl)`
- MTU setting: `wolfSSL_dtls_set_mtu(ssl, 1400)`

## Certificate Loading

```c
// File-based
wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM);
wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM);

// Buffer-based (for #embed in C23)
wolfSSL_CTX_use_certificate_buffer(ctx, cert_buf, cert_sz, WOLFSSL_FILETYPE_PEM);
```

## Error Handling

```c
int ret = wolfSSL_connect(ssl);
if (ret != WOLFSSL_SUCCESS) {
    int err = wolfSSL_get_error(ssl, ret);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
        // Non-blocking, retry later
        return RW_WANT_IO;
    }
    char errbuf[WOLFSSL_MAX_ERROR_SZ];
    wolfSSL_ERR_error_string(err, errbuf);
    // Log error
    return RW_ERROR;
}
```

## Cisco-Compatible Cipher Configuration

wolfSSL cipher strings must match Cisco Secure Client expectations.
See `/opt/projects/repositories/ringwall-docs/docs/openconnect-protocol/protocol/crypto.md`

```c
// TLS 1.3 ciphers (Cisco priority order)
wolfSSL_CTX_set_cipher_list(ctx,
    "TLS_AES_256_GCM_SHA384:"
    "TLS_AES_128_GCM_SHA256:"
    "TLS_CHACHA20_POLY1305_SHA256"
);

// TLS 1.2 ciphers (Cisco compatible)
wolfSSL_CTX_set_cipher_list(ctx,
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256"
);

// DTLS 1.2 ciphers (Cisco uses DHE, NOT ECDHE for DTLS)
wolfSSL_CTX_set_cipher_list(dtls_ctx,
    "DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:"
    "AES256-SHA:"
    "AES128-SHA"
);

// Elliptic curves (Cisco priority: X25519 > P-256 > P-384)
wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_X25519);
wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP384R1);

// Signature algorithms
wolfSSL_CTX_set1_sigalgs_list(ctx,
    "ECDSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA+SHA256"
);
```

## DTLS for Cisco Clients (DTLS 1.2 ONLY)

Cisco Secure Client does NOT support DTLS 1.3. Use DTLS 1.2 for Cisco compat:

```c
// For Cisco clients: DTLS 1.2
WOLFSSL_METHOD *dtls_method = wolfDTLSv1_2_server_method();

// For own client (ringwall-connect): DTLS 1.3
WOLFSSL_METHOD *dtls13_method = wolfDTLSv1_3_server_method();
```

## DTLS Master Secret Bootstrap

Cisco DTLS uses master secret from CSTP headers (NO separate handshake):

```c
// After CSTP HTTP CONNECT, server sends:
//   X-DTLS-Session-ID: <hex>
//   X-DTLS-Master-Secret: <hex>
// Client uses these to establish DTLS session

// Server must set pre-shared session params for DTLS
wolfSSL_set_session_id(dtls_ssl, session_id, 32);
// Master secret handling varies by wolfSSL version
```

## Certificate Validation with Template Filtering

```c
// Custom verify callback for multi-cert scenarios
static int rw_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *ctx) {
    WOLFSSL_X509 *cert = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
    // 1. Check validity period
    // 2. Check Enhanced Key Usage (Client Authentication)
    // 3. Check template name (MS OID 1.3.6.1.4.1.311.20.2) if configured
    // 4. Check CRL/OCSP status
    return preverify;  // 1 = success, 0 = fail
}

wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
                             WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       rw_verify_callback);
```

## Post-Quantum Crypto (wolfSSL 5.8.4+)

```c
// ML-KEM (Kyber) for key exchange
wolfSSL_UseKeyShare(ssl, WOLFSSL_ML_KEM_512);

// ML-DSA (Dilithium) for signatures — requires PQ-enabled build
// --enable-kyber --enable-dilithium
```

## Security Checklist

- [ ] Use `wolfSSL_ConstantCompare()` for all secret comparisons
- [ ] Call `ForceZero()` on sensitive buffers before freeing
- [ ] Verify certificate chain with custom verify callback
- [ ] Set minimum protocol version (TLS 1.2 for Cisco, TLS 1.3 for own client)
- [ ] Enable SNI with `wolfSSL_UseSNI()`
- [ ] Set ALPN with `wolfSSL_UseALPN()`
- [ ] Zero DTLS master secret after session setup
- [ ] Configure Cisco-compatible cipher suites
- [ ] Use DTLS 1.2 for Cisco, DTLS 1.3 for ringwall-connect
- [ ] Implement wolfSentry AcceptFilter integration
