---
name: wolfssl-api
description: Use when writing or modifying code that interacts with wolfSSL/wolfCrypt APIs — TLS/DTLS handshakes, certificate management, session caching, FIPS 140-3 constraints, buffer-based I/O integration with io_uring
---

# wolfSSL API Patterns for ioguard

## Context7 Reference
Always fetch latest docs: library ID `/wolfssl/wolfssl`

## Initialization Pattern

```c
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

[[nodiscard]]
static int iog_tls_init(void) {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return -1;
    }
    return 0;
}

static void iog_tls_cleanup(void) {
    wolfSSL_Cleanup();
}
```

## Context Creation

```c
[[nodiscard]]
static WOLFSSL_CTX *iog_create_ctx(bool is_server, bool use_dtls) {
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

## Buffer-Based I/O (io_uring integration)

wolfSSL MUST use custom I/O callbacks with intermediate cipher buffers.
io_uring reads/writes ciphertext into connection-owned buffers; wolfSSL never
touches the socket directly.

### Architecture

```
io_uring recv → cipher_in buffer → wolfSSL_read() → plaintext out
plaintext in → wolfSSL_write() → cipher_out buffer → io_uring send
```

### Cipher Buffers (per-connection)

```c
typedef struct {
    uint8_t *data;
    size_t   size;      // allocated capacity
    size_t   head;      // read position
    size_t   tail;      // write position
} iog_cipher_buf_t;

typedef struct {
    iog_cipher_buf_t cipher_in;    // io_uring recv target
    iog_cipher_buf_t cipher_out;   // io_uring send source
} iog_tls_io_t;
```

### I/O Callbacks

```c
wolfSSL_CTX_SetIORecv(ctx, iog_tls_recv_cb);
wolfSSL_CTX_SetIOSend(ctx, iog_tls_send_cb);

// Recv callback: reads from cipher_in buffer (NOT from socket)
static int iog_tls_recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    iog_tls_io_t *io = (iog_tls_io_t *)ctx;
    size_t avail = io->cipher_in.tail - io->cipher_in.head;
    if (avail == 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;  // need more data from io_uring recv
    }
    int n = (int)(avail < (size_t)sz ? avail : (size_t)sz);
    memcpy(buf, io->cipher_in.data + io->cipher_in.head, n);
    io->cipher_in.head += n;
    return n;
}

// Send callback: writes to cipher_out buffer (NOT to socket)
static int iog_tls_send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    iog_tls_io_t *io = (iog_tls_io_t *)ctx;
    size_t space = io->cipher_out.size - io->cipher_out.tail;
    if (space == 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;  // need io_uring send to drain
    }
    int n = (int)(space < (size_t)sz ? space : (size_t)sz);
    memcpy(io->cipher_out.data + io->cipher_out.tail, buf, n);
    io->cipher_out.tail += n;
    return n;
}
```

### TLS State Machine with io_uring

```c
// After io_uring recv CQE delivers ciphertext into cipher_in:
int ret = wolfSSL_read(ssl, plaintext, sizeof(plaintext));
int err = wolfSSL_get_error(ssl, ret);

switch (err) {
case WOLFSSL_ERROR_NONE:
    // Got plaintext — process CSTP/DTLS packet
    break;
case WOLFSSL_ERROR_WANT_READ:
    // Need more ciphertext — arm io_uring recv, resume later
    break;
case WOLFSSL_ERROR_WANT_WRITE:
    // TLS needs to send (renegotiation, alerts) — arm io_uring send
    // from cipher_out, resume later
    break;
default:
    // Fatal error — close connection
    break;
}

// After wolfSSL_write() fills cipher_out, drain via io_uring send:
if (io->cipher_out.tail > io->cipher_out.head) {
    // arm io_uring send with cipher_out data
}
```

### I/O Serialization (CRITICAL)

- **One wolfSSL_read() / wolfSSL_write() at a time** per SSL object
- wolfSSL maintains internal state — concurrent calls corrupt it
- Natural in ring-per-worker model: single thread owns the connection
- After WANT_READ/WANT_WRITE, do NOT call wolfSSL again until I/O completes

### Buffer Separation (CRITICAL)

| Buffer | Owner | io_uring target? | wolfSSL target? |
|--------|-------|-------------------|-----------------|
| cipher_in | Connection | YES (recv) | YES (recv callback reads from it) |
| cipher_out | Connection | YES (send) | YES (send callback writes to it) |
| plaintext | Stack/temp | NO | YES (wolfSSL_read output) |
| Provided buffer ring | Kernel→App | YES (recv into) | NO (copy to cipher_in first) |

**Never pass provided buffer ring memory directly to wolfSSL** — kernel
reclaims it when returned to ring. Copy to cipher_in first.

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
        return IOG_WANT_IO;
    }
    char errbuf[WOLFSSL_MAX_ERROR_SZ];
    wolfSSL_ERR_error_string(err, errbuf);
    // Log error
    return IOG_ERROR;
}
```

## Cisco-Compatible Cipher Configuration

wolfSSL cipher strings must match Cisco Secure Client expectations.
See `/opt/projects/repositories/ioguard-docs/docs/openconnect-protocol/protocol/crypto.md`

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

// For own client (ioguard-connect): DTLS 1.3
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
static int iog_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *ctx) {
    WOLFSSL_X509 *cert = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
    // 1. Check validity period
    // 2. Check Enhanced Key Usage (Client Authentication)
    // 3. Check template name (MS OID 1.3.6.1.4.1.311.20.2) if configured
    // 4. Check CRL/OCSP status
    return preverify;  // 1 = success, 0 = fail
}

wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER |
                             WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       iog_verify_callback);
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
- [ ] Use DTLS 1.2 for Cisco, DTLS 1.3 for ioguard-connect
- [ ] Implement wolfSentry AcceptFilter integration
