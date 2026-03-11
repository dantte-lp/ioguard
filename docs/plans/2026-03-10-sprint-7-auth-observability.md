# Sprint 7: Auth Backends + Observability — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Multi-backend authentication (RADIUS, LDAP, cert), HTTP parser migration (llhttp → iohttpparser), structured logging (stumpless), Prometheus metrics, and tech debt cleanup.

**Architecture:** Auth backends plug into auth-mod process via a common `iog_auth_backend_t` interface. Each backend (PAM, RADIUS, LDAP, cert) implements init/auth/destroy. Logging uses stumpless buffer targets flushed asynchronously via io_uring WRITEV. Prometheus metrics are exposed as a custom text formatter (~600 LOC) over the existing metrics counters.

**Tech Stack:** radcli (RADIUS), libldap (LDAP), wolfSSL (cert auth), iohttpparser (HTTP), stumpless (logging), io_uring (async I/O), Unity (tests)

**Skills:** `coding-standards`, `security-coding`, `wolfssl-api`, `io-uring-patterns`, `storage-patterns`

---

## Task Overview

| # | Task | Files | Tests | Est. |
|---|------|-------|-------|------|
| 1 | Fix test_priority_parser (6 failures) | `src/crypto/priority_parser.c` | 6 fixed | 30m |
| 2 | Fix test_tls_wolfssl (3 failures) | `src/crypto/tls_wolfssl.c` | 3 fixed | 30m |
| 3 | Worker loop TLS decrypt + CSTP forward | `src/core/worker_loop.c` | ~4 new | 45m |
| 4 | Auth backend interface | `src/auth/auth_backend.{h,c}` | ~6 new | 30m |
| 5 | RADIUS backend (radcli) | `src/auth/radius.{h,c}` | ~8 new | 45m |
| 6 | LDAP backend (libldap) | `src/auth/ldap.{h,c}` | ~8 new | 45m |
| 7 | Certificate auth (wolfSSL) | `src/auth/cert_auth.{h,c}` | ~6 new | 30m |
| 8 | HTTP parser migration (iohttpparser) | `src/network/http.{h,c}` | 7 updated + fuzz | 45m |
| 9 | Structured logging (stumpless) | `src/log/iog_log.{h,c}` | ~6 new | 45m |
| 10 | Prometheus metrics | `src/metrics/prometheus.{h,c}` | ~8 new | 45m |
| 11 | CMakeLists.txt + container updates | `CMakeLists.txt`, `Containerfile` | build check | 20m |

**Total:** ~60 new tests, ~6.5 hours estimated

---

## Task 1: Fix test_priority_parser (6 failures)

**Goal:** Fix 6 failing tokenizer tests in priority string parser.

**Files:**
- Debug: `tests/unit/test_priority_parser.c`
- Fix: `src/crypto/priority_parser.c`

**Step 1: Run failing tests to capture exact errors**

Run (in container):
```bash
ctest --preset clang-debug -R test_priority_parser --output-on-failure
```
Expected: 6 FAIL with specific assertion messages.

**Step 2: Identify root cause in tokenizer**

Read `src/crypto/priority_parser.c`, focusing on `priority_tokenize()` function.
The 6 failures are all in the tokenizer layer:
- `tokenize_empty_string_returns_error`
- `tokenize_null_pointer_returns_error`
- `tokenize_single_keyword_normal`
- `tokenize_keyword_with_modifier`
- `tokenize_version_addition`
- `tokenize_version_removal`

Look for: null/empty input handling, string splitting on `:` and `+`/`-` prefixes.

**Step 3: Fix the tokenizer**

Apply minimal fixes to `priority_tokenize()` based on the assertion failures.
Common issues: missing null check, incorrect string boundary detection, off-by-one in token extraction.

**Step 4: Verify all 32 tests pass**

Run:
```bash
ctest --preset clang-debug -R test_priority_parser --output-on-failure
```
Expected: 32 tests PASS.

**Step 5: Commit**

```bash
git add src/crypto/priority_parser.c
git commit -m "fix(crypto): resolve 6 priority parser tokenizer failures"
```

---

## Task 2: Fix test_tls_wolfssl (3 failures)

**Goal:** Fix 3 failing wolfSSL tests (DTLS MTU, error mapping, error strings).

**Files:**
- Debug: `tests/unit/test_tls_wolfssl.c`
- Fix: `src/crypto/tls_wolfssl.c`

**Step 1: Run failing tests to capture exact errors**

Run (in container):
```bash
ctest --preset clang-debug -R test_tls_wolfssl --output-on-failure
```
Expected: 3 FAIL. Note which of these fail:
- `test_dtls_set_get_mtu` — DTLS MTU getter/setter
- `test_error_mapping` — wolfSSL → abstraction error mapping
- `test_error_strings` — error string conversion

**Step 2: Diagnose each failure**

Read `src/crypto/tls_wolfssl.c`:
- For MTU: check `tls_session_set_mtu()` and `tls_session_get_mtu()` — likely `wolfSSL_dtls_set_mtu()` / `wolfSSL_dtls_get_peer_mtu()` API mismatch.
- For error mapping: check `tls_wolfssl_map_error()` — likely missing or wrong mappings.
- For error strings: check `tls_error_string()` — likely null return from wolfSSL.

**Step 3: Apply fixes**

Fix each based on diagnosis. Consult wolfSSL docs via context7 (`/wolfssl/wolfssl`) if API signatures are unclear.

**Step 4: Verify all 22 tests pass**

Run:
```bash
ctest --preset clang-debug -R test_tls_wolfssl --output-on-failure
```
Expected: 22 tests PASS.

**Step 5: Commit**

```bash
git add src/crypto/tls_wolfssl.c
git commit -m "fix(crypto): resolve 3 wolfSSL test failures — MTU, error mapping, error strings"
```

---

## Task 3: Worker Loop TLS Decrypt + CSTP Forward

**Goal:** Complete the worker data path: io_uring recv → wolfSSL decrypt → CSTP deframe → TUN write.

**Files:**
- Modify: `src/core/worker_loop.c:66-67` (replace TODOs)
- Modify: `src/core/worker_loop.h` (add cipher buffer fields)
- Test: `tests/unit/test_worker_loop.c` (add data path tests)

**Step 1: Write failing tests for TLS decrypt path**

In `tests/unit/test_worker_loop.c`, add:

```c
void test_worker_loop_tls_recv_decrypts_data(void)
{
    /* Test that on_tls_recv passes ciphertext through wolfSSL_read
     * and produces plaintext. Uses mock wolfSSL session. */
}

void test_worker_loop_tls_recv_want_read_rearms(void)
{
    /* Test that WOLFSSL_ERROR_WANT_READ re-arms io_uring recv */
}

void test_worker_loop_cstp_data_forwarded_to_tun(void)
{
    /* Test that decrypted CSTP DATA packets get written to TUN fd */
}

void test_worker_loop_tls_recv_error_closes_connection(void)
{
    /* Test that fatal TLS error triggers connection cleanup */
}
```

**Step 2: Run tests to verify they fail**

Run: `ctest --preset clang-debug -R test_worker_loop --output-on-failure`
Expected: 4 new tests FAIL.

**Step 3: Add cipher buffer to connection struct**

In `worker_loop.h` or `worker.h`, add per-connection cipher buffers:
```c
/* Per-connection TLS I/O state (wolfssl-api skill: cipher buffer pattern) */
typedef struct {
    uint8_t *data;
    size_t size;
    size_t head;
    size_t tail;
} rw_cipher_buf_t;
```

**Step 4: Implement TLS decrypt in on_tls_recv**

Replace TODO lines 66-67 in `worker_loop.c`:

```c
/* Feed ciphertext to cipher_in buffer */
memcpy(conn->cipher_in.data + conn->cipher_in.tail,
       conn->recv_buf, conn->recv_len);
conn->cipher_in.tail += conn->recv_len;

/* Attempt TLS decryption */
uint8_t plaintext[RW_CSTP_MAX_PAYLOAD];
int n = wolfSSL_read(conn->tls_session, plaintext, sizeof(plaintext));
int err = wolfSSL_get_error(conn->tls_session, n);

if (err == WOLFSSL_ERROR_NONE && n > 0) {
    /* CSTP deframe and forward to TUN */
    iog_io_prep_write_cb(loop->io, conn->tun_fd,
                        plaintext, (size_t)n, on_tun_write, ctx);
} else if (err == WOLFSSL_ERROR_WANT_READ) {
    /* Need more ciphertext — re-arm recv (normal) */
} else {
    /* Fatal TLS error — close connection */
}
```

**Step 5: Run tests and verify pass**

Run: `ctest --preset clang-debug -R test_worker_loop --output-on-failure`
Expected: All tests PASS.

**Step 6: Commit**

```bash
git add src/core/worker_loop.c src/core/worker_loop.h tests/unit/test_worker_loop.c
git commit -m "feat(core): implement TLS decrypt and CSTP forward in worker loop"
```

---

## Task 4: Auth Backend Interface

**Goal:** Define a pluggable auth backend interface that PAM, RADIUS, LDAP, and cert auth all implement.

**Files:**
- Create: `src/auth/auth_backend.h`
- Create: `src/auth/auth_backend.c`
- Test: `tests/unit/test_auth_backend.c`

**Step 1: Write failing tests**

Create `tests/unit/test_auth_backend.c`:

```c
#include <unity/unity.h>
#include "auth/auth_backend.h"

void setUp(void) {}
void tearDown(void) {}

void test_auth_backend_register_returns_zero(void)
{
    iog_auth_backend_t backend = {
        .name = "mock",
        .init = mock_init,
        .authenticate = mock_auth,
        .destroy = mock_destroy,
    };
    TEST_ASSERT_EQUAL_INT(0, iog_auth_backend_register(&backend));
}

void test_auth_backend_find_by_name(void)
{
    const iog_auth_backend_t *found = iog_auth_backend_find("mock");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("mock", found->name);
}

void test_auth_backend_find_unknown_returns_null(void)
{
    const iog_auth_backend_t *found = iog_auth_backend_find("nonexistent");
    TEST_ASSERT_NULL(found);
}

void test_auth_backend_register_null_returns_einval(void)
{
    TEST_ASSERT_EQUAL_INT(-EINVAL, iog_auth_backend_register(nullptr));
}

void test_auth_backend_register_duplicate_returns_eexist(void)
{
    iog_auth_backend_t backend = { .name = "dup", ... };
    iog_auth_backend_register(&backend);
    TEST_ASSERT_EQUAL_INT(-EEXIST, iog_auth_backend_register(&backend));
}

void test_auth_backend_list_returns_registered(void)
{
    size_t count = 0;
    const iog_auth_backend_t **list = iog_auth_backend_list(&count);
    TEST_ASSERT_GREATER_THAN(0, count);
    TEST_ASSERT_NOT_NULL(list);
}
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement auth_backend.h**

```c
#ifndef RINGWALL_AUTH_BACKEND_H
#define RINGWALL_AUTH_BACKEND_H

#include <stddef.h>
#include <stdint.h>

constexpr size_t RW_AUTH_BACKEND_NAME_MAX = 32;
constexpr size_t RW_AUTH_BACKEND_MAX = 16;

typedef enum {
    RW_AUTH_OK = 0,
    RW_AUTH_DENY = -1,
    RW_AUTH_ERR = -2,
    RW_AUTH_MFA_REQUIRED = -3,
    RW_AUTH_ACCOUNT_LOCKED = -4,
} iog_auth_status_t;

typedef struct {
    const char *username;
    const char *password;       /* nullptr for cert auth */
    const char *otp;            /* nullptr if no MFA */
    const uint8_t *client_cert; /* DER-encoded cert, nullptr if N/A */
    size_t client_cert_len;
    const char *source_ip;
    uint16_t source_port;
} iog_auth_request_t;

typedef struct {
    iog_auth_status_t status;
    char groups[256];           /* comma-separated group list */
    uint32_t framed_ip;         /* RADIUS Framed-IP-Address, 0 if N/A */
    uint8_t framed_ipv6[16];   /* RADIUS Framed-IPv6-Address */
    bool has_framed_ipv6;
} iog_auth_response_t;

typedef struct iog_auth_backend {
    const char *name;
    [[nodiscard]] int (*init)(const void *config);
    [[nodiscard]] iog_auth_status_t (*authenticate)(const iog_auth_request_t *req,
                                                    iog_auth_response_t *resp);
    void (*destroy)(void);
} iog_auth_backend_t;

[[nodiscard]] int iog_auth_backend_register(const iog_auth_backend_t *backend);
const iog_auth_backend_t *iog_auth_backend_find(const char *name);
const iog_auth_backend_t **iog_auth_backend_list(size_t *count);
void iog_auth_backend_cleanup(void);

#endif
```

**Step 4: Implement auth_backend.c**

Static array of `RW_AUTH_BACKEND_MAX` pointers. `register` copies pointer, `find` does linear scan by name.

**Step 5: Run tests and verify pass**

**Step 6: Add to CMakeLists.txt and commit**

```bash
git add src/auth/auth_backend.h src/auth/auth_backend.c tests/unit/test_auth_backend.c CMakeLists.txt
git commit -m "feat(auth): add pluggable auth backend interface"
```

---

## Task 5: RADIUS Backend (radcli)

**Goal:** RADIUS authentication via radcli library (Access-Request/Accept/Reject, Cisco VSAs, Framed-IP).

**Files:**
- Create: `src/auth/radius.h`
- Create: `src/auth/radius.c`
- Test: `tests/unit/test_auth_radius.c`

**Step 1: Write failing tests**

```c
void test_radius_init_null_config_returns_einval(void);
void test_radius_init_missing_server_returns_einval(void);
void test_radius_destroy_null_safe(void);
void test_radius_backend_registers(void);
void test_radius_build_avpairs_username_password(void);
void test_radius_build_avpairs_with_source_ip(void);
void test_radius_parse_accept_extracts_groups(void);
void test_radius_parse_accept_extracts_framed_ip(void);
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement radius.h**

```c
#ifndef RINGWALL_AUTH_RADIUS_H
#define RINGWALL_AUTH_RADIUS_H

#include "auth/auth_backend.h"

typedef struct {
    char server[256];           /* RADIUS server host:port */
    char secret[128];           /* shared secret */
    char dictionary_path[256];  /* radcli dictionary file */
    uint32_t timeout_ms;        /* request timeout (default 5000) */
    uint32_t retries;           /* retry count (default 3) */
    char nas_identifier[64];    /* NAS-Identifier */
} rw_radius_config_t;

[[nodiscard]] int rw_radius_init(const rw_radius_config_t *cfg);
void rw_radius_destroy(void);

/* Returns the backend descriptor for registration */
const iog_auth_backend_t *iog_radius_backend(void);

#endif
```

**Step 4: Implement radius.c**

Key radcli API calls:
```c
/* Init: */
rc_handle *rh = rc_new();
rc_config_init(rh);
rc_add_config(rh, "auth_order", "radius", "config", 0);
rc_add_config(rh, "radius_timeout", timeout_str, "config", 0);
rc_add_config(rh, "radius_retries", retries_str, "config", 0);
rc_read_dictionary(rh, dictionary_path);

/* Auth: */
VALUE_PAIR *send = nullptr;
rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0);
rc_avpair_add(rh, &send, PW_USER_PASSWORD, password, -1, 0);
rc_avpair_add(rh, &send, PW_NAS_IDENTIFIER, nas_id, -1, 0);
/* NAS-IP-Address (attr 4) */
rc_avpair_add(rh, &send, PW_NAS_IP_ADDRESS, &nas_ip, sizeof(nas_ip), 0);

VALUE_PAIR *recv = nullptr;
int result = rc_auth(rh, 0, send, &recv, nullptr);
/* result: OK_RC (accept), REJECT_RC (deny), TIMEOUT_RC, ERROR_RC */

/* Parse response: */
VALUE_PAIR *vp = rc_avpair_get(recv, PW_FRAMED_IP_ADDRESS, 0);
if (vp) resp->framed_ip = ntohl(*(uint32_t *)vp->strvalue);

/* Cisco VSA (vendor 9) for group assignment: */
VALUE_PAIR *cisco_vp = rc_avpair_get(recv, PW_VENDOR_SPECIFIC, VENDOR_CISCO);

/* Cleanup: */
rc_avpair_free(send);
rc_avpair_free(recv);
explicit_bzero(password_copy, sizeof(password_copy)); /* security: zero secret */
```

**Step 5: Run tests and verify pass**

**Step 6: Commit**

```bash
git add src/auth/radius.h src/auth/radius.c tests/unit/test_auth_radius.c CMakeLists.txt
git commit -m "feat(auth): add RADIUS authentication backend via radcli"
```

---

## Task 6: LDAP Backend (libldap)

**Goal:** LDAP authentication with bind + search, group membership, StartTLS.

**Files:**
- Create: `src/auth/ldap_auth.h`
- Create: `src/auth/ldap_auth.c`
- Test: `tests/unit/test_auth_ldap.c`

**Step 1: Write failing tests**

```c
void test_ldap_init_null_config_returns_einval(void);
void test_ldap_init_missing_uri_returns_einval(void);
void test_ldap_destroy_null_safe(void);
void test_ldap_backend_registers(void);
void test_ldap_build_bind_dn_with_template(void);
void test_ldap_build_search_filter(void);
void test_ldap_parse_group_membership(void);
void test_ldap_config_validates_uri_scheme(void);
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement ldap_auth.h**

```c
#ifndef RINGWALL_AUTH_LDAP_H
#define RINGWALL_AUTH_LDAP_H

#include "auth/auth_backend.h"

typedef struct {
    char uri[512];              /* ldap://host:389 or ldaps://host:636 */
    char bind_dn_template[512]; /* e.g. "uid=%s,ou=people,dc=example,dc=com" */
    char search_base[256];      /* e.g. "ou=groups,dc=example,dc=com" */
    char group_attr[64];        /* attribute for group membership (default: memberOf) */
    char group_filter[256];     /* LDAP filter for group search */
    bool use_starttls;          /* enable StartTLS on ldap:// connections */
    uint32_t timeout_ms;        /* search/bind timeout (default 5000) */
    char ca_cert_path[256];     /* CA cert for TLS verification */
} rw_ldap_config_t;

[[nodiscard]] int rw_ldap_init(const rw_ldap_config_t *cfg);
void rw_ldap_destroy(void);
const iog_auth_backend_t *iog_ldap_backend(void);

#endif
```

**Step 4: Implement ldap_auth.c**

Key libldap API calls:
```c
/* Init: */
LDAP *ld = nullptr;
ldap_initialize(&ld, cfg->uri);
int version = LDAP_VERSION3;
ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

/* StartTLS (if ldap://): */
if (cfg->use_starttls) {
    ldap_start_tls_s(ld, nullptr, nullptr);
}

/* Bind (authenticate): */
struct berval cred = { .bv_val = (char *)req->password, .bv_len = strlen(req->password) };
char bind_dn[512];
snprintf(bind_dn, sizeof(bind_dn), cfg->bind_dn_template, req->username);
int rc = ldap_sasl_bind_s(ld, bind_dn, LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
/* LDAP_SUCCESS = authenticated, LDAP_INVALID_CREDENTIALS = denied */

/* Group search: */
LDAPMessage *result = nullptr;
ldap_search_ext_s(ld, cfg->search_base, LDAP_SCOPE_SUBTREE,
                  filter, attrs, 0, nullptr, nullptr, &tv, 0, &result);
/* Extract group names from entries */

/* Cleanup: */
ldap_msgfree(result);
ldap_unbind_ext_s(ld, nullptr, nullptr);
explicit_bzero(&cred, sizeof(cred));
```

**Step 5: Run tests and verify pass**

**Step 6: Commit**

```bash
git add src/auth/ldap_auth.h src/auth/ldap_auth.c tests/unit/test_auth_ldap.c CMakeLists.txt
git commit -m "feat(auth): add LDAP authentication backend via libldap"
```

---

## Task 7: Certificate Authentication (wolfSSL)

**Goal:** Client certificate auth via wolfSSL verify callback, with MS AD template OID filtering.

**Files:**
- Create: `src/auth/cert_auth.h`
- Create: `src/auth/cert_auth.c`
- Test: `tests/unit/test_auth_cert.c`

**Step 1: Write failing tests**

```c
void test_cert_auth_init_null_config_returns_einval(void);
void test_cert_auth_destroy_null_safe(void);
void test_cert_auth_backend_registers(void);
void test_cert_auth_extract_cn_from_subject(void);
void test_cert_auth_extract_san_email(void);
void test_cert_auth_verify_eku_client_auth(void);
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement cert_auth.h**

```c
#ifndef RINGWALL_AUTH_CERT_H
#define RINGWALL_AUTH_CERT_H

#include "auth/auth_backend.h"

typedef struct {
    char ca_cert_path[256];     /* trusted CA for client certs */
    char crl_path[256];         /* CRL file path (optional) */
    bool require_eku;           /* require EKU: Client Authentication */
    char template_oid[128];     /* MS AD template OID filter (optional, e.g. 1.3.6.1.4.1.311.20.2) */
    char template_name[64];     /* Required template name (e.g. "VPN-User") */
    char username_field[32];    /* CN, SAN:email, SAN:UPN (default: CN) */
} rw_cert_auth_config_t;

[[nodiscard]] int rw_cert_auth_init(const rw_cert_auth_config_t *cfg);
void rw_cert_auth_destroy(void);
const iog_auth_backend_t *iog_cert_auth_backend(void);

/* Helper: extract username from X.509 certificate */
[[nodiscard]] int rw_cert_extract_username(const uint8_t *der, size_t der_len,
                                            const char *field, char *out, size_t out_size);
#endif
```

**Step 4: Implement cert_auth.c**

Key wolfSSL API calls:
```c
/* Parse DER cert: */
WOLFSSL_X509 *cert = wolfSSL_d2i_X509(nullptr, &der_ptr, (int)der_len);

/* Extract CN from subject: */
WOLFSSL_X509_NAME *subject = wolfSSL_X509_get_subject_name(cert);
wolfSSL_X509_NAME_get_text_by_NID(subject, NID_commonName, cn_buf, cn_buf_sz);

/* Check EKU (Client Authentication OID 1.3.6.1.5.5.7.3.2): */
/* Parse extensions, check for EKU, verify clientAuth is present */

/* Verify callback (set on TLS context): */
wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       rw_cert_verify_cb);
```

**Step 5: Run tests and verify pass**

**Step 6: Commit**

```bash
git add src/auth/cert_auth.h src/auth/cert_auth.c tests/unit/test_auth_cert.c CMakeLists.txt
git commit -m "feat(auth): add certificate authentication backend via wolfSSL"
```

---

## Task 8: HTTP Parser Migration (llhttp → iohttpparser)

**Goal:** Replace llhttp with iohttpparser in `src/network/http.{h,c}`. All 7 existing tests must pass. Update fuzz target.

**Files:**
- Modify: `src/network/http.h` — remove `llhttp.h`, use iohttpparser types
- Modify: `src/network/http.c` — rewrite from callback to pull-based parsing
- Modify: `tests/unit/test_http.c` — update method enum references
- Modify: `tests/fuzz/fuzz_http.c` — update for new API
- Modify: `CMakeLists.txt` — replace `llhttp` linkage with `iohttpparser`

### Key Migration Mapping

| llhttp (old) | iohttpparser (new) |
|---|---|
| `llhttp_t` + `llhttp_settings_t` + callbacks | `ihtp_parse_request()` (stateless, one call) |
| `llhttp_execute(parser, data, len)` | `ihtp_parse_request(buf, len, &req, policy, &consumed)` |
| `HPE_OK` | `IHTP_OK` |
| `HPE_PAUSED_UPGRADE` | Check `req.method == IHTP_METHOD_CONNECT` |
| `parser->method` (int) | `req.method` (`ihtp_method_t` enum) |
| `HTTP_POST`, `HTTP_CONNECT` | `IHTP_METHOD_POST`, `IHTP_METHOD_CONNECT` |
| `rw_http_parser_t` (stateful) | Accumulate in buffer, parse whole request |
| Headers: NUL-terminated strings | Headers: `{ptr, len}` pairs (NOT NUL-terminated) |

**Step 1: Write adapter test for iohttpparser**

Temporarily add a test in `test_http.c` that parses using the new API directly to validate the approach.

**Step 2: Run existing 7 tests to confirm they pass with llhttp**

```bash
ctest --preset clang-debug -R test_http --output-on-failure
```
Expected: 7 PASS (baseline).

**Step 3: Rewrite http.h**

Replace llhttp types:

```c
#ifndef RINGWALL_NETWORK_HTTP_H
#define RINGWALL_NETWORK_HTTP_H

#include <iohttpparser/ihtp_parser.h>
#include <iohttpparser/ihtp_body.h>
#include <stddef.h>
#include <stdint.h>

constexpr uint32_t RW_HTTP_MAX_HEADERS = 32;
constexpr size_t RW_HTTP_MAX_URL = 512;
constexpr size_t RW_HTTP_MAX_HEADER_NAME = 128;
constexpr size_t RW_HTTP_MAX_HEADER_VALUE = 1024;
constexpr size_t RW_HTTP_MAX_BODY = 8192;

typedef struct {
    char name[RW_HTTP_MAX_HEADER_NAME];
    char value[RW_HTTP_MAX_HEADER_VALUE];
} rw_http_header_t;

typedef struct {
    uint8_t method;     /* ihtp_method_t (was llhttp_method_t) */
    char url[RW_HTTP_MAX_URL];
    size_t url_len;
    rw_http_header_t headers[RW_HTTP_MAX_HEADERS];
    uint32_t header_count;
    char body[RW_HTTP_MAX_BODY];
    size_t body_len;
    bool headers_complete;
    bool message_complete;
    bool is_upgrade;
} rw_http_request_t;

/* Parser context: accumulation buffer for incremental parsing */
typedef struct {
    char buf[RW_HTTP_MAX_URL + RW_HTTP_MAX_HEADERS * (RW_HTTP_MAX_HEADER_NAME + RW_HTTP_MAX_HEADER_VALUE) + RW_HTTP_MAX_BODY + 1024];
    size_t buf_len;
    rw_http_request_t request;
    bool headers_parsed;
    ihtp_fixed_decoder_t body_decoder;
} rw_http_parser_t;

[[nodiscard]] int rw_http_parser_init(rw_http_parser_t *p);
void rw_http_parser_reset(rw_http_parser_t *p);
[[nodiscard]] int rw_http_parse(rw_http_parser_t *p, const char *data, size_t len);
const char *rw_http_get_header(const rw_http_request_t *req, const char *name);
[[nodiscard]] int rw_http_format_response(char *buf, size_t buf_size, int status_code,
                                          const rw_http_header_t *headers, uint32_t header_count,
                                          const char *body, size_t body_len);

#endif
```

**Step 4: Rewrite http.c**

Core parsing logic change — from callback-driven to pull-based:

```c
int rw_http_parse(rw_http_parser_t *p, const char *data, size_t len)
{
    /* Accumulate data */
    size_t space = sizeof(p->buf) - p->buf_len;
    size_t copy = len < space ? len : space;
    memcpy(p->buf + p->buf_len, data, copy);
    p->buf_len += copy;

    if (!p->headers_parsed) {
        ihtp_request_t req = {0};
        size_t consumed = 0;
        ihtp_status_t st = ihtp_parse_request(p->buf, p->buf_len, &req,
                                               nullptr, &consumed);
        if (st == IHTP_INCOMPLETE) return 0;   /* need more data */
        if (st != IHTP_OK) return -EPROTO;

        /* Copy parsed results into rw_http_request_t */
        p->request.method = (uint8_t)req.method;
        /* Copy URL (ihtp gives ptr+len, NOT NUL-terminated): */
        size_t url_copy = req.path_len < RW_HTTP_MAX_URL - 1 ? req.path_len : RW_HTTP_MAX_URL - 1;
        memcpy(p->request.url, req.path, url_copy);
        p->request.url[url_copy] = '\0';
        p->request.url_len = url_copy;
        /* Copy headers (ptr+len → NUL-terminated strings): */
        for (size_t i = 0; i < req.num_headers && i < RW_HTTP_MAX_HEADERS; i++) {
            /* ... bounded copy of name and value ... */
        }
        p->request.header_count = (uint32_t)req.num_headers;
        p->request.headers_complete = true;

        /* CONNECT → upgrade, no body */
        if (req.method == IHTP_METHOD_CONNECT) {
            p->request.is_upgrade = true;
            p->request.message_complete = true;
            p->headers_parsed = true;
            return 0;
        }

        /* Body handling: remaining bytes after consumed */
        size_t remaining = p->buf_len - consumed;
        /* ... copy body, track body_len ... */
        p->headers_parsed = true;
    }

    return 0;
}
```

Keep `rw_http_format_response()` and `rw_http_get_header()` unchanged — they don't depend on the parser library.

**Step 5: Update test_http.c method enum references**

Replace `HTTP_POST` → `IHTP_METHOD_POST`, `HTTP_CONNECT` → `IHTP_METHOD_CONNECT`.

**Step 6: Update fuzz_http.c**

Minimal change — same API (`rw_http_parser_init` / `rw_http_parse`).

**Step 7: Update CMakeLists.txt**

Replace:
```cmake
target_link_libraries(rw_http PUBLIC llhttp)
```
With:
```cmake
target_link_libraries(rw_http PUBLIC iohttpparser)
```
Add iohttpparser include path. Keep llhttp as a findable library for backward compat but don't link it to `rw_http`.

**Step 8: Run all 7 tests**

```bash
ctest --preset clang-debug -R test_http --output-on-failure
```
Expected: 7 PASS.

**Step 9: Commit**

```bash
git add src/network/http.h src/network/http.c tests/unit/test_http.c tests/fuzz/fuzz_http.c CMakeLists.txt
git commit -m "refactor(network): migrate HTTP parser from llhttp to iohttpparser"
```

---

## Task 9: Structured Logging (stumpless)

**Goal:** Async structured logging via stumpless buffer target + io_uring WRITEV flush.

**Files:**
- Create: `src/log/iog_log.h`
- Create: `src/log/iog_log.c`
- Test: `tests/unit/test_log.c`

**Step 1: Write failing tests**

```c
void test_log_init_returns_zero(void);
void test_log_write_info_message(void);
void test_log_write_with_structured_data(void);
void test_log_flush_reads_buffer(void);
void test_log_destroy_null_safe(void);
void test_log_severity_levels(void);
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement iog_log.h**

```c
#ifndef RINGWALL_LOG_H
#define RINGWALL_LOG_H

#include <stddef.h>

typedef enum {
    IOG_LOG_EMERG = 0,
    IOG_LOG_ALERT = 1,
    IOG_LOG_CRIT = 2,
    IOG_LOG_ERR = 3,
    IOG_LOG_WARN = 4,
    IOG_LOG_NOTICE = 5,
    IOG_LOG_INFO = 6,
    IOG_LOG_DEBUG = 7,
} iog_log_level_t;

typedef struct iog_logger iog_logger_t;

[[nodiscard]] int iog_log_init(iog_logger_t **out, size_t buffer_size);
void iog_log_destroy(iog_logger_t *logger);

[[nodiscard]] int iog_log_write(iog_logger_t *logger, iog_log_level_t level,
                                const char *component, const char *msg);

/* Structured data: RFC 5424 SD-ID with params */
[[nodiscard]] int iog_log_write_sd(iog_logger_t *logger, iog_log_level_t level,
                                   const char *component, const char *msg,
                                   const char *sd_id, const char *sd_params[][2],
                                   size_t param_count);

/* Flush buffer contents — returns bytes available for io_uring WRITEV */
[[nodiscard]] ssize_t iog_log_flush(iog_logger_t *logger, char *out, size_t out_size);

/* Set minimum log level (messages below this are dropped) */
void iog_log_set_level(iog_logger_t *logger, iog_log_level_t min_level);

#endif
```

**Step 4: Implement iog_log.c**

Key stumpless API calls:
```c
/* Init: */
struct stumpless_buffer_target *bt =
    stumpless_open_buffer_target("ioguard", buf, buf_size);
struct stumpless_target *target = stumpless_get_target_by_name("ioguard");

/* Write entry: */
struct stumpless_entry *entry =
    stumpless_new_entry(STUMPLESS_FACILITY_DAEMON, severity,
                        "ioguard", component, msg);
/* Add structured data: */
struct stumpless_element *elem = stumpless_new_element(sd_id);
struct stumpless_param *param = stumpless_new_param(key, value);
stumpless_add_param(elem, param);
stumpless_add_element(entry, elem);

stumpless_add_entry(target, entry);
stumpless_destroy_entry_and_contents(entry);

/* Flush: */
size_t read = stumpless_read_buffer(bt, out, out_size);
/* Caller writes `out` via io_uring WRITEV to log file fd */
```

**Step 5: Run tests and verify pass**

**Step 6: Commit**

```bash
git add src/log/iog_log.h src/log/iog_log.c tests/unit/test_log.c CMakeLists.txt
git commit -m "feat(log): add structured logging via stumpless with buffer target"
```

---

## Task 10: Prometheus Metrics

**Goal:** Custom Prometheus text exposition format. Counters, gauges, histograms. No external dependency.

**Files:**
- Create: `src/metrics/prometheus.h`
- Create: `src/metrics/prometheus.c`
- Test: `tests/unit/test_prometheus.c`

**Step 1: Write failing tests**

```c
void test_prom_registry_create_destroy(void);
void test_prom_counter_inc(void);
void test_prom_counter_add(void);
void test_prom_gauge_set(void);
void test_prom_gauge_inc_dec(void);
void test_prom_histogram_observe(void);
void test_prom_format_text_exposition(void);
void test_prom_format_includes_help_type(void);
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement prometheus.h**

```c
#ifndef RINGWALL_METRICS_PROMETHEUS_H
#define RINGWALL_METRICS_PROMETHEUS_H

#include <stddef.h>
#include <stdint.h>

typedef struct rw_prom_registry rw_prom_registry_t;

typedef struct {
    _Atomic uint64_t value;
    const char *name;
    const char *help;
} rw_prom_counter_t;

typedef struct {
    _Atomic int64_t value;   /* stored as fixed-point * 1000 for sub-integer precision */
    const char *name;
    const char *help;
} rw_prom_gauge_t;

constexpr size_t RW_PROM_HISTOGRAM_BUCKETS = 12;

typedef struct {
    const char *name;
    const char *help;
    double boundaries[RW_PROM_HISTOGRAM_BUCKETS];
    _Atomic uint64_t bucket_counts[RW_PROM_HISTOGRAM_BUCKETS + 1]; /* +1 for +Inf */
    _Atomic uint64_t sum_us;  /* sum in microseconds */
    _Atomic uint64_t count;
} rw_prom_histogram_t;

[[nodiscard]] int rw_prom_registry_create(rw_prom_registry_t **out);
void rw_prom_registry_destroy(rw_prom_registry_t *reg);

[[nodiscard]] int rw_prom_register_counter(rw_prom_registry_t *reg, rw_prom_counter_t *counter);
[[nodiscard]] int rw_prom_register_gauge(rw_prom_registry_t *reg, rw_prom_gauge_t *gauge);
[[nodiscard]] int rw_prom_register_histogram(rw_prom_registry_t *reg, rw_prom_histogram_t *hist);

void rw_prom_counter_inc(rw_prom_counter_t *counter);
void rw_prom_counter_add(rw_prom_counter_t *counter, uint64_t n);
void rw_prom_gauge_set(rw_prom_gauge_t *gauge, int64_t val);
void rw_prom_gauge_inc(rw_prom_gauge_t *gauge);
void rw_prom_gauge_dec(rw_prom_gauge_t *gauge);
void rw_prom_histogram_observe(rw_prom_histogram_t *hist, double value);

/* Format all metrics as Prometheus text exposition (OpenMetrics compatible) */
[[nodiscard]] ssize_t rw_prom_format(const rw_prom_registry_t *reg, char *buf, size_t buf_size);

#endif
```

**Step 4: Implement prometheus.c**

Key implementation details:
- Registry holds arrays of pointers to counter/gauge/histogram (max 64 each).
- `rw_prom_format()` writes:
  ```
  # HELP rw_connections_total Total VPN connections
  # TYPE rw_connections_total counter
  rw_connections_total 42
  ```
- Histogram format includes `_bucket{le="..."}`, `_sum`, `_count` lines.
- All metric operations are `_Atomic` — safe for lock-free reads from metrics endpoint.

**Standard metrics to pre-register:**

| Name | Type | Description |
|------|------|-------------|
| `rw_connections_total` | counter | Total VPN connections accepted |
| `rw_auth_attempts_total` | counter | Authentication attempts |
| `rw_auth_failures_total` | counter | Authentication failures |
| `rw_bytes_rx_total` | counter | Total bytes received |
| `rw_bytes_tx_total` | counter | Total bytes transmitted |
| `rw_active_sessions` | gauge | Currently active VPN sessions |
| `iog_memory_bytes` | gauge | Process memory usage |
| `rw_fd_count` | gauge | Open file descriptors |
| `iog_ipam_pool_utilization` | gauge | IPAM pool utilization (0.0-1.0) |
| `rw_tls_handshake_seconds` | histogram | TLS handshake duration |
| `rw_auth_duration_seconds` | histogram | Authentication processing time |

**Step 5: Run tests and verify pass**

**Step 6: Commit**

```bash
git add src/metrics/prometheus.h src/metrics/prometheus.c tests/unit/test_prometheus.c CMakeLists.txt
git commit -m "feat(metrics): add Prometheus metrics with text exposition format"
```

---

## Task 11: CMakeLists.txt + Container Updates

**Goal:** Wire all new components into the build system. Ensure container has all dependencies.

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `deploy/podman/Containerfile` (if iohttpparser not present)

**Step 1: Add new library targets to CMakeLists.txt**

```cmake
# Auth backend interface
add_library(iog_auth_backend STATIC src/auth/auth_backend.c)
target_include_directories(iog_auth_backend PUBLIC ${CMAKE_SOURCE_DIR}/src)

# RADIUS backend
if(RADCLI_FOUND)
    add_library(iog_auth_radius STATIC src/auth/radius.c)
    target_link_libraries(iog_auth_radius PUBLIC iog_auth_backend ${RADCLI_LIBRARIES})
    target_include_directories(iog_auth_radius PUBLIC ${RADCLI_INCLUDE_DIRS})
endif()

# LDAP backend
find_library(LDAP_LIBRARY ldap)
find_library(LBER_LIBRARY lber)
if(LDAP_LIBRARY AND LBER_LIBRARY)
    add_library(iog_auth_ldap STATIC src/auth/ldap_auth.c)
    target_link_libraries(iog_auth_ldap PUBLIC iog_auth_backend ${LDAP_LIBRARY} ${LBER_LIBRARY})
endif()

# Cert auth
add_library(iog_auth_cert STATIC src/auth/cert_auth.c)
target_link_libraries(iog_auth_cert PUBLIC iog_auth_backend rw_crypto)

# HTTP (migrate from llhttp to iohttpparser)
find_library(IOHTTPPARSER_LIBRARY iohttpparser)
add_library(rw_http STATIC src/network/http.c)
target_link_libraries(rw_http PUBLIC ${IOHTTPPARSER_LIBRARY})
target_include_directories(rw_http PUBLIC ${CMAKE_SOURCE_DIR}/src /usr/local/include)

# Logging
find_library(STUMPLESS_LIBRARY stumpless)
add_library(iog_log STATIC src/log/iog_log.c)
target_link_libraries(iog_log PUBLIC ${STUMPLESS_LIBRARY})

# Metrics
add_library(rw_metrics STATIC src/metrics/prometheus.c)
target_include_directories(rw_metrics PUBLIC ${CMAKE_SOURCE_DIR}/src)
```

**Step 2: Register new tests**

```cmake
rw_add_test(test_auth_backend tests/unit/test_auth_backend.c iog_auth_backend)
if(TARGET iog_auth_radius)
    rw_add_test(test_auth_radius tests/unit/test_auth_radius.c iog_auth_radius)
endif()
if(TARGET iog_auth_ldap)
    rw_add_test(test_auth_ldap tests/unit/test_auth_ldap.c iog_auth_ldap)
endif()
rw_add_test(test_auth_cert tests/unit/test_auth_cert.c iog_auth_cert)
rw_add_test(test_log tests/unit/test_log.c iog_log)
rw_add_test(test_prometheus tests/unit/test_prometheus.c rw_metrics)
```

**Step 3: Add iohttpparser to container (if needed)**

Check if iohttpparser is already built/installed in the container. If not, add:
```dockerfile
# iohttpparser — pull-based HTTP parser (replaces llhttp for VPN HTTP)
COPY --from=builder /opt/projects/repositories/iohttpparser /tmp/iohttpparser
RUN cd /tmp/iohttpparser && cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build build && cmake --install build && rm -rf /tmp/iohttpparser
```

**Step 4: Full build verification**

```bash
cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug
```
Expected: All tests pass, no build errors.

**Step 5: Commit**

```bash
git add CMakeLists.txt deploy/podman/Containerfile
git commit -m "build: add S7 components — auth backends, logging, metrics, iohttpparser"
```

---

## Execution Order

Tasks are ordered by dependency:

1. **Tasks 1-2** (tech debt): Fix existing failures first — clean baseline
2. **Task 11** (build): Wire dependencies early so incremental builds work
3. **Task 4** (auth interface): Required by Tasks 5-7
4. **Task 8** (HTTP migration): Independent of auth, can parallel with 5-7
5. **Tasks 5-7** (auth backends): Depend on Task 4, independent of each other
6. **Task 3** (worker loop): Depends on TLS layer being stable (Tasks 1-2)
7. **Tasks 9-10** (observability): Independent of auth and HTTP

**Recommended batch execution:**

| Batch | Tasks | Description |
|-------|-------|-------------|
| 1 | 1, 2 | Tech debt cleanup (clean baseline) |
| 2 | 4, 11 | Auth interface + build system |
| 3 | 5, 6, 7, 8 | Auth backends + HTTP migration |
| 4 | 3, 9, 10 | Worker loop + observability |

---

## Post-Sprint Checklist

- [ ] All ~60 new tests pass
- [ ] Pre-existing 9 test failures resolved (Task 1 + Task 2)
- [ ] `clang-format` clean
- [ ] `cppcheck` clean on new files
- [ ] Container build succeeds
- [ ] Run full quality pipeline: `./scripts/quality.sh`
- [ ] Zero PVS-Studio errors on S7 files
- [ ] Zero CodeChecker HIGH/MEDIUM on S7 files
