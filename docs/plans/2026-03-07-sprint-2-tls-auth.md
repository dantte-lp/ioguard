# Sprint 2: TLS & Auth Implementation Plan

> **For subagents:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate wolfSSL TLS 1.3, implement PAM authentication via sec-mod process, establish session cookie management, and parse OpenConnect HTTP/XML protocol.

**Architecture:** Worker accepts TLS connection (wolfSSL callback I/O → io_uring), parses HTTP POST /auth via llhttp, forwards auth request to sec-mod via IPC. sec-mod validates via PAM, generates session cookie (wolfCrypt RNG), returns response. Worker parses HTTP CONNECT for tunnel setup.

**Tech Stack:** wolfSSL 5.8.2+ (native API), llhttp 9.3.1+, PAM (system), protobuf-c 1.5.2+, wolfCrypt (RNG, HMAC)

**Existing code:** `src/crypto/` already has 4743 LOC (tls_wolfssl.c, tls_abstract.c, tls_gnutls.c, priority_parser.c, session_cache.c) and 1559 LOC tests from pre-Sprint 1. These need to be wired into CMake and verified before building on them.

---

## Task 1: Wire existing crypto module into CMake

**Files:**
- Modify: `CMakeLists.txt`
- Existing: `src/crypto/tls_abstract.h`, `src/crypto/tls_abstract.c`
- Existing: `src/crypto/tls_wolfssl.h`, `src/crypto/tls_wolfssl.c`
- Existing: `src/crypto/tls_gnutls.h`, `src/crypto/tls_gnutls.c`
- Existing: `src/crypto/priority_parser.h`, `src/crypto/priority_parser.c`
- Existing: `src/crypto/session_cache.h`, `src/crypto/session_cache.c`
- Existing: `tests/unit/test_tls_wolfssl.c`
- Existing: `tests/unit/test_tls_gnutls.c`
- Existing: `tests/unit/test_priority_parser.c`

**Step 1: Read all existing crypto source files**

Read every file in `src/crypto/` and `tests/unit/test_tls_*.c`, `tests/unit/test_priority_parser.c` to understand:
- What functions are implemented vs stubbed
- What needs `_GNU_SOURCE`, wolfSSL includes, etc.
- Include guard style (old `OCSERV_*` vs new `RINGWALL_*`)

**Step 2: Add rw_crypto library to CMakeLists.txt**

Add a new static library target `rw_crypto` with:
- wolfSSL backend: `src/crypto/tls_wolfssl.c`, `src/crypto/tls_abstract.c`, `src/crypto/priority_parser.c`, `src/crypto/session_cache.c`
- GnuTLS backend: same but with `tls_gnutls.c` instead of `tls_wolfssl.c`
- Find wolfSSL: `find_path(WOLFSSL_INCLUDE_DIR wolfssl/ssl.h)`, `find_library(WOLFSSL_LIBRARY wolfssl)`
- Find GnuTLS: `pkg_check_modules(GNUTLS gnutls)`
- Link: wolfssl or gnutls, plus pthread
- Compile definitions: `_GNU_SOURCE`
- Include dirs: `${CMAKE_SOURCE_DIR}/src/crypto` for internal headers

Add test executables:
- `test_tls_wolfssl` linking `rw_crypto` (wolfSSL variant) + unity
- `test_priority_parser` linking `rw_crypto` + unity
- Register with CTest

**Step 3: Fix any compilation issues**

Common issues to expect:
- Include guard rename: `OCSERV_*` → `RINGWALL_*` (update if needed for consistency, but not required for compilation)
- Missing `_GNU_SOURCE` for some functions
- wolfSSL header path: `/usr/local/include/wolfssl/`
- Test framework: existing tests use custom macros, may need Unity migration

**Step 4: Build and run inside container**

```bash
podman exec ioguard-dev bash -c "cd /workspace && rm -rf build/clang-debug && cmake --preset clang-debug && cmake --build --preset clang-debug 2>&1"
podman exec ioguard-dev bash -c "cd /workspace && ctest --preset clang-debug"
```

Expected: All existing tests pass (or identify specific failures to fix).

**Step 5: Commit**

```bash
git add CMakeLists.txt
git commit -m "build: wire existing crypto module (wolfSSL, GnuTLS, priority parser) into CMake"
```

---

## Task 2: HTTP parser with llhttp

**Files:**
- Create: `src/network/http.h`
- Create: `src/network/http.c`
- Create: `tests/unit/test_http.c`
- Modify: `CMakeLists.txt`

**Context:**

ioguard uses llhttp to parse HTTP requests from Cisco/OpenConnect clients. Two critical request types:
1. `POST /auth` — authentication (XML body with credentials)
2. `CONNECT /CSCOSSLC/tunnel` — tunnel establishment (returns `HPE_PAUSED_UPGRADE`)

Must extract headers: `Cookie`, `X-CSTP-*`, `X-DTLS-*`, `Content-Type`, `Content-Length`.

**API design** (`src/network/http.h`):

```c
#ifndef RINGWALL_NETWORK_HTTP_H
#define RINGWALL_NETWORK_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <llhttp.h>

#define RW_HTTP_MAX_HEADERS 32
#define RW_HTTP_MAX_URL 512
#define RW_HTTP_MAX_HEADER_NAME 128
#define RW_HTTP_MAX_HEADER_VALUE 1024
#define RW_HTTP_MAX_BODY 8192

typedef struct {
    char name[RW_HTTP_MAX_HEADER_NAME];
    char value[RW_HTTP_MAX_HEADER_VALUE];
} rw_http_header_t;

typedef struct {
    /* Request line */
    uint8_t method;          /* llhttp_method_t: HTTP_POST, HTTP_CONNECT, etc. */
    char url[RW_HTTP_MAX_URL];
    size_t url_len;

    /* Headers */
    rw_http_header_t headers[RW_HTTP_MAX_HEADERS];
    uint32_t header_count;

    /* Body */
    char body[RW_HTTP_MAX_BODY];
    size_t body_len;

    /* State */
    bool headers_complete;
    bool message_complete;
    bool is_upgrade;         /* CONNECT method detected */

    /* Internal parsing state */
    char _cur_header_field[RW_HTTP_MAX_HEADER_NAME];
    size_t _cur_field_len;
    char _cur_header_value[RW_HTTP_MAX_HEADER_VALUE];
    size_t _cur_value_len;
    bool _parsing_value;
} rw_http_request_t;

typedef struct {
    llhttp_t parser;
    llhttp_settings_t settings;
    rw_http_request_t request;
} rw_http_parser_t;

[[nodiscard]] int rw_http_parser_init(rw_http_parser_t *p);
void rw_http_parser_reset(rw_http_parser_t *p);

[[nodiscard]] int rw_http_parse(rw_http_parser_t *p, const char *data, size_t len);

const char *rw_http_get_header(const rw_http_request_t *req, const char *name);

[[nodiscard]] int rw_http_format_response(char *buf, size_t buf_size,
                                           int status_code,
                                           const rw_http_header_t *headers,
                                           uint32_t header_count,
                                           const char *body, size_t body_len);

#endif /* RINGWALL_NETWORK_HTTP_H */
```

**Step 1: Write failing tests** (`tests/unit/test_http.c`)

Tests (Unity framework):
1. `test_parse_post_auth` — parse `POST /auth HTTP/1.1` with headers and XML body
2. `test_parse_connect_tunnel` — parse `CONNECT /CSCOSSLC/tunnel HTTP/1.1`, verify `is_upgrade=true`
3. `test_get_header` — extract `Cookie`, `X-CSTP-Hostname`, `Content-Type`
4. `test_format_response` — build `HTTP/1.1 200 OK` with headers and body
5. `test_max_body_limit` — body larger than `RW_HTTP_MAX_BODY` truncated
6. `test_incremental_parse` — feed data in small chunks, same result as full parse
7. `test_invalid_request` — malformed HTTP returns error

**Step 2: Implement** (`src/network/http.c`)

llhttp callbacks:
- `on_url`: copy to `request.url`
- `on_header_field`: accumulate into `_cur_header_field`
- `on_header_value`: accumulate into `_cur_header_value`
- `on_header_value_complete`: store pair into `headers[]` array, increment count
- `on_body`: append to `request.body` (with bounds check)
- `on_headers_complete`: set `headers_complete = true`, check method
- `on_message_complete`: set `message_complete = true`

`rw_http_parse()` calls `llhttp_execute()`. On `HPE_PAUSED_UPGRADE`, set `is_upgrade = true`.

`rw_http_get_header()`: linear scan of headers array, case-insensitive compare with `strncasecmp`.

`rw_http_format_response()`: `snprintf` to build status line + headers + CRLF + body.

**Step 3: Wire into CMake**

Add `rw_http` static library, link llhttp. Add test target.

**Step 4: Build and test in container**

```bash
podman exec ioguard-dev bash -c "cd /workspace && cmake --preset clang-debug && cmake --build --preset clang-debug --target test_http && ctest --preset clang-debug -R test_http"
```

**Step 5: Commit**

```bash
git add src/network/http.h src/network/http.c tests/unit/test_http.c CMakeLists.txt
git commit -m "feat(network): HTTP parser wrapper around llhttp for POST /auth and CONNECT"
```

---

## Task 3: AggAuth XML parser/builder

**Files:**
- Create: `src/network/xml_auth.h`
- Create: `src/network/xml_auth.c`
- Create: `tests/unit/test_xml_auth.c`
- Modify: `CMakeLists.txt`

**Context:**

Cisco AnyConnect uses AggAuth XML protocol for authentication. No libxml2 — hand-rolled parser for the limited XML subset used by AggAuth. Reference: `/opt/projects/repositories/ioguard-docs/docs/openconnect-protocol/protocol/authentication.md`

**XML we must parse (client → server):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <version who="vpn">5.0</version>
  <device-id>linux-64</device-id>
  <group-select>default</group-select>
  <auth>
    <username>user</username>
    <password>pass</password>
  </auth>
</config-auth>
```

Also: init request (capabilities, device-id, mac-address), MFA challenge reply (otp, secondary_password).

**XML we must generate (server → client):**

1. Auth challenge form (username/password fields)
2. MFA challenge (OTP field)
3. Auth success (session-token, config)
4. Auth failure (error message, retry count)

**API design** (`src/network/xml_auth.h`):

```c
#ifndef RINGWALL_NETWORK_XML_AUTH_H
#define RINGWALL_NETWORK_XML_AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define IOG_XML_MAX_STR 256
#define IOG_XML_MAX_GROUPS 16

/* Parsed client auth request */
typedef struct {
    char username[IOG_XML_MAX_STR];
    char password[IOG_XML_MAX_STR];
    char group_select[IOG_XML_MAX_STR];
    char device_id[IOG_XML_MAX_STR];
    char platform_version[IOG_XML_MAX_STR];
    char session_token[IOG_XML_MAX_STR];
    char otp[64];
    char client_version[IOG_XML_MAX_STR];
    char auth_type[64];           /* "auth-request", "init", etc. */
    bool has_username;
    bool has_password;
    bool has_otp;
    bool has_session_token;
} iog_xml_auth_request_t;

/* Server response types */
typedef enum {
    IOG_XML_RESP_CHALLENGE,        /* Send login form */
    IOG_XML_RESP_MFA_CHALLENGE,    /* Send OTP/MFA challenge */
    IOG_XML_RESP_SUCCESS,          /* Auth success + session token */
    IOG_XML_RESP_FAILURE,          /* Auth failure */
} iog_xml_response_type_t;

typedef struct {
    char name[64];
    char label[128];
} iog_xml_group_t;

/* Parameters for building server responses */
typedef struct {
    iog_xml_response_type_t type;
    /* For challenge: form fields are standard (username, password, group) */
    iog_xml_group_t groups[IOG_XML_MAX_GROUPS];
    uint32_t group_count;
    char banner[512];
    /* For success */
    char session_token[IOG_XML_MAX_STR];
    /* For failure */
    char error_message[IOG_XML_MAX_STR];
    uint32_t retry_count;
    uint32_t max_retries;
    /* For MFA */
    char mfa_message[IOG_XML_MAX_STR];
} iog_xml_auth_response_t;

[[nodiscard]] int iog_xml_parse_auth_request(const char *xml, size_t len,
                                             iog_xml_auth_request_t *out);

[[nodiscard]] int iog_xml_build_auth_response(const iog_xml_auth_response_t *resp,
                                              char *buf, size_t buf_size,
                                              size_t *out_len);

void iog_xml_auth_request_zero(iog_xml_auth_request_t *req);

#endif /* RINGWALL_NETWORK_XML_AUTH_H */
```

**Step 1: Write failing tests** (`tests/unit/test_xml_auth.c`)

Tests (Unity):
1. `test_parse_init_request` — parse client init XML (device-id, version, capabilities)
2. `test_parse_auth_credentials` — parse username + password from `<config-auth type="auth-request">`
3. `test_parse_group_select` — parse group-select element
4. `test_parse_otp` — parse OTP/secondary_password from MFA reply
5. `test_parse_session_token` — parse session-token from client reply
6. `test_build_challenge_form` — build username/password challenge XML, verify well-formed
7. `test_build_mfa_challenge` — build OTP challenge XML
8. `test_build_success_response` — build auth success with session-token
9. `test_build_failure_response` — build auth failure with error message
10. `test_build_group_select` — build challenge with group `<select>` options
11. `test_parse_entity_decode` — `&amp;` → `&`, `&lt;` → `<`, `&quot;` → `"`
12. `test_password_zeroed` — after `iog_xml_auth_request_zero()`, password is zeroed
13. `test_malformed_xml` — returns error for invalid XML

**Step 2: Implement XML parser** (`src/network/xml_auth.c`)

Parser strategy — SAX-style, no DOM:
- Scan for `<tag>` and `</tag>` patterns
- Extract text content between open/close tags
- Extract attribute values from open tags: `name="value"`
- Entity decode: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`
- Nested context tracking: when inside `<auth>`, look for `<username>`, `<password>`
- Bounds checking on all string copies via `snprintf`

Builder: `snprintf` chain building XML response string. Helper function `xml_escape()` for `<`, `>`, `&`, `"`.

`iog_xml_auth_request_zero()`: calls `explicit_bzero()` on password and session_token fields.

**Step 3: Wire into CMake, build, test**

Add `iog_xml_auth` (or include in `rw_http` library). No external deps.

**Step 4: Commit**

```bash
git add src/network/xml_auth.h src/network/xml_auth.c tests/unit/test_xml_auth.c CMakeLists.txt
git commit -m "feat(network): AggAuth XML parser/builder for Cisco Secure Client compatibility"
```

---

## Task 4: Session cookie management

**Files:**
- Create: `src/core/session.h`
- Create: `src/core/session.c`
- Create: `tests/unit/test_session.c`
- Modify: `CMakeLists.txt`

**Context:**

Session cookies are 32-byte random values generated by wolfCrypt RNG. Stored in sec-mod process. Validation uses constant-time comparison. Memory zeroed on deletion.

Reference: `src/crypto/session_cache.h` (existing TLS session cache is different — that's for TLS session resumption, not VPN session cookies).

**API design** (`src/core/session.h`):

```c
#ifndef IOGUARD_CORE_SESSION_H
#define IOGUARD_CORE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define RW_SESSION_COOKIE_SIZE 32
#define RW_SESSION_MAX_SESSIONS 1024

typedef struct {
    uint8_t cookie[RW_SESSION_COOKIE_SIZE];
    char username[256];
    char group[256];
    char assigned_ip[46];     /* INET6_ADDRSTRLEN */
    char dns_server[46];
    time_t created;
    time_t last_activity;
    uint32_t ttl_seconds;
    bool active;
} iog_session_t;

typedef struct iog_session_store iog_session_store_t;

[[nodiscard]] iog_session_store_t *iog_session_store_create(uint32_t max_sessions);
void iog_session_store_destroy(iog_session_store_t *store);

[[nodiscard]] int iog_session_create(iog_session_store_t *store,
                                     const char *username,
                                     const char *group,
                                     uint32_t ttl_seconds,
                                     iog_session_t **out);

[[nodiscard]] int iog_session_validate(iog_session_store_t *store,
                                       const uint8_t *cookie, size_t cookie_len,
                                       iog_session_t **out);

int iog_session_delete(iog_session_store_t *store,
                       const uint8_t *cookie, size_t cookie_len);

uint32_t iog_session_cleanup_expired(iog_session_store_t *store);

uint32_t iog_session_count(const iog_session_store_t *store);

#endif /* IOGUARD_CORE_SESSION_H */
```

**Step 1: Write failing tests** (`tests/unit/test_session.c`)

Tests (Unity):
1. `test_store_create_destroy` — create store, destroy, no leaks
2. `test_session_create` — create session, verify cookie is 32 bytes, username copied
3. `test_session_validate` — create then validate with same cookie, returns same session
4. `test_session_validate_invalid` — validate with random cookie, returns error
5. `test_session_constant_time` — validate uses constant-time comparison (test that wrong cookie of same length doesn't short-circuit — can't directly test timing, but verify the code path)
6. `test_session_delete` — delete session, cookie memory zeroed, subsequent validate fails
7. `test_session_expiry` — create session with TTL=1, sleep(2), cleanup_expired removes it
8. `test_session_max_capacity` — fill store to max, next create returns error
9. `test_session_count` — count increases on create, decreases on delete

**Step 2: Implement** (`src/core/session.c`)

- Session store: array of `iog_session_t` (fixed size, `RW_SESSION_MAX_SESSIONS`)
- Cookie generation: `wc_RNG_GenerateBlock()` from wolfCrypt (`#include <wolfssl/wolfcrypt/random.h>`)
- Cookie validation: `wolfSSL_ConstantCompare()` or implement constant-time memcmp
- Zeroing: `explicit_bzero()` on cookie + password fields in delete
- Linear scan for lookup (O(n) is fine for 1024 max sessions)

Note: If wolfCrypt headers aren't available for unit tests, provide a fallback using `/dev/urandom` read for RNG, and manual constant-time compare.

**Step 3: Wire into CMake, build, test**

Link wolfssl (for wolfCrypt RNG) or provide test-only fallback.

**Step 4: Commit**

```bash
git add src/core/session.h src/core/session.c tests/unit/test_session.c CMakeLists.txt
git commit -m "feat(core): session cookie management with wolfCrypt RNG and constant-time validation"
```

---

## Task 5: PAM authentication backend

**Files:**
- Create: `src/auth/pam.h`
- Create: `src/auth/pam.c`
- Create: `tests/unit/test_auth_pam.c`
- Modify: `CMakeLists.txt`

**Context:**

PAM auth runs in sec-mod process (blocking calls are OK — sec-mod is dedicated to auth). Passwords MUST be zeroed after PAM call completes.

**API design** (`src/auth/pam.h`):

```c
#ifndef RINGWALL_AUTH_PAM_H
#define RINGWALL_AUTH_PAM_H

#include <stdbool.h>
#include <stddef.h>

#define RW_PAM_DEFAULT_SERVICE "ioguard"

typedef enum {
    RW_AUTH_SUCCESS = 0,
    RW_AUTH_FAILURE = -1,
    RW_AUTH_ERROR = -2,
    RW_AUTH_ACCOUNT_EXPIRED = -3,
    RW_AUTH_PASSWORD_EXPIRED = -4,
} rw_auth_result_t;

typedef struct {
    char service[64];          /* PAM service name */
} rw_pam_config_t;

[[nodiscard]] int rw_pam_init(rw_pam_config_t *cfg, const char *service);

[[nodiscard]] rw_auth_result_t rw_pam_authenticate(const rw_pam_config_t *cfg,
                                                     const char *username,
                                                     const char *password);

#endif /* RINGWALL_AUTH_PAM_H */
```

**Step 1: Write failing tests** (`tests/unit/test_auth_pam.c`)

Note: Real PAM tests require PAM configuration. Tests should:
1. `test_pam_init` — init with service name, verify stored
2. `test_pam_init_default` — init with NULL uses "ioguard"
3. `test_pam_authenticate_invalid_user` — authenticate nonexistent user, returns FAILURE
4. `test_pam_password_zeroing` — verify password buffer is zeroed after auth call (pass a mutable buffer, check it's zeroed after)

For tests 3-4, PAM "other" service with deny-all is sufficient.

**Step 2: Implement** (`src/auth/pam.c`)

```c
#include <security/pam_appl.h>

/* PAM conversation function */
static int pam_conversation(int num_msg, const struct pam_message **msg,
                             struct pam_response **resp, void *appdata_ptr);

/* Main auth function */
rw_auth_result_t rw_pam_authenticate(const rw_pam_config_t *cfg,
                                       const char *username,
                                       const char *password)
{
    /* 1. pam_start(cfg->service, username, &conv, &pamh) */
    /* 2. pam_authenticate(pamh, 0) */
    /* 3. pam_acct_mgmt(pamh, 0) */
    /* 4. pam_end(pamh, ret) */
    /* 5. explicit_bzero on password copy */
    /* 6. Map PAM error to rw_auth_result_t */
}
```

Conversation function: allocates `pam_response`, copies password into it. Password copy zeroed after `pam_end()`.

Error mapping:
- `PAM_SUCCESS` → `RW_AUTH_SUCCESS`
- `PAM_AUTH_ERR`, `PAM_USER_UNKNOWN`, `PAM_MAXTRIES` → `RW_AUTH_FAILURE`
- `PAM_ACCT_EXPIRED` → `RW_AUTH_ACCOUNT_EXPIRED`
- `PAM_NEW_AUTHTOK_REQD` → `RW_AUTH_PASSWORD_EXPIRED`
- Everything else → `RW_AUTH_ERROR`

**Step 3: Wire into CMake**

Link `pam` library. Add `_GNU_SOURCE` for `explicit_bzero`.

**Step 4: Build and test**

```bash
podman exec ioguard-dev bash -c "cd /workspace && cmake --build --preset clang-debug --target test_auth_pam && ctest --preset clang-debug -R test_auth_pam"
```

**Step 5: Commit**

```bash
git add src/auth/pam.h src/auth/pam.c tests/unit/test_auth_pam.c CMakeLists.txt
git commit -m "feat(auth): PAM authentication backend with password zeroing"
```

---

## Task 6: sec-mod process

**Files:**
- Create: `src/core/secmod.h`
- Create: `src/core/secmod.c`
- Create: `tests/unit/test_secmod.c`
- Modify: `CMakeLists.txt`
- Modify: `src/ipc/proto/rw_ipc.proto` — add session_open/session_close messages if needed

**Context:**

sec-mod is a dedicated child process spawned by Main. It:
1. Receives AUTH_REQUEST via SOCK_SEQPACKET IPC
2. Dispatches to PAM backend
3. Creates session cookie on success
4. Returns AUTH_RESPONSE with cookie + VPN config
5. Maintains session store (validates cookies for reconnection)

For Sprint 2, sec-mod runs a simple poll-based event loop (not io_uring — it doesn't do network I/O).

**API design** (`src/core/secmod.h`):

```c
#ifndef RINGWALL_CORE_SECMOD_H
#define RINGWALL_CORE_SECMOD_H

#include "auth/pam.h"
#include "core/session.h"
#include "config/config.h"

typedef struct {
    int ipc_fd;                    /* IPC socket (SOCK_SEQPACKET) */
    rw_pam_config_t pam_cfg;
    iog_session_store_t *sessions;
    const iog_config_t *config;
    bool running;
} iog_secmod_ctx_t;

[[nodiscard]] int iog_secmod_init(iog_secmod_ctx_t *ctx, int ipc_fd,
                                  const iog_config_t *config);

[[nodiscard]] int iog_secmod_run(iog_secmod_ctx_t *ctx);

void iog_secmod_stop(iog_secmod_ctx_t *ctx);

void iog_secmod_destroy(iog_secmod_ctx_t *ctx);

/* Entry point for child process (called after fork/pidfd_spawn) */
[[noreturn]] void iog_secmod_main(int ipc_fd, const iog_config_t *config);

#endif /* RINGWALL_CORE_SECMOD_H */
```

**Step 1: Write failing tests** (`tests/unit/test_secmod.c`)

Tests (Unity):
1. `test_secmod_init` — init with IPC fd and config, verify state
2. `test_secmod_handle_auth_request` — send AUTH_REQUEST over socketpair, receive AUTH_RESPONSE (mock PAM with "other" service)
3. `test_secmod_session_validation` — after successful auth, send another AUTH_REQUEST with cookie, get success response
4. `test_secmod_invalid_cookie` — send AUTH_REQUEST with bogus cookie, get failure response
5. `test_secmod_stop` — set running=false, run() returns

Note: Tests create a socketpair, run secmod in a thread or use non-blocking poll.

**Step 2: Implement** (`src/core/secmod.c`)

Event loop:
```c
int iog_secmod_run(iog_secmod_ctx_t *ctx) {
    ctx->running = true;
    while (ctx->running) {
        /* poll(ipc_fd, POLLIN, 1000ms) */
        /* if readable: recv IPC message */
        /* switch (msg.type):
         *   AUTH_REQUEST with cookie → iog_session_validate()
         *   AUTH_REQUEST without cookie → rw_pam_authenticate() → iog_session_create()
         *   SHUTDOWN → ctx->running = false
         */
        /* send AUTH_RESPONSE back */
        /* periodic: iog_session_cleanup_expired() */
    }
}
```

Uses existing IPC transport (`rw_ipc_send`, `rw_ipc_recv`) and message pack/unpack.

**Step 3: Wire into CMake, build, test**

Link: `rw_ipc`, `iog_config`, session module, PAM module.

**Step 4: Commit**

```bash
git add src/core/secmod.h src/core/secmod.c tests/unit/test_secmod.c CMakeLists.txt
git commit -m "feat(core): sec-mod authentication process with session management"
```

---

## Task 7: Integration test — full auth flow

**Files:**
- Create: `tests/integration/test_auth_flow.c`
- Modify: `CMakeLists.txt`

**Context:**

End-to-end test: fork sec-mod child, send auth request from parent (simulating worker), verify response.

**Test flow:**

```c
void test_full_auth_flow(void) {
    /* 1. Create socketpair (SOCK_SEQPACKET) */
    /* 2. Fork child → iog_secmod_main(child_fd, &config) */
    /* 3. Parent: pack AUTH_REQUEST (username="root", password="x", no cookie) */
    /* 4. Parent: rw_ipc_send(parent_fd, buf, len) */
    /* 5. Parent: rw_ipc_recv(parent_fd, buf, sizeof(buf)) */
    /* 6. Parent: unpack AUTH_RESPONSE */
    /* 7. Verify: response has session_cookie (32 bytes) */
    /*    Note: PAM will likely FAIL for "root"/"x" — that's OK,
     *    verify we get a well-formed failure response */
    /* 8. Send SHUTDOWN message */
    /* 9. waitpid(child) */
}

void test_session_revalidation(void) {
    /* Same as above but:
     * 1. First auth succeeds (configure PAM to allow)
     * 2. Second request with cookie → session validated
     */
}
```

**Step 1: Write test**

**Step 2: Wire into CMake, build, test**

**Step 3: Commit**

```bash
git add tests/integration/test_auth_flow.c CMakeLists.txt
git commit -m "test: integration test for full auth flow (worker → sec-mod → PAM → session)"
```

---

## Task 8: Update proto definitions for Sprint 2

**Files:**
- Modify: `src/ipc/proto/rw_ipc.proto`
- Modify: `src/ipc/messages.h`
- Modify: `src/ipc/messages.c`
- Modify: `tests/unit/test_ipc_messages.c`

**Context:**

Sprint 1 auth_request/response may need additional fields for Sprint 2:
- `auth_request`: add `password` field (was it missing?), `otp` field for MFA
- `auth_response`: add `assigned_ip`, `dns_server`, `default_domain`, `routes`
- New message type: `SESSION_VALIDATE` — validate existing cookie without re-auth

Review existing proto/messages and extend as needed. Keep backward compatible.

**Step 1: Read existing proto and messages files**

**Step 2: Add needed fields**

Check if `password` is in auth_request. If not, add it. Add `otp` for MFA.
Add VPN config fields to auth_response if missing.

**Step 3: Regenerate protobuf-c, update pack/unpack functions**

**Step 4: Update tests, build, verify**

**Step 5: Commit**

```bash
git add src/ipc/proto/rw_ipc.proto src/ipc/messages.h src/ipc/messages.c tests/unit/test_ipc_messages.c CMakeLists.txt
git commit -m "feat(ipc): extend auth messages with password, OTP, VPN config fields"
```

---

## Task 9: Final verification and cleanup

**Files:**
- Modify: `CLAUDE.md` — update status to "Sprint 2 complete"
- Modify: `docs/agile/SPRINTS.md` — mark Sprint 2 done

**Step 1: Run full test suite**

```bash
podman exec ioguard-dev bash -c "cd /workspace && rm -rf build/clang-debug && cmake --preset clang-debug && cmake --build --preset clang-debug && ctest --preset clang-debug --output-on-failure"
```

All tests must pass.

**Step 2: Run with ASan+UBSan**

```bash
podman exec ioguard-dev bash -c "cd /workspace && rm -rf build/clang-debug && cmake --preset clang-debug -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build --preset clang-debug && ctest --preset clang-debug --output-on-failure"
```

Zero errors.

**Step 3: Verify password/cookie zeroing works**

Run session and PAM tests under ASan — verify no leaks, no use-after-free.

**Step 4: Update docs and commit**

```bash
git add CLAUDE.md docs/agile/SPRINTS.md
git commit -m "docs: mark Sprint 2 (TLS & Auth) complete"
```

---

## Dependency Graph

```
Task 1 (crypto CMake)  ─── independent ───────────────────────────┐
Task 2 (HTTP llhttp)   ─── independent ───────────────────────────┤
Task 3 (XML AggAuth)   ─── depends on Task 2 (uses http types)  ─┤
Task 4 (Session)       ─── independent ───────────────────────────┤
Task 5 (PAM)           ─── independent ───────────────────────────┤
Task 6 (sec-mod)       ─── depends on Task 4 + Task 5 + Task 8  ─┤
Task 7 (Integration)   ─── depends on Task 6                     ─┤
Task 8 (Proto update)  ─── independent (do early) ────────────────┤
Task 9 (Verification)  ─── depends on ALL ────────────────────────┘
```

**Parallelizable:** Tasks 1, 2, 4, 5, 8 can all run in parallel.
**Sequential:** Task 3 after 2, Task 6 after 4+5+8, Task 7 after 6, Task 9 last.

---

## Security Checklist (mandatory for every task)

- [ ] All public API functions have `[[nodiscard]]`
- [ ] Passwords zeroed with `explicit_bzero()` after use
- [ ] Session cookies zeroed with `explicit_bzero()` on deletion
- [ ] Cookie validation uses constant-time comparison
- [ ] Cookie generation uses `wc_RNG_GenerateBlock()` (cryptographic RNG)
- [ ] No banned functions: strcpy, sprintf, gets, strcat, atoi, system()
- [ ] All string copies use `snprintf` with size bounds
- [ ] HTTP body size limited to prevent memory exhaustion
- [ ] XML parser has depth/size limits
- [ ] ASan+UBSan clean
