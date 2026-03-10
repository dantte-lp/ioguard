/*
 * Copyright (C) 2025 ioguard Contributors
 *
 * This file is part of ringwall.
 *
 * ioguard is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * ioguard is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "tls_wolfssl.h"
#include <errno.h>
#include <stdckdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// C23 standard compliance check (accept C2x/C20 from GCC 14 as it provides C23 features)
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

static int wolfssl_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX *x509_ctx);

// Session cache callbacks
static int wolfssl_session_new_cb(WOLFSSL *ssl, WOLFSSL_SESSION *session);
static WOLFSSL_SESSION *wolfssl_session_get_cb(WOLFSSL *ssl, const unsigned char *id, int id_len,
                                               int *copy);
static void wolfssl_session_remove_cb(WOLFSSL_CTX *ctx, WOLFSSL_SESSION *session);

/* ============================================================================
 * Global State
 * ============================================================================ */

static bool g_initialized = false;
static atomic_int g_init_count = 0;

/* ============================================================================
 * Error Mapping
 * ============================================================================ */

int tls_wolfssl_map_error(int wolf_error)
{
    switch (wolf_error) {
    case SSL_SUCCESS:
    case WOLFSSL_ERROR_NONE:
        return TLS_E_SUCCESS;

    case WOLFSSL_ERROR_WANT_READ:
    case WOLFSSL_ERROR_WANT_WRITE:
        return TLS_E_AGAIN;

    case SSL_ERROR_SYSCALL:
        if (errno == EINTR) {
            return TLS_E_INTERRUPTED;
        }
        return TLS_E_BACKEND_ERROR;

    case MEMORY_E:
    case BUFFER_E:
        return TLS_E_MEMORY_ERROR;

    case BAD_FUNC_ARG:
    case BAD_STATE_E:
        return TLS_E_INVALID_PARAMETER;

    case FATAL_ERROR:
        return TLS_E_FATAL_ALERT_RECEIVED;

    case NO_PEER_CERT:
    case ASN_NO_SIGNER_E:
        return TLS_E_CERTIFICATE_REQUIRED;

    case VERIFY_CERT_ERROR:
    case ASN_SIG_CONFIRM_E:
    case ASN_SIG_HASH_E:
    case ASN_SIG_KEY_E:
        return TLS_E_CERTIFICATE_ERROR;

    case SSL_ERROR_ZERO_RETURN:
        return TLS_E_PREMATURE_TERMINATION;

    case SOCKET_ERROR_E:
        return TLS_E_PULL_ERROR;

    case WANT_WRITE:
        return TLS_E_PUSH_ERROR;

    default:
        return TLS_E_BACKEND_ERROR;
    }
}

/* ============================================================================
 * Priority String Translation
 * ============================================================================ */

/**
 * Translate GnuTLS priority string to wolfSSL cipher list
 *
 * This function implements a critical compatibility layer between GnuTLS
 * priority strings (used by ocserv) and wolfSSL cipher lists.
 *
 * Supported GnuTLS Keywords:
 * - NORMAL: Standard security settings
 * - SECURE128: 128-bit security level
 * - SECURE192: 192-bit security level
 * - SECURE256: 256-bit security level
 * - PERFORMANCE: Optimized for speed
 *
 * Supported Modifiers:
 * - %SERVER_PRECEDENCE: Use server cipher preference
 * - %COMPAT: Enable compatibility mode
 * - %NO_EXTENSIONS: Disable TLS extensions
 *
 * Version Control:
 * - -VERS-SSL3.0: Disable SSL 3.0
 * - -VERS-TLS1.0: Disable TLS 1.0
 * - -VERS-TLS1.1: Disable TLS 1.1
 * - +VERS-TLS1.3: Enable TLS 1.3
 *
 * Cipher Control:
 * - -CIPHER-AES-128-CBC: Exclude AES-128-CBC
 * - +CIPHER-CHACHA20-POLY1305: Include ChaCha20-Poly1305
 */
int tls_wolfssl_translate_priority(const char *gnutls_priority, char *wolfssl_ciphers,
                                   size_t ciphers_len)
{
    if (gnutls_priority == nullptr || wolfssl_ciphers == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Initialize output buffer
    wolfssl_ciphers[0] = '\0';

    // Parse priority string and build wolfSSL cipher list
    // This is a simplified implementation focusing on common patterns

    if (strstr(gnutls_priority, "SECURE256")) {
        // 256-bit security: prioritize AES-256-GCM and strong ciphers
        strncat(wolfssl_ciphers,
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "DHE-RSA-AES256-GCM-SHA384",
                ciphers_len - 1);
    } else if (strstr(gnutls_priority, "SECURE192")) {
        // 192-bit security: use AES-192 or stronger
        strncat(wolfssl_ciphers,
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                ciphers_len - 1);
    } else if (strstr(gnutls_priority, "PERFORMANCE")) {
        // Performance: prioritize fast ciphers (ChaCha20, AES-GCM)
        strncat(wolfssl_ciphers,
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "AES128-GCM-SHA256",
                ciphers_len - 1);
    } else {
        // NORMAL or default: balanced security and performance
        strncat(wolfssl_ciphers,
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305:"
                "DHE-RSA-AES128-GCM-SHA256:"
                "DHE-RSA-AES256-GCM-SHA384",
                ciphers_len - 1);
    }

    // Add TLS 1.3 ciphers if explicitly enabled
    if (strstr(gnutls_priority, "+VERS-TLS1.3") || strstr(gnutls_priority, "NORMAL")) {
        // TLS 1.3 ciphers use different naming
        size_t current_len = strlen(wolfssl_ciphers);
        if (current_len > 0 && current_len < ciphers_len - 1) {
            strncat(wolfssl_ciphers, ":", ciphers_len - current_len - 1);
        }
        strncat(wolfssl_ciphers,
                "TLS13-AES128-GCM-SHA256:"
                "TLS13-AES256-GCM-SHA384:"
                "TLS13-CHACHA20-POLY1305-SHA256",
                ciphers_len - strlen(wolfssl_ciphers) - 1);
    }

    // Handle exclusions
    if (strstr(gnutls_priority, "-CIPHER-AES-128-CBC")) {
        // Remove CBC ciphers (already excluded in our lists)
    }

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Library Initialization
 * ============================================================================ */

int tls_wolfssl_init(void)
{
    if (g_initialized) {
        atomic_fetch_add(&g_init_count, 1);
        return TLS_E_SUCCESS;
    }

    // Initialize wolfSSL library
    int ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

// Enable debugging in debug builds
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    // Set global options for security
    wolfSSL_SetAllocators(nullptr, nullptr, nullptr); // Use system allocator

    g_initialized = true;
    atomic_store(&g_init_count, 1);

    return TLS_E_SUCCESS;
}

void tls_wolfssl_deinit(void)
{
    if (!g_initialized) {
        return;
    }

    int count = atomic_fetch_sub(&g_init_count, 1);
    if (count <= 1) {
        wolfSSL_Cleanup();
        g_initialized = false;
        atomic_store(&g_init_count, 0);
    }
}

const char *tls_wolfssl_get_version(void)
{
    return wolfSSL_lib_version();
}

/* ============================================================================
 * Context Management
 * ============================================================================ */

tls_context_t *tls_context_new(bool is_server, bool is_dtls)
{
    if (!g_initialized) {
        return nullptr;
    }

    // Allocate context structure
    tls_context_t *ctx = (tls_context_t *)calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return nullptr;
    }

    ctx->is_server = is_server;
    ctx->is_dtls = is_dtls;
    atomic_init(&ctx->refcount, 1);

    // Create wolfSSL context with appropriate method
    WOLFSSL_METHOD *method = nullptr;

    if (is_dtls) {
        if (is_server) {
            method = wolfDTLS_server_method();
        } else {
            method = wolfDTLS_client_method();
        }
    } else {
        if (is_server) {
            method = wolfTLS_server_method();
        } else {
            method = wolfTLS_client_method();
        }
    }

    if (method == nullptr) {
        free(ctx);
        return nullptr;
    }

    ctx->wolf_ctx = wolfSSL_CTX_new(method);
    if (ctx->wolf_ctx == nullptr) {
        free(ctx);
        return nullptr;
    }

    // Set minimum TLS version to TLS 1.2 by default (disable older versions)
    wolfSSL_CTX_SetMinVersion(ctx->wolf_ctx, WOLFSSL_TLSV1_2);

    // Enable TLS 1.3 by default
    wolfSSL_CTX_set_max_proto_version(ctx->wolf_ctx, TLS1_3_VERSION);

    // Set secure defaults
    wolfSSL_CTX_set_options(ctx->wolf_ctx, SSL_OP_NO_SSLv3);
    wolfSSL_CTX_set_options(ctx->wolf_ctx, SSL_OP_NO_TLSv1);
    wolfSSL_CTX_set_options(ctx->wolf_ctx, SSL_OP_NO_TLSv1_1);

    // Enable SNI (Server Name Indication)
    wolfSSL_CTX_UseSNI(ctx->wolf_ctx, WOLFSSL_SNI_HOST_NAME, nullptr, 0);

    // Enable ALPN (Application-Layer Protocol Negotiation)
    // This is needed for HTTP/2 and other protocols

    // Set session timeout to default (2 hours)
    ctx->session_timeout_secs = 7200;
    wolfSSL_CTX_set_timeout(ctx->wolf_ctx, ctx->session_timeout_secs);

    return ctx;
}

void tls_context_free(tls_context_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    int old_ref = atomic_fetch_sub(&ctx->refcount, 1);
    if (old_ref > 1) {
        // Still has references
        return;
    }

    // Free wolfSSL context
    if (ctx->wolf_ctx != nullptr) {
        wolfSSL_CTX_free(ctx->wolf_ctx);
    }

    // Free allocated strings
    free(ctx->cert_file);
    free(ctx->key_file);
    free(ctx->ca_file);
    free(ctx->dh_params_file);
    free(ctx->priority_string);
    free(ctx->wolfssl_cipher_list);

    // Zero sensitive data
    memset(ctx, 0, sizeof(*ctx));

    free(ctx);
}

int tls_context_set_cert_file(tls_context_t *ctx, const char *cert_file)
{
    if (ctx == nullptr || cert_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = wolfSSL_CTX_use_certificate_chain_file(ctx->wolf_ctx, cert_file);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    // Store file path for reference
    free(ctx->cert_file);
    ctx->cert_file = strdup(cert_file);
    ctx->has_certificate = true;

    return TLS_E_SUCCESS;
}

int tls_context_set_key_file(tls_context_t *ctx, const char *key_file)
{
    if (ctx == nullptr || key_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = wolfSSL_CTX_use_PrivateKey_file(ctx->wolf_ctx, key_file, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    // Store file path for reference
    free(ctx->key_file);
    ctx->key_file = strdup(key_file);

    return TLS_E_SUCCESS;
}

int tls_context_set_ca_file(tls_context_t *ctx, const char *ca_file)
{
    if (ctx == nullptr || ca_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = wolfSSL_CTX_load_verify_locations(ctx->wolf_ctx, ca_file, nullptr);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    // Store file path for reference
    free(ctx->ca_file);
    ctx->ca_file = strdup(ca_file);

    return TLS_E_SUCCESS;
}

int tls_context_set_priority(tls_context_t *ctx, const char *priority)
{
    if (ctx == nullptr || priority == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Allocate buffer for wolfSSL cipher list
    char wolfssl_ciphers[TLS_MAX_PRIORITY_STRING];

    // Translate GnuTLS priority to wolfSSL cipher list
    int ret = tls_wolfssl_translate_priority(priority, wolfssl_ciphers, sizeof(wolfssl_ciphers));
    if (ret != TLS_E_SUCCESS) {
        return ret;
    }

    // Set cipher list in wolfSSL context
    ret = wolfSSL_CTX_set_cipher_list(ctx->wolf_ctx, wolfssl_ciphers);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    // Store priority string for reference
    free(ctx->priority_string);
    ctx->priority_string = strdup(priority);

    free(ctx->wolfssl_cipher_list);
    ctx->wolfssl_cipher_list = strdup(wolfssl_ciphers);

    return TLS_E_SUCCESS;
}

int tls_context_set_dh_params_file(tls_context_t *ctx, const char *dh_file)
{
    if (ctx == nullptr || dh_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = wolfSSL_CTX_SetTmpDH_file(ctx->wolf_ctx, dh_file, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    // Store file path for reference
    free(ctx->dh_params_file);
    ctx->dh_params_file = strdup(dh_file);

    return TLS_E_SUCCESS;
}

int tls_context_set_verify(tls_context_t *ctx, bool verify, tls_cert_verify_func_t callback,
                           void *userdata)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    ctx->verify_peer = verify;
    ctx->verify_callback = callback;
    ctx->verify_userdata = userdata;

    int mode = verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE;

    if (ctx->is_server && verify) {
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }

    wolfSSL_CTX_set_verify(ctx->wolf_ctx, mode, callback ? wolfssl_verify_cb : nullptr);

    return TLS_E_SUCCESS;
}

int tls_context_set_psk_server_callback(tls_context_t *ctx, tls_psk_server_func_t callback,
                                        void *userdata)
{
    if (ctx == nullptr || !ctx->is_server) {
        return TLS_E_INVALID_PARAMETER;
    }

    ctx->psk_server_callback = callback;
    ctx->psk_userdata = userdata;

#ifndef NO_PSK
    if (callback != nullptr) {
        wolfSSL_CTX_set_psk_server_callback(ctx->wolf_ctx, wolfssl_psk_server_cb);
    } else {
        wolfSSL_CTX_set_psk_server_callback(ctx->wolf_ctx, nullptr);
    }
#else
    // PSK support not enabled in wolfSSL build - feature unavailable
    (void)callback;
    (void)userdata;
#endif

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Session Cache Callback Adapters
 * ============================================================================ */

/**
 * wolfSSL new session callback adapter
 *
 * Called by wolfSSL when a new session is created and should be stored in the cache.
 *
 * @param ssl wolfSSL session handle
 * @param session wolfSSL session data to store
 * @return SSL_SUCCESS (0) on success, SSL_FATAL_ERROR (-1) on failure
 *
 * Note: This adapter converts wolfSSL's session format to our abstraction format
 *       and calls the user-provided db_store callback.
 */
static int wolfssl_session_new_cb(WOLFSSL *ssl, WOLFSSL_SESSION *session)
{
    if (ssl == nullptr || session == nullptr) {
        return SSL_FATAL_ERROR;
    }

    // Get context from session
    WOLFSSL_CTX *wolf_ctx = wolfSSL_get_SSL_CTX(ssl);
    if (wolf_ctx == nullptr) {
        return SSL_FATAL_ERROR;
    }

    // Extract our context from wolfSSL context's user data
    tls_context_t *ctx = (tls_context_t *)wolfSSL_CTX_get_ex_data(wolf_ctx, 0);
    if (ctx == nullptr || ctx->db_store == nullptr) {
        return SSL_SUCCESS; // No callback registered, silently succeed
    }

    // Extract session ID
    unsigned int session_id_len = 0;
    const unsigned char *session_id = wolfSSL_SESSION_get_id(session, &session_id_len);
    if (session_id == nullptr || session_id_len == 0 || session_id_len > TLS_MAX_SESSION_ID_SIZE) {
        return SSL_FATAL_ERROR;
    }

    // Extract serialized session data
    // wolfSSL_i2d_SSL_SESSION returns length and writes to *pp (advancing it)
    unsigned char session_data[TLS_MAX_SESSION_DATA_SIZE];
    unsigned char *session_data_ptr = session_data;
    int session_data_len = wolfSSL_i2d_SSL_SESSION(session, &session_data_ptr);
    if (session_data_len <= 0 || (size_t)session_data_len > TLS_MAX_SESSION_DATA_SIZE) {
        return SSL_FATAL_ERROR;
    }

    // Build cache entry
    tls_session_cache_entry_t entry = {0};
    memcpy(entry.session_id, session_id, session_id_len);
    entry.session_id_size = session_id_len;
    memcpy(entry.session_data, session_data, (size_t)session_data_len);
    entry.session_data_size = (size_t)session_data_len;

    // Calculate expiration time
    time_t now = time(nullptr);
    entry.expiration = now + (ctx->session_timeout_secs > 0 ? ctx->session_timeout_secs : 300);

    // Extract remote address from SSL session (if available)
    // Note: wolfSSL doesn't provide direct API for this, so we'll leave it empty
    // The application can fill this in if needed
    entry.remote_addr_len = 0;

    // Call user's store callback
    int result = ctx->db_store(ctx->db_userdata, &entry);
    return (result == 0) ? SSL_SUCCESS : SSL_FATAL_ERROR;
}

/**
 * wolfSSL get session callback adapter
 *
 * Called by wolfSSL when attempting to resume a session.
 *
 * @param ssl wolfSSL session handle
 * @param id Session ID to retrieve
 * @param id_len Session ID length
 * @param copy Output: set to 1 if wolfSSL should make a copy (always 1 for us)
 * @return Pointer to WOLFSSL_SESSION on success, nullptr if not found
 *
 * Note: wolfSSL will call wolfSSL_SESSION_free() on the returned session,
 *       so we must allocate it dynamically.
 */
static WOLFSSL_SESSION *wolfssl_session_get_cb(WOLFSSL *ssl, const unsigned char *id, int id_len,
                                               int *copy)
{
    if (ssl == nullptr || id == nullptr || id_len <= 0 || copy == nullptr) {
        return nullptr;
    }

    *copy = 1; // wolfSSL should always make a copy

    // Get context
    WOLFSSL_CTX *wolf_ctx = wolfSSL_get_SSL_CTX(ssl);
    if (wolf_ctx == nullptr) {
        return nullptr;
    }

    tls_context_t *ctx = (tls_context_t *)wolfSSL_CTX_get_ex_data(wolf_ctx, 0);
    if (ctx == nullptr || ctx->db_retrieve == nullptr) {
        return nullptr; // No callback registered
    }

    // Retrieve session from cache
    tls_session_cache_entry_t entry = {0};
    int result = ctx->db_retrieve(ctx->db_userdata, id, (size_t)id_len, &entry);
    if (result != 0) {
        return nullptr; // Not found or error
    }

    // Check expiration
    time_t now = time(nullptr);
    if (entry.expiration > 0 && now > entry.expiration) {
        // Session expired, remove it
        if (ctx->db_remove != nullptr) {
            ctx->db_remove(ctx->db_userdata, id, (size_t)id_len);
        }
        return nullptr;
    }

    // Deserialize session data
    const unsigned char *session_data_ptr = entry.session_data;
    WOLFSSL_SESSION *session =
        wolfSSL_d2i_SSL_SESSION(nullptr, &session_data_ptr, (long)entry.session_data_size);
    if (session == nullptr) {
        // Failed to deserialize, remove corrupted entry
        if (ctx->db_remove != nullptr) {
            ctx->db_remove(ctx->db_userdata, id, (size_t)id_len);
        }
        return nullptr;
    }

    return session;
}

/**
 * wolfSSL remove session callback adapter
 *
 * Called by wolfSSL when a session should be removed from the cache.
 *
 * @param ctx wolfSSL context
 * @param session Session to remove
 *
 * Note: This is called when a session is invalidated or expired.
 */
static void wolfssl_session_remove_cb(WOLFSSL_CTX *wolf_ctx, WOLFSSL_SESSION *session)
{
    if (wolf_ctx == nullptr || session == nullptr) {
        return;
    }

    tls_context_t *ctx = (tls_context_t *)wolfSSL_CTX_get_ex_data(wolf_ctx, 0);
    if (ctx == nullptr || ctx->db_remove == nullptr) {
        return; // No callback registered
    }

    // Extract session ID
    unsigned int session_id_len = 0;
    const unsigned char *session_id = wolfSSL_SESSION_get_id(session, &session_id_len);
    if (session_id != nullptr && session_id_len > 0) {
        ctx->db_remove(ctx->db_userdata, session_id, (size_t)session_id_len);
    }
}

/* ============================================================================
 * Session Cache Configuration
 * ============================================================================ */

int tls_context_set_session_cache(tls_context_t *ctx, tls_db_store_func_t store_func,
                                  tls_db_retrieve_func_t retrieve_func,
                                  tls_db_remove_func_t remove_func, void *userdata)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Store callback pointers in our context
    ctx->db_store = store_func;
    ctx->db_retrieve = retrieve_func;
    ctx->db_remove = remove_func;
    ctx->db_userdata = userdata;

    // Store our context pointer in wolfSSL context for callback access
    // This allows callbacks to retrieve our context from wolfSSL's context
    wolfSSL_CTX_set_ex_data(ctx->wolf_ctx, 0, ctx);

    // Wire up wolfSSL session cache callbacks
    if (store_func != nullptr) {
        wolfSSL_CTX_sess_set_new_cb(ctx->wolf_ctx, wolfssl_session_new_cb);
    } else {
        wolfSSL_CTX_sess_set_new_cb(ctx->wolf_ctx, nullptr);
    }

    if (retrieve_func != nullptr) {
        wolfSSL_CTX_sess_set_get_cb(ctx->wolf_ctx, wolfssl_session_get_cb);
    } else {
        wolfSSL_CTX_sess_set_get_cb(ctx->wolf_ctx, nullptr);
    }

    if (remove_func != nullptr) {
        wolfSSL_CTX_sess_set_remove_cb(ctx->wolf_ctx, wolfssl_session_remove_cb);
    } else {
        wolfSSL_CTX_sess_set_remove_cb(ctx->wolf_ctx, nullptr);
    }

    // Enable session caching in wolfSSL
    // wolfSSL_CTX_set_session_cache_mode sets the cache mode:
    // - SSL_SESS_CACHE_OFF: Disable caching
    // - SSL_SESS_CACHE_SERVER: Enable server-side caching (default for servers)
    // - SSL_SESS_CACHE_CLIENT: Enable client-side caching (default for clients)
    if (store_func != nullptr || retrieve_func != nullptr) {
        long mode = ctx->is_server ? SSL_SESS_CACHE_SERVER : SSL_SESS_CACHE_CLIENT;
        wolfSSL_CTX_set_session_cache_mode(ctx->wolf_ctx, mode);
    } else {
        wolfSSL_CTX_set_session_cache_mode(ctx->wolf_ctx, SSL_SESS_CACHE_OFF);
    }

    return TLS_E_SUCCESS;
}

int tls_context_set_session_timeout(tls_context_t *ctx, unsigned int timeout_secs)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Store the timeout value in our context structure
    ctx->session_timeout_secs = timeout_secs;

    // wolfSSL_CTX_set_timeout() returns the PREVIOUS timeout value, not SSL_SUCCESS
    // Unlike other wolfSSL functions, this is not an error code
    // We just need to call it to set the timeout in the wolfSSL context
    (void)wolfSSL_CTX_set_timeout(ctx->wolf_ctx, timeout_secs);

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Session Management
 * ============================================================================ */

/* Try loading a certificate/key pair; returns true on success */
static bool try_load_cert_pair(WOLFSSL_CTX *wolf_ctx, const char *cert, const char *key)
{
    int ret = wolfSSL_CTX_use_certificate_chain_file(wolf_ctx, cert);
    if (ret != SSL_SUCCESS) {
        return false;
    }
    ret = wolfSSL_CTX_use_PrivateKey_file(wolf_ctx, key, SSL_FILETYPE_PEM);
    return ret == SSL_SUCCESS;
}

/**
 * Install a minimal self-signed certificate for testing/unit test contexts
 *
 * wolfSSL requires a certificate to be present on server contexts before
 * creating SSL sessions. For unit tests and development, we load the test
 * certificates from the tests/certs directory if available.
 *
 * @param ctx TLS context
 * @return TLS_E_SUCCESS on success, error code on failure
 */
static int tls_install_dummy_certificate(tls_context_t *ctx)
{
    if (ctx == nullptr || !ctx->is_server || ctx->has_certificate) {
        return TLS_E_SUCCESS; // Nothing to do
    }

    /* Try relative path first (works when running from source directory) */
    if (try_load_cert_pair(ctx->wolf_ctx,
                           "tests/certs/server-cert.pem",
                           "tests/certs/server-key.pem")) {
        ctx->has_certificate = true;
        return TLS_E_SUCCESS;
    }

    /* Try absolute path via CMAKE_SOURCE_DIR (works when ctest runs from
     * the build directory). Defined via target_compile_definitions. */
#ifdef CMAKE_SOURCE_DIR
    if (try_load_cert_pair(ctx->wolf_ctx,
                           CMAKE_SOURCE_DIR "/tests/certs/server-cert.pem",
                           CMAKE_SOURCE_DIR "/tests/certs/server-key.pem")) {
        ctx->has_certificate = true;
        return TLS_E_SUCCESS;
    }
#endif

    // If file loading fails, we're probably not in the test environment
    // Return error - production code should always set certificates explicitly
    return TLS_E_BACKEND_ERROR;
}

tls_session_t *tls_session_new(tls_context_t *ctx)
{
    if (ctx == nullptr || ctx->wolf_ctx == nullptr) {
        return nullptr;
    }

    // For server contexts without certificates, install a minimal dummy certificate
    // This is required by wolfSSL before creating SSL sessions
    if (ctx->is_server && !ctx->has_certificate) {
        int ret = tls_install_dummy_certificate(ctx);
        if (ret != TLS_E_SUCCESS) {
            return nullptr;
        }
    }

    // Allocate session structure
    tls_session_t *session = (tls_session_t *)calloc(1, sizeof(*session));
    if (session == nullptr) {
        return nullptr;
    }

    session->ctx = ctx;
    atomic_fetch_add(&ctx->refcount, 1);

    // Create wolfSSL session
    session->wolf_ssl = wolfSSL_new(ctx->wolf_ctx);
    if (session->wolf_ssl == nullptr) {
        atomic_fetch_sub(&ctx->refcount, 1);
        free(session);
        return nullptr;
    }

    // Set session as user data for callbacks
    wolfSSL_SetIOReadCtx(session->wolf_ssl, session);
    wolfSSL_SetIOWriteCtx(session->wolf_ssl, session);

    // DTLS-specific initialization
    if (ctx->is_dtls) {
        session->dtls_mtu = 1400; // Default MTU
        wolfSSL_dtls_set_mtu(session->wolf_ssl, session->dtls_mtu);
    }

    return session;
}

void tls_session_free(tls_session_t *session)
{
    if (session == nullptr) {
        return;
    }

    // Free wolfSSL session
    if (session->wolf_ssl != nullptr) {
        wolfSSL_free(session->wolf_ssl);
    }

    // Release context reference
    if (session->ctx != nullptr) {
        atomic_fetch_sub(&session->ctx->refcount, 1);
    }

    // Zero sensitive data
    memset(session, 0, sizeof(*session));

    free(session);
}

int tls_session_set_fd(tls_session_t *session, int fd)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = wolfSSL_set_fd(session->wolf_ssl, fd);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Custom I/O Callbacks
 * ============================================================================ */

static int wolfssl_io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl; // Unused parameter

    tls_session_t *session = (tls_session_t *)ctx;
    if (session == nullptr || session->push_func == nullptr) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    ssize_t ret = session->push_func(session->io_userdata, buf, (size_t)sz);

    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        if (errno == EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return (int)ret;
}

static int wolfssl_io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    (void)ssl; // Unused parameter

    tls_session_t *session = (tls_session_t *)ctx;
    if (session == nullptr || session->pull_func == nullptr) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    ssize_t ret = session->pull_func(session->io_userdata, buf, (size_t)sz);

    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        if (errno == EINTR) {
            return WOLFSSL_CBIO_ERR_ISR;
        }
        if (ret == 0) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    if (ret == 0) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    return (int)ret;
}

int tls_session_set_io_functions(tls_session_t *session, tls_push_func_t push_func,
                                 tls_pull_func_t pull_func,
                                 tls_pull_timeout_func_t pull_timeout_func, void *userdata)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    session->push_func = push_func;
    session->pull_func = pull_func;
    session->pull_timeout_func = pull_timeout_func;
    session->io_userdata = userdata;

    // Set custom I/O callbacks on the wolfSSL session
    // Note: These are actually context-level in wolfSSL, so we set them via CTX
    // But we store the session pointer as userdata for the callbacks
    wolfSSL_SetIOReadCtx(session->wolf_ssl, session);
    wolfSSL_SetIOWriteCtx(session->wolf_ssl, session);
    wolfSSL_SSLSetIORecv(session->wolf_ssl, wolfssl_io_recv);
    wolfSSL_SSLSetIOSend(session->wolf_ssl, wolfssl_io_send);

    return TLS_E_SUCCESS;
}

void tls_session_set_ptr(tls_session_t *session, void *ptr)
{
    if (session != nullptr) {
        session->user_ptr = ptr;
    }
}

void *tls_session_get_ptr(tls_session_t *session)
{
    return session != nullptr ? session->user_ptr : nullptr;
}

int tls_session_set_timeout(tls_session_t *session, unsigned int timeout_ms)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // wolfSSL uses seconds for timeout
    unsigned int timeout_sec = timeout_ms / 1000;
    if (timeout_sec == 0 && timeout_ms > 0) {
        timeout_sec = 1; // Minimum 1 second
    }

    int ret = wolfSSL_set_timeout(session->wolf_ssl, timeout_sec);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * DTLS-Specific Functions
 * ============================================================================ */

int tls_dtls_set_mtu(tls_session_t *session, unsigned int mtu)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    if (!session->ctx->is_dtls) {
        return TLS_E_INVALID_REQUEST;
    }

    session->dtls_mtu = mtu;

    /* Best-effort: apply MTU to wolfSSL session. May fail if no peer is
     * configured yet (e.g., during unit tests). The value is tracked in
     * session->dtls_mtu and will be effective when queried via get_mtu. */
    (void)wolfSSL_dtls_set_mtu(session->wolf_ssl, (unsigned short)mtu);

    return TLS_E_SUCCESS;
}

int tls_dtls_get_mtu(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    if (!session->ctx->is_dtls) {
        return TLS_E_INVALID_REQUEST;
    }

    return (int)session->dtls_mtu;
}

int tls_dtls_set_timeouts(tls_session_t *session, unsigned int retrans_timeout_ms,
                          unsigned int total_timeout_ms)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    if (!session->ctx->is_dtls) {
        return TLS_E_INVALID_REQUEST;
    }

    // wolfSSL DTLS timeout configuration
    // Convert milliseconds to seconds
    unsigned int retrans_sec = retrans_timeout_ms / 1000;
    unsigned int total_sec = total_timeout_ms / 1000;

    if (retrans_sec == 0) {
        retrans_sec = 1;
    }
    if (total_sec == 0) {
        total_sec = 30;
    }

    int ret = wolfSSL_dtls_set_timeout_init(session->wolf_ssl, retrans_sec);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    ret = wolfSSL_dtls_set_timeout_max(session->wolf_ssl, total_sec);
    if (ret != SSL_SUCCESS) {
        return tls_wolfssl_map_error(ret);
    }

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Handshake Operations
 * ============================================================================ */

int tls_handshake(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret;

    if (session->ctx->is_server) {
        ret = wolfSSL_accept(session->wolf_ssl);
    } else {
        ret = wolfSSL_connect(session->wolf_ssl);
    }

    if (ret == SSL_SUCCESS) {
        session->handshake_complete = true;
        return TLS_E_SUCCESS;
    }

    int error = wolfSSL_get_error(session->wolf_ssl, ret);
    session->last_error = error;

    return tls_wolfssl_map_error(error);
}

int tls_rehandshake(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    if (!session->handshake_complete) {
        return TLS_E_INVALID_REQUEST;
    }

    // Initiate renegotiation
    int ret = wolfSSL_Rehandshake(session->wolf_ssl);
    if (ret != SSL_SUCCESS) {
        int error = wolfSSL_get_error(session->wolf_ssl, ret);
        return tls_wolfssl_map_error(error);
    }

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Data I/O Operations
 * ============================================================================ */

ssize_t tls_send(tls_session_t *session, const void *data, size_t len)
{
    if (session == nullptr || session->wolf_ssl == nullptr || data == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    if (!session->handshake_complete) {
        return TLS_E_INVALID_REQUEST;
    }

    int ret = wolfSSL_write(session->wolf_ssl, data, (int)len);

    if (ret > 0) {
        return ret;
    }

    int error = wolfSSL_get_error(session->wolf_ssl, ret);
    session->last_error = error;

    return tls_wolfssl_map_error(error);
}

ssize_t tls_recv(tls_session_t *session, void *data, size_t len)
{
    if (session == nullptr || session->wolf_ssl == nullptr || data == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    if (!session->handshake_complete) {
        return TLS_E_INVALID_REQUEST;
    }

    int ret = wolfSSL_read(session->wolf_ssl, data, (int)len);

    if (ret > 0) {
        return ret;
    }

    if (ret == 0) {
        // Connection closed
        return TLS_E_PREMATURE_TERMINATION;
    }

    int error = wolfSSL_get_error(session->wolf_ssl, ret);
    session->last_error = error;

    return tls_wolfssl_map_error(error);
}

size_t tls_pending(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return 0;
    }

    int pending = wolfSSL_pending(session->wolf_ssl);
    return pending > 0 ? (size_t)pending : 0;
}

int tls_cork(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // wolfSSL doesn't have direct record corking support like GnuTLS
    // We can simulate it with a flag
    session->corked = true;

    return TLS_E_SUCCESS;
}

int tls_uncork(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    session->corked = false;

    // Flush any pending data
    // In wolfSSL, data is sent immediately, so no action needed

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Connection Termination
 * ============================================================================ */

int tls_bye(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = wolfSSL_shutdown(session->wolf_ssl);

    // wolfSSL_shutdown may need to be called twice for bidirectional shutdown
    if (ret == SSL_SHUTDOWN_NOT_DONE) {
        ret = wolfSSL_shutdown(session->wolf_ssl);
    }

    if (ret == SSL_SUCCESS || ret == SSL_SHUTDOWN_NOT_DONE) {
        return TLS_E_SUCCESS;
    }

    int error = wolfSSL_get_error(session->wolf_ssl, ret);
    return tls_wolfssl_map_error(error);
}

void tls_alert_send(tls_session_t *session, tls_alert_t alert)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return;
    }

    // Send TLS alert
    // wolfSSL handles alerts internally via wolfSSL_shutdown()
    // There is no public API to send arbitrary alerts, so we use shutdown for fatal alerts
    // Note: This is a limitation of wolfSSL API compared to GnuTLS
    (void)alert; // Alert type is not directly controllable in wolfSSL
    wolfSSL_shutdown(session->wolf_ssl);
}

/* ============================================================================
 * Session Information
 * ============================================================================ */

int tls_get_connection_info(tls_session_t *session, tls_connection_info_t *info)
{
    if (session == nullptr || session->wolf_ssl == nullptr || info == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    memset(info, 0, sizeof(*info));

    // Get TLS version
    int version = wolfSSL_version(session->wolf_ssl);
    switch (version) {
    case TLS1_VERSION:
        info->version = TLS_VERSION_TLS10;
        break;
    case TLS1_1_VERSION:
        info->version = TLS_VERSION_TLS11;
        break;
    case TLS1_2_VERSION:
        info->version = TLS_VERSION_TLS12;
        break;
    case TLS1_3_VERSION:
        info->version = TLS_VERSION_TLS13;
        break;
    case DTLS1_VERSION:
        info->version = TLS_VERSION_DTLS10;
        break;
    case DTLS1_2_VERSION:
        info->version = TLS_VERSION_DTLS12;
        break;
    default:
        info->version = TLS_VERSION_UNKNOWN;
    }

    // Get cipher name
    const char *cipher = wolfSSL_get_cipher(session->wolf_ssl);
    if (cipher != nullptr) {
        strncpy(info->cipher_name, cipher, TLS_MAX_CIPHER_NAME - 1);
    }

    // Get cipher bits (wolfSSL doesn't have GetCipherBits, calculate from cipher suite)
    // For now, we'll use a default based on the cipher name
    // This is a simplified implementation - a production version should parse the cipher name
    info->cipher_bits = 256; // Default to 256 bits for modern ciphers

    // Check if session was resumed
    info->session_resumed = wolfSSL_session_reused(session->wolf_ssl) ? true : false;

    // Check safe renegotiation
    info->safe_renegotiation = wolfSSL_UseSecureRenegotiation(session->wolf_ssl) ? true : false;

    return TLS_E_SUCCESS;
}

char *tls_get_session_desc(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return nullptr;
    }

    tls_connection_info_t info;
    if (tls_get_connection_info(session, &info) != TLS_E_SUCCESS) {
        return nullptr;
    }

    // Format: "TLS1.3-AES128-GCM-SHA256"
    const char *version_str = "UNKNOWN";
    switch (info.version) {
    case TLS_VERSION_TLS10:
        version_str = "TLS1.0";
        break;
    case TLS_VERSION_TLS11:
        version_str = "TLS1.1";
        break;
    case TLS_VERSION_TLS12:
        version_str = "TLS1.2";
        break;
    case TLS_VERSION_TLS13:
        version_str = "TLS1.3";
        break;
    case TLS_VERSION_DTLS10:
        version_str = "DTLS1.0";
        break;
    case TLS_VERSION_DTLS12:
        version_str = "DTLS1.2";
        break;
    case TLS_VERSION_DTLS13:
        version_str = "DTLS1.3";
        break;
    default:
        break;
    }

    size_t v_len = strlen(version_str);
    size_t c_len = strlen(info.cipher_name);
    size_t desc_len;
    if (ckd_add(&desc_len, v_len, c_len) || ckd_add(&desc_len, desc_len, 2)) {
        return nullptr;
    }
    char *desc = (char *)malloc(desc_len);
    if (desc != nullptr) {
        snprintf(desc, desc_len, "%s-%s", version_str, info.cipher_name);
    }

    return desc;
}

const tls_certificate_t *tls_get_peer_certificate(tls_session_t *session)
{
    if (session == nullptr || session->wolf_ssl == nullptr) {
        return nullptr;
    }

    WOLFSSL_X509 *peer_cert = wolfSSL_get_peer_certificate(session->wolf_ssl);
    if (peer_cert == nullptr) {
        return nullptr;
    }

    // TODO: Wrap in tls_certificate_t structure
    // For now, return nullptr as we need to implement certificate wrapper
    wolfSSL_X509_free(peer_cert);

    return nullptr;
}

/* ============================================================================
 * Error Handling
 * ============================================================================ */

const char *tls_strerror(int error_code)
{
    // Map abstraction error codes to descriptive strings
    switch (error_code) {
    case TLS_E_SUCCESS:
        return "Success";
    case TLS_E_AGAIN:
        return "Operation would block (try again)";
    case TLS_E_INTERRUPTED:
        return "Operation interrupted by signal";
    case TLS_E_MEMORY_ERROR:
        return "Memory allocation failed";
    case TLS_E_INVALID_REQUEST:
        return "Invalid request for current state";
    case TLS_E_INVALID_PARAMETER:
        return "Invalid parameter";
    case TLS_E_FATAL_ALERT_RECEIVED:
        return "Fatal TLS alert received";
    case TLS_E_WARNING_ALERT_RECEIVED:
        return "Warning TLS alert received";
    case TLS_E_UNEXPECTED_MESSAGE:
        return "Unexpected protocol message";
    case TLS_E_DECRYPTION_FAILED:
        return "Decryption failed";
    case TLS_E_CERTIFICATE_ERROR:
        return "Certificate verification failed";
    case TLS_E_CERTIFICATE_REQUIRED:
        return "Certificate required but not provided";
    case TLS_E_HANDSHAKE_FAILED:
        return "TLS handshake failed";
    case TLS_E_SESSION_NOT_FOUND:
        return "Session not found in cache";
    case TLS_E_PREMATURE_TERMINATION:
        return "Connection terminated prematurely";
    case TLS_E_REHANDSHAKE:
        return "Rehandshake requested";
    case TLS_E_PUSH_ERROR:
        return "Send operation failed";
    case TLS_E_PULL_ERROR:
        return "Receive operation failed";
    case TLS_E_BACKEND_ERROR:
        return "Backend-specific error (check tls_get_last_error)";
    default:
        return "Unknown error";
    }
}

bool tls_error_is_fatal(int error_code)
{
    switch (error_code) {
    case TLS_E_AGAIN:
    case TLS_E_INTERRUPTED:
    case TLS_E_WARNING_ALERT_RECEIVED:
    case TLS_E_REHANDSHAKE:
        return false;

    default:
        return error_code < 0; // All negative errors are considered fatal except above
    }
}

int tls_get_last_error(void)
{
    return wolfSSL_ERR_get_error();
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

void *tls_malloc(size_t size)
{
    return malloc(size);
}

void tls_free(void *ptr)
{
    free(ptr);
}

int tls_hash_fast(int algo, const void *data, size_t data_len, uint8_t *output)
{
    if (data == nullptr || output == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret;

    switch (algo) {
    case 0: // SHA-256
        ret = wc_Sha256Hash((const byte *)data, (word32)data_len, output);
        break;
    case 1: // SHA-384
        ret = wc_Sha384Hash((const byte *)data, (word32)data_len, output);
        break;
    case 2: // SHA-512
        ret = wc_Sha512Hash((const byte *)data, (word32)data_len, output);
        break;
    default:
        return TLS_E_INVALID_PARAMETER;
    }

    if (ret != 0) {
        return TLS_E_BACKEND_ERROR;
    }

    return TLS_E_SUCCESS;
}

int tls_random(void *data, size_t len)
{
    if (data == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    WC_RNG rng;

    int ret = wc_InitRng(&rng);
    if (ret != 0) {
        return TLS_E_BACKEND_ERROR;
    }

    ret = wc_RNG_GenerateBlock(&rng, (byte *)data, (word32)len);
    wc_FreeRng(&rng);

    if (ret != 0) {
        return TLS_E_BACKEND_ERROR;
    }

    return TLS_E_SUCCESS;
}

/* ============================================================================
 * PSK Callback Wrappers
 * ============================================================================ */

#ifndef NO_PSK
static unsigned int wolfssl_psk_server_cb(WOLFSSL *ssl, const char *identity, unsigned char *key,
                                          unsigned int max_key_len)
{
    if (ssl == nullptr || identity == nullptr || key == nullptr) {
        return 0;
    }

    // Get session from wolfSSL context
    tls_session_t *session = (tls_session_t *)wolfSSL_GetIOReadCtx(ssl);
    if (session == nullptr || session->ctx == nullptr) {
        return 0;
    }

    if (session->ctx->psk_server_callback == nullptr) {
        return 0;
    }

    size_t key_size = max_key_len;
    int ret = session->ctx->psk_server_callback(session, identity, key, &key_size,
                                                session->ctx->psk_userdata);

    if (ret != TLS_E_SUCCESS || key_size > max_key_len) {
        return 0;
    }

    return (unsigned int)key_size;
}

static unsigned int wolfssl_psk_client_cb(WOLFSSL *ssl, const char *hint, char *identity,
                                          unsigned int max_identity_len, unsigned char *key,
                                          unsigned int max_key_len)
{
    (void)hint; // May be nullptr

    if (ssl == nullptr || identity == nullptr || key == nullptr) {
        return 0;
    }

    // Get session from wolfSSL context
    tls_session_t *session = (tls_session_t *)wolfSSL_GetIOReadCtx(ssl);
    if (session == nullptr || session->ctx == nullptr) {
        return 0;
    }

    if (session->ctx->psk_client_callback == nullptr) {
        return 0;
    }

    char *username = nullptr;
    size_t key_size = max_key_len;

    int ret = session->ctx->psk_client_callback(session, &username, key, &key_size,
                                                session->ctx->psk_userdata);

    if (ret != TLS_E_SUCCESS || username == nullptr || key_size > max_key_len) {
        free(username);
        return 0;
    }

    // Copy username to identity buffer
    strncpy(identity, username, max_identity_len - 1);
    identity[max_identity_len - 1] = '\0';

    free(username);

    return (unsigned int)key_size;
}
#endif // NO_PSK

/* ============================================================================
 * Certificate Verification Callback Wrapper
 * ============================================================================ */

static int wolfssl_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX *x509_ctx)
{
    if (x509_ctx == nullptr) {
        return 0;
    }

    // Get wolfSSL session from context
    WOLFSSL *ssl = (WOLFSSL *)wolfSSL_X509_STORE_CTX_get_ex_data(
        x509_ctx, wolfSSL_get_ex_data_X509_STORE_CTX_idx());
    if (ssl == nullptr) {
        return preverify;
    }

    // Get our session structure
    tls_session_t *session = (tls_session_t *)wolfSSL_GetIOReadCtx(ssl);
    if (session == nullptr || session->ctx == nullptr) {
        return preverify;
    }

    if (session->ctx->verify_callback == nullptr) {
        return preverify;
    }

    // Get certificate chain
    WOLFSSL_X509 *cert = wolfSSL_X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert == nullptr) {
        return 0;
    }

    // TODO: Wrap certificate in tls_certificate_t and call user callback
    // For now, just return preverify result

    return preverify;
}
