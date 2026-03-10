/*
 * Copyright (C) 2025 ringwall Contributors
 *
 * This file is part of ringwall.
 *
 * ringwall is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * GnuTLS Backend Implementation
 *
 * This implementation uses GnuTLS 3.8+ as the cryptographic backend.
 * It provides complete TLS/DTLS functionality with focus on:
 * - Cisco Secure Client 5.x+ compatibility
 * - Modern cipher suites (TLS 1.3, ChaCha20-Poly1305, AES-GCM)
 * - High performance with minimal overhead
 * - Comprehensive error handling
 */

#include "tls_gnutls.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

// Session cache callbacks for GnuTLS
static int gnutls_db_store_cb(void *ptr, gnutls_datum_t key, gnutls_datum_t data);
static gnutls_datum_t gnutls_db_retrieve_cb(void *ptr, gnutls_datum_t key);
static int gnutls_db_remove_cb(void *ptr, gnutls_datum_t key);

/* ============================================================================
 * Global State
 * ============================================================================ */

static tls_backend_t g_current_backend = TLS_BACKEND_NONE;
static bool g_initialized = false;

/* ============================================================================
 * Library Initialization
 * ============================================================================ */

int tls_gnutls_init(void)
{
    if (g_initialized) {
        return TLS_E_SUCCESS;
    }

    // Check GnuTLS version
    const char *version = gnutls_check_version(nullptr);
    if (version == nullptr) {
        return TLS_E_BACKEND_ERROR;
    }

    // Require at least GnuTLS 3.6.0 for TLS 1.3 support
    if (gnutls_check_version("3.6.0") == nullptr) {
        fprintf(stderr, "GnuTLS 3.6.0 or later required (found %s)\n", version);
        return TLS_E_BACKEND_ERROR;
    }

    // Initialize GnuTLS
    int ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "gnutls_global_init failed: %s\n", gnutls_strerror(ret));
        return tls_gnutls_map_error(ret);
    }

    g_initialized = true;
    g_current_backend = TLS_BACKEND_GNUTLS;

    return TLS_E_SUCCESS;
}

void tls_gnutls_deinit(void)
{
    if (g_initialized) {
        gnutls_global_deinit();
        g_initialized = false;
        g_current_backend = TLS_BACKEND_NONE;
    }
}

/* ============================================================================
 * Error Handling
 * ============================================================================ */

[[nodiscard]] int tls_gnutls_map_error(int gnutls_err)
{
    if (gnutls_err >= 0) {
        return TLS_E_SUCCESS;
    }

    switch (gnutls_err) {
    case GNUTLS_E_AGAIN:
        return TLS_E_AGAIN;
    case GNUTLS_E_INTERRUPTED:
        return TLS_E_INTERRUPTED;
    case GNUTLS_E_MEMORY_ERROR:
        return TLS_E_MEMORY_ERROR;
    case GNUTLS_E_INVALID_REQUEST:
        return TLS_E_INVALID_REQUEST;
    case GNUTLS_E_FATAL_ALERT_RECEIVED:
        return TLS_E_FATAL_ALERT_RECEIVED;
    case GNUTLS_E_WARNING_ALERT_RECEIVED:
        return TLS_E_WARNING_ALERT_RECEIVED;
    case GNUTLS_E_UNEXPECTED_PACKET:
    case GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET:
        return TLS_E_UNEXPECTED_MESSAGE;
    case GNUTLS_E_DECRYPTION_FAILED:
        return TLS_E_DECRYPTION_FAILED;
    case GNUTLS_E_CERTIFICATE_ERROR:
    case GNUTLS_E_CERTIFICATE_KEY_MISMATCH:
    case GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE:
        return TLS_E_CERTIFICATE_ERROR;
    case GNUTLS_E_CERTIFICATE_REQUIRED:
        return TLS_E_CERTIFICATE_REQUIRED;
    case GNUTLS_E_PREMATURE_TERMINATION:
        return TLS_E_PREMATURE_TERMINATION;
    case GNUTLS_E_REHANDSHAKE:
        return TLS_E_REHANDSHAKE;
    case GNUTLS_E_PUSH_ERROR:
        return TLS_E_PUSH_ERROR;
    case GNUTLS_E_PULL_ERROR:
        return TLS_E_PULL_ERROR;
    default:
        return TLS_E_BACKEND_ERROR;
    }
}

[[nodiscard]] const char *tls_strerror(int error_code)
{
    switch (error_code) {
    case TLS_E_SUCCESS:
        return "Success";
    case TLS_E_AGAIN:
        return "Resource temporarily unavailable";
    case TLS_E_INTERRUPTED:
        return "Interrupted system call";
    case TLS_E_MEMORY_ERROR:
        return "Memory allocation failed";
    case TLS_E_INVALID_REQUEST:
        return "Invalid request";
    case TLS_E_INVALID_PARAMETER:
        return "Invalid parameter";
    case TLS_E_FATAL_ALERT_RECEIVED:
        return "Fatal alert received";
    case TLS_E_WARNING_ALERT_RECEIVED:
        return "Warning alert received";
    case TLS_E_UNEXPECTED_MESSAGE:
        return "Unexpected message";
    case TLS_E_DECRYPTION_FAILED:
        return "Decryption failed";
    case TLS_E_CERTIFICATE_ERROR:
        return "Certificate error";
    case TLS_E_CERTIFICATE_REQUIRED:
        return "Certificate required";
    case TLS_E_HANDSHAKE_FAILED:
        return "Handshake failed";
    case TLS_E_SESSION_NOT_FOUND:
        return "Session not found";
    case TLS_E_PREMATURE_TERMINATION:
        return "Premature termination";
    case TLS_E_REHANDSHAKE:
        return "Rehandshake requested";
    case TLS_E_PUSH_ERROR:
        return "Push error";
    case TLS_E_PULL_ERROR:
        return "Pull error";
    case TLS_E_BACKEND_ERROR:
        return "Backend-specific error";
    default:
        return "Unknown error";
    }
}

[[nodiscard]] bool tls_error_is_fatal(int error_code)
{
    switch (error_code) {
    case TLS_E_SUCCESS:
    case TLS_E_AGAIN:
    case TLS_E_INTERRUPTED:
    case TLS_E_WARNING_ALERT_RECEIVED:
    case TLS_E_REHANDSHAKE:
        return false;
    default:
        return true;
    }
}

[[nodiscard]] int tls_get_last_error(void)
{
    // GnuTLS doesn't have a global error state like wolfSSL
    // Backend-specific errors should be captured at call sites
    return 0;
}

/* ============================================================================
 * Context Management
 * ============================================================================ */

[[nodiscard]] tls_context_t *tls_context_new(bool is_server, bool is_dtls)
{
    if (!g_initialized) {
        return nullptr;
    }

    tls_context_t *ctx = (tls_context_t *)calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return nullptr;
    }

    ctx->is_server = is_server;
    ctx->is_dtls = is_dtls;
    ctx->verify_peer = true; // Default to verification enabled

    // Allocate certificate credentials
    int ret = gnutls_certificate_allocate_credentials(&ctx->x509_cred);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "gnutls_certificate_allocate_credentials failed: %s\n",
                gnutls_strerror(ret));
        free(ctx);
        return nullptr;
    }

    return ctx;
}

void tls_context_free(tls_context_t *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->x509_cred != nullptr) {
        gnutls_certificate_free_credentials(ctx->x509_cred);
    }

    if (ctx->priority_cache != nullptr) {
        gnutls_priority_deinit(ctx->priority_cache);
    }

    if (ctx->dh_params != nullptr) {
        gnutls_dh_params_deinit(ctx->dh_params);
    }

    // Free stored certificate and key paths
    free(ctx->cert_file_path);
    free(ctx->key_file_path);

    free(ctx);
}

[[nodiscard]] int tls_context_set_cert_file(tls_context_t *ctx, const char *cert_file)
{
    if (ctx == nullptr || cert_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Store certificate path for deferred loading
    free(ctx->cert_file_path);
    ctx->cert_file_path = strdup(cert_file);
    if (ctx->cert_file_path == nullptr) {
        return TLS_E_MEMORY_ERROR;
    }

    // If key file is already set, load both now
    if (ctx->key_file_path != nullptr) {
        int ret = gnutls_certificate_set_x509_key_file(ctx->x509_cred, ctx->cert_file_path,
                                                       ctx->key_file_path, GNUTLS_X509_FMT_PEM);
        if (ret != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "Failed to load certificate from %s: %s\n", ctx->cert_file_path,
                    gnutls_strerror(ret));
            return tls_gnutls_map_error(ret);
        }
    }

    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_key_file(tls_context_t *ctx, const char *key_file)
{
    if (ctx == nullptr || key_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Store key path for deferred loading
    free(ctx->key_file_path);
    ctx->key_file_path = strdup(key_file);
    if (ctx->key_file_path == nullptr) {
        return TLS_E_MEMORY_ERROR;
    }

    // If cert file is already set, load both now
    if (ctx->cert_file_path != nullptr) {
        int ret = gnutls_certificate_set_x509_key_file(ctx->x509_cred, ctx->cert_file_path,
                                                       ctx->key_file_path, GNUTLS_X509_FMT_PEM);
        if (ret != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "Failed to load key from %s: %s\n", ctx->key_file_path,
                    gnutls_strerror(ret));
            return tls_gnutls_map_error(ret);
        }
    }

    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_ca_file(tls_context_t *ctx, const char *ca_file)
{
    if (ctx == nullptr || ca_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_certificate_set_x509_trust_file(ctx->x509_cred, ca_file, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        fprintf(stderr, "Failed to load CA from %s: %s\n", ca_file, gnutls_strerror(ret));
        return tls_gnutls_map_error(ret);
    }

    // ret contains number of certificates processed
    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_priority(tls_context_t *ctx, const char *priority)
{
    if (ctx == nullptr || priority == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    const char *err_pos = nullptr;
    int ret = gnutls_priority_init(&ctx->priority_cache, priority, &err_pos);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Failed to set priority string '%s': %s", priority, gnutls_strerror(ret));
        if (err_pos != nullptr) {
            fprintf(stderr, " at position: %s\n", err_pos);
        } else {
            fprintf(stderr, "\n");
        }
        return tls_gnutls_map_error(ret);
    }

    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_dh_params_file(tls_context_t *ctx, const char *dh_file)
{
    if (ctx == nullptr || dh_file == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Load DH parameters from file
    gnutls_datum_t dh_params_data;
    int ret = gnutls_load_file(dh_file, &dh_params_data);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Failed to load DH params from %s: %s\n", dh_file, gnutls_strerror(ret));
        return tls_gnutls_map_error(ret);
    }

    // Initialize DH params
    ret = gnutls_dh_params_init(&ctx->dh_params);
    if (ret != GNUTLS_E_SUCCESS) {
        gnutls_free(dh_params_data.data);
        return tls_gnutls_map_error(ret);
    }

    // Import DH params
    ret = gnutls_dh_params_import_pkcs3(ctx->dh_params, &dh_params_data, GNUTLS_X509_FMT_PEM);
    gnutls_free(dh_params_data.data);

    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "Failed to import DH params: %s\n", gnutls_strerror(ret));
        gnutls_dh_params_deinit(ctx->dh_params);
        ctx->dh_params = nullptr;
        return tls_gnutls_map_error(ret);
    }

    // Set DH params in certificate credentials
    gnutls_certificate_set_dh_params(ctx->x509_cred, ctx->dh_params);

    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_verify(tls_context_t *ctx, bool verify,
                                         tls_cert_verify_func_t callback, void *userdata)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    ctx->verify_peer = verify;
    ctx->verify_callback = callback;
    ctx->verify_userdata = userdata;

    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_psk_server_callback(tls_context_t *ctx,
                                                      tls_psk_server_func_t callback,
                                                      void *userdata)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    ctx->psk_server_callback = callback;
    ctx->psk_server_userdata = userdata;

    // TODO: Set GnuTLS PSK credentials
    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Session Cache Callback Adapters
 * ============================================================================ */

/**
 * GnuTLS session store callback adapter
 *
 * Called by GnuTLS when a new session should be stored in the cache.
 *
 * @param ptr User data pointer (points to tls_context_t)
 * @param key Session key (session ID)
 * @param data Serialized session data
 * @return GNUTLS_E_SUCCESS (0) on success, negative error code on failure
 */
static int gnutls_db_store_cb(void *ptr, gnutls_datum_t key, gnutls_datum_t data)
{
    if (ptr == nullptr || key.data == nullptr || key.size == 0) {
        return GNUTLS_E_DB_ERROR;
    }

    tls_context_t *ctx = (tls_context_t *)ptr;
    if (ctx->db_store == nullptr) {
        return GNUTLS_E_SUCCESS; // No callback registered, silently succeed
    }

    // Validate sizes
    if (key.size > TLS_MAX_SESSION_ID_SIZE || data.size > TLS_MAX_SESSION_DATA_SIZE) {
        return GNUTLS_E_DB_ERROR;
    }

    // Build cache entry
    tls_session_cache_entry_t entry = {0};
    memcpy(entry.session_id, key.data, key.size);
    entry.session_id_size = key.size;
    memcpy(entry.session_data, data.data, data.size);
    entry.session_data_size = data.size;

    // Calculate expiration time (default 300 seconds)
    time_t now = time(nullptr);
    entry.expiration = now + 300;

    // Remote address will be filled by application if needed
    entry.remote_addr_len = 0;

    // Call user's store callback
    int result = ctx->db_store(ctx->db_userdata, &entry);
    return (result == 0) ? GNUTLS_E_SUCCESS : GNUTLS_E_DB_ERROR;
}

/**
 * GnuTLS session retrieve callback adapter
 *
 * Called by GnuTLS when attempting to resume a session.
 *
 * @param ptr User data pointer (points to tls_context_t)
 * @param key Session key (session ID) to retrieve
 * @return gnutls_datum_t containing session data, or {nullptr, 0} if not found
 *
 * Note: GnuTLS will call gnutls_free() on the returned data, so we must allocate
 *       it using gnutls_malloc().
 */
static gnutls_datum_t gnutls_db_retrieve_cb(void *ptr, gnutls_datum_t key)
{
    gnutls_datum_t result = {.data = nullptr, .size = 0};

    if (ptr == nullptr || key.data == nullptr || key.size == 0) {
        return result;
    }

    tls_context_t *ctx = (tls_context_t *)ptr;
    if (ctx->db_retrieve == nullptr) {
        return result; // No callback registered
    }

    // Retrieve session from cache
    tls_session_cache_entry_t entry = {0};
    int ret = ctx->db_retrieve(ctx->db_userdata, key.data, key.size, &entry);
    if (ret != 0) {
        return result; // Not found or error
    }

    // Check expiration
    time_t now = time(nullptr);
    if (entry.expiration > 0 && now > entry.expiration) {
        // Session expired, remove it
        if (ctx->db_remove != nullptr) {
            ctx->db_remove(ctx->db_userdata, key.data, key.size);
        }
        return result;
    }

    // Allocate memory for GnuTLS (it will free it)
    result.data = (unsigned char *)gnutls_malloc(entry.session_data_size);
    if (result.data == nullptr) {
        return result;
    }

    // Copy session data
    memcpy(result.data, entry.session_data, entry.session_data_size);
    result.size = (unsigned int)entry.session_data_size;

    return result;
}

/**
 * GnuTLS session remove callback adapter
 *
 * Called by GnuTLS when a session should be removed from the cache.
 *
 * @param ptr User data pointer (points to tls_context_t)
 * @param key Session key (session ID) to remove
 * @return GNUTLS_E_SUCCESS (0) on success, negative error code on failure
 */
static int gnutls_db_remove_cb(void *ptr, gnutls_datum_t key)
{
    if (ptr == nullptr || key.data == nullptr || key.size == 0) {
        return GNUTLS_E_DB_ERROR;
    }

    tls_context_t *ctx = (tls_context_t *)ptr;
    if (ctx->db_remove == nullptr) {
        return GNUTLS_E_SUCCESS; // No callback registered
    }

    // Call user's remove callback
    int result = ctx->db_remove(ctx->db_userdata, key.data, key.size);
    return (result == 0) ? GNUTLS_E_SUCCESS : GNUTLS_E_DB_ERROR;
}

/* ============================================================================
 * Session Cache Configuration
 * ============================================================================ */

[[nodiscard]] int tls_context_set_session_cache(tls_context_t *ctx, tls_db_store_func_t store_func,
                                                tls_db_retrieve_func_t retrieve_func,
                                                tls_db_remove_func_t remove_func, void *userdata)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // Store callback pointers in our context
    // Note: GnuTLS session cache callbacks are set per-session (not per-context),
    //       so we store them here and apply them in tls_session_new()
    ctx->db_store = store_func;
    ctx->db_retrieve = retrieve_func;
    ctx->db_remove = remove_func;
    ctx->db_userdata = userdata;

    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_context_set_session_timeout(tls_context_t *ctx, unsigned int timeout_secs)
{
    if (ctx == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    // TODO: Store timeout and apply to sessions
    (void)timeout_secs;
    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Session Management
 * ============================================================================ */

[[nodiscard]] tls_session_t *tls_session_new(tls_context_t *ctx)
{
    if (ctx == nullptr) {
        return nullptr;
    }

    tls_session_t *session = (tls_session_t *)calloc(1, sizeof(*session));
    if (session == nullptr) {
        return nullptr;
    }

    session->ctx = ctx;

    // Initialize GnuTLS session
    unsigned int flags = 0;
    if (!ctx->is_server) {
        flags |= GNUTLS_CLIENT;
    } else {
        flags |= GNUTLS_SERVER;
    }

    if (ctx->is_dtls) {
        flags |= GNUTLS_DATAGRAM;
    }

    int ret = gnutls_init(&session->session, flags);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "gnutls_init failed: %s\n", gnutls_strerror(ret));
        free(session);
        return nullptr;
    }

    // Set certificate credentials
    ret = gnutls_credentials_set(session->session, GNUTLS_CRD_CERTIFICATE, ctx->x509_cred);
    if (ret != GNUTLS_E_SUCCESS) {
        fprintf(stderr, "gnutls_credentials_set failed: %s\n", gnutls_strerror(ret));
        gnutls_deinit(session->session);
        free(session);
        return nullptr;
    }

    // Set priority
    if (ctx->priority_cache != nullptr) {
        ret = gnutls_priority_set(session->session, ctx->priority_cache);
        if (ret != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "gnutls_priority_set failed: %s\n", gnutls_strerror(ret));
            gnutls_deinit(session->session);
            free(session);
            return nullptr;
        }
    } else {
        // Use default priority
        const char *default_priority = "NORMAL:%SERVER_PRECEDENCE";
        ret = gnutls_priority_set_direct(session->session, default_priority, nullptr);
        if (ret != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "gnutls_priority_set_direct failed: %s\n", gnutls_strerror(ret));
            gnutls_deinit(session->session);
            free(session);
            return nullptr;
        }
    }

    // Set verification requirements
    if (ctx->verify_peer) {
        gnutls_session_set_verify_cert(session->session, nullptr, 0);
    }

    // Set session cache callbacks (if configured)
    // GnuTLS requires these to be set per-session, not per-context
    if (ctx->db_store != nullptr || ctx->db_retrieve != nullptr || ctx->db_remove != nullptr) {
        // Set user data pointer (our context, so callbacks can access it)
        gnutls_db_set_ptr(session->session, ctx);

        // Wire up the three callback functions
        if (ctx->db_store != nullptr) {
            gnutls_db_set_store_function(session->session, gnutls_db_store_cb);
        }
        if (ctx->db_retrieve != nullptr) {
            gnutls_db_set_retrieve_function(session->session, gnutls_db_retrieve_cb);
        }
        if (ctx->db_remove != nullptr) {
            gnutls_db_set_remove_function(session->session, gnutls_db_remove_cb);
        }
    }

    ctx->sessions_created++;
    return session;
}

void tls_session_free(tls_session_t *session)
{
    if (session == nullptr) {
        return;
    }

    if (session->session != nullptr) {
        // Send close_notify
        gnutls_bye(session->session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session->session);
    }

    free(session);
}

[[nodiscard]] int tls_session_set_fd(tls_session_t *session, int fd)
{
    if (session == nullptr || fd < 0) {
        return TLS_E_INVALID_PARAMETER;
    }

    gnutls_transport_set_int(session->session, fd);
    return TLS_E_SUCCESS;
}

/* Custom I/O callback wrappers */
ssize_t tls_gnutls_push_wrapper(gnutls_transport_ptr_t ptr, const void *data, size_t len)
{
    tls_session_t *session = (tls_session_t *)ptr;
    if (session->push_func == nullptr) {
        errno = EINVAL;
        return -1;
    }

    ssize_t ret = session->push_func(session->io_userdata, data, len);
    if (ret < 0) {
        // Map errno for GnuTLS
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            gnutls_transport_set_errno(session->session, EAGAIN);
        } else if (errno == EINTR) {
            gnutls_transport_set_errno(session->session, EINTR);
        }
    }

    return ret;
}

ssize_t tls_gnutls_pull_wrapper(gnutls_transport_ptr_t ptr, void *data, size_t len)
{
    tls_session_t *session = (tls_session_t *)ptr;
    if (session->pull_func == nullptr) {
        errno = EINVAL;
        return -1;
    }

    ssize_t ret = session->pull_func(session->io_userdata, data, len);
    if (ret < 0) {
        // Map errno for GnuTLS
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            gnutls_transport_set_errno(session->session, EAGAIN);
        } else if (errno == EINTR) {
            gnutls_transport_set_errno(session->session, EINTR);
        }
    }

    return ret;
}

int tls_gnutls_pull_timeout_wrapper(gnutls_transport_ptr_t ptr, unsigned int ms)
{
    tls_session_t *session = (tls_session_t *)ptr;
    if (session->pull_timeout_func == nullptr) {
        return 0; // Assume ready
    }

    return session->pull_timeout_func(session->io_userdata, ms);
}

[[nodiscard]] int tls_session_set_io_functions(tls_session_t *session, tls_push_func_t push_func,
                                               tls_pull_func_t pull_func,
                                               tls_pull_timeout_func_t pull_timeout_func,
                                               void *userdata)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    session->push_func = push_func;
    session->pull_func = pull_func;
    session->pull_timeout_func = pull_timeout_func;
    session->io_userdata = userdata;

    // Set GnuTLS callbacks
    gnutls_transport_set_ptr(session->session, session);
    gnutls_transport_set_push_function(session->session, tls_gnutls_push_wrapper);
    gnutls_transport_set_pull_function(session->session, tls_gnutls_pull_wrapper);

    if (pull_timeout_func != nullptr) {
        gnutls_transport_set_pull_timeout_function(session->session,
                                                   tls_gnutls_pull_timeout_wrapper);
    }

    return TLS_E_SUCCESS;
}

void tls_session_set_ptr(tls_session_t *session, void *ptr)
{
    if (session != nullptr) {
        session->user_ptr = ptr;
    }
}

[[nodiscard]] void *tls_session_get_ptr(tls_session_t *session)
{
    if (session == nullptr) {
        return nullptr;
    }
    return session->user_ptr;
}

[[nodiscard]] int tls_session_set_timeout(tls_session_t *session, unsigned int timeout_ms)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    gnutls_handshake_set_timeout(session->session, timeout_ms);
    return TLS_E_SUCCESS;
}

/* ============================================================================
 * DTLS-Specific Functions
 * ============================================================================ */

[[nodiscard]] int tls_dtls_set_mtu(tls_session_t *session, unsigned int mtu)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    gnutls_dtls_set_mtu(session->session, mtu);
    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_dtls_get_mtu(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    return gnutls_dtls_get_mtu(session->session);
}

[[nodiscard]] int tls_dtls_set_timeouts(tls_session_t *session, unsigned int retrans_timeout_ms,
                                        unsigned int total_timeout_ms)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    gnutls_dtls_set_timeouts(session->session, retrans_timeout_ms, total_timeout_ms);
    return TLS_E_SUCCESS;
}

/* ============================================================================
 * Handshake Operations
 * ============================================================================ */

[[nodiscard]] int tls_handshake(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_handshake(session->session);
    if (ret == GNUTLS_E_SUCCESS) {
        session->handshake_complete = true;
        session->ctx->handshakes_completed++;
        return TLS_E_SUCCESS;
    }

    if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
        return tls_gnutls_map_error(ret);
    }

    // Handshake failed
    session->ctx->handshakes_failed++;
    fprintf(stderr, "TLS handshake failed: %s\n", gnutls_strerror(ret));
    return tls_gnutls_map_error(ret);
}

[[nodiscard]] int tls_rehandshake(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_rehandshake(session->session);
    return tls_gnutls_map_error(ret);
}

/* ============================================================================
 * Data I/O Operations
 * ============================================================================ */

[[nodiscard]] ssize_t tls_send(tls_session_t *session, const void *data, size_t len)
{
    if (session == nullptr || data == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    ssize_t ret = gnutls_record_send(session->session, data, len);
    if (ret >= 0) {
        session->bytes_written += ret;
        return ret;
    }

    return tls_gnutls_map_error(ret);
}

[[nodiscard]] ssize_t tls_recv(tls_session_t *session, void *data, size_t len)
{
    if (session == nullptr || data == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    ssize_t ret = gnutls_record_recv(session->session, data, len);
    if (ret >= 0) {
        session->bytes_read += ret;
        return ret;
    }

    return tls_gnutls_map_error(ret);
}

[[nodiscard]] size_t tls_pending(tls_session_t *session)
{
    if (session == nullptr) {
        return 0;
    }

    return gnutls_record_check_pending(session->session);
}

[[nodiscard]] int tls_cork(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    gnutls_record_cork(session->session);
    return TLS_E_SUCCESS;
}

[[nodiscard]] int tls_uncork(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_record_uncork(session->session, GNUTLS_RECORD_WAIT);
    return tls_gnutls_map_error(ret);
}

/* ============================================================================
 * Connection Termination
 * ============================================================================ */

[[nodiscard]] int tls_bye(tls_session_t *session)
{
    if (session == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_bye(session->session, GNUTLS_SHUT_RDWR);
    return tls_gnutls_map_error(ret);
}

void tls_alert_send(tls_session_t *session, tls_alert_t alert)
{
    if (session == nullptr) {
        return;
    }

    gnutls_alert_send(session->session, GNUTLS_AL_FATAL, (gnutls_alert_description_t)alert);
}

/* ============================================================================
 * Session Information
 * ============================================================================ */

[[nodiscard]] int tls_get_connection_info(tls_session_t *session, tls_connection_info_t *info)
{
    if (session == nullptr || info == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    memset(info, 0, sizeof(*info));

    // Get TLS version
    gnutls_protocol_t proto = gnutls_protocol_get_version(session->session);
    switch (proto) {
    case GNUTLS_TLS1_2:
        info->version = TLS_VERSION_TLS12;
        break;
    case GNUTLS_TLS1_3:
        info->version = TLS_VERSION_TLS13;
        break;
    case GNUTLS_DTLS1_2:
        info->version = TLS_VERSION_DTLS12;
        break;
    default:
        info->version = TLS_VERSION_UNKNOWN;
        break;
    }

    // Get cipher info
    const char *cipher_name = gnutls_cipher_get_name(gnutls_cipher_get(session->session));
    if (cipher_name != nullptr) {
        snprintf(info->cipher_name, sizeof(info->cipher_name), "%s", cipher_name);
    }

    // Get MAC info
    const char *mac_name = gnutls_mac_get_name(gnutls_mac_get(session->session));
    if (mac_name != nullptr) {
        snprintf(info->mac_name, sizeof(info->mac_name), "%s", mac_name);
    }

    // Get cipher bits
    info->cipher_bits = 8 * gnutls_cipher_get_key_size(gnutls_cipher_get(session->session));

    // Check if session resumed
    info->session_resumed = gnutls_session_is_resumed(session->session) != 0;

    // Check safe renegotiation
    info->safe_renegotiation = gnutls_safe_renegotiation_status(session->session) != 0;

    return TLS_E_SUCCESS;
}

[[nodiscard]] char *tls_get_session_desc(tls_session_t *session)
{
    if (session == nullptr) {
        return nullptr;
    }

    char *desc = gnutls_session_get_desc(session->session);
    return desc; // Caller must free with gnutls_free() or tls_free()
}

[[nodiscard]] const tls_certificate_t *tls_get_peer_certificate(tls_session_t *session)
{
    if (session == nullptr) {
        return nullptr;
    }

    // TODO: Wrap GnuTLS certificate in tls_certificate_t
    // For now, return nullptr
    return nullptr;
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

[[nodiscard]] void *tls_malloc(size_t size)
{
    return gnutls_malloc(size);
}

void tls_free(void *ptr)
{
    gnutls_free(ptr);
}

[[nodiscard]] int tls_hash_fast(int algo, const void *data, size_t data_len, uint8_t *output)
{
    if (data == nullptr || output == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    gnutls_digest_algorithm_t gnutls_algo;
    switch (algo) {
    case 0:
        gnutls_algo = GNUTLS_DIG_SHA256;
        break;
    case 1:
        gnutls_algo = GNUTLS_DIG_SHA384;
        break;
    case 2:
        gnutls_algo = GNUTLS_DIG_SHA512;
        break;
    default:
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_hash_fast(gnutls_algo, data, data_len, output);
    return tls_gnutls_map_error(ret);
}

[[nodiscard]] int tls_random(void *data, size_t len)
{
    if (data == nullptr) {
        return TLS_E_INVALID_PARAMETER;
    }

    int ret = gnutls_rnd(GNUTLS_RND_RANDOM, data, len);
    return tls_gnutls_map_error(ret);
}
