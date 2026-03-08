/*
 * Copyright (C) 2025 ringwall Contributors
 *
 * This file is part of ringwall.
 *
 * ringwall is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * ringwall is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RINGWALL_TLS_GNUTLS_H
#define RINGWALL_TLS_GNUTLS_H

/**
 * GnuTLS Backend Implementation for TLS Abstraction Layer
 *
 * This file implements the TLS abstraction layer using GnuTLS.
 * It serves as the reference implementation and baseline for performance
 * comparison with the wolfSSL backend.
 *
 * Features:
 * - Full TLS 1.2 and TLS 1.3 support
 * - DTLS 1.2 support (DTLS 1.3 when GnuTLS adds it)
 * - Session caching and resumption
 * - PSK authentication
 * - Custom I/O callbacks
 * - Certificate verification
 * - OCSP stapling
 *
 * Requirements:
 * - GnuTLS 3.8.0 or newer (for TLS 1.3 improvements)
 * - C23 compiler support
 */

#include "tls_abstract.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/dtls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

/* Backend initialization (called by tls_global_init) */
[[nodiscard]] int tls_gnutls_init(void);
void tls_gnutls_deinit(void);

/* GnuTLS-specific opaque structures (internal) */
struct tls_context {
    gnutls_certificate_credentials_t x509_cred;
    gnutls_priority_t priority_cache;
    gnutls_dh_params_t dh_params;

    /* Configuration flags */
    bool is_server;
    bool is_dtls;
    bool verify_peer;

    /* Certificate and key paths (deferred loading for GnuTLS) */
    char *cert_file_path;
    char *key_file_path;

    /* Callbacks */
    tls_cert_verify_func_t verify_callback;
    void *verify_userdata;

    tls_psk_server_func_t psk_server_callback;
    void *psk_server_userdata;

    tls_db_store_func_t db_store;
    tls_db_retrieve_func_t db_retrieve;
    tls_db_remove_func_t db_remove;
    void *db_userdata;

    /* Statistics */
    uint64_t sessions_created;
    uint64_t handshakes_completed;
    uint64_t handshakes_failed;
};

struct tls_session {
    gnutls_session_t session;
    tls_context_t *ctx;

    /* User data pointer */
    void *user_ptr;

    /* Custom I/O */
    tls_push_func_t push_func;
    tls_pull_func_t pull_func;
    tls_pull_timeout_func_t pull_timeout_func;
    void *io_userdata;

    /* Statistics */
    uint64_t bytes_read;
    uint64_t bytes_written;
    bool handshake_complete;
};

struct tls_certificate {
    gnutls_x509_crt_t cert;
};

struct tls_private_key {
    gnutls_privkey_t key;
};

/* Helper functions for error mapping */
[[nodiscard]] int tls_gnutls_map_error(int gnutls_err);

/* GnuTLS I/O callback wrappers */
ssize_t tls_gnutls_push_wrapper(gnutls_transport_ptr_t ptr, const void *data, size_t len);
ssize_t tls_gnutls_pull_wrapper(gnutls_transport_ptr_t ptr, void *data, size_t len);
int tls_gnutls_pull_timeout_wrapper(gnutls_transport_ptr_t ptr, unsigned int ms);

#endif /* RINGWALL_TLS_GNUTLS_H */
