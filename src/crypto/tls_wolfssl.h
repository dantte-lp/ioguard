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

#ifndef RINGWALL_TLS_WOLFSSL_H
#define RINGWALL_TLS_WOLFSSL_H

/**
 * wolfSSL Backend Implementation for TLS Abstraction Layer
 *
 * This module implements the TLS abstraction API using wolfSSL v5.8.2+.
 *
 * Key Features:
 * - TLS 1.3 and DTLS 1.3 support (RFC 8446, RFC 9147)
 * - AES-NI hardware acceleration
 * - Session resumption and 0-RTT
 * - PSK, OCSP, and CRL support
 * - Constant-time crypto operations
 * - Memory-efficient design
 *
 * wolfSSL Configuration:
 * The wolfSSL library must be built with the following options:
 * - --enable-tls13         (TLS 1.3 support)
 * - --enable-dtls          (DTLS support)
 * - --enable-dtls13        (DTLS 1.3 support)
 * - --enable-session-ticket (Session resumption)
 * - --enable-alpn          (Application-Layer Protocol Negotiation)
 * - --enable-sni           (Server Name Indication)
 * - --enable-opensslextra  (OpenSSL compatibility layer)
 * - --enable-curve25519    (Modern elliptic curves)
 * - --enable-ed25519       (EdDSA signatures)
 * - --enable-quic          (QUIC protocol support)
 */

#include "tls_abstract.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <stdatomic.h>

// C23 standard compliance (accept C2x/C20 from GCC 14 as it provides C23 features)
#if __STDC_VERSION__ < 202000L
#error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

/* ============================================================================
 * Opaque Structure Definitions
 * ============================================================================ */

/**
 * TLS context structure (server/client configuration)
 *
 * This structure holds the wolfSSL context (WOLFSSL_CTX) and associated
 * configuration including certificates, cipher lists, and callbacks.
 *
 * Thread Safety: Multiple threads can create sessions from the same context
 * simultaneously. However, modifying the context is NOT thread-safe.
 */
struct tls_context {
    WOLFSSL_CTX *wolf_ctx;                // wolfSSL context
    bool is_server;                        // Server vs client
    bool is_dtls;                          // DTLS vs TLS

    // Certificates and keys
    char *cert_file;                       // Certificate file path
    char *key_file;                        // Private key file path
    char *ca_file;                         // CA bundle file path
    char *dh_params_file;                  // DH parameters file path
    bool has_certificate;                  // Certificate loaded flag

    // Priority/cipher configuration
    char *priority_string;                 // GnuTLS priority string (stored for reference)
    char *wolfssl_cipher_list;             // Translated wolfSSL cipher list

    // Certificate verification
    bool verify_peer;                      // Enable peer verification
    tls_cert_verify_func_t verify_callback;
    void *verify_userdata;

    // PSK callbacks
    tls_psk_server_func_t psk_server_callback;
    tls_psk_client_func_t psk_client_callback;
    void *psk_userdata;

    // Session cache callbacks
    tls_db_store_func_t db_store;
    tls_db_retrieve_func_t db_retrieve;
    tls_db_remove_func_t db_remove;
    void *db_userdata;
    unsigned int session_timeout_secs;

    // OCSP callback
    tls_ocsp_status_func_t ocsp_callback;
    void *ocsp_userdata;

    // Reference counting for multi-threaded safety
    atomic_int refcount;
};

/**
 * TLS session structure (individual connection)
 *
 * This structure holds the wolfSSL session (WOLFSSL) and connection-specific
 * state including I/O callbacks and user data.
 *
 * Thread Safety: Each session should be used by only one thread at a time.
 * Multiple sessions can be used concurrently from the same context.
 */
struct tls_session {
    WOLFSSL *wolf_ssl;                     // wolfSSL session
    tls_context_t *ctx;                    // Parent context

    // I/O functions
    tls_push_func_t push_func;
    tls_pull_func_t pull_func;
    tls_pull_timeout_func_t pull_timeout_func;
    void *io_userdata;

    // Session state
    bool handshake_complete;               // Handshake finished
    bool corked;                           // Record corking enabled

    // User pointer
    void *user_ptr;

    // DTLS-specific
    unsigned int dtls_mtu;

    // Error tracking
    int last_error;
};

/**
 * Certificate structure
 *
 * Wrapper around wolfSSL certificate (WOLFSSL_X509)
 */
struct tls_certificate {
    WOLFSSL_X509 *wolf_cert;
};

/**
 * Private key structure
 *
 * Wrapper around wolfSSL private key
 */
struct tls_private_key {
    void *wolf_key;                        // wolfSSL private key (type depends on algorithm)
};

/* ============================================================================
 * Backend-Specific Functions
 * ============================================================================ */

/**
 * Initialize wolfSSL backend
 *
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_wolfssl_init(void);

/**
 * Cleanup wolfSSL backend
 */
void tls_wolfssl_deinit(void);

/**
 * Map wolfSSL error code to TLS abstraction error
 *
 * @param wolf_error wolfSSL error code
 * @return Abstraction error code
 */
[[nodiscard]] int tls_wolfssl_map_error(int wolf_error);

/**
 * Translate GnuTLS priority string to wolfSSL cipher list
 *
 * This is a critical compatibility function that parses GnuTLS priority
 * strings (used by ocserv) and generates equivalent wolfSSL cipher lists.
 *
 * GnuTLS Priority String Format:
 * - Keywords: NORMAL, PERFORMANCE, SECURE128, SECURE192, SECURE256
 * - Modifiers: %SERVER_PRECEDENCE, %COMPAT, %NO_EXTENSIONS
 * - Exclusions: -VERS-TLS1.0, -CIPHER-AES-128-CBC
 * - Inclusions: +VERS-TLS1.3, +CIPHER-CHACHA20-POLY1305
 *
 * Example Translations:
 * - "NORMAL" -> "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
 * - "SECURE256" -> "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384"
 * - "PERFORMANCE" -> "AES128-GCM-SHA256:CHACHA20-POLY1305"
 *
 * @param gnutls_priority GnuTLS priority string
 * @param wolfssl_ciphers Output buffer for wolfSSL cipher list
 * @param ciphers_len Buffer size
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_wolfssl_translate_priority(const char *gnutls_priority,
                                                  char *wolfssl_ciphers,
                                                  size_t ciphers_len);

/**
 * Get wolfSSL version information
 *
 * @return Version string (e.g., "5.8.2")
 */
[[nodiscard]] const char* tls_wolfssl_get_version(void);

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * Note: Internal callback functions (wolfssl_io_send, wolfssl_io_recv,
 * wolfssl_psk_server_cb, wolfssl_psk_client_cb, wolfssl_verify_cb, etc.)
 * are defined as static in the implementation file and not exposed in this header.
 */

#endif // RINGWALL_TLS_WOLFSSL_H
