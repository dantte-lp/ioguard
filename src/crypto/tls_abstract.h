/*
 * Copyright (C) 2025 ioguard Contributors
 *
 * This file is part of ioguard.
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

#ifndef IOGUARD_TLS_ABSTRACT_H
#define IOGUARD_TLS_ABSTRACT_H

/**
 * TLS Abstraction Layer for ioguard
 *
 * This abstraction provides a unified API for both GnuTLS and wolfSSL backends,
 * enabling gradual migration and performance comparison. The API is designed to:
 *
 * 1. Support both TLS and DTLS protocols
 * 2. Enable runtime backend selection (GnuTLS vs wolfSSL)
 * 3. Maintain 100% Cisco Secure Client 5.x+ compatibility
 * 4. Provide modern C23 safety features (nodiscard, cleanup, etc.)
 * 5. Support all ocserv features (PSK, session caching, OCSP, etc.)
 *
 * Design Principles:
 * - Opaque types for backend independence
 * - Error codes compatible with both backends
 * - Zero-copy where possible
 * - Constant-time crypto operations
 * - Explicit lifetimes and ownership
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

// C23 standard compliance (accept C2x/C20 from GCC 14 as it provides C23 features)
#if __STDC_VERSION__ < 202000L
#    error "This code requires C23 standard (ISO/IEC 9899:2024) or C2x support (GCC 14+)"
#endif

// C23 provides nullptr as a keyword — no macro needed

/* ============================================================================
 * Constants and Configuration
 * ============================================================================ */

// Buffer sizes (using C23 digit separators for readability)
constexpr size_t TLS_MAX_CERT_SIZE = 16'384;
constexpr size_t TLS_MAX_SESSION_ID_SIZE = 256;
constexpr size_t TLS_MAX_SESSION_DATA_SIZE = 4'096;
constexpr size_t TLS_MAX_PSK_KEY_SIZE = 64;
constexpr size_t TLS_MAX_PRIORITY_STRING = 512;
constexpr size_t TLS_MAX_CIPHER_NAME = 128;
constexpr size_t TLS_MAX_ERROR_STRING = 256;

// TLS/DTLS versions (using C23 binary literals)
typedef enum {
    TLS_VERSION_UNKNOWN = 0,
    TLS_VERSION_SSL3 = 0b0011'0000,   // 0x30 (deprecated)
    TLS_VERSION_TLS10 = 0b0011'0001,  // 0x31
    TLS_VERSION_TLS11 = 0b0011'0010,  // 0x32
    TLS_VERSION_TLS12 = 0b0011'0011,  // 0x33
    TLS_VERSION_TLS13 = 0b0011'0100,  // 0x34
    TLS_VERSION_DTLS10 = 0b0001'0001, // DTLS 1.0 (based on TLS 1.1)
    TLS_VERSION_DTLS12 = 0b0001'0011, // DTLS 1.2 (based on TLS 1.2)
    TLS_VERSION_DTLS13 = 0b0001'0100, // DTLS 1.3 (based on TLS 1.3)
} tls_version_t;

/* ============================================================================
 * Backend Selection
 * ============================================================================ */

typedef enum {
    TLS_BACKEND_NONE = 0,
    TLS_BACKEND_GNUTLS,
    TLS_BACKEND_WOLFSSL,
} tls_backend_t;

/* ============================================================================
 * Opaque Types (Implementation-Specific)
 * ============================================================================ */

// Forward declarations for opaque types
typedef struct tls_context tls_context_t;
typedef struct tls_session tls_session_t;
typedef struct tls_credentials tls_credentials_t;
typedef struct tls_priority tls_priority_t;
typedef struct tls_certificate tls_certificate_t;
typedef struct tls_private_key tls_private_key_t;

/* ============================================================================
 * Data Structures
 * ============================================================================ */

// Datum structure (compatible with GnuTLS gnutls_datum_t)
typedef struct {
    uint8_t *data;
    size_t size;
} tls_datum_t;

// Session cache entry
typedef struct {
    uint8_t session_id[TLS_MAX_SESSION_ID_SIZE];
    size_t session_id_size;
    uint8_t session_data[TLS_MAX_SESSION_DATA_SIZE];
    size_t session_data_size;
    time_t expiration;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addr_len;
} tls_session_cache_entry_t;

// Certificate verification result
typedef struct {
    bool verified;
    uint32_t status_flags;
    char *issuer;
    char *subject;
    time_t not_before;
    time_t not_after;
} tls_cert_verify_result_t;

// TLS connection information
typedef struct {
    tls_version_t version;
    char cipher_name[TLS_MAX_CIPHER_NAME];
    char mac_name[TLS_MAX_CIPHER_NAME];
    uint16_t cipher_bits;
    bool session_resumed;
    bool safe_renegotiation;
} tls_connection_info_t;

/* ============================================================================
 * Error Codes
 * ============================================================================ */

typedef enum {
    TLS_E_SUCCESS = 0,
    TLS_E_AGAIN = -1,
    TLS_E_INTERRUPTED = -2,
    TLS_E_MEMORY_ERROR = -3,
    TLS_E_INVALID_REQUEST = -4,
    TLS_E_INVALID_PARAMETER = -5,
    TLS_E_FATAL_ALERT_RECEIVED = -6,
    TLS_E_WARNING_ALERT_RECEIVED = -7,
    TLS_E_UNEXPECTED_MESSAGE = -8,
    TLS_E_DECRYPTION_FAILED = -9,
    TLS_E_CERTIFICATE_ERROR = -10,
    TLS_E_CERTIFICATE_REQUIRED = -11,
    TLS_E_HANDSHAKE_FAILED = -12,
    TLS_E_SESSION_NOT_FOUND = -13,
    TLS_E_PREMATURE_TERMINATION = -14,
    TLS_E_REHANDSHAKE = -15,
    TLS_E_PUSH_ERROR = -16,
    TLS_E_PULL_ERROR = -17,
    TLS_E_BACKEND_ERROR = -100, // Backend-specific error (check tls_get_error)
} tls_error_t;

/* ============================================================================
 * Alert Codes (RFC 8446 Section 6)
 * ============================================================================ */

typedef enum {
    TLS_ALERT_CLOSE_NOTIFY = 0,
    TLS_ALERT_UNEXPECTED_MESSAGE = 10,
    TLS_ALERT_BAD_RECORD_MAC = 20,
    TLS_ALERT_DECRYPTION_FAILED = 21,
    TLS_ALERT_RECORD_OVERFLOW = 22,
    TLS_ALERT_DECOMPRESSION_FAILURE = 30,
    TLS_ALERT_HANDSHAKE_FAILURE = 40,
    TLS_ALERT_NO_CERTIFICATE = 41,
    TLS_ALERT_BAD_CERTIFICATE = 42,
    TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43,
    TLS_ALERT_CERTIFICATE_REVOKED = 44,
    TLS_ALERT_CERTIFICATE_EXPIRED = 45,
    TLS_ALERT_CERTIFICATE_UNKNOWN = 46,
    TLS_ALERT_ILLEGAL_PARAMETER = 47,
    TLS_ALERT_UNKNOWN_CA = 48,
    TLS_ALERT_ACCESS_DENIED = 49,
    TLS_ALERT_DECODE_ERROR = 50,
    TLS_ALERT_DECRYPT_ERROR = 51,
    TLS_ALERT_PROTOCOL_VERSION = 70,
    TLS_ALERT_INSUFFICIENT_SECURITY = 71,
    TLS_ALERT_INTERNAL_ERROR = 80,
    TLS_ALERT_INAPPROPRIATE_FALLBACK = 86,
    TLS_ALERT_USER_CANCELED = 90,
    TLS_ALERT_NO_RENEGOTIATION = 100,
    TLS_ALERT_MISSING_EXTENSION = 109,
    TLS_ALERT_UNSUPPORTED_EXTENSION = 110,
    TLS_ALERT_CERTIFICATE_UNOBTAINABLE = 111,
    TLS_ALERT_UNRECOGNIZED_NAME = 112,
    TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE = 114,
    TLS_ALERT_UNKNOWN_PSK_IDENTITY = 115,
    TLS_ALERT_CERTIFICATE_REQUIRED = 116,
    TLS_ALERT_NO_APPLICATION_PROTOCOL = 120,
} tls_alert_t;

/* ============================================================================
 * Callback Function Types
 * ============================================================================ */

// Custom I/O callbacks
typedef ssize_t (*tls_push_func_t)(void *userdata, const void *data, size_t len);
typedef ssize_t (*tls_pull_func_t)(void *userdata, void *data, size_t len);
typedef int (*tls_pull_timeout_func_t)(void *userdata, unsigned int ms);

// Certificate verification callback
typedef int (*tls_cert_verify_func_t)(tls_session_t *session, const tls_certificate_t *cert_chain,
                                      size_t chain_length, void *userdata);

// PSK callback (server side)
typedef int (*tls_psk_server_func_t)(tls_session_t *session, const char *username, uint8_t *key,
                                     size_t *key_size, void *userdata);

// PSK callback (client side)
typedef int (*tls_psk_client_func_t)(tls_session_t *session, char **username, uint8_t *key,
                                     size_t *key_size, void *userdata);

// Session cache callbacks
typedef int (*tls_db_store_func_t)(void *userdata, const tls_session_cache_entry_t *entry);
typedef int (*tls_db_retrieve_func_t)(void *userdata, const uint8_t *session_id,
                                      size_t session_id_size, tls_session_cache_entry_t *entry);
typedef int (*tls_db_remove_func_t)(void *userdata, const uint8_t *session_id,
                                    size_t session_id_size);

// OCSP status request callback
typedef int (*tls_ocsp_status_func_t)(tls_session_t *session, tls_datum_t *response,
                                      void *userdata);

/* ============================================================================
 * Library Initialization and Global State
 * ============================================================================ */

/**
 * Initialize TLS library subsystem
 *
 * @param backend Backend to use (TLS_BACKEND_GNUTLS or TLS_BACKEND_WOLFSSL)
 * @return TLS_E_SUCCESS on success, negative error code on failure
 *
 * Note: This function MUST be called before any other TLS operations.
 *       It is NOT thread-safe and should be called once during startup.
 */
[[nodiscard]] int tls_global_init(tls_backend_t backend);

/**
 * Cleanup TLS library subsystem
 *
 * Call this once during shutdown to free global resources.
 */
void tls_global_deinit(void);

/**
 * Get currently active backend
 *
 * @return Current backend (TLS_BACKEND_GNUTLS or TLS_BACKEND_WOLFSSL)
 */
[[nodiscard]] tls_backend_t tls_get_backend(void);

/**
 * Get library version string
 *
 * @return Version string (e.g., "wolfSSL 5.8.2" or "GnuTLS 3.8.0")
 */
[[nodiscard]] const char *tls_get_version_string(void);

/* ============================================================================
 * Context Management (Server/Client Configuration)
 * ============================================================================ */

/**
 * Create new TLS context
 *
 * @param is_server true for server context, false for client
 * @param is_dtls true for DTLS, false for TLS
 * @return Context pointer on success, nullptr on failure
 *
 * Note: Context holds server/client configuration including certificates,
 *       cipher suites, and verification settings. One context can be used
 *       for multiple sessions.
 */
[[nodiscard]] tls_context_t *tls_context_new(bool is_server, bool is_dtls);

/**
 * Free TLS context
 *
 * @param ctx Context to free
 *
 * Note: All sessions using this context must be freed first.
 */
void tls_context_free(tls_context_t *ctx);

/**
 * Set certificate file for context
 *
 * @param ctx Context
 * @param cert_file Path to certificate file (PEM or DER format)
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_cert_file(tls_context_t *ctx, const char *cert_file);

/**
 * Set private key file for context
 *
 * @param ctx Context
 * @param key_file Path to private key file (PEM or DER format)
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_key_file(tls_context_t *ctx, const char *key_file);

/**
 * Set CA certificate file for verification
 *
 * @param ctx Context
 * @param ca_file Path to CA certificate file or bundle
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_ca_file(tls_context_t *ctx, const char *ca_file);

/**
 * Set cipher priority string
 *
 * @param ctx Context
 * @param priority Priority string (GnuTLS format, will be translated for wolfSSL)
 * @return TLS_E_SUCCESS on success, negative error code on failure
 *
 * Example: "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0"
 *
 * Note: This is a critical compatibility function. The abstraction layer
 *       will parse GnuTLS priority strings and map them to appropriate
 *       wolfSSL cipher list configurations.
 */
[[nodiscard]] int tls_context_set_priority(tls_context_t *ctx, const char *priority);

/**
 * Set DH parameters file
 *
 * @param ctx Context
 * @param dh_file Path to DH parameters file
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_dh_params_file(tls_context_t *ctx, const char *dh_file);

/**
 * Enable/disable certificate verification
 *
 * @param ctx Context
 * @param verify true to enable verification, false to disable
 * @param callback Optional custom verification callback
 * @param userdata User data passed to callback
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_verify(tls_context_t *ctx, bool verify,
                                         tls_cert_verify_func_t callback, void *userdata);

/**
 * Set PSK credentials (server)
 *
 * @param ctx Context
 * @param callback PSK lookup callback
 * @param userdata User data passed to callback
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_psk_server_callback(tls_context_t *ctx,
                                                      tls_psk_server_func_t callback,
                                                      void *userdata);

/**
 * Set session cache callbacks
 *
 * @param ctx Context
 * @param store_func Store callback
 * @param retrieve_func Retrieve callback
 * @param remove_func Remove callback
 * @param userdata User data passed to callbacks
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_session_cache(tls_context_t *ctx, tls_db_store_func_t store_func,
                                                tls_db_retrieve_func_t retrieve_func,
                                                tls_db_remove_func_t remove_func, void *userdata);

/**
 * Set session cache timeout
 *
 * @param ctx Context
 * @param timeout_secs Timeout in seconds
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_context_set_session_timeout(tls_context_t *ctx, unsigned int timeout_secs);

/* ============================================================================
 * Session Management (Individual TLS/DTLS Connections)
 * ============================================================================ */

/**
 * Create new TLS session
 *
 * @param ctx Context to use
 * @return Session pointer on success, nullptr on failure
 */
[[nodiscard]] tls_session_t *tls_session_new(tls_context_t *ctx);

/**
 * Free TLS session
 *
 * @param session Session to free
 *
 * Note: This will gracefully close the connection if still open.
 */
void tls_session_free(tls_session_t *session);

/**
 * Set file descriptor for session
 *
 * @param session Session
 * @param fd File descriptor (socket)
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_session_set_fd(tls_session_t *session, int fd);

/**
 * Set custom I/O functions
 *
 * @param session Session
 * @param push_func Send function
 * @param pull_func Receive function
 * @param pull_timeout_func Timeout function (optional, can be nullptr)
 * @param userdata User data passed to I/O functions
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_session_set_io_functions(tls_session_t *session, tls_push_func_t push_func,
                                               tls_pull_func_t pull_func,
                                               tls_pull_timeout_func_t pull_timeout_func,
                                               void *userdata);

/**
 * Set user pointer for session
 *
 * @param session Session
 * @param ptr User pointer
 */
void tls_session_set_ptr(tls_session_t *session, void *ptr);

/**
 * Get user pointer from session
 *
 * @param session Session
 * @return User pointer
 */
[[nodiscard]] void *tls_session_get_ptr(tls_session_t *session);

/**
 * Set handshake timeout
 *
 * @param session Session
 * @param timeout_ms Timeout in milliseconds
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_session_set_timeout(tls_session_t *session, unsigned int timeout_ms);

/* ============================================================================
 * DTLS-Specific Functions
 * ============================================================================ */

/**
 * Set DTLS MTU
 *
 * @param session DTLS session
 * @param mtu MTU size in bytes
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_dtls_set_mtu(tls_session_t *session, unsigned int mtu);

/**
 * Get DTLS MTU
 *
 * @param session DTLS session
 * @return MTU size on success, negative error code on failure
 */
[[nodiscard]] int tls_dtls_get_mtu(tls_session_t *session);

/**
 * Set DTLS timeouts
 *
 * @param session DTLS session
 * @param retrans_timeout_ms Retransmission timeout in milliseconds
 * @param total_timeout_ms Total handshake timeout in milliseconds
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_dtls_set_timeouts(tls_session_t *session, unsigned int retrans_timeout_ms,
                                        unsigned int total_timeout_ms);

/* ============================================================================
 * Handshake Operations
 * ============================================================================ */

/**
 * Perform TLS/DTLS handshake
 *
 * @param session Session
 * @return TLS_E_SUCCESS on success, TLS_E_AGAIN if need to retry,
 *         negative error code on failure
 *
 * Note: This function may return TLS_E_AGAIN for non-blocking I/O.
 *       Caller should call again when socket is ready.
 */
[[nodiscard]] int tls_handshake(tls_session_t *session);

/**
 * Initiate renegotiation
 *
 * @param session Session
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_rehandshake(tls_session_t *session);

/* ============================================================================
 * Data I/O Operations
 * ============================================================================ */

/**
 * Send data over TLS/DTLS
 *
 * @param session Session
 * @param data Data buffer
 * @param len Data length
 * @return Number of bytes sent on success, negative error code on failure
 *
 * Note: May return TLS_E_AGAIN for non-blocking I/O.
 */
[[nodiscard]] ssize_t tls_send(tls_session_t *session, const void *data, size_t len);

/**
 * Receive data over TLS/DTLS
 *
 * @param session Session
 * @param data Data buffer
 * @param len Buffer size
 * @return Number of bytes received on success, negative error code on failure
 *
 * Note: May return TLS_E_AGAIN for non-blocking I/O.
 */
[[nodiscard]] ssize_t tls_recv(tls_session_t *session, void *data, size_t len);

/**
 * Check if data is pending in TLS buffer
 *
 * @param session Session
 * @return Number of bytes pending, 0 if none
 */
[[nodiscard]] size_t tls_pending(tls_session_t *session);

/**
 * Enable record corking (buffer multiple records)
 *
 * @param session Session
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_cork(tls_session_t *session);

/**
 * Flush corked records
 *
 * @param session Session
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_uncork(tls_session_t *session);

/* ============================================================================
 * Connection Termination
 * ============================================================================ */

/**
 * Send close_notify alert and close session
 *
 * @param session Session
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_bye(tls_session_t *session);

/**
 * Send alert and close session immediately
 *
 * @param session Session
 * @param alert Alert code to send
 */
void tls_alert_send(tls_session_t *session, tls_alert_t alert);

/* ============================================================================
 * Session Information
 * ============================================================================ */

/**
 * Get connection information
 *
 * @param session Session
 * @param info Output structure
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_get_connection_info(tls_session_t *session, tls_connection_info_t *info);

/**
 * Get session description string
 *
 * @param session Session
 * @return Description string (e.g., "TLS1.3-CHACHA20-POLY1305")
 *         Caller must free with tls_free()
 */
[[nodiscard]] char *tls_get_session_desc(tls_session_t *session);

/**
 * Get peer certificate
 *
 * @param session Session
 * @return Certificate pointer on success, nullptr if no certificate
 *         Certificate is valid until session is freed
 */
[[nodiscard]] const tls_certificate_t *tls_get_peer_certificate(tls_session_t *session);

/* ============================================================================
 * Error Handling
 * ============================================================================ */

/**
 * Get error string for error code
 *
 * @param error_code Error code
 * @return Error string (static buffer, do not free)
 */
[[nodiscard]] const char *tls_strerror(int error_code);

/**
 * Check if error is fatal
 *
 * @param error_code Error code
 * @return true if fatal, false if recoverable
 */
[[nodiscard]] bool tls_error_is_fatal(int error_code);

/**
 * Get last backend-specific error
 *
 * @return Backend error code
 */
[[nodiscard]] int tls_get_last_error(void);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * Allocate memory using TLS library allocator
 *
 * @param size Size to allocate
 * @return Pointer on success, nullptr on failure
 */
[[nodiscard]] void *tls_malloc(size_t size);

/**
 * Free memory allocated by TLS library
 *
 * @param ptr Pointer to free
 */
void tls_free(void *ptr);

/**
 * Fast hash computation
 *
 * @param algo Hash algorithm (0=SHA256, 1=SHA384, 2=SHA512)
 * @param data Input data
 * @param data_len Input length
 * @param output Output buffer (must be large enough for hash)
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_hash_fast(int algo, const void *data, size_t data_len, uint8_t *output);

/**
 * Generate random bytes
 *
 * @param data Output buffer
 * @param len Number of bytes to generate
 * @return TLS_E_SUCCESS on success, negative error code on failure
 */
[[nodiscard]] int tls_random(void *data, size_t len);

/* ============================================================================
 * C23 Cleanup Attribute Support
 * ============================================================================ */

/**
 * Cleanup function for automatic session freeing
 *
 * Usage:
 *   __attribute__((cleanup(tls_session_cleanup)))
 *   tls_session_t *session = tls_session_new(ctx);
 */
static inline void tls_session_cleanup(tls_session_t **session_ptr)
{
    if (session_ptr != nullptr && *session_ptr != nullptr) {
        tls_session_free(*session_ptr);
        *session_ptr = nullptr;
    }
}

/**
 * Cleanup function for automatic context freeing
 *
 * Usage:
 *   __attribute__((cleanup(tls_context_cleanup)))
 *   tls_context_t *ctx = tls_context_new(true, false);
 */
static inline void tls_context_cleanup(tls_context_t **ctx_ptr)
{
    if (ctx_ptr != nullptr && *ctx_ptr != nullptr) {
        tls_context_free(*ctx_ptr);
        *ctx_ptr = nullptr;
    }
}

#endif // IOGUARD_TLS_ABSTRACT_H
